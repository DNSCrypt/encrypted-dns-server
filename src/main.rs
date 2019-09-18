#![allow(clippy::assertions_on_constants)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate clap;
#[macro_use]
extern crate derivative;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_big_array;

mod config;
mod crypto;
mod dns;
mod dnscrypt;
mod dnscrypt_certs;
mod errors;
mod globals;

use config::*;
use crypto::*;
use dns::*;
use dnscrypt::*;
use dnscrypt_certs::*;
use errors::*;
use globals::*;

use byteorder::{BigEndian, ByteOrder};
use clap::Arg;
use dnsstamps::{InformalProperty, WithInformalProperty};
use failure::{bail, ensure};
use futures::prelude::*;
use parking_lot::Mutex;
use rand::prelude::*;
use std::collections::vec_deque::VecDeque;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::mem;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio_net::driver::Handle;

#[derive(Debug)]
struct UdpClientCtx {
    net_udp_socket: std::net::UdpSocket,
    client_addr: SocketAddr,
}

#[derive(Debug)]
struct TcpClientCtx {
    client_connection: TcpStream,
}

#[derive(Debug)]
enum ClientCtx {
    Udp(UdpClientCtx),
    Tcp(TcpClientCtx),
}

fn maybe_truncate_response(
    client_ctx: &ClientCtx,
    packet: Vec<u8>,
    response: Vec<u8>,
    original_packet_size: usize,
) -> Result<Vec<u8>, Error> {
    if let ClientCtx::Udp(_) = client_ctx {
        let encrypted_response_min_len = response.len() + DNSCRYPT_RESPONSE_MIN_OVERHEAD;
        if encrypted_response_min_len > original_packet_size
            || encrypted_response_min_len > DNSCRYPT_UDP_RESPONSE_MAX_SIZE
        {
            return Ok(dns::serve_truncated(packet)?);
        }
    }
    Ok(response)
}

async fn respond_to_query(
    client_ctx: ClientCtx,
    packet: Vec<u8>,
    response: Vec<u8>,
    original_packet_size: usize,
    shared_key: Option<SharedKey>,
    nonce: Option<[u8; DNSCRYPT_FULL_NONCE_SIZE]>,
) -> Result<(), Error> {
    ensure!(dns::is_response(&response), "Packet is not a response");
    let max_response_size = match client_ctx {
        ClientCtx::Udp(_) => original_packet_size,
        ClientCtx::Tcp(_) => DNSCRYPT_TCP_RESPONSE_MAX_SIZE,
    };
    let response = match &shared_key {
        None => response,
        Some(shared_key) => dnscrypt::encrypt(
            maybe_truncate_response(&client_ctx, packet, response, original_packet_size)?,
            shared_key,
            nonce.as_ref().unwrap(),
            max_response_size,
        )?,
    };
    match client_ctx {
        ClientCtx::Udp(client_ctx) => {
            let net_udp_socket = client_ctx.net_udp_socket;
            net_udp_socket.send_to(&response, client_ctx.client_addr)?;
        }
        ClientCtx::Tcp(client_ctx) => {
            let response_len = response.len();
            ensure!(
                response_len <= DNSCRYPT_TCP_RESPONSE_MAX_SIZE,
                "Packet too large"
            );
            let mut client_connection = client_ctx.client_connection;
            let mut binlen = [0u8, 0];
            BigEndian::write_u16(&mut binlen[..], response_len as u16);
            client_connection.write_all(&binlen).await?;
            client_connection.write_all(&response).await?;
            client_connection.flush();
        }
    }
    Ok(())
}

async fn handle_client_query(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    encrypted_packet: Vec<u8>,
) -> Result<(), Error> {
    let original_packet_size = encrypted_packet.len();
    let (shared_key, nonce, mut packet) =
        match dnscrypt::decrypt(&encrypted_packet, &globals.dnscrypt_encryption_params_set) {
            Ok(x) => x,
            Err(_) => {
                let packet = encrypted_packet;
                if let Some(synth_packet) = serve_certificates(
                    &packet,
                    &globals.provider_name,
                    &globals.dnscrypt_encryption_params_set,
                )? {
                    return respond_to_query(
                        client_ctx,
                        packet,
                        synth_packet,
                        original_packet_size,
                        None,
                        None,
                    )
                    .await;
                }
                bail!("Unencrypted query");
            }
        };
    ensure!(packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(&packet) == 1, "No question");
    ensure!(
        !dns::is_response(&packet),
        "Question expected, but got a response instead"
    );

    let original_tid = dns::tid(&packet);
    let tid = random();
    dns::set_tid(&mut packet, tid);
    let mut ext_socket = UdpSocket::bind(&globals.external_addr).await?;
    ext_socket.connect(&globals.upstream_addr).await?;
    set_edns_max_payload_size(&mut packet, DNS_MAX_PACKET_SIZE as u16)?;
    ext_socket.send(&packet).await?;
    let mut response;
    loop {
        response = vec![0u8; DNS_MAX_PACKET_SIZE];
        let (response_len, response_addr) = ext_socket.recv_from(&mut response[..]).await?;
        response.truncate(response_len);
        if response_addr == globals.upstream_addr
            && response_len >= DNS_HEADER_SIZE
            && dns::tid(&response) == tid
            && dns::qname(&packet)? == dns::qname(&response)?
        {
            break;
        }
        dbg!("Response collision");
    }
    if dns::is_truncated(&response) {
        let std_socket = match globals.external_addr {
            SocketAddr::V4(_) => net2::TcpBuilder::new_v4(),
            SocketAddr::V6(_) => net2::TcpBuilder::new_v6(),
        }?
        .bind(&globals.external_addr)?
        .to_tcp_stream()?;
        let mut ext_socket =
            TcpStream::connect_std(std_socket, &globals.upstream_addr, &Handle::default()).await?;
        ext_socket.set_nodelay(true)?;
        let mut binlen = [0u8, 0];
        BigEndian::write_u16(&mut binlen[..], packet.len() as u16);
        ext_socket.write_all(&binlen).await?;
        ext_socket.write_all(&packet).await?;
        ext_socket.flush();
        ext_socket.read_exact(&mut binlen).await?;
        let response_len = BigEndian::read_u16(&binlen) as usize;
        ensure!(
            (DNS_HEADER_SIZE..=DNS_MAX_PACKET_SIZE).contains(&response_len),
            "Unexpected response size"
        );
        response = vec![0u8; response_len];
        ext_socket.read_exact(&mut response).await?;
        ensure!(dns::tid(&response) == tid, "Unexpected transaction ID");
        ensure!(
            dns::qname(&packet)? == dns::qname(&response)?,
            "Unexpected query name in the response"
        );
    }
    dns::set_tid(&mut response, original_tid);
    respond_to_query(
        client_ctx,
        packet,
        response,
        original_packet_size,
        Some(shared_key),
        Some(nonce),
    )
    .await
}

async fn tcp_acceptor(globals: Arc<Globals>, tcp_listener: TcpListener) -> Result<(), Error> {
    let runtime = globals.runtime.clone();
    let mut tcp_listener = tcp_listener.incoming();
    let timeout = globals.tcp_timeout;
    let concurrent_connections = globals.tcp_concurrent_connections.clone();
    let active_connections = globals.tcp_active_connections.clone();
    while let Some(client) = tcp_listener.next().await {
        let mut client_connection: TcpStream = match client {
            Ok(client_connection) => client_connection,
            Err(e) => bail!(e),
        };
        let (tx, rx) = oneshot::channel::<()>();
        {
            let mut active_connections = active_connections.lock();
            if active_connections.len() >= globals.tcp_max_active_connections as _ {
                let tx_oldest = active_connections.pop_back().unwrap();
                let _ = tx_oldest.send(());
            }
            active_connections.push_front(tx);
        }
        concurrent_connections.fetch_add(1, Ordering::Relaxed);
        client_connection.set_nodelay(true)?;
        let globals = globals.clone();
        let concurrent_connections = concurrent_connections.clone();
        let fut = async {
            let mut binlen = [0u8, 0];
            client_connection.read_exact(&mut binlen).await?;
            let packet_len = BigEndian::read_u16(&binlen) as usize;
            ensure!(
                (DNSCRYPT_TCP_QUERY_MIN_SIZE..=DNSCRYPT_TCP_QUERY_MAX_SIZE).contains(&packet_len),
                "Unexpected query size"
            );
            let mut packet = vec![0u8; packet_len];
            client_connection.read_exact(&mut packet).await?;
            let client_ctx = ClientCtx::Tcp(TcpClientCtx { client_connection });
            let _ = handle_client_query(globals, client_ctx, packet).await;
            Ok(())
        };
        let fut_abort = rx;
        let fut_all = future::select(fut.boxed(), fut_abort).timeout(timeout);
        runtime.spawn(fut_all.map(move |_| {
            concurrent_connections.fetch_sub(1, Ordering::Relaxed);
        }));
    }
    Ok(())
}

async fn udp_acceptor(
    globals: Arc<Globals>,
    net_udp_socket: std::net::UdpSocket,
) -> Result<(), Error> {
    let runtime = globals.runtime.clone();
    let mut tokio_udp_socket = UdpSocket::try_from(net_udp_socket.try_clone()?)?;
    let timeout = globals.udp_timeout;
    let concurrent_connections = globals.udp_concurrent_connections.clone();
    let active_connections = globals.udp_active_connections.clone();
    loop {
        let mut packet = vec![0u8; DNSCRYPT_UDP_QUERY_MAX_SIZE];
        let (packet_len, client_addr) = tokio_udp_socket.recv_from(&mut packet).await?;
        if packet_len < DNSCRYPT_UDP_QUERY_MIN_SIZE {
            continue;
        }
        let net_udp_socket = net_udp_socket.try_clone()?;
        packet.truncate(packet_len);
        let client_ctx = ClientCtx::Udp(UdpClientCtx {
            net_udp_socket,
            client_addr,
        });
        let (tx, rx) = oneshot::channel::<()>();
        {
            let mut active_connections = active_connections.lock();
            if active_connections.len() >= globals.tcp_max_active_connections as _ {
                let tx_oldest = active_connections.pop_back().unwrap();
                let _ = tx_oldest.send(());
            }
            active_connections.push_front(tx);
        }
        concurrent_connections.fetch_add(1, Ordering::Relaxed);
        let globals = globals.clone();
        let concurrent_connections = concurrent_connections.clone();
        let fut = handle_client_query(globals, client_ctx, packet);
        let fut_abort = rx;
        let fut_all = future::select(fut.boxed(), fut_abort).timeout(timeout);
        runtime.spawn(fut_all.map(move |_| {
            concurrent_connections.fetch_sub(1, Ordering::Relaxed);
        }));
    }
}

async fn start(globals: Arc<Globals>, runtime: Arc<Runtime>) -> Result<(), Error> {
    let socket_addr: SocketAddr = globals.listen_addr;
    let tcp_listener = TcpListener::bind(&socket_addr).await?;
    let udp_socket = std::net::UdpSocket::bind(&socket_addr)?;
    runtime.spawn(tcp_acceptor(globals.clone(), tcp_listener).map(|_| {}));
    runtime.spawn(udp_acceptor(globals.clone(), udp_socket).map(|_| {}));
    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::init();
    crypto::init()?;
    let updater = coarsetime::Updater::new(1000).start()?;
    mem::forget(updater);

    let matches = app_from_crate!()
        .arg(
            Arg::with_name("listen-addr")
                .value_name("listen-addr")
                .takes_value(true)
                .default_value("127.0.0.1:4443")
                .required(true)
                .help("Address and port to listen to"),
        )
        .arg(
            Arg::with_name("provider-name")
                .value_name("provider-name")
                .takes_value(true)
                .default_value("2.dnscrypt.test")
                .required(true)
                .help("Provider name"),
        )
        .arg(
            Arg::with_name("upstream-addr")
                .value_name("upstream-addr")
                .takes_value(true)
                .default_value("9.9.9.9:53")
                .required(true)
                .help("Address and port of the upstream server"),
        )
        .arg(
            Arg::with_name("external-addr")
                .value_name("external-addr")
                .takes_value(true)
                .default_value("0.0.0.0:0")
                .required(true)
                .help("Address and port to connect from"),
        )
        .arg(
            Arg::with_name("state-file")
                .value_name("state-file")
                .takes_value(true)
                .default_value("dnscrypt-server.state")
                .required(true)
                .help("File to store the server state"),
        )
        .get_matches();

    let provider_name = match matches.value_of("provider-name").unwrap() {
        provider_name if provider_name.starts_with("2.dnscrypt.") => provider_name.to_string(),
        provider_name => format!("2.dnscrypt.{}", provider_name),
    };

    let listen_addr_s = matches.value_of("listen-addr").unwrap();
    let listen_addr: SocketAddr = listen_addr_s.parse()?;

    let upstream_addr_s = matches.value_of("upstream-addr").unwrap();
    let upstream_addr: SocketAddr = upstream_addr_s.parse()?;

    let external_addr_s = matches.value_of("external-addr").unwrap();
    let external_addr: SocketAddr = external_addr_s.parse()?;

    let udp_timeout = Duration::from_secs(10);
    let tcp_timeout = Duration::from_secs(10);

    let state_file_s = matches.value_of("state-file").unwrap();
    let state_file = PathBuf::from(state_file_s);

    let state = match File::open(&state_file) {
        Err(_) => {
            println!("No state file found... creating a new provider key");
            let state = State::new();
            let mut fp = File::create(&state_file)?;
            let state_bin = bincode::serialize(&state)?;
            fp.write_all(&state_bin)?;
            state
        }
        Ok(mut fp) => {
            println!(
                "State file [{}] found; using existing provider key",
                state_file.as_os_str().to_string_lossy()
            );
            let mut state_bin = vec![];
            fp.read_to_end(&mut state_bin)?;
            bincode::deserialize(&state_bin)?
        }
    };
    let provider_kp = state.provider_kp;

    info!("Server address: {}", listen_addr);
    info!("Provider public key: {}", provider_kp.pk.as_string());
    info!("Provider name: {}", provider_name);

    let stamp = dnsstamps::DNSCryptBuilder::new(dnsstamps::DNSCryptProvider::new(
        provider_name.clone(),
        provider_kp.pk.as_bytes().to_vec(),
    ))
    .with_addr(listen_addr_s.to_string())
    .with_informal_property(InformalProperty::DNSSEC)
    .with_informal_property(InformalProperty::NoFilters)
    .with_informal_property(InformalProperty::NoLogs)
    .serialize()
    .unwrap();
    println!("DNS Stamp: {}", stamp);

    let dnscrypt_encryption_params = DNSCryptEncryptionParams::new(&provider_kp);

    let runtime = Arc::new(Runtime::new()?);
    let udp_max_active_connections = 1000;
    let tcp_max_active_connections = 100;
    let globals = Arc::new(Globals {
        runtime: runtime.clone(),
        dnscrypt_encryption_params_set: vec![dnscrypt_encryption_params],
        provider_name,
        listen_addr,
        upstream_addr,
        external_addr,
        tcp_timeout,
        udp_timeout,
        udp_concurrent_connections: Arc::new(AtomicU32::new(0)),
        tcp_concurrent_connections: Arc::new(AtomicU32::new(0)),
        udp_max_active_connections,
        tcp_max_active_connections,
        udp_active_connections: Arc::new(Mutex::new(VecDeque::with_capacity(
            udp_max_active_connections as _,
        ))),
        tcp_active_connections: Arc::new(Mutex::new(VecDeque::with_capacity(
            tcp_max_active_connections as _,
        ))),
    });
    runtime.spawn(start(globals, runtime.clone()).map(|_| ()));
    runtime.block_on(future::pending::<()>());

    Ok(())
}
