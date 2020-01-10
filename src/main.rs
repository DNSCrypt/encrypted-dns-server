#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::cognitive_complexity)]
#![allow(dead_code)]

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate clap;
#[macro_use]
extern crate derivative;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_big_array;
#[cfg(feature = "metrics")]
#[macro_use]
extern crate prometheus;

mod anonymized_dns;
mod blacklist;
mod cache;
mod config;
mod crypto;
mod dns;
mod dnscrypt;
mod dnscrypt_certs;
mod errors;
mod globals;
#[cfg(feature = "metrics")]
mod metrics;
mod resolver;
#[cfg(feature = "metrics")]
mod varz;

use anonymized_dns::*;
use blacklist::*;
use cache::*;
use config::*;
use crypto::*;
use dns::*;
use dnscrypt::*;
use dnscrypt_certs::*;
use errors::*;
use globals::*;
#[cfg(feature = "metrics")]
use varz::*;

use byteorder::{BigEndian, ByteOrder};
use clap::Arg;
use clockpro_cache::ClockProCache;
use dnsstamps::{InformalProperty, WithInformalProperty};
use futures::join;
use futures::prelude::*;
use parking_lot::Mutex;
use parking_lot::RwLock;
use privdrop::PrivDrop;
use rand::prelude::*;
use siphasher::sip128::SipHasher13;
use std::collections::vec_deque::VecDeque;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct UdpClientCtx {
    net_udp_socket: std::net::UdpSocket,
    client_addr: SocketAddr,
}

#[derive(Debug)]
pub struct TcpClientCtx {
    client_connection: TcpStream,
}

#[derive(Debug)]
pub enum ClientCtx {
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
            return Ok(dns::serve_truncated_response(packet)?);
        }
    }
    Ok(response)
}

pub async fn respond_to_query(client_ctx: ClientCtx, response: Vec<u8>) -> Result<(), Error> {
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

async fn encrypt_and_respond_to_query(
    globals: Arc<Globals>,
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
    globals.varz.client_queries_resolved.inc();
    if dns::rcode_nxdomain(&response) {
        globals.varz.client_queries_rcode_nxdomain.inc();
    }
    respond_to_query(client_ctx, response).await
}

async fn handle_client_query(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    encrypted_packet: Vec<u8>,
) -> Result<(), Error> {
    let original_packet_size = encrypted_packet.len();
    ensure!(original_packet_size >= DNS_HEADER_SIZE, "Short packet");
    debug_assert!(DNSCRYPT_QUERY_MIN_OVERHEAD > ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len());
    if globals.anonymized_dns_enabled
        && original_packet_size >= ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len() + DNS_HEADER_SIZE
        && encrypted_packet[..ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()]
            == ANONYMIZED_DNSCRYPT_QUERY_MAGIC
    {
        return handle_anonymized_dns(
            globals,
            client_ctx,
            &encrypted_packet[ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()..],
        )
        .await;
    }
    if !globals.dnscrypt_enabled {
        return Ok(());
    }
    let mut dnscrypt_encryption_params_set = vec![];
    for params in &**globals.dnscrypt_encryption_params_set.read() {
        dnscrypt_encryption_params_set.push((*params).clone())
    }
    let (shared_key, nonce, mut packet) =
        match dnscrypt::decrypt(&encrypted_packet, &dnscrypt_encryption_params_set) {
            Ok(x) => x,
            Err(_) => {
                let packet = encrypted_packet;
                if let Some(synth_packet) = serve_certificates(
                    &packet,
                    &globals.provider_name,
                    &dnscrypt_encryption_params_set,
                )? {
                    return encrypt_and_respond_to_query(
                        globals,
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
    let response = resolver::get_cached_response_or_resolve(&globals, &mut packet).await?;

    let qname = dns::qname(&response);
    let qname = qname
        .as_ref()
        .map(|x| std::str::from_utf8(x).unwrap_or("?"))
        .unwrap_or("?");
    writeln!(
        globals.log.lock(),
        "{}\t{}\t{}",
        qname,
        packet.len(),
        response.len()
    )
    .unwrap();

    encrypt_and_respond_to_query(
        globals,
        client_ctx,
        packet,
        response,
        original_packet_size,
        Some(shared_key),
        Some(nonce),
    )
    .await
}

async fn tls_proxy(
    globals: Arc<Globals>,
    binlen: [u8; 2],
    mut client_connection: TcpStream,
) -> Result<(), Error> {
    let tls_upstream_addr = match &globals.tls_upstream_addr {
        None => return Ok(()),
        Some(tls_upstream_addr) => tls_upstream_addr,
    };
    let std_socket = match globals.external_addr {
        Some(x @ SocketAddr::V4(_)) => net2::TcpBuilder::new_v4()?.bind(&x)?.to_tcp_stream()?,
        Some(x @ SocketAddr::V6(_)) => net2::TcpBuilder::new_v6()?.bind(&x)?.to_tcp_stream()?,
        None => match tls_upstream_addr {
            SocketAddr::V4(_) => net2::TcpBuilder::new_v4()?.to_tcp_stream()?,
            SocketAddr::V6(_) => net2::TcpBuilder::new_v6()?.to_tcp_stream()?,
        },
    };
    let mut ext_socket = TcpStream::connect_std(std_socket, tls_upstream_addr).await?;
    let (mut erh, mut ewh) = ext_socket.split();
    let (mut rh, mut wh) = client_connection.split();
    ewh.write_all(&binlen).await?;
    let fut_proxy_1 = tokio::io::copy(&mut rh, &mut ewh);
    let fut_proxy_2 = tokio::io::copy(&mut erh, &mut wh);
    match join!(fut_proxy_1, fut_proxy_2) {
        (Ok(_), Ok(_)) => Ok(()),
        _ => bail!("TLS proxy error"),
    }
}

async fn tcp_acceptor(globals: Arc<Globals>, mut tcp_listener: TcpListener) -> Result<(), Error> {
    let runtime_handle = globals.runtime_handle.clone();
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
        let _count = concurrent_connections.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        let varz = globals.varz.clone();
        #[cfg(feature = "metrics")]
        {
            varz.inflight_tcp_queries.set(_count.saturating_add(1) as _);
            varz.client_queries_tcp.inc();
        }
        client_connection.set_nodelay(true)?;
        let globals = globals.clone();
        let concurrent_connections = concurrent_connections.clone();
        let fut = async {
            let mut binlen = [0u8, 0];
            client_connection.read_exact(&mut binlen).await?;
            let packet_len = BigEndian::read_u16(&binlen) as usize;
            if packet_len == 0x1603 {
                return tls_proxy(globals, binlen, client_connection).await;
            }
            ensure!(
                (DNS_HEADER_SIZE..=DNSCRYPT_TCP_QUERY_MAX_SIZE).contains(&packet_len),
                "Unexpected query size"
            );
            let mut packet = vec![0u8; packet_len];
            client_connection.read_exact(&mut packet).await?;
            let client_ctx = ClientCtx::Tcp(TcpClientCtx { client_connection });
            let _ = handle_client_query(globals, client_ctx, packet).await;
            Ok(())
        };
        let fut_abort = rx;
        let fut_all = tokio::time::timeout(timeout, future::select(fut.boxed(), fut_abort));
        runtime_handle.spawn(fut_all.map(move |_| {
            let _count = concurrent_connections.fetch_sub(1, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            varz.inflight_tcp_queries.set(_count.saturating_sub(1) as _);
        }));
    }
    Ok(())
}

#[allow(unreachable_code)]
async fn udp_acceptor(
    globals: Arc<Globals>,
    net_udp_socket: std::net::UdpSocket,
) -> Result<(), Error> {
    let runtime_handle = globals.runtime_handle.clone();
    let mut tokio_udp_socket = UdpSocket::try_from(net_udp_socket.try_clone()?)?;
    let timeout = globals.udp_timeout;
    let concurrent_connections = globals.udp_concurrent_connections.clone();
    let active_connections = globals.udp_active_connections.clone();
    loop {
        let mut packet = vec![0u8; DNSCRYPT_UDP_QUERY_MAX_SIZE];
        let (packet_len, client_addr) = tokio_udp_socket.recv_from(&mut packet).await?;
        if packet_len < DNS_HEADER_SIZE {
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
        let _count = concurrent_connections.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        let varz = globals.varz.clone();
        #[cfg(feature = "metrics")]
        {
            varz.inflight_udp_queries.set(_count.saturating_add(1) as _);
            varz.client_queries_udp.inc();
        }
        let globals = globals.clone();
        let concurrent_connections = concurrent_connections.clone();
        let fut = handle_client_query(globals, client_ctx, packet);
        let fut_abort = rx;
        let fut_all = tokio::time::timeout(timeout, future::select(fut.boxed(), fut_abort));
        runtime_handle.spawn(fut_all.map(move |_| {
            let _count = concurrent_connections.fetch_sub(1, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            varz.inflight_udp_queries.set(_count.saturating_sub(1) as _);
        }));
    }
}

async fn start(
    globals: Arc<Globals>,
    runtime_handle: Handle,
    listeners: Vec<(std::net::TcpListener, std::net::UdpSocket)>,
) -> Result<(), Error> {
    for listener in listeners {
        let tcp_listener_str = format!("{:?}", listener.0);
        let tokio_tcp_listener = match TcpListener::from_std(listener.0) {
            Ok(tcp_listener) => tcp_listener,
            Err(e) => bail!("{}/TCP: {}", tcp_listener_str, e),
        };
        runtime_handle.spawn(tcp_acceptor(globals.clone(), tokio_tcp_listener).map(|_| {}));
        runtime_handle.spawn(udp_acceptor(globals.clone(), listener.1).map(|_| {}));
    }
    Ok(())
}

fn bind_listeners(
    listen_addrs: &[SocketAddr],
) -> Result<Vec<(std::net::TcpListener, std::net::UdpSocket)>, Error> {
    let mut sockets = Vec::with_capacity(listen_addrs.len());
    for listen_addr in listen_addrs {
        let tcp_listener = match listen_addr {
            SocketAddr::V4(_) => net2::TcpBuilder::new_v4()?
                .reuse_address(true)?
                .bind(&listen_addr)?
                .listen(1024)?,
            SocketAddr::V6(_) => net2::TcpBuilder::new_v6()?
                .reuse_address(true)?
                .only_v6(true)?
                .bind(&listen_addr)?
                .listen(1024)?,
        };
        let std_socket = match listen_addr {
            SocketAddr::V4(_) => net2::UdpBuilder::new_v4()?
                .reuse_address(true)?
                .bind(&listen_addr),
            SocketAddr::V6(_) => net2::UdpBuilder::new_v6()?
                .reuse_address(true)?
                .only_v6(true)?
                .bind(&listen_addr),
        };
        let udp_socket = match std_socket {
            Ok(udp_socket) => udp_socket,
            Err(e) => bail!("{}/UDP: {}", listen_addr, e),
        };
        sockets.push((tcp_listener, udp_socket))
    }
    Ok(sockets)
}

fn privdrop(config: &Config) -> Result<(), Error> {
    let mut pd = PrivDrop::default();
    if let Some(user) = &config.user {
        pd = pd.user(user);
    }
    if let Some(group) = &config.group {
        pd = pd.group(group);
    }
    if let Some(chroot) = &config.chroot {
        if !config.daemonize {
            pd = pd.chroot(chroot);
        }
    }
    if config.user.is_some() || config.group.is_some() || config.chroot.is_some() {
        info!("Dropping privileges");
        pd.apply()?;
    }
    if config.daemonize {
        let mut daemon = daemonize_simple::Daemonize::default();
        daemon.stdout_file = config.log_file.clone();
        daemon.stderr_file = config.log_file.clone();
        daemon.pid_file = config.pid_file.clone();
        if let Some(chroot) = &config.chroot {
            daemon.chdir = Some(chroot.into());
            daemon.chroot = true;
        }
        daemon
            .doit()
            .map_err(|e| anyhow!("Unable to daemonize: [{}]", e))?;
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::Builder::from_default_env()
        .write_style(env_logger::WriteStyle::Never)
        .format_module_path(false)
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .target(env_logger::Target::Stdout)
        .init();

    crypto::init()?;
    let time_updater = coarsetime::Updater::new(1000).start()?;
    let matches = app_from_crate!()
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .value_name("file")
                .takes_value(true)
                .default_value("encrypted-dns.toml")
                .help("Path to the configuration file"),
        )
        .arg(
            Arg::with_name("import-from-dnscrypt-wrapper")
                .long("import-from-dnscrypt-wrapper")
                .value_name("secret.key file")
                .takes_value(true)
                .help("Path to the dnscrypt-wrapper secret key"),
        )
        .arg(
            Arg::with_name("dry-run")
                .long("dry-run")
                .takes_value(false)
                .help("Only print the connection information and quit"),
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = Config::from_path(config_path)?;
    let dnscrypt_enabled = config.dnscrypt.enabled.unwrap_or(true);
    let provider_name = match &config.dnscrypt.provider_name {
        provider_name if provider_name.starts_with("2.dnscrypt-cert.") => provider_name.to_string(),
        provider_name => format!("2.dnscrypt-cert.{}", provider_name),
    };
    let external_addr = config.external_addr.map(|addr| SocketAddr::new(addr, 0));

    let mut runtime_builder = tokio::runtime::Builder::new();
    runtime_builder.enable_all();
    runtime_builder.threaded_scheduler();
    runtime_builder.thread_name("encrypted-dns-");
    let mut runtime = runtime_builder.build()?;

    let listen_addrs: Vec<_> = config.listen_addrs.iter().map(|x| x.local).collect();
    let listeners = bind_listeners(&listen_addrs)
        .map_err(|e| {
            error!("Unable to listen to the requested IPs and ports: [{}]", e);
            std::process::exit(1);
        })
        .unwrap();
    privdrop(&config)?;

    let key_cache_capacity = config.dnscrypt.key_cache_capacity;
    let cache_capacity = config.cache_capacity;
    let state_file = &config.state_file;

    if let Some(secret_key_path) = matches.value_of("import-from-dnscrypt-wrapper") {
        let secret_key_path = Path::new(secret_key_path);
        warn!("Importing dnscrypt-wrapper key");
        let mut key = vec![];
        File::open(secret_key_path)?.read_to_end(&mut key)?;
        if key.len() != 64 {
            bail!("Key doesn't have the expected size");
        }
        let mut sign_sk_u8 = [0u8; 64];
        let mut sign_pk_u8 = [0u8; 32];
        sign_sk_u8.copy_from_slice(&key);
        sign_pk_u8.copy_from_slice(&key[32..]);
        let provider_kp = SignKeyPair {
            sk: SignSK::from_bytes(sign_sk_u8),
            pk: SignPK::from_bytes(sign_pk_u8),
        };
        runtime.block_on(
            State::with_key_pair(provider_kp, key_cache_capacity).async_save(state_file),
        )?;
        warn!("Key successfully imported");
    }

    let (state, state_is_new) = match State::from_file(state_file, key_cache_capacity) {
        Err(_) => {
            warn!("No state file found... creating a new provider key");
            let state = State::new(key_cache_capacity);
            runtime.block_on(state.async_save(state_file))?;
            (state, true)
        }
        Ok(state) => {
            info!(
                "State file [{}] found; using existing provider key",
                state_file.as_os_str().to_string_lossy()
            );
            (state, false)
        }
    };
    let provider_kp = state.provider_kp;
    for listen_addr_s in &config.listen_addrs {
        info!("Public server address: {}", listen_addr_s.external);
        info!("Provider public key: {}", provider_kp.pk.as_string());
        info!("Provider name: {}", provider_name);
        let mut stamp = dnsstamps::DNSCryptBuilder::new(dnsstamps::DNSCryptProvider::new(
            provider_name.clone(),
            provider_kp.pk.as_bytes().to_vec(),
        ))
        .with_addr(listen_addr_s.external.to_string());
        if config.dnscrypt.dnssec {
            stamp = stamp.with_informal_property(InformalProperty::DNSSEC);
        }
        if config.dnscrypt.no_filters {
            stamp = stamp.with_informal_property(InformalProperty::NoFilters);
        }
        if config.dnscrypt.no_logs {
            stamp = stamp.with_informal_property(InformalProperty::NoLogs);
        }
        let stamp = stamp.serialize().unwrap();
        info!("DNS Stamp: {}", stamp);

        if let Some(anonymized_dns) = &config.anonymized_dns {
            if anonymized_dns.enabled {
                let relay_stamp = dnsstamps::DNSCryptRelayBuilder::new()
                    .with_addr(listen_addr_s.external.to_string())
                    .serialize()
                    .unwrap();
                info!("DNS Stamp for Anonymized DNS relaying: {}", relay_stamp);
            }
        }
    }
    if matches.is_present("dry-run") {
        return Ok(());
    }
    let dnscrypt_encryption_params_set = state
        .dnscrypt_encryption_params_set
        .into_iter()
        .map(Arc::new)
        .collect::<Vec<_>>();

    let (sh_k0, sh_k1) = rand::thread_rng().gen();
    let hasher = SipHasher13::new_with_keys(sh_k0, sh_k1);

    let cache = Cache::new(
        ClockProCache::new(cache_capacity)
            .map_err(|e| anyhow!("Unable to create the DNS cache: [{}]", e))?,
        config.cache_ttl_min,
        config.cache_ttl_max,
        config.cache_ttl_error,
    );
    let cert_cache = Cache::new(
        ClockProCache::new(RELAYED_CERT_CACHE_SIZE)
            .map_err(|e| anyhow!("Unable to create the relay cert cache: [{}]", e))?,
        RELAYED_CERT_CACHE_TTL,
        RELAYED_CERT_CACHE_TTL,
        RELAYED_CERT_CACHE_TTL,
    );
    let blacklist = match config.filtering.domain_blacklist {
        None => None,
        Some(path) => Some(
            BlackList::load(&path)
                .map_err(|e| anyhow!("Unable to load the blacklist [{:?}]: [{}]", path, e))?,
        ),
    };
    let undelegated_list = match config.filtering.undelegated_list {
        None => None,
        Some(path) => Some(BlackList::load(&path).map_err(|e| {
            anyhow!(
                "Unable to load the list of undelegated TLDs [{:?}]: [{}]",
                path,
                e
            )
        })?),
    };
    let ignore_unqualified_hostnames = config
        .filtering
        .ignore_unqualified_hostnames
        .unwrap_or(true);
    let (
        anonymized_dns_enabled,
        anonymized_dns_allowed_ports,
        anonymized_dns_allow_non_reserved_ports,
        anonymized_dns_blacklisted_ips,
    ) = match config.anonymized_dns {
        None => (false, vec![], false, vec![]),
        Some(anonymized_dns) => (
            anonymized_dns.enabled,
            anonymized_dns.allowed_ports,
            anonymized_dns.allow_non_reserved_ports.unwrap_or(false),
            anonymized_dns.blacklisted_ips,
        ),
    };
    let runtime_handle = runtime.handle();

    let log = File::create("/tmp/packet-sizes.log").unwrap();
    let log = Arc::new(Mutex::new(BufWriter::new(log)));

    let globals = Arc::new(Globals {
        runtime_handle: runtime_handle.clone(),
        state_file: state_file.to_path_buf(),
        dnscrypt_encryption_params_set: Arc::new(RwLock::new(Arc::new(
            dnscrypt_encryption_params_set,
        ))),
        provider_name,
        provider_kp,
        listen_addrs,
        upstream_addr: config.upstream_addr,
        tls_upstream_addr: config.tls.upstream_addr,
        external_addr,
        tcp_timeout: Duration::from_secs(u64::from(config.tcp_timeout)),
        udp_timeout: Duration::from_secs(u64::from(config.udp_timeout)),
        udp_concurrent_connections: Arc::new(AtomicU32::new(0)),
        tcp_concurrent_connections: Arc::new(AtomicU32::new(0)),
        udp_max_active_connections: config.udp_max_active_connections,
        tcp_max_active_connections: config.tcp_max_active_connections,
        udp_active_connections: Arc::new(Mutex::new(VecDeque::with_capacity(
            config.udp_max_active_connections as _,
        ))),
        tcp_active_connections: Arc::new(Mutex::new(VecDeque::with_capacity(
            config.tcp_max_active_connections as _,
        ))),
        key_cache_capacity,
        hasher,
        cache,
        cert_cache,
        blacklist,
        undelegated_list,
        ignore_unqualified_hostnames,
        dnscrypt_enabled,
        anonymized_dns_enabled,
        anonymized_dns_allowed_ports,
        anonymized_dns_allow_non_reserved_ports,
        anonymized_dns_blacklisted_ips,
        #[cfg(feature = "metrics")]
        varz: Varz::default(),
        log,
    });
    let updater = DNSCryptEncryptionParamsUpdater::new(globals.clone());
    if !state_is_new {
        updater.update();
    }
    #[cfg(feature = "metrics")]
    {
        if let Some(metrics_config) = config.metrics {
            runtime_handle.spawn(
                metrics::prometheus_service(
                    globals.varz.clone(),
                    metrics_config,
                    runtime_handle.clone(),
                )
                .map_err(|e| {
                    error!("Unable to start the metrics service: [{}]", e);
                    std::process::exit(1);
                })
                .map(|_| ()),
            );
        }
    }
    runtime_handle.spawn(
        start(globals, runtime_handle.clone(), listeners)
            .map_err(|e| {
                error!("Unable to start the service: [{}]", e);
                std::process::exit(1);
            })
            .map(|_| ()),
    );
    runtime.block_on(updater.run());
    time_updater.stop()?;
    Ok(())
}
