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

mod config;
mod crypto;
mod dns;
mod dnscrypt_certs;
mod errors;
mod globals;

use crypto::*;
use dns::*;
use dnscrypt_certs::*;
use errors::*;
use globals::*;

use byteorder::{BigEndian, ByteOrder};
use clap::Arg;
use dnsstamps::{InformalProperty, WithInformalProperty};
use failure::{bail, ensure};
use futures::prelude::*;
use futures::{FutureExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::prelude::*;
use tokio::runtime::Runtime;

const DNSCRYPT_QUERY_MIN_SIZE: usize = 12;
const DNSCRYPT_QUERY_MAX_SIZE: usize = 512;

async fn tcp_acceptor(globals: Arc<Globals>, tcp_listener: TcpListener) -> Result<(), Error> {
    let mut tcp_listener = tcp_listener.incoming();
    while let Some(client) = tcp_listener.next().await {
        let mut client = match client {
            Ok(client) => client,
            Err(_) => continue,
        };
        let mut binlen = [0u8, 0];
        client.read_exact(&mut binlen).await?;
        let packet_len = BigEndian::read_u16(&binlen) as usize;
        ensure!(
            (DNSCRYPT_QUERY_MIN_SIZE..=DNSCRYPT_QUERY_MAX_SIZE).contains(&packet_len),
            "Unexpected query size"
        );
        let mut packet = vec![0u8; packet_len];
        client.read_exact(&mut packet).await?;
        dbg!(packet);
    }
    Ok(())
}

async fn udp_acceptor(globals: Arc<Globals>, mut udp_listener: UdpSocket) -> Result<(), Error> {
    loop {
        let mut packet = vec![0u8; DNSCRYPT_QUERY_MAX_SIZE];
        let (packet_len, client_addr) = udp_listener.recv_from(&mut packet).await?;
        dbg!(&packet);
        let mut packet = &mut packet[..packet_len];
        if let Some(synth_packet) =
            serve_certificates(&packet, &globals.provider_name, &globals.dnscrypt_certs)?
        {
            let _ = udp_listener.send_to(&synth_packet, client_addr).await;
            continue;
        }
        truncate(&mut packet);
        let _ = udp_listener.send_to(&packet, client_addr).await;
    }
}

async fn start(globals: Arc<Globals>, runtime: Arc<Runtime>) -> Result<(), Error> {
    let socket_addr: SocketAddr = globals.listen_addr;
    let tcp_listener = TcpListener::bind(&socket_addr).await?;
    let udp_listener = UdpSocket::bind(&socket_addr).await?;
    runtime.spawn(tcp_acceptor(globals.clone(), tcp_listener).map(|_| {}));
    runtime.spawn(udp_acceptor(globals.clone(), udp_listener).map(|_| {}));
    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::init();
    crypto::init()?;

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
        .get_matches();
    let listen_addr = matches
        .value_of("listen-addr")
        .unwrap()
        .to_ascii_lowercase();
    let provider_name = match matches.value_of("provider-name").unwrap() {
        provider_name if provider_name.starts_with("2.dnscrypt.") => provider_name.to_string(),
        provider_name => format!("2.dnscrypt.{}", provider_name),
    };
    let listen_addr_s = matches.value_of("listen-addr").unwrap();
    let listen_addr: SocketAddr = listen_addr_s.parse()?;
    let resolver_kp = SignKeyPair::new();

    info!("Server address: {}", listen_addr);
    info!("Provider public key: {}", resolver_kp.pk.as_string());
    info!("Provider name: {}", provider_name);

    let stamp = dnsstamps::DNSCryptBuilder::new(dnsstamps::DNSCryptProvider::new(
        provider_name.clone(),
        resolver_kp.pk.as_bytes().to_vec(),
    ))
    .with_addr(listen_addr_s.to_string())
    .with_informal_property(InformalProperty::DNSSEC)
    .with_informal_property(InformalProperty::NoFilters)
    .with_informal_property(InformalProperty::NoLogs)
    .serialize()
    .unwrap();
    println!("DNS Stamp: {}", stamp);

    let dnscrypt_cert = DNSCryptCert::new(&resolver_kp);

    let runtime = Arc::new(Runtime::new()?);
    let globals = Arc::new(Globals {
        runtime: runtime.clone(),
        resolver_kp,
        dnscrypt_certs: vec![dnscrypt_cert],
        provider_name,
        listen_addr,
    });
    runtime.spawn(start(globals, runtime.clone()).map(|_| ()));
    runtime.block_on(future::pending::<()>());

    Ok(())
}
