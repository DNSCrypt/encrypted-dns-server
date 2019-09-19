use crate::crypto::*;
use crate::errors::*;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct DNSCryptConfig {
    pub provider_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TLSConfig {
    pub upstream_addr: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub listen_addrs: Vec<SocketAddr>,
    pub external_addr: IpAddr,
    pub upstream_addr: SocketAddr,
    pub state_file: PathBuf,
    pub udp_timeout: u32,
    pub tcp_timeout: u32,
    pub udp_max_active_connections: u32,
    pub tcp_max_active_connections: u32,
    pub dnscrypt: DNSCryptConfig,
    pub tls: TLSConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub provider_kp: SignKeyPair,
}

impl State {
    pub fn new() -> Self {
        let provider_kp = SignKeyPair::new();
        State { provider_kp }
    }
}
