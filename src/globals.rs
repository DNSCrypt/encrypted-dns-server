use crate::crypto::*;
use crate::dnscrypt_certs::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct Globals {
    pub runtime: Arc<Runtime>,
    pub resolver_kp: SignKeyPair,
    pub dnscrypt_certs: Vec<DNSCryptCert>,
    pub provider_name: String,
    pub listen_addr: SocketAddr,
    pub external_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub udp_timeout: Duration,
    pub tcp_timeout: Duration,
}
