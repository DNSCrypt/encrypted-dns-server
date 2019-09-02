use crate::crypto::*;
use crate::dnscrypt_certs::*;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct Globals {
    pub runtime: Arc<Runtime>,
    pub resolver_kp: SignKeyPair,
    pub dnscrypt_certs: Vec<DNSCryptCert>,
    pub provider_name: String,
    pub listen_addr: SocketAddr,
}
