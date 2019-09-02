use crate::crypto::*;
use crate::dnscrypt_certs::*;

use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct Globals {
    pub runtime: Arc<Runtime>,
    pub resolver_kp: SignKeyPair,
    pub dnscrypt_certs: Vec<DNSCryptCert>,
}

impl Globals {
    pub fn new(
        runtime: Arc<Runtime>,
        resolver_kp: SignKeyPair,
        dnscrypt_certs: Vec<DNSCryptCert>,
    ) -> Self {
        Globals {
            runtime,
            resolver_kp,
            dnscrypt_certs,
        }
    }
}
