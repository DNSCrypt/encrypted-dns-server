use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use siphasher::sip128::SipHasher13;
use slabigator::Slab;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use crate::blacklist::*;
use crate::cache::*;
use crate::crypto::*;
use crate::dnscrypt_certs::*;
#[cfg(feature = "metrics")]
use crate::varz::*;

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Globals {
    pub runtime_handle: Handle,
    pub state_file: PathBuf,
    pub dnscrypt_encryption_params_set: Arc<RwLock<Arc<Vec<Arc<DNSCryptEncryptionParams>>>>>,
    pub provider_name: String,
    pub provider_kp: SignKeyPair,
    pub listen_addrs: Vec<SocketAddr>,
    pub external_addr: Option<SocketAddr>,
    pub upstream_addr: SocketAddr,
    pub tls_upstream_addr: Option<SocketAddr>,
    pub udp_timeout: Duration,
    pub tcp_timeout: Duration,
    pub udp_concurrent_connections: Arc<AtomicU32>,
    pub tcp_concurrent_connections: Arc<AtomicU32>,
    pub udp_max_active_connections: u32,
    pub tcp_max_active_connections: u32,
    pub udp_active_connections: Arc<Mutex<Slab<oneshot::Sender<()>>>>,
    pub tcp_active_connections: Arc<Mutex<Slab<oneshot::Sender<()>>>>,
    pub key_cache_capacity: usize,
    pub hasher: SipHasher13,
    pub cache: Cache,
    pub cert_cache: Cache,
    pub blacklist: Option<BlackList>,
    pub undelegated_list: Option<BlackList>,
    pub ignore_unqualified_hostnames: bool,
    pub dnscrypt_enabled: bool,
    pub anonymized_dns_enabled: bool,
    pub anonymized_dns_allowed_ports: Vec<u16>,
    pub anonymized_dns_allow_non_reserved_ports: bool,
    pub anonymized_dns_blacklisted_ips: Vec<IpAddr>,
    pub access_control_tokens: Option<Vec<String>>,
    pub client_ttl_holdon: u32,
    pub my_ip: Option<Vec<u8>>,
    #[cfg(feature = "metrics")]
    #[derivative(Debug = "ignore")]
    pub varz: Varz,
}
