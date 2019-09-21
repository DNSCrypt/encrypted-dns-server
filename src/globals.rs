use crate::cache::*;
use crate::crypto::*;
use crate::dnscrypt_certs::*;

use parking_lot::{Mutex, RwLock};
use siphasher::sip128::SipHasher13;
use std::collections::vec_deque::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub struct Globals {
    pub runtime: Arc<Runtime>,
    pub state_file: PathBuf,
    pub dnscrypt_encryption_params_set: Arc<RwLock<Arc<Vec<Arc<DNSCryptEncryptionParams>>>>>,
    pub provider_name: String,
    pub provider_kp: SignKeyPair,
    pub listen_addrs: Vec<SocketAddr>,
    pub external_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub tls_upstream_addr: Option<SocketAddr>,
    pub udp_timeout: Duration,
    pub tcp_timeout: Duration,
    pub udp_concurrent_connections: Arc<AtomicU32>,
    pub tcp_concurrent_connections: Arc<AtomicU32>,
    pub udp_max_active_connections: u32,
    pub tcp_max_active_connections: u32,
    pub udp_active_connections: Arc<Mutex<VecDeque<oneshot::Sender<()>>>>,
    pub tcp_active_connections: Arc<Mutex<VecDeque<oneshot::Sender<()>>>>,
    pub key_cache_capacity: usize,
    pub hasher: SipHasher13,
    pub cache: Cache,
}
