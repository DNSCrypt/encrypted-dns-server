use crate::crypto::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

use std::fs::File;
use std::io::prelude::*;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::prelude::*;

#[cfg(feature = "metrics")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetricsConfig {
    pub r#type: String,
    pub listen_addr: SocketAddr,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DNSCryptConfig {
    pub provider_name: String,
    pub key_cache_capacity: usize,
    pub dnssec: bool,
    pub no_filters: bool,
    pub no_logs: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TLSConfig {
    pub upstream_addr: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListenAddrConfig {
    pub local: SocketAddr,
    pub external: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FilteringConfig {
    pub domain_blacklist: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub listen_addrs: Vec<ListenAddrConfig>,
    pub external_addr: IpAddr,
    pub upstream_addr: SocketAddr,
    pub state_file: PathBuf,
    pub udp_timeout: u32,
    pub tcp_timeout: u32,
    pub udp_max_active_connections: u32,
    pub tcp_max_active_connections: u32,
    pub cache_capacity: usize,
    pub cache_ttl_min: u32,
    pub cache_ttl_max: u32,
    pub cache_ttl_error: u32,
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot: Option<String>,
    pub filtering: FilteringConfig,
    pub dnscrypt: DNSCryptConfig,
    pub tls: TLSConfig,
    pub daemonize: bool,
    pub pid_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    #[cfg(feature = "metrics")]
    pub metrics: Option<MetricsConfig>,
}

impl Config {
    pub fn from_string(toml: &str) -> Result<Config, Error> {
        let config: Config = match toml::from_str(toml) {
            Ok(config) => config,
            Err(e) => bail!(format_err!("Parse error in the configuration file: {}", e)),
        };
        Ok(config)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Config, Error> {
        let mut fd = File::open(path)?;
        let mut toml = String::new();
        fd.read_to_string(&mut toml)?;
        Config::from_string(&toml)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub provider_kp: SignKeyPair,
    pub dnscrypt_encryption_params_set: Vec<DNSCryptEncryptionParams>,
}

impl State {
    pub fn with_key_pair(provider_kp: SignKeyPair, key_cache_capacity: usize) -> Self {
        let dnscrypt_encryption_params_set = vec![DNSCryptEncryptionParams::new(
            &provider_kp,
            key_cache_capacity,
        )];
        State {
            provider_kp,
            dnscrypt_encryption_params_set,
        }
    }

    pub fn new(key_cache_capacity: usize) -> Self {
        let provider_kp = SignKeyPair::new();
        State::with_key_pair(provider_kp, key_cache_capacity)
    }

    pub async fn async_save<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path_tmp = path.as_ref().with_extension("tmp");
        let mut fpb = tokio::fs::OpenOptions::new();
        let fpb = fpb.create(true).write(true);
        let mut fp = fpb.open(&path_tmp).await?;
        let state_bin = toml::to_vec(&self)?;
        fp.write_all(&state_bin).await?;
        fp.sync_data().await?;
        mem::drop(fp);
        tokio::fs::rename(path_tmp, path).await?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P, key_cache_capacity: usize) -> Result<Self, Error> {
        let mut fp = File::open(path.as_ref())?;
        let mut state_bin = vec![];
        fp.read_to_end(&mut state_bin)?;
        let mut state: State = toml::from_slice(&state_bin)?;
        for params_set in &mut state.dnscrypt_encryption_params_set {
            params_set.add_key_cache(key_cache_capacity);
        }
        Ok(state)
    }
}
