use std::fs;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

use crate::crypto::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessControlConfig {
    pub enabled: bool,
    pub tokens: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub max_queries_per_second: u32,
    pub capacity: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnonymizedDNSConfig {
    pub enabled: bool,
    pub allowed_ports: Vec<u16>,
    pub allow_non_reserved_ports: Option<bool>,
    pub blacklisted_ips: Vec<IpAddr>,
}

#[cfg(feature = "metrics")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetricsConfig {
    pub r#type: String,
    pub listen_addr: SocketAddr,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DNSCryptConfig {
    pub enabled: Option<bool>,
    pub pq_enabled: Option<bool>,
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

fn quic_default_idle_timeout() -> u32 {
    crate::quic_proxy::QUIC_PROXY_DEFAULT_IDLE_TIMEOUT_SECS
}

fn quic_default_max_active_flows() -> u32 {
    crate::quic_proxy::QUIC_PROXY_DEFAULT_MAX_ACTIVE_FLOWS
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QUICConfig {
    pub upstream_addr: Option<SocketAddr>,
    #[serde(default = "quic_default_idle_timeout")]
    pub idle_timeout: u32,
    #[serde(default = "quic_default_max_active_flows")]
    pub max_active_flows: u32,
}

impl Default for QUICConfig {
    fn default() -> Self {
        QUICConfig {
            upstream_addr: None,
            idle_timeout: quic_default_idle_timeout(),
            max_active_flows: quic_default_max_active_flows(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListenAddrConfig {
    pub local: SocketAddr,
    pub external: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FilteringConfig {
    pub domain_blacklist: Option<PathBuf>,
    pub undelegated_list: Option<PathBuf>,
    pub ignore_unqualified_hostnames: Option<bool>,
}

fn deserialize_upstream_addrs<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SingleOrVec {
        Single(SocketAddr),
        Vec(Vec<SocketAddr>),
    }

    match SingleOrVec::deserialize(deserializer)? {
        SingleOrVec::Single(addr) => Ok(vec![addr]),
        SingleOrVec::Vec(addrs) => Ok(addrs),
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub listen_addrs: Vec<ListenAddrConfig>,
    pub external_addr: Option<IpAddr>,
    #[serde(
        alias = "upstream_addr",
        deserialize_with = "deserialize_upstream_addrs"
    )]
    pub upstream_addrs: Vec<SocketAddr>,
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
    #[serde(default)]
    pub quic: QUICConfig,
    pub daemonize: bool,
    pub pid_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub my_ip: Option<String>,
    pub client_ttl_holdon: Option<u32>,
    #[cfg(feature = "metrics")]
    pub metrics: Option<MetricsConfig>,
    pub anonymized_dns: Option<AnonymizedDNSConfig>,
    pub access_control: Option<AccessControlConfig>,
    pub rate_limit: Option<RateLimitConfig>,
}

impl Config {
    pub fn from_string(toml_str: &str) -> Result<Config, Error> {
        let config: Config = match toml::from_str(toml_str) {
            Ok(config) => config,
            Err(e) => bail!("Parse error in the configuration file: {}", e),
        };
        if config.upstream_addrs.is_empty() {
            bail!("At least one upstream address must be specified");
        }
        Ok(config)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Config, Error> {
        let toml_str = fs::read_to_string(path)?;
        Config::from_string(&toml_str)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub provider_kp: SignKeyPair,
    pub dnscrypt_encryption_params_set: Vec<DNSCryptEncryptionParams>,
}

impl State {
    pub fn with_key_pair(
        provider_kp: SignKeyPair,
        key_cache_capacity: usize,
        pq_enabled: bool,
    ) -> Self {
        let dnscrypt_encryption_params_set =
            DNSCryptEncryptionParams::new(&provider_kp, key_cache_capacity, None, pq_enabled);
        State {
            provider_kp,
            dnscrypt_encryption_params_set,
        }
    }

    pub fn new(key_cache_capacity: usize, pq_enabled: bool) -> Self {
        let provider_kp = SignKeyPair::new();
        State::with_key_pair(provider_kp, key_cache_capacity, pq_enabled)
    }

    pub async fn async_save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let path_tmp = path.with_extension("tmp");
        let mut fpb = tokio::fs::OpenOptions::new();
        let fpb = fpb.create(true).write(true).truncate(true);
        let mut fp = fpb.open(&path_tmp).await?;
        let state_str = toml::to_string(&self)?;
        fp.write_all(state_str.as_bytes()).await?;
        fp.sync_data().await?;
        mem::drop(fp);
        tokio::fs::rename(path_tmp, path).await?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let dir = tokio::fs::File::open(parent.unwrap_or_else(|| Path::new("."))).await?;
        dir.sync_all().await?;
        Ok(())
    }

    pub fn from_file(path: impl AsRef<Path>, key_cache_capacity: usize) -> Result<Self, Error> {
        let state_str = fs::read_to_string(path)?;
        let mut state: State = toml::from_str(&state_str)?;
        for params_set in &mut state.dnscrypt_encryption_params_set {
            params_set.add_key_cache(key_cache_capacity);
        }
        Ok(state)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn save_state_to_a_bare_filename() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let path = PathBuf::from(format!(".test-state-{:016x}.state", rand::random::<u64>()));
        let state = State {
            provider_kp: SignKeyPair::default(),
            dnscrypt_encryption_params_set: vec![],
        };
        let result = runtime.block_on(state.async_save(&path));
        let loaded = State::from_file(&path, 10);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("tmp"));
        result.unwrap();
        assert_eq!(
            loaded.unwrap().provider_kp.pk.as_bytes(),
            state.provider_kp.pk.as_bytes()
        );
    }
}
