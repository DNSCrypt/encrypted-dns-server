use crate::crypto::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
    pub user: Option<String>,
    pub group: Option<String>,
    pub chroot: Option<String>,
    pub dnscrypt: DNSCryptConfig,
    pub tls: TLSConfig,
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
    pub fn new() -> Self {
        let provider_kp = SignKeyPair::new();
        let dnscrypt_encryption_params_set = vec![DNSCryptEncryptionParams::new(&provider_kp)];
        State {
            provider_kp,
            dnscrypt_encryption_params_set,
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut fpb = OpenOptions::new();
        let mut fpb = fpb.create(true).write(true);
        #[cfg(unix)]
        {
            fpb = fpb.mode(0o600);
        }
        let mut fp = fpb.open(path.as_ref())?;
        let state_bin = toml::to_vec(&self)?;
        fp.write_all(&state_bin)?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut fp = File::open(path.as_ref())?;
        let mut state_bin = vec![];
        fp.read_to_end(&mut state_bin)?;
        let state = toml::from_slice(&state_bin)?;
        Ok(state)
    }
}
