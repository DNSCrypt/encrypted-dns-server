use crate::anonymized_dns::*;
use crate::config::*;
use crate::crypto::*;
use crate::dnscrypt::*;
use crate::globals::*;

use byteorder::{BigEndian, ByteOrder};
use clockpro_cache::ClockProCache;
use parking_lot::Mutex;
use std::mem;
use std::slice;
use std::sync::Arc;
use std::time::SystemTime;

pub const DNSCRYPT_CERTS_TTL: u32 = 86400;
pub const DNSCRYPT_CERTS_RENEWAL: u32 = 28800;

fn now() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("The clock is completely off")
        .as_secs() as _
}

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C, packed)]
pub struct DNSCryptCertInner {
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: [u8; 4],
    ts_start: [u8; 4],
    ts_end: [u8; 4],
}

impl DNSCryptCertInner {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of_val(self)) }
    }
}

big_array! { BigArray; 64 }

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Debug, Default, Clone)]
#[repr(C, packed)]
pub struct DNSCryptCert {
    cert_magic: [u8; 4],
    es_version: [u8; 2],
    minor_version: [u8; 2],
    #[derivative(Debug = "ignore", Default(value = "[0u8; 64]"))]
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    inner: DNSCryptCertInner,
}

impl DNSCryptCert {
    pub fn new(provider_kp: &SignKeyPair, resolver_kp: &CryptKeyPair) -> Self {
        let ts_start = now();
        let ts_end = ts_start + DNSCRYPT_CERTS_TTL;

        let mut dnscrypt_cert = DNSCryptCert::default();

        let dnscrypt_cert_inner = &mut dnscrypt_cert.inner;
        dnscrypt_cert_inner
            .resolver_pk
            .copy_from_slice(resolver_kp.pk.as_bytes());
        dnscrypt_cert_inner
            .client_magic
            .copy_from_slice(&dnscrypt_cert_inner.resolver_pk[..8]);
        BigEndian::write_u32(&mut dnscrypt_cert_inner.serial, 1);
        BigEndian::write_u32(&mut dnscrypt_cert_inner.ts_start, ts_start);
        BigEndian::write_u32(&mut dnscrypt_cert_inner.ts_end, ts_end);

        BigEndian::write_u32(&mut dnscrypt_cert.cert_magic, 0x44_4e_53_43);
        BigEndian::write_u16(&mut dnscrypt_cert.es_version, 2);
        BigEndian::write_u16(&mut dnscrypt_cert.minor_version, 0);

        dnscrypt_cert.signature.copy_from_slice(
            provider_kp
                .sk
                .sign(dnscrypt_cert_inner.as_bytes())
                .as_bytes(),
        );
        dnscrypt_cert
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of_val(self)) }
    }

    pub fn client_magic(&self) -> &[u8] {
        &self.inner.client_magic
    }

    pub fn ts_end(&self) -> u32 {
        BigEndian::read_u32(&self.inner.ts_end)
    }
}

#[derive(Serialize, Deserialize, Clone, Derivative)]
#[derivative(Debug)]
pub struct DNSCryptEncryptionParams {
    dnscrypt_cert: DNSCryptCert,
    resolver_kp: CryptKeyPair,
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub cache: Option<Arc<Mutex<ClockProCache<[u8; DNSCRYPT_QUERY_PK_SIZE], SharedKey>>>>,
}

impl DNSCryptEncryptionParams {
    pub fn new(provider_kp: &SignKeyPair, cache_capacity: usize) -> Self {
        let mut resolver_kp;
        while {
            resolver_kp = CryptKeyPair::new();
            resolver_kp.pk.as_bytes()
                == &ANONYMIZED_DNSCRYPT_QUERY_MAGIC[..DNSCRYPT_QUERY_MAGIC_SIZE]
        } {}
        let dnscrypt_cert = DNSCryptCert::new(&provider_kp, &resolver_kp);
        let cache = ClockProCache::new(cache_capacity).unwrap();
        DNSCryptEncryptionParams {
            dnscrypt_cert,
            resolver_kp,
            cache: Some(Arc::new(Mutex::new(cache))),
        }
    }

    pub fn add_key_cache(&mut self, cache_capacity: usize) {
        let cache = ClockProCache::new(cache_capacity).unwrap();
        self.cache = Some(Arc::new(Mutex::new(cache)));
    }

    pub fn client_magic(&self) -> &[u8] {
        self.dnscrypt_cert.client_magic()
    }

    pub fn dnscrypt_cert(&self) -> &DNSCryptCert {
        &self.dnscrypt_cert
    }

    pub fn resolver_kp(&self) -> &CryptKeyPair {
        &self.resolver_kp
    }
}

pub struct DNSCryptEncryptionParamsUpdater {
    globals: Arc<Globals>,
}

impl DNSCryptEncryptionParamsUpdater {
    pub fn new(globals: Arc<Globals>) -> Self {
        DNSCryptEncryptionParamsUpdater { globals }
    }

    pub fn update(&self) {
        let now = now();
        let mut new_params_set = vec![];
        {
            let params_set = self.globals.dnscrypt_encryption_params_set.read();
            for params in &**params_set {
                if params.dnscrypt_cert().ts_end() >= now {
                    new_params_set.push(params.clone());
                }
            }
        }
        let new_params = DNSCryptEncryptionParams::new(
            &self.globals.provider_kp,
            self.globals.key_cache_capacity,
        );
        new_params_set.push(Arc::new(new_params));
        let state = State {
            provider_kp: self.globals.provider_kp.clone(),
            dnscrypt_encryption_params_set: new_params_set.iter().map(|x| (**x).clone()).collect(),
        };
        let state_file = self.globals.state_file.to_path_buf();
        self.globals.runtime_handle.spawn(async move {
            let _ = state.async_save(state_file).await;
        });
        *self.globals.dnscrypt_encryption_params_set.write() = Arc::new(new_params_set);
        debug!("New certificate issued");
    }

    pub async fn run(self) {
        let mut fut_interval = tokio::time::interval(std::time::Duration::from_secs(u64::from(
            DNSCRYPT_CERTS_RENEWAL,
        )));
        let fut = async move {
            loop {
                fut_interval.tick().await;
                self.update();
                debug!("New cert issued");
            }
        };
        fut.await
    }
}
