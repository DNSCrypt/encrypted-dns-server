use std::mem;
use std::slice;
use std::sync::Arc;
use std::time::SystemTime;

use byteorder::{BigEndian, ByteOrder};
use parking_lot::Mutex;
use rand::prelude::*;
use serde_big_array::BigArray;
use sieve_cache::SieveCache;

use crate::anonymized_dns::*;
use crate::config::*;
use crate::crypto::*;
use crate::dnscrypt::*;
use crate::globals::*;
use crate::pq;

pub const DNSCRYPT_CERTS_TTL: u32 = 86400;
pub const DNSCRYPT_CERTS_RENEWAL: u32 = 28800;

const PQ_CERT_LEN: usize = 1320;
const PQ_OFF_RESOLVER_PK: usize = 72;
const PQ_OFF_CLIENT_MAGIC: usize = PQ_OFF_RESOLVER_PK + pq::XWING_PK_SIZE;
const PQ_OFF_SERIAL: usize = PQ_OFF_CLIENT_MAGIC + 8;
const PQ_OFF_TS_START: usize = PQ_OFF_SERIAL + 4;
const PQ_OFF_TS_END: usize = PQ_OFF_TS_START + 4;

/// Post-quantum (X-Wing) parameters bound to a classical encryption window.
/// Derived deterministically from the X25519 resolver key and the provider
/// signing key, so it is recomputed on load rather than persisted.
#[derive(Clone)]
pub struct PqParams {
    keypair: pq::XWingKeyPair,
    cert_bytes: Vec<u8>,
    cert_context: Vec<u8>,
    profile_extension_hash: [u8; 32],
}

impl std::fmt::Debug for PqParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqParams").finish_non_exhaustive()
    }
}

impl PqParams {
    /// Derive the PQ parameters from the classical resolver key seed and the
    /// provider signing key, reusing the classical window's serial and dates.
    fn derive(
        provider_kp: &SignKeyPair,
        resolver_sk_seed: &[u8; 32],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Self {
        let mut seed_input = Vec::with_capacity(19 + 32);
        seed_input.extend_from_slice(b"DNSCrypt-PQ-seed-v1");
        seed_input.extend_from_slice(resolver_sk_seed);
        let xwing_seed = pq::sha256(&seed_input);
        let keypair = pq::XWingKeyPair::from_seed(xwing_seed);
        let resolver_pk = keypair.public_key_bytes();

        let mut client_magic = [0u8; 8];
        client_magic.copy_from_slice(&pq::sha256(&resolver_pk)[..8]);
        if client_magic[..7] == [0u8; 7] || client_magic == pq::PQ_RESUME_MAGIC {
            client_magic[0] ^= 0xff;
        }

        let extensions = pq::profile_extension();
        let serial_be = serial.to_be_bytes();
        let ts_start_be = ts_start.to_be_bytes();
        let ts_end_be = ts_end.to_be_bytes();

        let mut signed = Vec::with_capacity(pq::XWING_PK_SIZE + 8 + 4 + 4 + 4 + extensions.len());
        signed.extend_from_slice(&resolver_pk);
        signed.extend_from_slice(&client_magic);
        signed.extend_from_slice(&serial_be);
        signed.extend_from_slice(&ts_start_be);
        signed.extend_from_slice(&ts_end_be);
        signed.extend_from_slice(&extensions);
        let signature = provider_kp.sk.sign(&signed);

        let mut cert_bytes = Vec::with_capacity(PQ_CERT_LEN);
        cert_bytes.extend_from_slice(&[0x44, 0x4e, 0x53, 0x43]);
        cert_bytes.extend_from_slice(&pq::PQ_ES_VERSION);
        cert_bytes.extend_from_slice(&[0x00, 0x00]);
        cert_bytes.extend_from_slice(signature.as_bytes());
        cert_bytes.extend_from_slice(&signed);
        debug_assert_eq!(cert_bytes.len(), PQ_CERT_LEN);

        // The HKDF context and the extension hash are fixed for the lifetime of
        // a certificate window, so derive them once here rather than on every
        // query.
        let cert_context = pq::cert_context(
            &pq::PQ_ES_VERSION,
            &[0x00, 0x00],
            &resolver_pk,
            &client_magic,
            &serial_be,
            &ts_start_be,
            &ts_end_be,
            &extensions,
        );
        let profile_extension_hash = pq::sha256(&extensions);

        PqParams {
            keypair,
            cert_bytes,
            cert_context,
            profile_extension_hash,
        }
    }

    pub fn keypair(&self) -> &pq::XWingKeyPair {
        &self.keypair
    }

    pub fn cert_bytes(&self) -> &[u8] {
        &self.cert_bytes
    }

    pub fn client_magic(&self) -> &[u8] {
        &self.cert_bytes[PQ_OFF_CLIENT_MAGIC..PQ_OFF_CLIENT_MAGIC + 8]
    }

    pub fn es_version(&self) -> [u8; 2] {
        [self.cert_bytes[4], self.cert_bytes[5]]
    }

    pub fn serial(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out.copy_from_slice(&self.cert_bytes[PQ_OFF_SERIAL..PQ_OFF_SERIAL + 4]);
        out
    }

    pub fn ts_end(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out.copy_from_slice(&self.cert_bytes[PQ_OFF_TS_END..PQ_OFF_TS_END + 4]);
        out
    }

    pub fn profile_extension_hash(&self) -> [u8; 32] {
        self.profile_extension_hash
    }

    /// The `cert-context` used as HKDF info for this certificate.
    pub fn cert_context(&self) -> &[u8] {
        &self.cert_context
    }
}

pub fn now() -> u32 {
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

#[derive(Educe, Serialize, Deserialize)]
#[educe(Debug, Default, Clone)]
#[repr(C, packed)]
pub struct DNSCryptCert {
    cert_magic: [u8; 4],
    es_version: [u8; 2],
    minor_version: [u8; 2],
    #[educe(Debug(ignore), Default = [0u8; 64])]
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    inner: DNSCryptCertInner,
}

impl DNSCryptCert {
    pub fn new(provider_kp: &SignKeyPair, resolver_kp: &CryptKeyPair, ts_start: u32) -> Self {
        let ts_end = ts_start.saturating_add(DNSCRYPT_CERTS_TTL);

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

    pub fn ts_start(&self) -> u32 {
        BigEndian::read_u32(&self.inner.ts_start)
    }

    pub fn ts_end(&self) -> u32 {
        BigEndian::read_u32(&self.inner.ts_end)
    }

    pub fn serial(&self) -> u32 {
        BigEndian::read_u32(&self.inner.serial)
    }
}

#[derive(Serialize, Deserialize, Clone, Educe)]
#[educe(Debug)]
pub struct DNSCryptEncryptionParams {
    dnscrypt_cert: DNSCryptCert,
    resolver_kp: CryptKeyPair,
    #[serde(skip)]
    #[educe(Debug(ignore))]
    pub key_cache: Option<Arc<Mutex<SieveCache<[u8; DNSCRYPT_QUERY_PK_SIZE], SharedKey>>>>,
    #[serde(skip)]
    #[educe(Debug(ignore))]
    pq: Option<PqParams>,
}

impl DNSCryptEncryptionParams {
    pub fn new(
        provider_kp: &SignKeyPair,
        key_cache_capacity: usize,
        previous_params: Option<Arc<DNSCryptEncryptionParams>>,
        pq_enabled: bool,
    ) -> Vec<Self> {
        let now = now();
        let (mut ts_start, mut seed) = match &previous_params {
            None => (now, rand::rng().random()),
            Some(p) => (
                p.dnscrypt_cert().ts_start() + DNSCRYPT_CERTS_RENEWAL,
                *p.resolver_kp().sk.as_bytes(),
            ),
        };
        let mut active_params = vec![];
        loop {
            if ts_start > now + DNSCRYPT_CERTS_RENEWAL {
                break;
            }
            let resolver_kp = CryptKeyPair::from_seed(seed);
            seed = *resolver_kp.sk.as_bytes();
            if resolver_kp.pk.as_bytes()
                == &ANONYMIZED_DNSCRYPT_QUERY_MAGIC[..DNSCRYPT_QUERY_MAGIC_SIZE]
            {
                ts_start += DNSCRYPT_CERTS_RENEWAL;
                continue;
            }
            if now >= ts_start {
                let dnscrypt_cert = DNSCryptCert::new(provider_kp, &resolver_kp, ts_start);
                let cache = SieveCache::new(key_cache_capacity).unwrap();
                let mut params = DNSCryptEncryptionParams {
                    dnscrypt_cert,
                    resolver_kp,
                    key_cache: Some(Arc::new(Mutex::new(cache))),
                    pq: None,
                };
                if pq_enabled {
                    params.derive_pq(provider_kp);
                }
                active_params.push(params);
            }
            ts_start += DNSCRYPT_CERTS_RENEWAL;
        }
        if active_params.is_empty() && previous_params.is_none() {
            warn!("Unable to recover a seed; creating an emergency certificate");
            let ts_start = now - (now % DNSCRYPT_CERTS_RENEWAL);
            let resolver_kp = CryptKeyPair::from_seed(seed);
            let dnscrypt_cert = DNSCryptCert::new(provider_kp, &resolver_kp, ts_start);
            let cache = SieveCache::new(key_cache_capacity).unwrap();
            let mut params = DNSCryptEncryptionParams {
                dnscrypt_cert,
                resolver_kp,
                key_cache: Some(Arc::new(Mutex::new(cache))),
                pq: None,
            };
            if pq_enabled {
                params.derive_pq(provider_kp);
            }
            active_params.push(params);
        }
        active_params
    }

    pub fn add_key_cache(&mut self, cache_capacity: usize) {
        let cache = SieveCache::new(cache_capacity).unwrap();
        self.key_cache = Some(Arc::new(Mutex::new(cache)));
    }

    /// (Re)derive the post-quantum parameters from the X25519 resolver key and
    /// the provider signing key, reusing this window's serial and dates.
    pub fn derive_pq(&mut self, provider_kp: &SignKeyPair) {
        let resolver_sk_seed = *self.resolver_kp.sk.as_bytes();
        let serial = self.dnscrypt_cert.serial();
        let ts_start = self.dnscrypt_cert.ts_start();
        let ts_end = self.dnscrypt_cert.ts_end();
        self.pq = Some(PqParams::derive(
            provider_kp,
            &resolver_sk_seed,
            serial,
            ts_start,
            ts_end,
        ));
    }

    pub fn pq(&self) -> Option<&PqParams> {
        self.pq.as_ref()
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
        let previous_params = {
            let params_set = self.globals.dnscrypt_encryption_params_set.read();
            for params in &**params_set {
                if params.dnscrypt_cert().ts_end() >= now {
                    new_params_set.push(params.clone());
                }
            }
            params_set.last().cloned()
        };
        let active_params = DNSCryptEncryptionParams::new(
            &self.globals.provider_kp,
            self.globals.key_cache_capacity,
            previous_params,
            self.globals.pq_enabled,
        );
        for params in active_params {
            new_params_set.push(Arc::new(params));
        }
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
