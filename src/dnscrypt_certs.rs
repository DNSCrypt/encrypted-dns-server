use crate::crypto::*;

use byteorder::{BigEndian, ByteOrder};
use std::mem;
use std::slice;
use std::time::SystemTime;

fn now() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

#[derive(Debug, Default)]
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

#[derive(Derivative)]
#[derivative(Debug, Default)]
#[repr(C, packed)]
pub struct DNSCryptCert {
    cert_magic: [u8; 4],
    es_version: [u8; 2],
    minor_version: [u8; 2],
    #[derivative(Debug = "ignore", Default(value = "[0u8; 64]"))]
    signature: [u8; 64],
    inner: DNSCryptCertInner,
}

impl DNSCryptCert {
    pub fn new(resolver_kp: &SignKeyPair) -> Self {
        let ts_start = now();
        let ts_end = ts_start + 86400;

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
            resolver_kp
                .sk
                .sign(dnscrypt_cert_inner.as_bytes())
                .as_bytes(),
        );
        dnscrypt_cert
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, mem::size_of_val(self)) }
    }
}
