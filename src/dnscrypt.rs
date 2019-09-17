use crate::crypto::*;
use crate::dns::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

use libsodium_sys::*;
use std::ffi::CStr;
use std::ptr;

pub const DNSCRYPT_CLIENT_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_CLIENT_PK_SIZE: usize = 32;
pub const DNSCRYPT_CLIENT_NONCE_SIZE: usize = 12;

pub struct DNSCryptQuery<'t> {
    wrapped_packet: &'t [u8],
}

impl<'t> DNSCryptQuery<'t> {
    pub fn new(
        wrapped_packet: &'t [u8],
        dnscrypt_encryption_params_set: &[DNSCryptEncryptionParams],
    ) -> Result<Self, Error> {
        ensure!(
            wrapped_packet.len()
                >= DNSCRYPT_CLIENT_MAGIC_SIZE
                    + DNSCRYPT_CLIENT_PK_SIZE
                    + DNSCRYPT_CLIENT_NONCE_SIZE
                    + DNS_HEADER_SIZE,
            "Short packet"
        );
        let dnscrypt_query = DNSCryptQuery { wrapped_packet };
        let client_magic = dnscrypt_query.client_magic();
        let dnscrypt_encryption_params = dnscrypt_encryption_params_set
            .iter()
            .find(|p| p.client_magic() == client_magic)
            .ok_or_else(|| format_err!("Client magic not found"))?;

        let encrypted_packet = dnscrypt_query.encrypted_packet();
        let encrypted_packet_len = encrypted_packet.len();
        let mut nonce = vec![0u8; crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize];
        &mut nonce[..crypto_box_curve25519xchacha20poly1305_HALFNONCEBYTES]
            .copy_from_slice(dnscrypt_query.client_nonce());
        let resolver_kp = dnscrypt_encryption_params.resolver_kp();
        resolver_kp.decrypt(dnscrypt_query.client_pk(), &nonce, encrypted_packet)?;
        dbg!("ok");
        Ok(dnscrypt_query)
    }

    pub fn client_magic(&self) -> &[u8] {
        &self.wrapped_packet[..DNSCRYPT_CLIENT_MAGIC_SIZE]
    }

    pub fn client_pk(&self) -> &[u8] {
        &self.wrapped_packet
            [DNSCRYPT_CLIENT_MAGIC_SIZE..DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE]
    }

    pub fn client_nonce(&self) -> &[u8] {
        &self.wrapped_packet[DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE
            ..DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE + DNSCRYPT_CLIENT_NONCE_SIZE]
    }

    pub fn encrypted_packet(&self) -> &[u8] {
        &self.wrapped_packet
            [DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE + DNSCRYPT_CLIENT_NONCE_SIZE..]
    }

    pub fn into_packet(self) -> Vec<u8> {
        self.encrypted_packet().to_vec()
    }
}
