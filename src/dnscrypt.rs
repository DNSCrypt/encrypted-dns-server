use crate::crypto::*;
use crate::dns::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;

use libsodium_sys::*;
use rand::prelude::*;
use std::ffi::CStr;
use std::ptr;

pub const DNSCRYPT_CLIENT_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_CLIENT_PK_SIZE: usize = 32;
pub const DNSCRYPT_CLIENT_NONCE_SIZE: usize =
    crypto_box_curve25519xchacha20poly1305_HALFNONCEBYTES as usize;
pub const DNSCRYPT_FULL_NONCE_SIZE: usize =
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;

pub fn decrypt(
    wrapped_packet: &[u8],
    dnscrypt_encryption_params_set: &[DNSCryptEncryptionParams],
) -> Result<(SharedKey, [u8; DNSCRYPT_FULL_NONCE_SIZE as usize], Vec<u8>), Error> {
    ensure!(
        wrapped_packet.len()
            >= DNSCRYPT_CLIENT_MAGIC_SIZE
                + DNSCRYPT_CLIENT_PK_SIZE
                + DNSCRYPT_CLIENT_NONCE_SIZE
                + DNS_HEADER_SIZE,
        "Short packet"
    );
    let client_magic = &wrapped_packet[..DNSCRYPT_CLIENT_MAGIC_SIZE];
    let client_pk = &wrapped_packet
        [DNSCRYPT_CLIENT_MAGIC_SIZE..DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE];
    let client_nonce = &wrapped_packet[DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE
        ..DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE + DNSCRYPT_CLIENT_NONCE_SIZE];
    let encrypted_packet = &wrapped_packet
        [DNSCRYPT_CLIENT_MAGIC_SIZE + DNSCRYPT_CLIENT_PK_SIZE + DNSCRYPT_CLIENT_NONCE_SIZE..];
    let encrypted_packet_len = encrypted_packet.len();

    let dnscrypt_encryption_params = dnscrypt_encryption_params_set
        .iter()
        .find(|p| p.client_magic() == client_magic)
        .ok_or_else(|| format_err!("Client magic not found"))?;

    let mut nonce = [0u8; DNSCRYPT_FULL_NONCE_SIZE as usize];
    &mut nonce[..DNSCRYPT_CLIENT_NONCE_SIZE].copy_from_slice(client_nonce);
    let resolver_kp = dnscrypt_encryption_params.resolver_kp();
    let shared_key = resolver_kp.compute_shared_key(client_pk)?;
    let packet = shared_key.decrypt(&nonce, encrypted_packet)?;
    rand::thread_rng().fill_bytes(&mut nonce[DNSCRYPT_CLIENT_NONCE_SIZE..]);

    Ok((shared_key, nonce, packet))
}

pub fn encrypt(
    packet: Vec<u8>,
    shared_key: &SharedKey,
    nonce: &[u8; DNSCRYPT_FULL_NONCE_SIZE as usize],
) -> Result<Vec<u8>, Error> {
    let mut wrapped_packet = vec![0x72u8, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
    wrapped_packet.extend_from_slice(nonce);
    shared_key.encrypt_into(&mut wrapped_packet, nonce, packet)?;
    Ok(wrapped_packet)
}
