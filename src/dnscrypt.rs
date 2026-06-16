use std::sync::Arc;

use libsodium_sys::*;
use rand::prelude::*;

use crate::crypto::*;
use crate::dns::*;
use crate::dnscrypt_certs::*;
use crate::errors::*;
use crate::pq;

pub const DNSCRYPT_FULL_NONCE_SIZE: usize =
    crypto_box_curve25519xchacha20poly1305_NONCEBYTES as usize;
pub const DNSCRYPT_MAC_SIZE: usize = crypto_box_curve25519xchacha20poly1305_MACBYTES as usize;

pub const DNSCRYPT_QUERY_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_QUERY_PK_SIZE: usize = 32;
pub const DNSCRYPT_QUERY_NONCE_SIZE: usize = DNSCRYPT_FULL_NONCE_SIZE / 2;
pub const DNSCRYPT_QUERY_HEADER_SIZE: usize =
    DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE + DNSCRYPT_QUERY_NONCE_SIZE;
pub const DNSCRYPT_QUERY_MIN_PADDING_SIZE: usize = 1;
pub const DNSCRYPT_QUERY_MIN_OVERHEAD: usize =
    DNSCRYPT_QUERY_HEADER_SIZE + DNSCRYPT_MAC_SIZE + DNSCRYPT_QUERY_MIN_PADDING_SIZE;

pub const DNSCRYPT_RESPONSE_MAGIC_SIZE: usize = 8;
pub const DNSCRYPT_RESPONSE_MAGIC: [u8; DNSCRYPT_RESPONSE_MAGIC_SIZE] =
    [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
pub const DNSCRYPT_RESPONSE_CERT_PREFIX_OFFSET: usize = 4;
pub const DNSCRYPT_RESPONSE_NONCE_SIZE: usize = DNSCRYPT_FULL_NONCE_SIZE;
pub const DNSCRYPT_RESPONSE_HEADER_SIZE: usize =
    DNSCRYPT_RESPONSE_MAGIC_SIZE + DNSCRYPT_RESPONSE_NONCE_SIZE;
pub const DNSCRYPT_RESPONSE_MIN_PADDING_SIZE: usize = 1;
pub const DNSCRYPT_RESPONSE_MIN_OVERHEAD: usize =
    DNSCRYPT_RESPONSE_HEADER_SIZE + DNSCRYPT_MAC_SIZE + DNSCRYPT_RESPONSE_MIN_PADDING_SIZE;

pub const DNSCRYPT_UDP_QUERY_MIN_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_UDP_QUERY_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNSCRYPT_TCP_QUERY_MIN_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_TCP_QUERY_MAX_SIZE: usize = DNSCRYPT_QUERY_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;

pub const DNSCRYPT_UDP_RESPONSE_MIN_SIZE: usize = DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_UDP_RESPONSE_MAX_SIZE: usize = DNS_MAX_PACKET_SIZE;
pub const DNSCRYPT_TCP_RESPONSE_MIN_SIZE: usize = DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_HEADER_SIZE;
pub const DNSCRYPT_TCP_RESPONSE_MAX_SIZE: usize =
    DNSCRYPT_RESPONSE_MIN_OVERHEAD + DNS_MAX_PACKET_SIZE;

/// Everything needed to encrypt the response to a query, carried from the
/// decryption stage to the response stage.
pub enum EncryptionParams {
    Classical {
        shared_key: SharedKey,
        nonce: [u8; DNSCRYPT_FULL_NONCE_SIZE],
    },
    Pq {
        shared_key: SharedKey,
        nonce: [u8; DNSCRYPT_FULL_NONCE_SIZE],
        control: Vec<u8>,
    },
}

pub fn decrypt(
    wrapped_packet: &[u8],
    dnscrypt_encryption_params_set: &[Arc<DNSCryptEncryptionParams>],
    pq_ticket_key: &pq::TicketKey,
    pq_enabled: bool,
) -> Result<(EncryptionParams, Vec<u8>), Error> {
    ensure!(wrapped_packet.len() >= DNSCRYPT_QUERY_MAGIC_SIZE, "Short packet");

    if pq_enabled && wrapped_packet[..pq::PQ_RESUME_MAGIC.len()] == pq::PQ_RESUME_MAGIC {
        return decrypt_pq_resumed(wrapped_packet, dnscrypt_encryption_params_set, pq_ticket_key);
    }

    let client_magic = &wrapped_packet[..DNSCRYPT_QUERY_MAGIC_SIZE];

    if pq_enabled {
        if let Some(params) = dnscrypt_encryption_params_set
            .iter()
            .find(|p| p.pq().is_some_and(|pq| pq.client_magic() == client_magic))
        {
            return decrypt_pq_ciphertext(wrapped_packet, params, pq_ticket_key);
        }
    }

    ensure!(
        wrapped_packet.len()
            >= DNSCRYPT_QUERY_MAGIC_SIZE
                + DNSCRYPT_QUERY_PK_SIZE
                + DNSCRYPT_QUERY_NONCE_SIZE
                + DNS_HEADER_SIZE,
        "Short packet"
    );
    let client_pk = &wrapped_packet
        [DNSCRYPT_QUERY_MAGIC_SIZE..DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE];
    let client_nonce = &wrapped_packet[DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE
        ..DNSCRYPT_QUERY_MAGIC_SIZE + DNSCRYPT_QUERY_PK_SIZE + DNSCRYPT_QUERY_NONCE_SIZE];
    let encrypted_packet = &wrapped_packet[DNSCRYPT_QUERY_HEADER_SIZE..];

    let dnscrypt_encryption_params = dnscrypt_encryption_params_set
        .iter()
        .find(|p| p.client_magic() == client_magic)
        .ok_or_else(|| anyhow!("Client magic not found"))?;

    let mut nonce = [0u8; DNSCRYPT_FULL_NONCE_SIZE];
    nonce[..DNSCRYPT_QUERY_NONCE_SIZE].copy_from_slice(client_nonce);

    let cached_shared_key = {
        let mut key_cache = dnscrypt_encryption_params
            .key_cache
            .as_ref()
            .unwrap()
            .lock();
        key_cache
            .get(client_pk)
            .map(|cached_shared_key| (*cached_shared_key).clone())
    };
    let shared_key = match cached_shared_key {
        Some(cached_shared_key) => cached_shared_key,
        None => {
            let shared_key = dnscrypt_encryption_params
                .resolver_kp()
                .compute_shared_key(client_pk)?;
            let mut client_pk_ = [0u8; DNSCRYPT_QUERY_PK_SIZE];
            client_pk_.copy_from_slice(client_pk);
            dnscrypt_encryption_params
                .key_cache
                .as_ref()
                .unwrap()
                .lock()
                .insert(client_pk_, shared_key.clone());
            shared_key
        }
    };
    let packet = shared_key.decrypt(&nonce, encrypted_packet)?;
    rand::rng().fill_bytes(&mut nonce[DNSCRYPT_QUERY_NONCE_SIZE..]);

    Ok((EncryptionParams::Classical { shared_key, nonce }, packet))
}

/// Decrypt a PQ query that carries an X-Wing ciphertext, and prepare a
/// freshly issued resumption ticket for the response.
fn decrypt_pq_ciphertext(
    wrapped_packet: &[u8],
    params: &Arc<DNSCryptEncryptionParams>,
    pq_ticket_key: &pq::TicketKey,
) -> Result<(EncryptionParams, Vec<u8>), Error> {
    let pq_params = params.pq().ok_or_else(|| anyhow!("No PQ params"))?;
    let cm = DNSCRYPT_QUERY_MAGIC_SIZE;
    let ct_len = pq::XWING_CT_SIZE;
    let nonce_size = DNSCRYPT_QUERY_NONCE_SIZE;
    ensure!(
        wrapped_packet.len() >= cm + ct_len + nonce_size + DNSCRYPT_MAC_SIZE + DNS_HEADER_SIZE,
        "Short PQ query"
    );
    let mut client_magic = [0u8; 8];
    client_magic.copy_from_slice(&wrapped_packet[..cm]);
    let ct = &wrapped_packet[cm..cm + ct_len];
    let client_nonce = &wrapped_packet[cm + ct_len..cm + ct_len + nonce_size];
    let encrypted_packet = &wrapped_packet[cm + ct_len + nonce_size..];

    let kem_ss = pq_params.keypair().decapsulate(ct)?;
    let cert_ctx = pq_params.cert_context();
    let es_version = pq_params.es_version();
    let shared_key = pq::derive_shared_key(&kem_ss, &es_version, &client_magic, cert_ctx, ct);

    let mut nonce = [0u8; DNSCRYPT_FULL_NONCE_SIZE];
    nonce[..nonce_size].copy_from_slice(client_nonce);
    let packet = shared_key.decrypt(&nonce, encrypted_packet)?;

    let sk_bytes = *shared_key.as_raw_bytes();
    let rs = pq::resume_secret(&sk_bytes, &client_magic, client_nonce);
    let mut ticket_nonce = [0u8; pq::TICKET_NONCE_SIZE];
    rand::rng().fill_bytes(&mut ticket_nonce);
    let ticket_expiry = now().saturating_add(pq::PQ_TICKET_LIFETIME);
    let peh = pq_params.profile_extension_hash();
    let serial = pq_params.serial();
    let ts_end = pq_params.ts_end();
    let tp = pq::ticket_plain(&rs, &es_version, &client_magic, &serial, &ts_end, ticket_expiry, &peh);
    let ticket = pq::seal_ticket(pq_ticket_key, &ticket_nonce, &tp);
    let control = pq::control_block(pq::PQ_TICKET_LIFETIME, &ticket);
    debug!("PQ X-Wing query decapsulated; resumption ticket issued");

    rand::rng().fill_bytes(&mut nonce[nonce_size..]);
    Ok((
        EncryptionParams::Pq {
            shared_key,
            nonce,
            control,
        },
        packet,
    ))
}

/// Decrypt a resumed PQ query, validating its ticket and deriving the
/// per-query key without a KEM decapsulation.
fn decrypt_pq_resumed(
    wrapped_packet: &[u8],
    dnscrypt_encryption_params_set: &[Arc<DNSCryptEncryptionParams>],
    pq_ticket_key: &pq::TicketKey,
) -> Result<(EncryptionParams, Vec<u8>), Error> {
    let magic = pq::PQ_RESUME_MAGIC.len();
    let nonce_size = DNSCRYPT_QUERY_NONCE_SIZE;
    ensure!(wrapped_packet.len() >= magic + 2, "Short resumed query");
    let ticket_len =
        u16::from_be_bytes([wrapped_packet[magic], wrapped_packet[magic + 1]]) as usize;
    let ticket_off = magic + 2;
    ensure!(
        wrapped_packet.len() >= ticket_off + ticket_len + nonce_size + DNSCRYPT_MAC_SIZE + DNS_HEADER_SIZE,
        "Short resumed query"
    );
    let ticket = &wrapped_packet[ticket_off..ticket_off + ticket_len];
    let client_nonce = &wrapped_packet[ticket_off + ticket_len..ticket_off + ticket_len + nonce_size];
    let encrypted_packet = &wrapped_packet[ticket_off + ticket_len + nonce_size..];

    let opened = pq::open_ticket(pq_ticket_key, ticket)?;
    let fields = pq::parse_ticket_plain(&opened)?;
    ensure!(fields.ticket_expiry > now(), "Expired ticket");
    ensure!(
        dnscrypt_encryption_params_set.iter().any(|p| p.pq().is_some_and(|pq| {
            pq.client_magic() == fields.client_magic && pq.es_version() == fields.es_version
        })),
        "Ticket does not match a current certificate"
    );

    let resumed_key =
        pq::resumed_shared_key(&fields.resume_secret, &fields.client_magic, client_nonce, ticket);
    let mut nonce = [0u8; DNSCRYPT_FULL_NONCE_SIZE];
    nonce[..nonce_size].copy_from_slice(client_nonce);
    let packet = resumed_key.decrypt(&nonce, encrypted_packet)?;
    debug!("PQ resumed query accepted (no decapsulation)");
    rand::rng().fill_bytes(&mut nonce[nonce_size..]);
    Ok((
        EncryptionParams::Pq {
            shared_key: resumed_key,
            nonce,
            control: Vec::new(),
        },
        packet,
    ))
}

pub fn encrypt(
    packet: Vec<u8>,
    params: &EncryptionParams,
    max_packet_size: usize,
) -> Result<Vec<u8>, Error> {
    // Every response is framed the same way: the response magic followed by the
    // full nonce. Only the encryption of the payload differs between schemes.
    let nonce = match params {
        EncryptionParams::Classical { nonce, .. } | EncryptionParams::Pq { nonce, .. } => nonce,
    };
    let mut wrapped_packet = Vec::with_capacity(DNS_MAX_PACKET_SIZE);
    wrapped_packet.extend_from_slice(&DNSCRYPT_RESPONSE_MAGIC);
    wrapped_packet.extend_from_slice(nonce);
    match params {
        EncryptionParams::Classical { shared_key, nonce } => {
            ensure!(
                max_packet_size >= wrapped_packet.len(),
                "Max packet size too short"
            );
            let max_encrypted_size = max_packet_size - wrapped_packet.len();
            shared_key.encrypt_into(
                &mut wrapped_packet,
                nonce,
                &nonce[..DNSCRYPT_QUERY_NONCE_SIZE],
                packet,
                max_encrypted_size,
            )?;
        }
        EncryptionParams::Pq {
            shared_key,
            nonce,
            control,
        } => {
            ensure!(
                max_packet_size >= wrapped_packet.len() + DNSCRYPT_MAC_SIZE,
                "Max packet size too short"
            );
            let max_plaintext = max_packet_size - wrapped_packet.len() - DNSCRYPT_MAC_SIZE;
            let mut plaintext = Vec::with_capacity(2 + control.len() + packet.len() + 64);
            plaintext.extend_from_slice(&(control.len() as u16).to_be_bytes());
            plaintext.extend_from_slice(control);
            plaintext.extend_from_slice(&packet);
            pq::pad7816(&mut plaintext, 64);
            ensure!(plaintext.len() <= max_plaintext, "PQ response too large to pad");
            let encrypted = shared_key.seal_raw(nonce, &plaintext);
            wrapped_packet.extend_from_slice(&encrypted);
        }
    }
    Ok(wrapped_packet)
}

pub fn may_be_quic(packet: &[u8]) -> bool {
    !packet.is_empty() && ((80..=127).contains(&packet[0]) || (192..=255).contains(&packet[0]))
}
