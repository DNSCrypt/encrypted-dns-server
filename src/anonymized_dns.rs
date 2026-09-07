use std::hash::Hasher;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder};
use ipext::IpExt;
use siphasher::sip128::Hasher128;

use crate::errors::*;
use crate::*;

pub const ANONYMIZED_DNSCRYPT_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

pub const ANONYMIZED_DNSCRYPT_OVERHEAD: usize = 16 + 2;

pub const ANONYMIZED_DNSCRYPT_UDP_QUERY_MAX_SIZE: usize = ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()
    + ANONYMIZED_DNSCRYPT_OVERHEAD
    + DNSCRYPT_UDP_QUERY_MAX_SIZE;

pub fn starts_with_relay_magic(packet: &[u8]) -> bool {
    packet.len() >= ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()
        && packet[..ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len()] == ANONYMIZED_DNSCRYPT_QUERY_MAGIC
}

pub const RELAYED_CERT_CACHE_SIZE: usize = 1000;
pub const RELAYED_CERT_CACHE_TTL: u32 = 600;

pub async fn handle_anonymized_dns(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    relayed_packet: &[u8],
) -> Result<(), Error> {
    ensure!(
        relayed_packet.len() > ANONYMIZED_DNSCRYPT_OVERHEAD,
        "Short packet"
    );
    let ip_bin = &relayed_packet[..16];
    let ip_v6 = Ipv6Addr::new(
        BigEndian::read_u16(&ip_bin[0..2]),
        BigEndian::read_u16(&ip_bin[2..4]),
        BigEndian::read_u16(&ip_bin[4..6]),
        BigEndian::read_u16(&ip_bin[6..8]),
        BigEndian::read_u16(&ip_bin[8..10]),
        BigEndian::read_u16(&ip_bin[10..12]),
        BigEndian::read_u16(&ip_bin[12..14]),
        BigEndian::read_u16(&ip_bin[14..16]),
    );
    let ip = match ip_v6.to_ipv4() {
        Some(ip_v4) => IpAddr::V4(ip_v4),
        None => IpAddr::V6(ip_v6),
    };
    #[cfg(feature = "metrics")]
    globals.varz.anonymized_queries.inc();

    ensure!(IpExt::is_global(&ip), "Forbidden upstream address");
    ensure!(
        !globals.anonymized_dns_blacklisted_ips.contains(&ip),
        "Blacklisted upstream IP"
    );
    let port = BigEndian::read_u16(&relayed_packet[16..18]);
    ensure!(
        (globals.anonymized_dns_allow_non_reserved_ports && port >= 1024)
            || globals.anonymized_dns_allowed_ports.contains(&port),
        "Forbidden upstream port"
    );
    let upstream_address = SocketAddr::new(ip, port);
    ensure!(
        !globals.listen_addrs.contains(&upstream_address)
            && globals.external_addr != Some(upstream_address),
        "Would be relaying to self"
    );
    let encrypted_packet = &relayed_packet[ANONYMIZED_DNSCRYPT_OVERHEAD..];
    let encrypted_packet_len = encrypted_packet.len();
    ensure!(
        encrypted_packet_len >= ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len() + DNS_HEADER_SIZE
            && encrypted_packet_len <= DNSCRYPT_UDP_QUERY_MAX_SIZE,
        "Unexpected encapsulated query length"
    );
    ensure!(
        encrypted_packet_len > 8 && [0u8, 0, 0, 0, 0, 0, 0, 1] != encrypted_packet[..8],
        "Protocol confusion with QUIC"
    );
    debug_assert!(DNSCRYPT_UDP_QUERY_MIN_SIZE > ANONYMIZED_DNSCRYPT_QUERY_MAGIC.len());
    ensure!(!starts_with_relay_magic(encrypted_packet), "Loop detected");
    let ext_socket =
        crate::resolver::upstream_udp_socket(upstream_address, globals.external_addr).await?;
    ext_socket.send(encrypted_packet).await?;
    let mut response = vec![0u8; DNSCRYPT_UDP_RESPONSE_MAX_SIZE];
    let (response_len, is_certificate_response) = loop {
        let fut = ext_socket.recv_from(&mut response[..]);
        let (response_len, response_addr) = fut.await?;
        if response_addr != upstream_address {
            continue;
        }
        // Anti-amplification: the relay must never return more bytes to the
        // client than the client sent, so an upstream response larger than the
        // request is dropped. This holds for post-quantum certificates too: a
        // client that wants a large PQ certificate over UDP pads its query to at
        // least the response size, exactly as a query carrying a ciphertext is
        // already large enough to cover its response.
        if response_len > encrypted_packet_len {
            continue;
        }
        if is_encrypted_response(&response, response_len) {
            break (response_len, false);
        }
        if is_certificate_response(&response, response_len, encrypted_packet) {
            break (response_len, true);
        }
    };
    response.truncate(response_len);
    if is_certificate_response {
        response = cache_certificate_response(&globals, relayed_packet, response)?;
    }

    #[cfg(feature = "metrics")]
    globals.varz.anonymized_responses.inc();

    respond_to_query(client_ctx, response).await
}

fn cache_certificate_response(
    globals: &Globals,
    relayed_packet: &[u8],
    mut response: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let encrypted_packet = &relayed_packet[ANONYMIZED_DNSCRYPT_OVERHEAD..];
    let mut hasher = globals.hasher;
    hasher.write(&relayed_packet[..ANONYMIZED_DNSCRYPT_OVERHEAD]);
    hasher.write(&dns::qname(encrypted_packet)?);
    let packet_hash = hasher.finish128().as_u128();
    let cached_response = {
        match globals.cert_cache.lock().get(&packet_hash) {
            None => None,
            Some(response) if !(*response).has_expired() => {
                trace!("Relayed certificate cached");
                let mut cached_response = (*response).clone();
                cached_response.set_tid(dns::tid(encrypted_packet));
                let cached_response = cached_response.into_response();
                // Cached certificates must obey the same amplification limit
                // as the response just received from the upstream.
                (cached_response.len() <= encrypted_packet.len()).then_some(cached_response)
            }
            Some(_) => {
                trace!("Relayed certificate expired");
                None
            }
        }
    };
    match cached_response {
        None if !dns::is_truncated(&response) => {
            globals.cert_cache.lock().insert(
                packet_hash,
                CachedResponse::new(&globals.cert_cache, response.clone()),
            );
        }
        None => {}
        Some(cached_response) => response = cached_response,
    }
    Ok(response)
}

#[inline]
fn is_encrypted_response(response: &[u8], response_len: usize) -> bool {
    (DNSCRYPT_UDP_RESPONSE_MIN_SIZE..=DNSCRYPT_UDP_RESPONSE_MAX_SIZE).contains(&response_len)
        && response[..DNSCRYPT_RESPONSE_MAGIC_SIZE] == DNSCRYPT_RESPONSE_MAGIC
}

fn is_certificate_response(response: &[u8], response_len: usize, query: &[u8]) -> bool {
    let response = &response[..response_len];
    let prefix = b"2.dnscrypt-cert.";
    if !((DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&query.len())
        && (DNS_HEADER_SIZE + prefix.len() + 4..=DNS_MAX_PACKET_SIZE).contains(&response.len())
        && dns::tid(response) == dns::tid(query)
        && dns::is_response(response)
        && !dns::is_response(query))
    {
        debug!("Unexpected relayed cert response");
        return false;
    }
    let expected_question = (dns::DNS_TYPE_TXT, dns::DNS_CLASS_INET);
    if dns::qtype_qclass(query).ok() != Some(expected_question)
        || dns::qtype_qclass(response).ok() != Some(expected_question)
    {
        debug!("Relayed cert query or response wasn't TXT/IN");
        return false;
    }
    let qname = match (dns::qname(query), dns::qname(response)) {
        (Ok(response_qname), Ok(query_qname)) if response_qname == query_qname => query_qname,
        _ => {
            debug!("Relayed cert qname response didn't match the query qname");
            return false;
        }
    };
    if qname.len() <= prefix.len() || &qname[..prefix.len()] != prefix {
        debug!("Relayed cert qname response didn't start with the standard prefix");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_packet(qtype: u16, is_response: bool) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'2',
            0x0d, b'd', b'n', b's', b'c', b'r', b'y', b'p', b't', b'-', b'c', b'e', b'r', b't',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00,
        ];
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&dns::DNS_CLASS_INET.to_be_bytes());
        if is_response {
            packet[2] |= 0x80;
        }
        packet
    }

    #[test]
    fn only_txt_in_answers_are_certificate_responses() {
        let txt_query = cert_packet(dns::DNS_TYPE_TXT, false);
        let txt_response = cert_packet(dns::DNS_TYPE_TXT, true);
        assert!(is_certificate_response(
            &txt_response,
            txt_response.len(),
            &txt_query
        ));

        let a_query = cert_packet(dns::DNS_TYPE_A, false);
        let a_response = cert_packet(dns::DNS_TYPE_A, true);
        assert!(!is_certificate_response(
            &a_response,
            a_response.len(),
            &a_query
        ));
        assert!(!is_certificate_response(
            &a_response,
            a_response.len(),
            &txt_query
        ));
    }

    #[test]
    fn certificate_validation_ignores_bytes_beyond_the_received_datagram() {
        let query = cert_packet(dns::DNS_TYPE_TXT, false);
        let response = cert_packet(dns::DNS_TYPE_TXT, true);
        let mut buffer = vec![0; DNSCRYPT_UDP_RESPONSE_MAX_SIZE];
        buffer[..response.len()].copy_from_slice(&response);
        assert!(is_certificate_response(&buffer, response.len(), &query));
        // A subsequent datagram leaves the earlier question in the receive buffer.
        for len in [DNS_HEADER_SIZE, response.len() - 1] {
            assert!(!is_certificate_response(&buffer, len, &query));
        }
    }

    fn relayed_cert_query(size: usize) -> Vec<u8> {
        let mut packet = vec![0; ANONYMIZED_DNSCRYPT_OVERHEAD];
        let mut query = cert_packet(dns::DNS_TYPE_TXT, false);
        query.resize(size, 0);
        packet.extend(query);
        packet
    }

    fn cert_response(txt_size: usize) -> Vec<u8> {
        let mut response = cert_packet(dns::DNS_TYPE_TXT, true);
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 2, 88]);
        response.extend_from_slice(&((txt_size + 1) as u16).to_be_bytes());
        response.push(txt_size as u8);
        response.resize(response.len() + txt_size, 0x42);
        response
    }

    #[test]
    fn cached_certificate_respects_the_current_query_size() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let globals = crate::tests::globals("127.0.0.1:9".parse().unwrap());
            let large = cert_response(255);
            cache_certificate_response(&globals, &relayed_cert_query(512), large).unwrap();
            let small = cert_response(124);
            let response =
                cache_certificate_response(&globals, &relayed_cert_query(256), small.clone())
                    .unwrap();
            assert!(
                response.len() <= 256,
                "cache bypassed the relay amplification limit"
            );
            assert_eq!(response, small);
        });
    }

    #[test]
    fn truncated_certificate_does_not_replace_a_complete_response() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let globals = crate::tests::globals("127.0.0.1:9".parse().unwrap());
            let mut truncated = cert_response(124);
            dns::truncate(&mut truncated);
            cache_certificate_response(&globals, &relayed_cert_query(256), truncated).unwrap();
            let complete = cert_response(255);
            let response =
                cache_certificate_response(&globals, &relayed_cert_query(512), complete.clone())
                    .unwrap();
            assert!(!dns::is_truncated(&response));
            assert_eq!(response, complete);
        });
    }

    #[test]
    fn complete_cached_certificate_is_reused_when_it_fits() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let globals = crate::tests::globals("127.0.0.1:9".parse().unwrap());
            let mut query = relayed_cert_query(512);
            let mut cached = cert_response(124);
            cache_certificate_response(&globals, &query, cached.clone()).unwrap();
            dns::set_tid(&mut query[ANONYMIZED_DNSCRYPT_OVERHEAD..], 0xabcd);
            dns::set_tid(&mut cached, 0xabcd);
            for mut fresh in [cert_response(255), cert_response(124)] {
                dns::set_tid(&mut fresh, 0xabcd);
                let response = cache_certificate_response(&globals, &query, fresh).unwrap();
                assert_eq!(response, cached);
            }
        });
    }
}
