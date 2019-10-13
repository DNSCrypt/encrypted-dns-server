use crate::*;

use byteorder::{BigEndian, ByteOrder};
use failure::ensure;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub const ANONYMIZED_DNSCRYPT_QUERY_MAGIC: [u8; 10] =
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

pub const ANONYMIZED_DNSCRYPT_OVERHEAD: usize = 16 + 2;

pub async fn handle_anonymized_dns(
    globals: Arc<Globals>,
    client_ctx: ClientCtx,
    encrypted_packet: &[u8],
) -> Result<(), Error> {
    ensure!(
        encrypted_packet.len() > ANONYMIZED_DNSCRYPT_OVERHEAD,
        "Short packet"
    );
    let ip_bin = &encrypted_packet[..16];
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

    ensure!(ip.is_global(), "Forbidden upstream address");
    let port = BigEndian::read_u16(&encrypted_packet[16..18]);
    ensure!([443].contains(&port), "Forbidden upstream port");
    let upstream_address = SocketAddr::new(ip, port);
    ensure!(
        !globals.listen_addrs.contains(&upstream_address)
            && globals.external_addr != upstream_address,
        "Would be relaying to self"
    );
    let encrypted_packet = &encrypted_packet[ANONYMIZED_DNSCRYPT_OVERHEAD..];
    let encrypted_packet_len = encrypted_packet.len();
    ensure!(
        encrypted_packet_len >= DNSCRYPT_UDP_QUERY_MIN_SIZE
            && encrypted_packet_len <= DNSCRYPT_UDP_QUERY_MAX_SIZE,
        "Unexpected encapsulated query length"
    );
    ensure!(
        encrypted_packet_len > 8 && [0u8, 0, 0, 0, 0, 0, 0, 1] != encrypted_packet[..8],
        "Protocol confusion with QUIC"
    );
    let mut ext_socket = UdpSocket::bind(&globals.external_addr).await?;
    ext_socket.connect(&upstream_address).await?;
    ext_socket.send(&encrypted_packet).await?;
    let mut response = vec![0u8; DNSCRYPT_UDP_RESPONSE_MAX_SIZE];
    loop {
        let fut = ext_socket.recv_from(&mut response[..]);
        let (response_len, response_addr) = fut.await?;
        if response_addr == upstream_address
            && (DNSCRYPT_UDP_RESPONSE_MIN_SIZE..=DNSCRYPT_UDP_RESPONSE_MAX_SIZE)
                .contains(&response_len)
            && response[..DNSCRYPT_RESPONSE_MAGIC_SIZE] == DNSCRYPT_RESPONSE_MAGIC
        {
            response.truncate(response_len);
            break;
        }
    }

    #[cfg(feature = "metrics")]
    globals.varz.anonymized_responses.inc();

    respond_to_query(client_ctx, response).await
}
