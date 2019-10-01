use crate::cache::*;
use crate::dns::{self, *};
use crate::errors::*;
use crate::globals::*;

use byteorder::{BigEndian, ByteOrder};
use rand::prelude::*;
use siphasher::sip128::Hasher128;
use std::hash::Hasher;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio_net::driver::Handle;

pub async fn resolve_udp(
    globals: &Globals,
    mut packet: &mut Vec<u8>,
    packet_qname: &[u8],
    tid: u16,
    has_cached_response: bool,
) -> Result<Vec<u8>, Error> {
    let mut ext_socket = UdpSocket::bind(&globals.external_addr).await?;
    ext_socket.connect(&globals.upstream_addr).await?;
    dns::set_edns_max_payload_size(&mut packet, DNS_MAX_PACKET_SIZE as u16)?;
    let mut response;
    let timeout_if_cached = globals.udp_timeout / 2;
    loop {
        ext_socket.send(&packet).await?;
        response = vec![0u8; DNS_MAX_PACKET_SIZE];
        dns::set_rcode_servfail(&mut response);
        let fut = ext_socket
            .recv_from(&mut response[..])
            .timeout(timeout_if_cached);
        match fut.await {
            Ok(Ok((response_len, response_addr))) => {
                response.truncate(response_len);
                if response_addr == globals.upstream_addr
                    && response_len >= DNS_HEADER_SIZE
                    && dns::tid(&response) == tid
                    && packet_qname == dns::qname(&response)?.as_slice()
                {
                    break;
                }
            }
            _ => {
                if has_cached_response {
                    trace!("Timeout, but cached response is present");
                    break;
                }
                trace!("Timeout, no cached response");
            }
        }
    }
    Ok(response)
}

pub async fn resolve_tcp(
    globals: &Globals,
    packet: &mut Vec<u8>,
    packet_qname: &[u8],
    tid: u16,
) -> Result<Vec<u8>, Error> {
    let std_socket = match globals.external_addr {
        SocketAddr::V4(_) => net2::TcpBuilder::new_v4(),
        SocketAddr::V6(_) => net2::TcpBuilder::new_v6(),
    }?
    .bind(&globals.external_addr)?
    .to_tcp_stream()?;
    let mut ext_socket =
        TcpStream::connect_std(std_socket, &globals.upstream_addr, &Handle::default()).await?;
    ext_socket.set_nodelay(true)?;
    let mut binlen = [0u8, 0];
    BigEndian::write_u16(&mut binlen[..], packet.len() as u16);
    ext_socket.write_all(&binlen).await?;
    ext_socket.write_all(&packet).await?;
    ext_socket.flush();
    ext_socket.read_exact(&mut binlen).await?;
    let response_len = BigEndian::read_u16(&binlen) as usize;
    ensure!(
        (DNS_HEADER_SIZE..=DNS_MAX_PACKET_SIZE).contains(&response_len),
        "Unexpected response size"
    );
    let mut response = vec![0u8; response_len];
    ext_socket.read_exact(&mut response).await?;
    ensure!(dns::tid(&response) == tid, "Unexpected transaction ID");
    ensure!(
        packet_qname == dns::qname(&response)?.as_slice(),
        "Unexpected query name in the response"
    );
    Ok(response)
}

pub async fn resolve(
    globals: &Globals,
    mut packet: &mut Vec<u8>,
    packet_qname: Vec<u8>,
    cached_response: Option<CachedResponse>,
    packet_hash: u128,
    original_tid: u16,
) -> Result<Vec<u8>, Error> {
    let tid = random();
    dns::set_tid(&mut packet, tid);
    let mut response = resolve_udp(
        globals,
        packet,
        &packet_qname,
        tid,
        cached_response.is_some(),
    )
    .await?;
    if dns::is_truncated(&response) {
        response = resolve_tcp(globals, packet, &packet_qname, tid).await?;
    }
    if dns::rcode_servfail(&response) {
        trace!("SERVFAIL");
        if let Some(cached_response) = cached_response {
            trace!("Serving stale");
            return Ok(cached_response.into_response());
        }
    } else {
        trace!("Adding to cache");
        let cached_response = CachedResponse::new(&globals.cache, response.clone());
        globals.cache.lock().insert(packet_hash, cached_response);
    }
    dns::set_tid(&mut response, original_tid);
    Ok(response)
}

pub async fn get_cached_response_or_resolve(
    globals: &Globals,
    mut packet: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let packet_qname = dns::qname(&packet)?;
    if let Some(blacklist) = &globals.blacklist {
        if blacklist.find(&packet_qname) {
            return dns::serve_empty_response(packet.to_vec());
        }
    }
    let original_tid = dns::tid(&packet);
    dns::set_tid(&mut packet, 0);
    let mut hasher = globals.hasher;
    hasher.write(&packet);
    let packet_hash = hasher.finish128().as_u128();
    let cached_response = {
        match globals.cache.lock().get(&packet_hash) {
            None => None,
            Some(response) => {
                let cached_response = (*response).clone();
                Some(cached_response)
            }
        }
    };
    let cached_response = match cached_response {
        None => None,
        Some(mut cached_response) => {
            cached_response.set_tid(original_tid);
            if !cached_response.has_expired() {
                trace!("Cached");
                return Ok(cached_response.into_response());
            }
            trace!("Expired");
            Some(cached_response)
        }
    };
    resolve(
        globals,
        packet,
        packet_qname,
        cached_response,
        packet_hash,
        original_tid,
    )
    .await
}
