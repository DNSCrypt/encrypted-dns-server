use std::cmp;
use std::hash::Hasher;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
use rand::{random, rng, Rng};
use siphasher::sip128::Hasher128;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};

use crate::cache::*;
use crate::dns::{self, *};
use crate::errors::*;
use crate::globals::*;
use crate::ClientCtx;

async fn resolve_udp_single(
    upstream_addr: SocketAddr,
    external_addr: Option<SocketAddr>,
    packet: &[u8],
    packet_qname: &[u8],
    tid: u16,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let ext_socket = match external_addr {
        Some(x) => UdpSocket::bind(x).await?,
        None => match upstream_addr {
            SocketAddr::V4(_) => {
                UdpSocket::bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                    .await?
            }
            SocketAddr::V6(s) => {
                UdpSocket::bind(&SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    0,
                    s.flowinfo(),
                    s.scope_id(),
                )))
                .await?
            }
        },
    };
    ext_socket.connect(upstream_addr).await?;
    ext_socket.send(packet).await?;
    let mut response = vec![0u8; DNS_MAX_PACKET_SIZE];
    let fut = tokio::time::timeout(timeout, ext_socket.recv_from(&mut response[..]));
    match fut.await {
        Ok(Ok((response_len, response_addr))) => {
            response.truncate(response_len);
            if response_addr == upstream_addr
                && response_len >= DNS_HEADER_SIZE
                && dns::tid(&response) == tid
                && packet_qname.eq_ignore_ascii_case(dns::qname(&response)?.as_slice())
            {
                return Ok(response);
            }
            bail!("Invalid response from upstream");
        }
        Ok(Err(e)) => bail!("UDP receive error: {}", e),
        Err(_) => bail!("UDP timeout"),
    }
}

pub async fn resolve_udp(
    globals: &Globals,
    packet: &mut Vec<u8>,
    packet_qname: &[u8],
    tid: u16,
    has_cached_response: bool,
) -> Result<Vec<u8>, Error> {
    dns::set_edns_max_payload_size(packet, DNS_MAX_PACKET_SIZE as u16)?;
    let timeout = if has_cached_response {
        globals.udp_timeout / 2
    } else {
        globals.udp_timeout
    };

    let mut last_error = None;
    for upstream_addr in &globals.upstream_addrs {
        match resolve_udp_single(
            *upstream_addr,
            globals.external_addr,
            packet,
            packet_qname,
            tid,
            timeout,
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(e) => {
                trace!("Upstream {} failed: {}", upstream_addr, e);
                last_error = Some(e);
            }
        }
    }

    if has_cached_response {
        trace!("All upstreams failed, but cached response is present");
        let mut response = vec![0u8; DNS_MAX_PACKET_SIZE];
        dns::set_rcode_servfail(&mut response);
        return Ok(response);
    }

    Err(last_error.unwrap_or_else(|| anyhow!("No upstream servers configured")))
}

async fn resolve_tcp_single(
    upstream_addr: SocketAddr,
    external_addr: Option<SocketAddr>,
    packet: &[u8],
    packet_qname: &[u8],
    tid: u16,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let socket = match external_addr {
        Some(x @ SocketAddr::V4(_)) => {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true).ok();
            socket.bind(x)?;
            socket
        }
        Some(x @ SocketAddr::V6(_)) => {
            let socket = TcpSocket::new_v6()?;
            socket.set_reuseaddr(true).ok();
            socket.bind(x)?;
            socket
        }
        None => match upstream_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        },
    };

    let connect_fut = tokio::time::timeout(timeout, socket.connect(upstream_addr));
    let mut ext_socket = match connect_fut.await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => bail!("TCP connect error: {}", e),
        Err(_) => bail!("TCP connect timeout"),
    };

    ext_socket.set_nodelay(true)?;
    let mut binlen = [0u8, 0];
    BigEndian::write_u16(&mut binlen[..], packet.len() as u16);

    let write_fut = async {
        ext_socket.write_all(&binlen).await?;
        ext_socket.write_all(packet).await?;
        ext_socket.flush().await?;
        Ok::<_, std::io::Error>(())
    };
    tokio::time::timeout(timeout, write_fut)
        .await
        .map_err(|_| anyhow!("TCP write timeout"))?
        .map_err(|e| anyhow!("TCP write error: {}", e))?;

    let read_fut = async {
        ext_socket.read_exact(&mut binlen).await?;
        let response_len = BigEndian::read_u16(&binlen) as usize;
        if !(DNS_HEADER_SIZE..=DNS_MAX_PACKET_SIZE).contains(&response_len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected response size",
            ));
        }
        let mut response = vec![0u8; response_len];
        ext_socket.read_exact(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };

    let response = tokio::time::timeout(timeout, read_fut)
        .await
        .map_err(|_| anyhow!("TCP read timeout"))?
        .map_err(|e| anyhow!("TCP read error: {}", e))?;

    ensure!(dns::tid(&response) == tid, "Unexpected transaction ID");
    ensure!(
        packet_qname.eq_ignore_ascii_case(dns::qname(&response)?.as_slice()),
        "Unexpected query name in the response"
    );
    Ok(response)
}

pub async fn resolve_tcp(
    globals: &Globals,
    packet: &mut [u8],
    packet_qname: &[u8],
    tid: u16,
) -> Result<Vec<u8>, Error> {
    let mut last_error = None;
    for upstream_addr in &globals.upstream_addrs {
        match resolve_tcp_single(
            *upstream_addr,
            globals.external_addr,
            packet,
            packet_qname,
            tid,
            globals.tcp_timeout,
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(e) => {
                trace!("Upstream {} TCP failed: {}", upstream_addr, e);
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("No upstream servers configured")))
}

pub async fn resolve(
    globals: &Globals,
    packet: &mut Vec<u8>,
    packet_qname: Vec<u8>,
    cached_response: Option<CachedResponse>,
    packet_hash: u128,
    original_tid: u16,
) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "metrics")]
    globals.varz.upstream_sent.inc();
    let tid = random();
    dns::set_tid(packet, tid);
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
    #[cfg(feature = "metrics")]
    {
        globals.varz.upstream_received.inc();
        if dns::rcode_nxdomain(&response) {
            globals.varz.upstream_rcode_nxdomain.inc();
        }
    }
    if dns::rcode_servfail(&response) || dns::rcode_refused(&response) {
        trace!("SERVFAIL/REFUSED: {}", dns::rcode(&response));
        if let Some(cached_response) = cached_response {
            trace!("Serving stale");
            #[cfg(feature = "metrics")]
            {
                globals.varz.client_queries_offline.inc();
                globals.varz.client_queries_cached.inc();
            }
            return Ok(cached_response.into_response());
        } else {
            #[cfg(feature = "metrics")]
            globals.varz.upstream_errors.inc();
        }
    } else {
        trace!("Adding to cache");
        let cached_response = CachedResponse::new(&globals.cache, response.clone());
        globals.cache.lock().insert(packet_hash, cached_response);
    }
    dns::set_tid(&mut response, original_tid);
    dns::recase_qname(&mut response, &packet_qname)?;
    #[cfg(feature = "metrics")]
    globals
        .varz
        .upstream_response_sizes
        .observe(response.len() as f64);
    Ok(response)
}

pub async fn get_cached_response_or_resolve(
    globals: &Globals,
    client_ctx: &ClientCtx,
    packet: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let packet_qname = dns::qname(packet)?;
    if let Some(my_ip) = &globals.my_ip {
        if &packet_qname.to_ascii_lowercase() == my_ip {
            let client_ip = match client_ctx {
                ClientCtx::Udp(u) => u.client_addr,
                ClientCtx::Tcp(t) => t.client_connection.peer_addr()?,
            }
            .ip();
            return serve_ip_response(packet.to_vec(), client_ip, 1);
        }
    }
    if let Some(blacklist) = &globals.blacklist {
        if blacklist.find(&packet_qname) {
            #[cfg(feature = "metrics")]
            globals.varz.client_queries_blocked.inc();
            return dns::serve_blocked_response(packet.to_vec());
        }
    }
    let tld = dns::qname_tld(&packet_qname);
    let synthesize_nxdomain = {
        if globals.ignore_unqualified_hostnames && tld.len() == packet_qname.len() {
            let (qtype, qclass) = dns::qtype_qclass(packet)?;
            qclass == dns::DNS_CLASS_INET
                && (qtype == dns::DNS_TYPE_A || qtype == dns::DNS_TYPE_AAAA)
        } else if let Some(undelegated_list) = &globals.undelegated_list {
            undelegated_list.find(tld)
        } else {
            false
        }
    };
    if synthesize_nxdomain {
        #[cfg(feature = "metrics")]
        globals.varz.client_queries_rcode_nxdomain.inc();
        return dns::serve_nxdomain_response(packet.to_vec());
    }
    let original_tid = dns::tid(packet);
    dns::set_tid(packet, 0);
    dns::normalize_qname(packet)?;
    // Create a new hasher instance to avoid race conditions
    let (sh_k0, sh_k1) = rng().random::<(u64, u64)>();
    let mut hasher = siphasher::sip128::SipHasher13::new_with_keys(sh_k0, sh_k1);
    hasher.write(packet);
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
            if !cached_response.has_expired() {
                trace!("Cached");
                #[cfg(feature = "metrics")]
                globals.varz.client_queries_cached.inc();
                cached_response.set_tid(original_tid);
                let original_ttl = cached_response.original_ttl();
                let mut ttl = cached_response.ttl();
                if ttl.saturating_add(globals.client_ttl_holdon) > original_ttl {
                    ttl = original_ttl;
                }
                ttl = cmp::max(1, ttl);
                let mut response = cached_response.into_response();
                dns::set_ttl(&mut response, ttl)?;
                dns::recase_qname(&mut response, &packet_qname)?;
                return Ok(response);
            }
            trace!("Expired");
            #[cfg(feature = "metrics")]
            globals.varz.client_queries_expired.inc();
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
