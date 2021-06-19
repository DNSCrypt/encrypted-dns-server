use crate::cache::*;
use crate::dns::{self, *};
use crate::errors::*;
use crate::globals::*;
use crate::ClientCtx;

use byteorder::{BigEndian, ByteOrder};
use rand::prelude::*;
use siphasher::sip128::Hasher128;
use std::cmp;
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};

pub async fn resolve_udp(
    globals: &Globals,
    mut packet: &mut Vec<u8>,
    packet_qname: &[u8],
    tid: u16,
    opt_rdata: &Vec<u8>,
    has_cached_response: bool,
) -> Result<Vec<u8>, Error> {
    let ext_socket = match globals.external_addr {
        Some(x) => UdpSocket::bind(x).await?,
        None => match globals.upstream_addr {
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
    ext_socket.connect(globals.upstream_addr).await?;
    dns::set_edns_max_payload_size(&mut packet, DNS_MAX_PACKET_SIZE as u16, opt_rdata)?;
    let mut response;
    let timeout = if has_cached_response {
        globals.udp_timeout / 2
    } else {
        globals.udp_timeout
    };
    loop {
        ext_socket.send(&packet).await?;
        response = vec![0u8; DNS_MAX_PACKET_SIZE];
        dns::set_rcode_servfail(&mut response);
        let fut = tokio::time::timeout(timeout, ext_socket.recv_from(&mut response[..]));
        match fut.await {
            Ok(Ok((response_len, response_addr))) => {
                response.truncate(response_len);
                if response_addr == globals.upstream_addr
                    && response_len >= DNS_HEADER_SIZE
                    && dns::tid(&response) == tid
                    && packet_qname.eq_ignore_ascii_case(dns::qname(&response)?.as_slice())
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
    mut packet: &mut Vec<u8>,
    packet_qname: &[u8],
    tid: u16,
    opt_rdata: &Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let socket = match globals.external_addr {
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
        None => match globals.upstream_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        },
    };
    let mut ext_socket = socket.connect(globals.upstream_addr).await?;
    ext_socket.set_nodelay(true)?;
    dns::set_edns_max_payload_size(&mut packet, DNS_MAX_PACKET_SIZE as u16, opt_rdata)?;
    let mut binlen = [0u8, 0];
    BigEndian::write_u16(&mut binlen[..], packet.len() as u16);
    ext_socket.write_all(&binlen).await?;
    ext_socket.write_all(&packet).await?;
    ext_socket.flush().await?;
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
        packet_qname.eq_ignore_ascii_case(dns::qname(&response)?.as_slice()),
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
    opt_rdata: &Vec<u8>,
) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "metrics")]
    globals.varz.upstream_sent.inc();
    let tid = random();
    dns::set_tid(&mut packet, tid);
    let mut response = resolve_udp(
        globals,
        packet,
        &packet_qname,
        tid,
        opt_rdata,
        cached_response.is_some(),
    )
    .await?;
    if dns::is_truncated(&response) {
        response = resolve_tcp(globals, packet, &packet_qname, tid, opt_rdata).await?;
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
    mut packet: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let packet_qname = dns::qname(&packet)?;
    let client_ip = match client_ctx {
        ClientCtx::Udp(u) => u.client_addr,
        ClientCtx::Tcp(t) => t.client_connection.peer_addr()?,
    }
    .ip();
    if let Some(my_ip) = &globals.my_ip {
        if &packet_qname.to_ascii_lowercase() == my_ip {
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
            let (qtype, qclass) = dns::qtype_qclass(&packet)?;
            qtype == dns::DNS_CLASS_INET
                && (qclass == dns::DNS_TYPE_A || qclass == dns::DNS_TYPE_AAAA)
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
    let original_tid = dns::tid(&packet);
    dns::set_tid(&mut packet, 0);
    dns::normalize_qname(&mut packet)?;
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

    let mut opt_rdata = vec![
        0,  // 2 octets, all RDATA length https://tools.ietf.org/html/rfc6891#page-7
        0
    ];
    if globals.ecs_enabled {
        opt_rdata.push(0);  // (Defined in [RFC6891]) OPTION-CODE, 2 octets
        opt_rdata.push(8);  // for ECS is 8 (0x00 0x08)
        opt_rdata.push(0);  // (Defined in [RFC6891]) OPTION-LENGTH, 2 octets
        opt_rdata.push(8);  // contains length of the payload (everything after OPTION-LENGTH) in octets.
        opt_rdata.push(0);  // FAMILY, 2 octets
        opt_rdata.push(1);  // (0x00 0x01 ipv4)
        // SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost number of significant bits of ADDRESS
        // SCOPE PREFIX-LENGTH, an unsigned octet representing.. In queries, it MUST be set to 0
        // ADDRESS, variable number of octets, contains either an IPv4 or
        // IPv6 address, depending on FAMILY, which MUST be truncated to the
        // number of bits indicated by the SOURCE PREFIX-LENGTH field,
        // padding with 0 bits to pad to the end of the last octet needed
        let mut iplen:usize;
        match client_ip {
            IpAddr::V4(ipv4) => {
                opt_rdata.push(globals.ecs_source_prefix_ipv4);
                opt_rdata.push(0);
                let mut mask:u32 = 0xFFFFFFFF;
                let mut n = 32 - globals.ecs_source_prefix_ipv4;
                while n > 0 {
                    mask <<= 1;
                    n -= 1;
                }
                let ipnum = u32::from(ipv4) & mask;
                let iparr: [u8; 4] = ipnum.to_be_bytes();
                iplen = iparr.len();
                while iplen > 1 && iparr[iplen-1] == 0 {
                    if iparr[iplen-2] != 0 { break; }
                    iplen -= 1;
                }
                let mut z = 0;
                while z < iplen {
                    opt_rdata.push(iparr[z]);
                    z += 1;
                }
            }
            IpAddr::V6(ipv6) => {
                opt_rdata.push(globals.ecs_source_prefix_ipv6);
                opt_rdata.push(0);
                opt_rdata[7] = 2;  // family number 2 = ipv6
                let mut mask:u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
                let mut n = 128 - globals.ecs_source_prefix_ipv6;
                while n > 0 {
                    mask <<= 1;
                    n -= 1;
                }
                let ipnum = u128::from(ipv6) & mask;
                let iparr: [u8; 16] = ipnum.to_be_bytes();
                iplen = iparr.len();
                while iplen > 1 && iparr[iplen-1] == 0 {
                    if iparr[iplen-2] != 0 { break; }
                    iplen -= 1;
                }
                let mut z = 0;
                while z < iplen {
                    opt_rdata.push(iparr[z]);
                    z += 1;
                }
            }
        }
        opt_rdata[1] = 8 + iplen as u8;
    }
    //info!("ECS data {:?}", opt_rdata);

    resolve(
        globals,
        packet,
        packet_qname,
        cached_response,
        packet_hash,
        original_tid,
        &opt_rdata,
    )
    .await
}
