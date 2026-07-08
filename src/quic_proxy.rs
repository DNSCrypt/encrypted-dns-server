use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::AbortHandle;

use crate::anonymized_dns::starts_with_relay_magic;
use crate::dns::{self, DNS_HEADER_SIZE};
use crate::dnscrypt::{may_be_quic, DNSCRYPT_QUERY_MAGIC_SIZE};
use crate::errors::*;
use crate::globals::Globals;
use crate::pq;
use crate::resolver::upstream_udp_socket;

pub const QUIC_PROXY_DEFAULT_IDLE_TIMEOUT_SECS: u32 = 30;
pub const QUIC_PROXY_DEFAULT_MAX_ACTIVE_FLOWS: u32 = 512;

/// RFC 9000 requires a client to expand every datagram carrying an Initial
/// packet to at least 1200 bytes, and the first datagram of a connection
/// always carries one, so anything shorter cannot start a QUIC connection.
const QUIC_MIN_FIRST_DATAGRAM_SIZE: usize = 1200;

/// Largest possible UDP payload, so forwarded QUIC datagrams are never
/// truncated, whatever MTU the path supports.
pub const QUIC_PROXY_BUFFER_SIZE: usize = 65535;

fn now_ticks() -> u64 {
    coarsetime::Instant::recent().as_ticks()
}

struct QuicFlow {
    ext_socket: UdpSocket,
    last_activity: AtomicU64,
}

impl QuicFlow {
    fn touch(&self) {
        self.last_activity.store(now_ticks(), Ordering::Relaxed)
    }

    fn idle_ticks(&self) -> u64 {
        now_ticks().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }
}

struct FlowEntry {
    flow: Arc<QuicFlow>,
    abort: AbortHandle,
}

struct CreationGuard<'t>(&'t AtomicU64);

impl Drop for CreationGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct QuicProxy {
    upstream_addr: SocketAddr,
    external_addr: Option<SocketAddr>,
    max_active_flows: usize,
    idle_timeout: Duration,
    idle_timeout_ticks: u64,
    flows: Mutex<HashMap<SocketAddr, FlowEntry>>,
    // Mirrors flows.len(), updated while holding the flows lock, so the
    // per-datagram fast path can skip the lock when there are no flows.
    active_flows: AtomicUsize,
    creations_in_flight: AtomicU64,
}

impl QuicProxy {
    pub fn new(
        upstream_addr: SocketAddr,
        external_addr: Option<SocketAddr>,
        max_active_flows: usize,
        idle_timeout_secs: u32,
    ) -> Self {
        let idle_timeout_secs = u64::from(idle_timeout_secs.max(1));
        QuicProxy {
            upstream_addr,
            external_addr,
            max_active_flows: max_active_flows.max(1),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            idle_timeout_ticks: coarsetime::Duration::from_secs(idle_timeout_secs).as_ticks(),
            flows: Mutex::new(HashMap::new()),
            active_flows: AtomicUsize::new(0),
            creations_in_flight: AtomicU64::new(0),
        }
    }

    /// Look up a flow and mark it active under the table lock, so idle
    /// expiry (which re-checks under the same lock) cannot race the hand-out.
    fn lookup(&self, client_addr: &SocketAddr) -> Option<Arc<QuicFlow>> {
        let flows = self.flows.lock();
        let flow = flows.get(client_addr).map(|e| e.flow.clone());
        if let Some(flow) = &flow {
            flow.touch();
        }
        flow
    }

    fn evict_oldest(flows: &mut HashMap<SocketAddr, FlowEntry>) {
        let oldest = flows
            .iter()
            .min_by_key(|(_, e)| e.flow.last_activity.load(Ordering::Relaxed))
            .map(|(k, _)| *k);
        if let Some(oldest) = oldest {
            if let Some(entry) = flows.remove(&oldest) {
                entry.abort.abort();
            }
        }
    }

    /// Remove the entry for `client_addr` only if it still refers to `flow`,
    /// leaving a newer replacement untouched.
    fn remove_if_current(
        &self,
        flows: &mut HashMap<SocketAddr, FlowEntry>,
        client_addr: &SocketAddr,
        flow: &Arc<QuicFlow>,
    ) {
        if let Some(entry) = flows.get(client_addr) {
            if Arc::ptr_eq(&entry.flow, flow) {
                flows.remove(client_addr);
                self.active_flows.store(flows.len(), Ordering::Relaxed);
            }
        }
    }
}

/// True when the packet begins with a byte sequence reserved by the DNSCrypt
/// protocol: the Anonymized DNSCrypt relay magic, the PQ session resumption
/// magic, or the client magic of any currently valid certificate. Client
/// magics are randomly derived, so they can land in the QUIC first-byte
/// ranges; packets carrying one must always stay on the DNSCrypt path.
fn is_dnscrypt_reserved_prefix(globals: &Globals, packet: &[u8]) -> bool {
    if starts_with_relay_magic(packet) {
        return true;
    }
    if packet.len() < DNSCRYPT_QUERY_MAGIC_SIZE {
        return false;
    }
    let magic = &packet[..DNSCRYPT_QUERY_MAGIC_SIZE];
    if magic == pq::PQ_RESUME_MAGIC {
        return true;
    }
    // Unlike decrypt(), the PQ checks are deliberately not gated on
    // pq_enabled: a prefix the protocol reserves must stay on the DNSCrypt
    // path whatever the local configuration says.
    let params_set = globals.dnscrypt_encryption_params_set.read();
    params_set.iter().any(|p| {
        p.client_magic() == magic || p.pq().is_some_and(|pq| pq.client_magic() == magic)
    })
}

/// True when the packet could be a plaintext DNS query, such as a certificate
/// query for the provider name. The DNS transaction identifier is random, so
/// its first byte regularly collides with the QUIC ranges; anything that
/// parses as a query must go through the regular DNS path.
fn may_be_dns_query(packet: &[u8]) -> bool {
    packet.len() >= DNS_HEADER_SIZE && dns::qdcount(packet) == 1 && !dns::is_response(packet)
}

fn is_quic_long_header(packet: &[u8]) -> bool {
    !packet.is_empty() && packet[0] >= 0xc0
}

/// Forward a packet that belongs to an established QUIC flow, without going
/// through DNS processing or rate limiting. Only packets that provably cannot
/// be DNSCrypt, Anonymized DNSCrypt, or plaintext DNS are taken here; anything
/// ambiguous falls through to the regular path, where actual decryption
/// settles what the packet is. Returns true when the packet was consumed.
pub fn try_forward_established(globals: &Globals, client_addr: SocketAddr, packet: &[u8]) -> bool {
    let proxy = match &globals.quic_proxy {
        Some(proxy) => proxy,
        None => return false,
    };
    if proxy.active_flows.load(Ordering::Relaxed) == 0 || !may_be_quic(packet) {
        return false;
    }
    let flow = match proxy.lookup(&client_addr) {
        Some(flow) => flow,
        None => return false,
    };
    if is_dnscrypt_reserved_prefix(globals, packet) || may_be_dns_query(packet) {
        return false;
    }
    // A full socket buffer just drops the datagram; QUIC treats it as loss.
    let _ = flow.ext_socket.try_send(packet);
    true
}

/// Forward a packet that cannot be a DNSCrypt query — decryption failed, or
/// it exceeds the maximum DNSCrypt size — and matches the QUIC ranges of
/// RFC 9443. An existing flow is reused; otherwise the packet must plausibly
/// be a client first flight for a new flow to be created.
pub async fn relay(
    globals: &Arc<Globals>,
    net_udp_socket: std::net::UdpSocket,
    client_addr: SocketAddr,
    packet: &[u8],
) -> Result<(), Error> {
    let proxy = globals
        .quic_proxy
        .as_ref()
        .ok_or_else(|| anyhow!("QUIC proxying is not enabled"))?;
    // A packet that still carries a reserved DNSCrypt prefix at this point
    // is simply invalid; drop it rather than leak it upstream.
    ensure!(
        !is_dnscrypt_reserved_prefix(globals, packet),
        "Reserved DNSCrypt prefix"
    );
    if let Some(flow) = proxy.lookup(&client_addr) {
        flow.ext_socket.send(packet).await?;
        return Ok(());
    }
    ensure!(
        is_quic_long_header(packet),
        "Not a QUIC long header, and no active flow"
    );
    ensure!(
        packet.len() >= QUIC_MIN_FIRST_DATAGRAM_SIZE,
        "Too short for a QUIC first flight"
    );
    ensure!(client_addr != proxy.upstream_addr, "QUIC relay loop");
    // The flow table is bounded at insertion, but sockets are created before
    // that; bound concurrent creations too, so a flood of spoofed first
    // flights cannot exhaust file descriptors.
    let in_flight = proxy.creations_in_flight.fetch_add(1, Ordering::Relaxed);
    let _creation_guard = CreationGuard(&proxy.creations_in_flight);
    ensure!(
        (in_flight as usize) < proxy.max_active_flows,
        "Too many QUIC flows in creation"
    );

    // Amplification towards a spoofed client address is bounded: a flow is
    // only created for a padded (>= 1200 bytes) first flight, and a compliant
    // QUIC upstream responds to an unvalidated address with at most three
    // times the bytes it received (RFC 9000, section 8).
    let ext_socket = upstream_udp_socket(proxy.upstream_addr, proxy.external_addr).await?;
    let listener_socket = UdpSocket::from_std(net_udp_socket)?;
    let new_flow = Arc::new(QuicFlow {
        ext_socket,
        last_activity: AtomicU64::new(now_ticks()),
    });
    let flow = {
        let mut flows = proxy.flows.lock();
        match flows.get(&client_addr) {
            // Another task created the flow first; use it and drop ours.
            Some(entry) => entry.flow.clone(),
            None => {
                if flows.len() >= proxy.max_active_flows {
                    QuicProxy::evict_oldest(&mut flows);
                }
                let task = globals.runtime_handle.spawn(flow_responder(
                    proxy.clone(),
                    new_flow.clone(),
                    client_addr,
                    listener_socket,
                ));
                flows.insert(
                    client_addr,
                    FlowEntry {
                        flow: new_flow.clone(),
                        abort: task.abort_handle(),
                    },
                );
                proxy.active_flows.store(flows.len(), Ordering::Relaxed);
                new_flow
            }
        }
    };
    flow.touch();
    flow.ext_socket.send(packet).await?;
    Ok(())
}

async fn flow_responder(
    proxy: Arc<QuicProxy>,
    flow: Arc<QuicFlow>,
    client_addr: SocketAddr,
    listener_socket: UdpSocket,
) {
    let mut buf = vec![0u8; QUIC_PROXY_BUFFER_SIZE];
    loop {
        match tokio::time::timeout(proxy.idle_timeout, flow.ext_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                flow.touch();
                let _ = listener_socket.send_to(&buf[..len], client_addr).await;
            }
            Ok(Err(e)) => {
                debug!("QUIC flow upstream error for {}: {}", client_addr, e);
                break;
            }
            Err(_) => {
                if flow.idle_ticks() < proxy.idle_timeout_ticks {
                    continue;
                }
                // Re-check under the table lock: lookup() touches flows while holding it.
                let mut flows = proxy.flows.lock();
                if flow.idle_ticks() < proxy.idle_timeout_ticks {
                    continue;
                }
                proxy.remove_if_current(&mut flows, &client_addr, &flow);
                return;
            }
        }
    }
    proxy.remove_if_current(&mut proxy.flows.lock(), &client_addr, &flow);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anonymized_dns::ANONYMIZED_DNSCRYPT_QUERY_MAGIC;

    #[test]
    fn quic_ranges_match_rfc9443() {
        for b in 0u8..=255 {
            let expected = (80..=127).contains(&b) || (192..=255).contains(&b);
            assert_eq!(may_be_quic(&[b]), expected, "byte {}", b);
        }
        assert!(!may_be_quic(&[]));
    }

    #[test]
    fn reserved_magics_fall_in_quic_ranges() {
        // These DNSCrypt prefixes collide with the QUIC first-byte ranges,
        // which is why prefix checks must run before any QUIC forwarding.
        assert!(may_be_quic(&pq::PQ_RESUME_MAGIC));
        assert!(may_be_quic(&ANONYMIZED_DNSCRYPT_QUERY_MAGIC));
    }

    #[test]
    fn long_header_detection() {
        assert!(is_quic_long_header(&[0xc0]));
        assert!(is_quic_long_header(&[0xff]));
        assert!(!is_quic_long_header(&[0x7f]));
        assert!(!is_quic_long_header(&[0x50]));
        assert!(!is_quic_long_header(&[]));
    }

    #[test]
    fn quic_v1_initial_is_not_mistaken_for_dns_query() {
        // Long header, version 1: the version bytes land where DNS puts the
        // flags and qdcount, and qdcount comes out as 0x01xx, never 1.
        let mut packet = vec![0u8; 1200];
        packet[0] = 0xc3;
        packet[1..5].copy_from_slice(&[0, 0, 0, 1]);
        packet[5] = 8;
        assert!(!may_be_dns_query(&packet));
        assert!(may_be_quic(&packet));
        assert!(is_quic_long_header(&packet));
    }

    #[test]
    fn cert_query_is_dns_query() {
        // Minimal DNS query header with a QUIC-looking transaction identifier.
        let mut packet = vec![0u8; 32];
        packet[0] = 0xc3;
        packet[1] = 0x42;
        packet[2] = 0x01; // RD
        packet[5] = 0x01; // qdcount = 1
        assert!(may_be_dns_query(&packet));
    }
}
