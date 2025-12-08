use std::net::IpAddr;
use std::sync::Arc;

use coarsetime::Instant;
use parking_lot::Mutex;
use sieve_cache::SieveCache;

const DEFAULT_CAPACITY: usize = 10000;
const DEFAULT_MAX_QPS: u32 = 100;
const MICROTOKENS_PER_TOKEN: u64 = 1_000_000;

struct ClientState {
    microtokens: u64,
    last_update: Instant,
}

pub struct RateLimiter {
    clients: Mutex<SieveCache<IpAddr, ClientState>>,
    max_microtokens: u64,
    refill_rate: u64, // microtokens per microsecond (equals max_qps)
}

impl RateLimiter {
    pub fn new(capacity: usize, max_queries_per_second: u32) -> Self {
        let capacity = if capacity == 0 {
            DEFAULT_CAPACITY
        } else {
            capacity
        };
        let max_qps = if max_queries_per_second == 0 {
            DEFAULT_MAX_QPS
        } else {
            max_queries_per_second
        };
        RateLimiter {
            clients: Mutex::new(
                SieveCache::new(capacity).expect("Failed to create rate limiter cache"),
            ),
            max_microtokens: (max_qps as u64).saturating_mul(MICROTOKENS_PER_TOKEN),
            refill_rate: max_qps as u64,
        }
    }

    pub fn is_allowed(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut clients = self.clients.lock();

        if let Some(state) = clients.get_mut(&client_ip) {
            let elapsed_us = now.as_ticks().saturating_sub(state.last_update.as_ticks());
            let refill = elapsed_us.saturating_mul(self.refill_rate);
            state.microtokens = state.microtokens.saturating_add(refill).min(self.max_microtokens);
            state.last_update = now;

            if state.microtokens >= MICROTOKENS_PER_TOKEN {
                state.microtokens -= MICROTOKENS_PER_TOKEN;
                true
            } else {
                false
            }
        } else {
            let state = ClientState {
                microtokens: self.max_microtokens.saturating_sub(MICROTOKENS_PER_TOKEN),
                last_update: now,
            };
            clients.insert(client_ip, state);
            true
        }
    }
}

pub type SharedRateLimiter = Option<Arc<RateLimiter>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let limiter = RateLimiter::new(100, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        assert!(limiter.is_allowed(ip));
    }

    #[test]
    fn test_rate_limiter_exhausts_tokens() {
        let limiter = RateLimiter::new(100, 3);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let mut allowed = 0;
        for _ in 0..10 {
            if limiter.is_allowed(ip) {
                allowed += 1;
            }
        }
        assert!(allowed >= 3 && allowed <= 5);
    }

    #[test]
    fn test_rate_limiter_separate_clients() {
        let limiter = RateLimiter::new(100, 100);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2));
        assert!(limiter.is_allowed(ip1));
        assert!(limiter.is_allowed(ip2));
    }
}
