use crate::dns;

use clockpro_cache::ClockProCache;
use coarsetime::{Duration, Instant};
use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct CachedResponse {
    response: Vec<u8>,
    expiry: Instant,
}

impl CachedResponse {
    pub fn new(cache: &Cache, response: Vec<u8>) -> Self {
        let ttl = dns::min_ttl(&response, cache.ttl_min, cache.ttl_max, cache.ttl_error)
            .unwrap_or(cache.ttl_error);
        let expiry = Instant::recent() + Duration::from_secs(u64::from(ttl));
        CachedResponse { response, expiry }
    }

    pub fn set_tid(&mut self, tid: u16) {
        dns::set_tid(&mut self.response, tid)
    }

    pub fn into_response(self) -> Vec<u8> {
        self.response
    }

    pub fn has_expired(&self) -> bool {
        Instant::recent() > self.expiry
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Cache {
    #[derivative(Debug = "ignore")]
    cache: Arc<Mutex<ClockProCache<u128, CachedResponse>>>,
    ttl_min: u32,
    ttl_max: u32,
    ttl_error: u32,
}

impl Cache {
    pub fn new(
        clockpro_cache: ClockProCache<u128, CachedResponse>,
        ttl_min: u32,
        ttl_max: u32,
        ttl_error: u32,
    ) -> Self {
        Cache {
            cache: Arc::new(Mutex::new(clockpro_cache)),
            ttl_min,
            ttl_max,
            ttl_error,
        }
    }

    #[inline]
    pub fn lock(&self) -> MutexGuard<ClockProCache<u128, CachedResponse>> {
        self.cache.lock()
    }
}
