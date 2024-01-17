use std::sync::Arc;

use coarsetime::{Duration, Instant};
use parking_lot::{Mutex, MutexGuard};
use sieve_cache::SieveCache;

use crate::dns;

#[derive(Clone, Debug)]
pub struct CachedResponse {
    response: Vec<u8>,
    expiry: Instant,
    original_ttl: u32,
}

impl CachedResponse {
    pub fn new(cache: &Cache, response: Vec<u8>) -> Self {
        let ttl = dns::min_ttl(&response, cache.ttl_min, cache.ttl_max, cache.ttl_error)
            .unwrap_or(cache.ttl_error);
        let expiry = Instant::recent() + Duration::from_secs(u64::from(ttl));
        CachedResponse {
            response,
            expiry,
            original_ttl: ttl,
        }
    }

    #[inline]
    pub fn set_tid(&mut self, tid: u16) {
        dns::set_tid(&mut self.response, tid)
    }

    #[inline]
    pub fn into_response(self) -> Vec<u8> {
        self.response
    }

    #[inline]
    pub fn has_expired(&self) -> bool {
        Instant::recent() > self.expiry
    }

    #[inline]
    pub fn ttl(&self) -> u32 {
        (self.expiry - Instant::recent()).as_secs() as _
    }

    #[inline]
    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Cache {
    #[derivative(Debug = "ignore")]
    cache: Arc<Mutex<SieveCache<u128, CachedResponse>>>,
    pub ttl_min: u32,
    pub ttl_max: u32,
    pub ttl_error: u32,
}

impl Cache {
    pub fn new(
        sieve_cache: SieveCache<u128, CachedResponse>,
        ttl_min: u32,
        ttl_max: u32,
        ttl_error: u32,
    ) -> Self {
        Cache {
            cache: Arc::new(Mutex::new(sieve_cache)),
            ttl_min,
            ttl_max,
            ttl_error,
        }
    }

    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, SieveCache<u128, CachedResponse>> {
        self.cache.lock()
    }
}
