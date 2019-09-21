use crate::dns;

use coarsetime::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CachedResponse {
    response: Vec<u8>,
    expiry: Instant,
}

impl CachedResponse {
    pub fn new(response: Vec<u8>) -> Self {
        let ttl = dns::min_ttl(&response, 1, 86400, 3600).unwrap_or(3600);
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
