use std::sync::Arc;

use coarsetime::Instant;
use prometheus::{Histogram, IntCounter, IntGauge};

pub struct StartInstant(pub Instant);

pub struct Inner {
    pub start_instant: StartInstant,
    pub uptime: IntGauge,
    pub anonymized_queries: IntCounter,
    pub anonymized_responses: IntCounter,
    pub client_queries: IntGauge,
    pub client_queries_udp: IntCounter,
    pub client_queries_tcp: IntCounter,
    pub client_queries_cached: IntCounter,
    pub client_queries_expired: IntCounter,
    pub client_queries_offline: IntCounter,
    pub client_queries_errors: IntCounter,
    pub client_queries_blocked: IntCounter,
    pub client_queries_resolved: IntCounter,
    pub client_queries_rcode_nxdomain: IntCounter,
    pub inflight_udp_queries: IntGauge,
    pub inflight_tcp_queries: IntGauge,
    pub upstream_errors: IntCounter,
    pub upstream_sent: IntCounter,
    pub upstream_received: IntCounter,
    pub upstream_response_sizes: Histogram,
    pub upstream_rcode_nxdomain: IntCounter,
}

pub type Varz = Arc<Inner>;

pub fn new() -> Varz {
    Arc::new(Inner::new())
}

impl Inner {
    pub fn new() -> Inner {
        Inner {
            start_instant: StartInstant::default(),
            uptime: register_int_gauge!(opts!(
                "encrypted_dns_uptime",
                "Uptime",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            anonymized_queries: register_int_counter!(opts!(
                "encrypted_dns_anonymized_queries",
                "Number of anonymized queries received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            anonymized_responses: register_int_counter!(opts!(
                "encrypted_dns_anonymized_responses",
                "Number of anonymized responses received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries: register_int_gauge!(opts!(
                "encrypted_dns_client_queries",
                "Number of client queries received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_udp: register_int_counter!(opts!(
                "encrypted_dns_client_queries_udp",
                "Number of client queries received using UDP",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_tcp: register_int_counter!(opts!(
                "encrypted_dns_client_queries_tcp",
                "Number of client queries received using TCP",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_cached: register_int_counter!(opts!(
                "encrypted_dns_client_queries_cached",
                "Number of client queries sent from the cache",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_expired: register_int_counter!(opts!(
                "encrypted_dns_client_queries_expired",
                "Number of expired client queries",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_offline: register_int_counter!(opts!(
                "encrypted_dns_client_queries_offline",
                "Number of client queries answered while upstream resolvers are unresponsive",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_errors: register_int_counter!(opts!(
                "encrypted_dns_client_queries_errors",
                "Number of bogus client queries",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_blocked: register_int_counter!(opts!(
                "encrypted_dns_client_queries_blocked",
                "Number of blocked client queries",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_resolved: register_int_counter!(opts!(
                "encrypted_dns_client_queries_resolved",
                "Number of blocked client resolved",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            client_queries_rcode_nxdomain: register_int_counter!(opts!(
                "encrypted_dns_client_queries_rcode_nxdomain",
                "Number of responses with an NXDOMAIN error code",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            inflight_udp_queries: register_int_gauge!(opts!(
                "encrypted_dns_inflight_udp_queries",
                "Number of UDP queries currently waiting for a response",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            inflight_tcp_queries: register_int_gauge!(opts!(
                "encrypted_dns_inflight_tcp_queries",
                "Number of TCP queries currently waiting for a response",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_errors: register_int_counter!(opts!(
                "encrypted_dns_upstream_errors",
                "Number of bogus upstream servers responses",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_sent: register_int_counter!(opts!(
                "encrypted_dns_upstream_sent",
                "Number of upstream servers queries sent",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_received: register_int_counter!(opts!(
                "encrypted_dns_upstream_received",
                "Number of upstream servers responses received",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
            upstream_response_sizes: register_histogram!(histogram_opts!(
                "encrypted_dns_upstream_response_sizes",
                "Response size in bytes",
                vec![64.0, 128.0, 192.0, 256.0, 512.0, 1024.0, 2048.0]
            ))
            .unwrap(),
            upstream_rcode_nxdomain: register_int_counter!(opts!(
                "encrypted_dns_upstream_rcode_nxdomain",
                "Number of upstream responses with an NXDOMAIN error code",
                labels! {"handler" => "all",}
            ))
            .unwrap(),
        }
    }
}

impl Default for Inner {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StartInstant {
    fn default() -> StartInstant {
        StartInstant(Instant::now())
    }
}
