use std::mem;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[allow(unused_imports)]
use futures::prelude::*;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use prometheus::{self, Encoder, TextEncoder};
use tokio::net::TcpListener;
use tokio::runtime::Handle;

use crate::config::*;
use crate::errors::*;
use crate::varz::*;

const METRICS_CONNECTION_TIMEOUT_SECS: u64 = 10;
const METRICS_MAX_CONCURRENT_CONNECTIONS: u32 = 2;

async fn handle_client_connection(
    req: Request<Body>,
    varz: Varz,
    path: Arc<String>,
) -> Result<Response<Body>, Error> {
    let mut buffer = vec![];
    if req.uri().path() != path.as_str() {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())?;
        return Ok(response);
    }
    let StartInstant(start_instant) = varz.start_instant;
    let uptime = start_instant.elapsed().as_secs();
    varz.uptime.set(uptime as _);
    let client_queries = varz.client_queries_udp.get() + varz.client_queries_tcp.get();
    varz.client_queries.set(client_queries as _);
    let metric_families = prometheus::gather();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer)?;
    let response = Response::builder()
        .header(CONTENT_TYPE, encoder.format_type())
        .body(buffer.into())?;
    Ok(response)
}

#[allow(unreachable_code)]
pub async fn prometheus_service(
    varz: Varz,
    metrics_config: MetricsConfig,
    runtime_handle: Handle,
) -> Result<(), Error> {
    let path = Arc::new(metrics_config.path);
    let stream = TcpListener::bind(metrics_config.listen_addr).await?;
    let concurrent_connections = Arc::new(AtomicU32::new(0));
    loop {
        let (client, _client_addr) = match stream.accept().await {
            Ok(x) => x,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                warn!("Error accepting Prometheus connection: {}", e);
                continue;
            }
        };
        let count = concurrent_connections.fetch_add(1, Ordering::Relaxed);
        if count >= METRICS_MAX_CONCURRENT_CONNECTIONS {
            concurrent_connections.fetch_sub(1, Ordering::Relaxed);
            mem::drop(client);
            continue;
        }
        let path = path.clone();
        let varz = varz.clone();
        let service =
            service_fn(move |req| handle_client_connection(req, varz.clone(), path.clone()));
        let connection = Http::new().serve_connection(client, service);
        let concurrent_connections = concurrent_connections.clone();
        runtime_handle.spawn(
            tokio::time::timeout(
                std::time::Duration::from_secs(METRICS_CONNECTION_TIMEOUT_SECS),
                connection,
            )
            .map(move |_| {
                concurrent_connections.fetch_sub(1, Ordering::Relaxed);
            }),
        );
    }
    Ok(())
}
