use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[allow(unused_imports)]
use futures::prelude::*;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{self, Encoder, TextEncoder};
use tokio::net::TcpListener;
use tokio::runtime::Handle;

use crate::config::*;
use crate::errors::*;
use crate::varz::*;

const METRICS_CONNECTION_TIMEOUT_SECS: u64 = 10;
const METRICS_MAX_CONCURRENT_CONNECTIONS: u32 = 2;

type BoxBody = http_body_util::Full<hyper::body::Bytes>;

async fn handle_client_connection(
    req: Request<hyper::body::Incoming>,
    _varz: Varz,
    path: Arc<String>,
) -> Result<Response<BoxBody>, Error> {
    if req.uri().path() != path.as_str() {
        return Ok(Response::builder().status(StatusCode::NOT_FOUND).body(
            http_body_util::Full::new(hyper::body::Bytes::from("404 Not Found")),
        )?);
    }
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(http_body_util::Full::new(hyper::body::Bytes::from(buffer)))?)
}

pub async fn prometheus_service(
    varz: Varz,
    metrics_config: MetricsConfig,
    runtime_handle: Handle,
) -> Result<(), Error> {
    let listener = TcpListener::bind(metrics_config.listen_addr).await?;
    let path = Arc::new(metrics_config.path);
    let connection_count = Arc::new(AtomicU32::new(0));

    loop {
        let (stream, _) = listener.accept().await?;
        let varz = varz.clone();
        let path = path.clone();
        let connection_count = Arc::clone(&connection_count);

        if connection_count.load(Ordering::Relaxed) >= METRICS_MAX_CONCURRENT_CONNECTIONS {
            continue;
        }
        connection_count.fetch_add(1, Ordering::Relaxed);

        runtime_handle.spawn(async move {
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_client_connection(req, varz.clone(), path.clone())
                    }),
                )
                .with_upgrades()
                .await;

            connection_count.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
