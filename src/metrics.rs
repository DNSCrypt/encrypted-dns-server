use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
const HEALTH_PATH: &str = "/health";

type BoxBody = http_body_util::Full<hyper::body::Bytes>;

async fn handle_client_connection(
    req: Request<hyper::body::Incoming>,
    varz: Varz,
    path: Arc<String>,
) -> Result<Response<BoxBody>, Error> {
    let request_path = req.uri().path();

    if request_path == HEALTH_PATH {
        return handle_health_request(&varz);
    }

    if request_path != path.as_str() {
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

fn handle_health_request(varz: &Varz) -> Result<Response<BoxBody>, Error> {
    let uptime_secs = varz.start_instant.0.elapsed().as_secs();

    let upstream_sent = varz.upstream_sent.get() as u64;
    let upstream_received = varz.upstream_received.get() as u64;
    let upstream_errors = varz.upstream_errors.get() as u64;

    let upstream_status = if upstream_sent == 0 {
        "unknown"
    } else if upstream_errors > upstream_received {
        "degraded"
    } else {
        "healthy"
    };

    let status = if upstream_status == "degraded" {
        "degraded"
    } else {
        "healthy"
    };

    let body = format!(
        r#"{{"status":"{}","uptime_secs":{},"upstream":{{"status":"{}","sent":{},"received":{},"errors":{}}}}}"#,
        status, uptime_secs, upstream_status, upstream_sent, upstream_received, upstream_errors
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(body)))?)
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
            let connection = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_client_connection(req, varz.clone(), path.clone())
                    }),
                )
                .with_upgrades();
            let _ = tokio::time::timeout(
                Duration::from_secs(METRICS_CONNECTION_TIMEOUT_SECS),
                connection,
            )
            .await;

            connection_count.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn idle_metrics_connections_time_out() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = reserved.local_addr().unwrap();
            let varz = crate::tests::globals(addr).varz;
            drop(reserved);
            let task = tokio::spawn(prometheus_service(
                varz,
                MetricsConfig {
                    r#type: "prometheus".into(),
                    listen_addr: addr,
                    path: "/metrics".into(),
                },
                Handle::current(),
            ));
            let client = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    match TcpStream::connect(addr).await {
                        Ok(client) => break client,
                        Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            })
            .await
            .unwrap();
            async fn get(mut client: TcpStream, path: &str) -> String {
                client
                    .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                let mut response = String::new();
                tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(response.starts_with("HTTP/1.1 200"));
                response
            }
            assert!(get(client, "/health").await.contains("\"uptime_secs\""));
            assert!(get(TcpStream::connect(addr).await.unwrap(), "/metrics")
                .await
                .contains("encrypted_dns_upstream_sent"));
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut second_client = TcpStream::connect(addr).await.unwrap();
            let mut byte = [0];
            let result = tokio::time::timeout(
                Duration::from_secs(METRICS_CONNECTION_TIMEOUT_SECS + 2),
                client.read(&mut byte),
            )
            .await;
            assert_eq!(
                result
                    .expect("idle connection kept its slot past the timeout")
                    .unwrap(),
                0
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), second_client.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert!(get(TcpStream::connect(addr).await.unwrap(), "/metrics")
                .await
                .contains("encrypted_dns_upstream_sent"));
            task.abort();
        });
    }
}
