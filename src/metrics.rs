use crate::errors::*;

use futures::FutureExt;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

async fn handle_client_connection(_req: Request<Body>) -> Result<Response<Body>, Error> {
    let res = Response::new(Body::from("OK\n"));
    Ok(res)
}

pub async fn prometheus_service(runtime: Arc<Runtime>) -> Result<(), Error> {
    let mut stream = TcpListener::bind("0.0.0.0:8000").await?;
    loop {
        let (client, _client_addr) = stream.accept().await?;
        let service = service_fn(handle_client_connection);
        let connection = Http::new().serve_connection(client, service);
        runtime.spawn(connection.map(|_| {}));
    }
}
