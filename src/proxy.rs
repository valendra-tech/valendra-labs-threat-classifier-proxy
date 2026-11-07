use crate::{
    model::{ClassificationError, Classifier},
    request::RequestFields,
};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State, connect_info::Connected},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, Version},
    response::{IntoResponse, Response},
    serve::IncomingStream,
};
use chrono::Utc;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::{net::TcpListener, sync::Semaphore};

type HttpClient = Client<HttpsConnector<HttpConnector>, Body>;

#[derive(Clone)]
pub struct ProxyState {
    upstream: Uri,
    classifier: Arc<dyn Classifier>,
    client: HttpClient,
    permits: Arc<Semaphore>,
}

impl ProxyState {
    pub fn new(
        upstream: Uri,
        classifier: Arc<dyn Classifier>,
        workers: usize,
    ) -> anyhow::Result<Self> {
        validate_upstream(&upstream)?;
        anyhow::ensure!(workers > 0, "inference workers must be greater than zero");
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            upstream,
            classifier,
            client,
            permits: Arc::new(Semaphore::new(workers)),
        })
    }
}

pub fn validate_upstream(upstream: &Uri) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(upstream.scheme_str(), Some("http" | "https")),
        "upstream URL must use http or https"
    );
    let authority = upstream
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream URL requires an authority"))?;
    anyhow::ensure!(
        !authority.as_str().contains('@'),
        "upstream credentials are not supported"
    );
    anyhow::ensure!(
        upstream.path().is_empty() || upstream.path() == "/",
        "upstream URL must not contain a base path"
    );
    anyhow::ensure!(
        upstream.query().is_none(),
        "upstream URL must not contain a query"
    );
    Ok(())
}

#[derive(Clone)]
struct Connection {
    peer: SocketAddr,
    local: Option<SocketAddr>,
}

impl Connected<IncomingStream<'_, TcpListener>> for Connection {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self {
            peer: *stream.remote_addr(),
            local: stream.io().local_addr().ok(),
        }
    }
}

fn remove_hop_headers(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in names {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    ] {
        headers.remove(name);
    }
}

fn upgrade_requested(headers: &HeaderMap) -> bool {
    headers.contains_key("upgrade")
        || headers
            .get_all("connection")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
}

fn protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/unknown",
    }
}

async fn handle(
    State(state): State<ProxyState>,
    ConnectInfo(connection): ConnectInfo<Connection>,
    request: Request,
) -> Response {
    let started = Instant::now();
    if request.method() == Method::CONNECT || upgrade_requested(request.headers()) {
        return StatusCode::NOT_IMPLEMENTED.into_response();
    }
    let Some(local) = connection.local else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, usize::MAX).await {
        Ok(body) => body,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body_text = String::from_utf8_lossy(&body).into_owned();
    let path_and_query = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
    let fields = RequestFields {
        timestamp: Utc::now().format("%d/%b/%Y:%H:%M:%S %z").to_string(),
        source: connection.peer,
        destination: local,
        method: parts.method.to_string(),
        path: path_and_query.to_string(),
        protocol: protocol(parts.version).into(),
        headers: parts.headers.clone(),
        body: body_text,
    };
    let text = fields.serialize();
    let permit = match state.permits.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let classifier = state.classifier.clone();
    let decision = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        classifier.classify(&text)
    })
    .await;
    match decision {
        Ok(Ok(verdict)) if verdict.is_attack() => {
            tracing::info!(decision = "block", label = %verdict.label, score = verdict.score, elapsed_ms = started.elapsed().as_millis(), "request classified");
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "category": verdict.label,
                    "score": verdict.score,
                    "categories": verdict.categories,
                })),
            )
                .into_response();
        }
        Ok(Ok(verdict)) => {
            tracing::info!(decision = "allow", label = %verdict.label, score = verdict.score, elapsed_ms = started.elapsed().as_millis(), "request classified");
        }
        Ok(Err(ClassificationError::Unavailable)) | Err(_) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    parts.uri = match Uri::builder()
        .scheme(state.upstream.scheme().unwrap().clone())
        .authority(state.upstream.authority().unwrap().clone())
        .path_and_query(path_and_query)
        .build()
    {
        Ok(uri) => uri,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    remove_hop_headers(&mut parts.headers);
    let outbound = Request::from_parts(parts, Body::from(body));
    match state.client.request(outbound).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            remove_hop_headers(&mut parts.headers);
            Response::from_parts(parts, Body::new(body))
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

pub async fn serve(listener: TcpListener, state: ProxyState) -> std::io::Result<()> {
    let app = Router::new().fallback(handle).with_state(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<Connection>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not register SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
