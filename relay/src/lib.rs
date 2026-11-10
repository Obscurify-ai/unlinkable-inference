//! A minimal Oblivious HTTP relay.
//!
//! It sees who connects and an encrypted blob; the gateway sees the blob's
//! contents and the relay's address. It forwards only to the gateways it was
//! started with (it is not an open proxy), passes on only the content type,
//! streams answers back unbuffered, and logs nothing about clients.
//!
//! `GET /<name>/keys` fetches the gateway's keyset itself, so a client can
//! compare keys without the server seeing its address.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures::TryStreamExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const ACCEPTED: &[&str] = &["message/ohttp-req", "message/ohttp-chunked-req"];
const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Target {
    /// Server origin, e.g. `https://obscurify.ai`
    pub origin: String,
}

#[derive(Clone)]
pub struct Relay {
    targets: Arc<HashMap<String, Target>>,
    http: reqwest::Client,
    pub forwarded: Arc<AtomicU64>,
}

impl Relay {
    pub fn new(targets: HashMap<String, Target>) -> Self {
        Self {
            targets: Arc::new(targets),
            http: reqwest::Client::builder()
                .user_agent("unlinkable-relay")
                .build()
                .expect("http client"),
            forwarded: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Parse `name=https://origin` pairs.
    pub fn from_specs(specs: &[String]) -> anyhow::Result<Self> {
        let mut targets = HashMap::new();
        for spec in specs {
            let (name, origin) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--target must be name=https://origin, got {spec}"))?;
            targets.insert(
                name.to_string(),
                Target {
                    origin: origin.trim_end_matches('/').to_string(),
                },
            );
        }
        anyhow::ensure!(!targets.is_empty(), "give at least one --target");
        Ok(Self::new(targets))
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(|| async { "unlinkable relay\n" }))
            .route("/{name}", post(forward))
            .route("/{name}/keys", get(keys))
            .with_state(self)
    }
}

async fn forward(
    State(relay): State<Relay>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(target) = relay.targets.get(&name) else {
        return (StatusCode::NOT_FOUND, "no such gateway").into_response();
    };
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !ACCEPTED.contains(&content_type.as_str()) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "OHTTP requests only").into_response();
    }
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too large").into_response();
    };
    relay.forwarded.fetch_add(1, Ordering::Relaxed);
    // Only the content type travels on: no client address, no forwarding
    // headers, no user agent of the client's.
    let upstream = relay
        .http
        .post(format!("{}/ohttp", target.origin))
        .header("content-type", content_type)
        .body(body)
        .send()
        .await;
    let upstream = match upstream {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, "gateway unreachable").into_response(),
    };
    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(
            upstream.bytes_stream().map_err(std::io::Error::other),
        ))
        .expect("valid response")
}

async fn keys(State(relay): State<Relay>, Path(name): Path<String>) -> Response {
    let Some(target) = relay.targets.get(&name) else {
        return (StatusCode::NOT_FOUND, "no such gateway").into_response();
    };
    match relay
        .http
        .get(format!("{}/u/keys", target.origin))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => (
                [("content-type", "application/json"), ("cache-control", "no-store")],
                b,
            )
                .into_response(),
            Err(_) => (StatusCode::BAD_GATEWAY, "gateway unreachable").into_response(),
        },
        Ok(r) => (r.status(), "gateway refused").into_response(),
        Err(_) => (StatusCode::BAD_GATEWAY, "gateway unreachable").into_response(),
    }
}
