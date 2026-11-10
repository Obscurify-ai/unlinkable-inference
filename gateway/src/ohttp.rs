//! Oblivious HTTP gateway (RFC 9458, plus chunked OHTTP for streaming).
//!
//! A relay posts encapsulated requests to `POST /ohttp`. The gateway opens
//! them, runs them through the wrapped app as ordinary requests, and seals the
//! answer back. The app sees no client IP (the connection comes from the
//! relay), no cookies and no forwarding headers: they are stripped here.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig, SymmetricSuite};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceExt;
use unlinkable_core::pipe::{bhttp_stream, ChannelWriter};

pub const REQ: &str = "message/ohttp-req";
pub const RES: &str = "message/ohttp-res";
pub const CHUNKED_REQ: &str = "message/ohttp-chunked-req";
pub const CHUNKED_RES: &str = "message/ohttp-chunked-res";
const MAX_REQUEST: usize = 32 * 1024 * 1024;

/// Marker on requests that arrived through the OHTTP gateway.
#[derive(Debug, Clone, Copy)]
pub struct ViaOhttp;

/// Request headers never passed to the app: they could carry identity the
/// client did not mean to send, or claim an address.
const DROPPED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "connection",
    "content-length",
    "transfer-encoding",
    "te",
    "upgrade",
];

const DROPPED_RESPONSE_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "set-cookie",
];

pub struct OhttpKeys {
    server: ohttp::Server,
    encoded: Vec<u8>,
}

impl OhttpKeys {
    /// Keys derived from a 32-byte seed (key id 1, X25519, HKDF-SHA256,
    /// AES-128-GCM or ChaCha20-Poly1305).
    pub fn from_seed(seed: &[u8]) -> anyhow::Result<Self> {
        let config = KeyConfig::derive(
            1,
            Kem::X25519Sha256,
            vec![
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
                SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
            ],
            seed,
        )
        .map_err(|e| anyhow::anyhow!("OHTTP key: {e}"))?;
        let encoded = config
            .encode()
            .map_err(|e| anyhow::anyhow!("OHTTP key: {e}"))?;
        let server = ohttp::Server::new(config).map_err(|e| anyhow::anyhow!("OHTTP: {e}"))?;
        Ok(Self { server, encoded })
    }

    pub fn ephemeral() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(&seed).expect("fresh OHTTP key")
    }

    /// Load the seed from `path` (hex), creating it on first start.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        let seed = if path.exists() {
            hex::decode(std::fs::read_to_string(path)?.trim())?
        } else {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, hex::encode(seed))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            tracing::warn!(path = %path.display(), "Created a new OHTTP gateway key; back it up");
            seed.to_vec()
        };
        anyhow::ensure!(seed.len() >= 32, "{} is too short", path.display());
        Self::from_seed(&seed)
    }

    /// The single key configuration, as listed in the keyset.
    pub fn encoded_config(&self) -> &[u8] {
        &self.encoded
    }

    /// `application/ohttp-keys`: a list of length-prefixed configurations.
    pub fn encoded_list(&self) -> Vec<u8> {
        let mut out = (self.encoded.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&self.encoded);
        out
    }
}

#[derive(Clone)]
struct GatewayState {
    keys: Arc<OhttpKeys>,
    inner: Router,
    allowed: Arc<Vec<String>>,
}

/// Put an OHTTP gateway at `POST /ohttp` (and its keys at `GET /ohttp-keys`)
/// in front of `inner`. Only paths starting with one of `allowed_prefixes`
/// can be reached through it. Every other path goes straight to `inner`.
pub fn wrap(keys: Arc<OhttpKeys>, inner: Router, allowed_prefixes: &[&str]) -> Router {
    let state = GatewayState {
        keys,
        inner: inner.clone(),
        allowed: Arc::new(allowed_prefixes.iter().map(|s| s.to_string()).collect()),
    };
    Router::new()
        .route("/ohttp", post(handle))
        .route("/ohttp-keys", get(key_list))
        .with_state(state)
        .fallback_service(inner)
}

async fn key_list(State(state): State<GatewayState>) -> Response {
    (
        [
            ("content-type", "application/ohttp-keys"),
            ("cache-control", "public, max-age=300"),
        ],
        state.keys.encoded_list(),
    )
        .into_response()
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

async fn handle(State(state): State<GatewayState>, headers: HeaderMap, body: Body) -> Response {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = match axum::body::to_bytes(body, MAX_REQUEST).await {
        Ok(b) => b,
        Err(_) => return plain_error(StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
    };
    match content_type.as_str() {
        CHUNKED_REQ => handle_chunked(state, body).await,
        REQ => handle_whole(state, body).await,
        _ => plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "send message/ohttp-req or message/ohttp-chunked-req",
        ),
    }
}

/// The inner request as the app will see it, or a response to send back
/// (sealed) when the path is not allowed.
#[allow(clippy::result_large_err)]
fn inner_request(state: &GatewayState, plain: &[u8]) -> Result<Request<Body>, Response> {
    let message = bhttp::Message::read_bhttp::<std::io::Cursor<&[u8]>, std::io::Cursor<&[u8]>>(
        &mut std::io::Cursor::new(plain),
    )
    .map_err(|_| plain_error(StatusCode::BAD_REQUEST, "invalid binary HTTP request"))?;
    let control = message.control();
    let method = control
        .method()
        .and_then(|m| http::Method::from_bytes(m).ok())
        .ok_or_else(|| plain_error(StatusCode::BAD_REQUEST, "no method"))?;
    let path = control
        .path()
        .and_then(|p| std::str::from_utf8(p).ok())
        .filter(|p| p.starts_with('/'))
        .ok_or_else(|| plain_error(StatusCode::BAD_REQUEST, "no path"))?
        .to_string();
    if !state.allowed.iter().any(|prefix| path.starts_with(prefix.as_str())) {
        return Err(plain_error(
            StatusCode::NOT_FOUND,
            "that path is not reachable through the OHTTP gateway",
        ));
    }
    let mut builder = Request::builder().method(method).uri(path);
    for field in message.header().iter() {
        let name = String::from_utf8_lossy(field.name()).to_ascii_lowercase();
        if DROPPED_REQUEST_HEADERS.contains(&name.as_str()) {
            continue;
        }
        if let Ok(value) = HeaderValue::from_bytes(field.value()) {
            builder = builder.header(name, value);
        }
    }
    let mut request = builder
        .body(Body::from(message.content().to_vec()))
        .map_err(|_| plain_error(StatusCode::BAD_REQUEST, "invalid request"))?;
    // Handlers that ask for the peer address get an unroutable placeholder:
    // never a trusted proxy, never anyone's IP.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([0, 0, 0, 0], 0))));
    request.extensions_mut().insert(ViaOhttp);
    Ok(request)
}

fn response_fields(response: &Response) -> Vec<(Vec<u8>, Vec<u8>)> {
    response
        .headers()
        .iter()
        .filter(|(k, _)| !DROPPED_RESPONSE_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

async fn handle_chunked(state: GatewayState, body: Bytes) -> Response {
    let mut request = state
        .keys
        .server
        .clone()
        .decapsulate_stream(futures::io::Cursor::new(body.to_vec()));
    let mut plain = Vec::new();
    if request.read_to_end(&mut plain).await.is_err() {
        return plain_error(StatusCode::BAD_REQUEST, "cannot open that request");
    }
    let (tx, rx) = futures::channel::mpsc::unbounded::<Bytes>();
    let mut writer = match request.response(ChannelWriter(Some(tx))) {
        Ok(w) => w,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "cannot open that request"),
    };
    let response = match inner_request(&state, &plain) {
        Ok(req) => match state.inner.clone().oneshot(req).await {
            Ok(r) => r,
            Err(never) => match never {},
        },
        Err(refusal) => refusal,
    };

    tokio::spawn(async move {
        let status = response.status().as_u16();
        let fields = response_fields(&response);
        let head = bhttp_stream::response_head(
            status,
            fields.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        if writer.write_all(&head).await.is_err() {
            return;
        }
        let mut stream = response.into_body().into_data_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) if !bytes.is_empty() => {
                    if writer
                        .write_all(&bhttp_stream::content_chunk(&bytes))
                        .await
                        .is_err()
                    {
                        return; // the relay or client went away
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
        let _ = writer.write_all(&bhttp_stream::end()).await;
        let _ = writer.close().await;
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", CHUNKED_RES)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(rx.map(Ok::<_, std::convert::Infallible>)))
        .expect("valid response")
}

async fn handle_whole(state: GatewayState, body: Bytes) -> Response {
    let Ok((plain, sealer)) = state.keys.server.decapsulate(&body) else {
        return plain_error(StatusCode::BAD_REQUEST, "cannot open that request");
    };
    let response = match inner_request(&state, &plain) {
        Ok(req) => match state.inner.clone().oneshot(req).await {
            Ok(r) => r,
            Err(never) => match never {},
        },
        Err(refusal) => refusal,
    };
    let status = response.status().as_u16();
    let fields = response_fields(&response);
    let Ok(content) = axum::body::to_bytes(response.into_body(), MAX_REQUEST).await else {
        return plain_error(StatusCode::BAD_GATEWAY, "response too large");
    };
    let Ok(code) = bhttp::StatusCode::try_from(status) else {
        return plain_error(StatusCode::BAD_GATEWAY, "bad status");
    };
    let mut message = bhttp::Message::response(code);
    for (k, v) in fields {
        message.put_header(k, v);
    }
    message.write_content(&content);
    let mut encoded = Vec::new();
    if message
        .write_bhttp(bhttp::Mode::KnownLength, &mut encoded)
        .is_err()
    {
        return plain_error(StatusCode::BAD_GATEWAY, "cannot encode response");
    }
    match sealer.encapsulate(&encoded) {
        Ok(sealed) => (
            [("content-type", RES), ("cache-control", "no-store")],
            sealed,
        )
            .into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "cannot seal response"),
    }
}
