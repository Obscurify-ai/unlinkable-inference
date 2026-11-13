//! The local proxy server.
//!
//! Agents and SDKs talk to it as if it were the OpenAI or Anthropic API. For
//! each conversation it opens a session paid with vouchers from the wallet,
//! sends the request with the session secret in place of any key, streams the
//! answer back, and closes the session once the conversation goes quiet,
//! putting the change back in the wallet. Whatever key the client sends stays
//! here: it only names which session to use.

use crate::{dollars, Options};
use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Json, Router,
};
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use unlinkable_core::net::{Client, Observed, Request as Inner, Session};
use unlinkable_core::{Family, Voucher, Wallet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A new session for each conversation (system prompt + first user message)
    Conversation,
    /// One session per API key the client sends (name keys per agent run)
    Key,
    /// One session for everything until it goes idle
    Run,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "conversation" => Ok(Mode::Conversation),
            "key" => Ok(Mode::Key),
            "run" => Ok(Mode::Run),
            _ => Err("use conversation, key or run".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// What each new session is funded with, in cents
    pub funding_cents: i64,
    pub mode: Mode,
    /// Close a session after this long without a request
    pub idle_close: Duration,
    pub show_traffic: bool,
    /// The account's API key, for keeping the wallet and passes topped up.
    /// Never sent with a chat. If unset, the proxy learns it from the first
    /// `sk-obs1_` key a client sends.
    pub account_key: Option<String>,
    /// Withdraw when the wallet holds less than this many cents…
    pub keep_cents: i64,
    /// …this much (one of the fixed withdrawal sizes)
    pub refill_cents: i64,
    /// Fetch passes when fewer than this many are left this month
    pub keep_passes: usize,
    /// Client keys starting with this are taken to be the account's key
    pub account_key_prefix: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            funding_cents: 50,
            mode: Mode::Conversation,
            idle_close: Duration::from_secs(300),
            show_traffic: false,
            account_key: None,
            keep_cents: 50,
            refill_cents: 100,
            keep_passes: 10,
            account_key_prefix: "sk-obs1_".into(),
        }
    }
}

struct Entry {
    session: Session,
    last_used: AtomicU64,
    busy: AtomicUsize,
    opened_at: u64,
    requests: AtomicU64,
}

pub struct Proxy {
    client: Client,
    wallet: tokio::sync::Mutex<Wallet>,
    sessions: Mutex<HashMap<String, Arc<Entry>>>,
    /// Held-conversation revs (x-obscurify-thread) to the session that owns them
    threads: Mutex<HashMap<String, String>>,
    traffic: Arc<Mutex<VecDeque<(u64, Observed)>>>,
    opening: tokio::sync::Mutex<()>,
    settings: Settings,
    opts: Options,
    account_key: Mutex<Option<String>>,
    /// After a failed top-up, wait before trying again
    refill_backoff: Mutex<Option<std::time::Instant>>,
    /// The helper session's last seen balance (see [`Proxy::helper_secret`])
    helper_balance: Mutex<String>,
}

/// The session handed out by `/_unlinkable/key` for agents that talk to the
/// server directly (Claude Code's `apiKeyHelper`).
const HELPER: &str = "helper";

/// The server no longer knows this session (expired or closed elsewhere).
fn gone(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<unlinkable_core::net::ApiError>(),
        Some(unlinkable_core::net::ApiError::Server { status: 401 | 404 | 410, .. })
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Request headers passed on. Everything else (user agents, SDK telemetry,
/// the client's own key) stays on this machine.
const PASSED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
];

const DROPPED_RESPONSE_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "set-cookie",
];

const MAX_BODY: usize = 32 * 1024 * 1024;

/// POST endpoints (and anything under them) forwarded to the server.
const FORWARDED_POSTS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/v1/messages",
    "/v1/embeddings",
    "/v1/images",
    "/v1/tools",
];

fn text(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"error": {"message": message, "type": "unlinkable_proxy_error"}})),
    )
        .into_response()
}

/// The part of a request that stays the same for a whole conversation.
pub fn conversation_fingerprint(path: &str, body: &Value) -> String {
    let parts = if path.ends_with("/chat/completions") {
        let messages = body["messages"].as_array().cloned().unwrap_or_default();
        let end = messages
            .iter()
            .position(|m| m["role"] == "user")
            .map(|i| i + 1)
            .unwrap_or(messages.len());
        json!(messages[..end])
    } else if path.ends_with("/messages") {
        json!([body["system"], body["messages"][0]])
    } else if path.ends_with("/responses") {
        let first = match &body["input"] {
            Value::Array(items) => items.first().cloned().unwrap_or(Value::Null),
            other => other.clone(),
        };
        json!([body["instructions"], first])
    } else {
        Value::Null
    };
    unlinkable_core::sha256_hex(parts.to_string())[..16].to_string()
}

fn client_key(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_start_matches("Bearer ").trim().to_string())
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

impl Proxy {
    pub fn new(mut client: Client, wallet: Wallet, settings: Settings, opts: Options) -> Arc<Self> {
        let traffic: Arc<Mutex<VecDeque<(u64, Observed)>>> = Arc::new(Mutex::new(VecDeque::new()));
        let log = traffic.clone();
        let show = settings.show_traffic;
        client.transport = client.transport.clone().observe(Arc::new(move |o: &Observed| {
            if show {
                eprintln!("→ {}: {}", o.server, o.server_sees);
            }
            let mut log = log.lock().unwrap();
            log.push_front((now(), o.clone()));
            log.truncate(100);
        }));
        Arc::new(Self {
            client,
            wallet: tokio::sync::Mutex::new(wallet),
            sessions: Mutex::new(HashMap::new()),
            threads: Mutex::new(HashMap::new()),
            traffic,
            opening: tokio::sync::Mutex::new(()),
            account_key: Mutex::new(settings.account_key.clone()),
            refill_backoff: Mutex::new(None),
            helper_balance: Mutex::new(String::new()),
            settings,
            opts,
        })
    }

    fn session_key(&self, path: &str, headers: &HeaderMap, body: &Value) -> String {
        if let Some(rev) = body["thread"]["rev"].as_str() {
            if let Some(key) = self.threads.lock().unwrap().get(rev) {
                return key.clone();
            }
        }
        match self.settings.mode {
            Mode::Run => "run".to_string(),
            Mode::Key => format!("key:{}", client_key(headers)),
            Mode::Conversation => format!(
                "conv:{}:{}",
                client_key(headers),
                conversation_fingerprint(path, body)
            ),
        }
    }

    async fn family_to_spend(&self) -> Family {
        let wallet = self.wallet.lock().await;
        if wallet.balance_cents(Family::Paid) == 0 && wallet.balance_cents(Family::Promo) > 0 {
            Family::Promo
        } else {
            Family::Paid
        }
    }

    /// Keep the wallet and passes topped up from the account, in the
    /// background, so customers never move money by hand. Withdrawals happen
    /// when the wallet runs low, not when a session opens, so their timing
    /// says little about any one conversation. `urgent` skips the backoff
    /// (the wallet is empty and a request is waiting).
    pub async fn refill(&self, urgent: bool) {
        let Some(key) = self.account_key.lock().unwrap().clone() else {
            return;
        };
        if !urgent {
            if let Some(at) = *self.refill_backoff.lock().unwrap() {
                if at.elapsed() < Duration::from_secs(600) {
                    return;
                }
            }
        }
        let mut wallet = self.wallet.lock().await;
        let mut failed = false;
        if wallet.balance_cents(Family::Paid) < self.settings.keep_cents {
            match self
                .client
                .withdraw(&mut wallet, &key, self.settings.refill_cents)
                .await
            {
                Ok(c) => tracing::info!("topped up the wallet with {} from the account", dollars(c)),
                Err(e) => {
                    failed = true;
                    tracing::warn!("could not top up the wallet: {e:#}");
                }
            }
        }
        if self.client.keyset.pass_key.is_some() {
            let period = unlinkable_core::pass::current_period();
            let held = wallet.passes(&period).len();
            if held < self.settings.keep_passes {
                match self.client.get_passes(&mut wallet, &key, 30).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!("got {n} passes for this month"),
                    Err(e) => {
                        failed = true;
                        tracing::warn!("could not get passes: {e:#}");
                    }
                }
            }
        }
        let _ = wallet.save();
        *self.refill_backoff.lock().unwrap() = failed.then(std::time::Instant::now);
    }

    fn learn_account_key(&self, headers: &HeaderMap) {
        let key = client_key(headers);
        if !self.settings.account_key_prefix.is_empty() && key.starts_with(&self.settings.account_key_prefix) {
            let mut known = self.account_key.lock().unwrap();
            if known.is_none() {
                *known = Some(key);
            }
        }
    }

    async fn entry(&self, key: &str) -> Result<Arc<Entry>> {
        if let Some(e) = self.sessions.lock().unwrap().get(key) {
            return Ok(e.clone());
        }
        let _guard = self.opening.lock().await;
        if let Some(e) = self.sessions.lock().unwrap().get(key) {
            return Ok(e.clone());
        }
        let family = self.family_to_spend().await;
        let opened = {
            let mut wallet = self.wallet.lock().await;
            self.client
                .open(&mut wallet, family, self.settings.funding_cents)
                .await
        };
        let session = match opened {
            Ok(s) => s,
            Err(e) if e.to_string().contains("has no") => {
                // Empty wallet and a request waiting: top up now rather
                // than fail (the background refill should prevent this).
                self.refill(true).await;
                let mut wallet = self.wallet.lock().await;
                self.client
                    .open(&mut wallet, family, self.settings.funding_cents)
                    .await?
            }
            Err(e) => return Err(e),
        };
        let entry = Arc::new(Entry {
            session,
            last_used: AtomicU64::new(now()),
            busy: AtomicUsize::new(0),
            opened_at: now(),
            requests: AtomicU64::new(0),
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(key.to_string(), entry.clone());
        Ok(entry)
    }

    /// The secret of the helper session, opening one if there is none or the
    /// server has closed it. Agents that send it straight to the server
    /// (Claude Code's `apiKeyHelper`) ask again after a 401.
    pub async fn helper_secret(&self) -> Result<String> {
        let existing = self.sessions.lock().unwrap().get(HELPER).cloned();
        if let Some(entry) = existing {
            match self.client.status(&entry.session).await {
                Ok(st) if st.closed => self.retire_entry(HELPER).await,
                Err(e) if gone(&e) => self.retire_entry(HELPER).await,
                // Open, or the server is unreachable: keep it, never drop a
                // session that may still hold money.
                _ => return Ok(entry.session.secret.clone()),
            }
        }
        Ok(self.entry(HELPER).await?.session.secret.clone())
    }

    /// The helper session's requests never pass through here, so watch its
    /// balance instead: a change means it is in use (not idle), and a low
    /// balance gets topped up before a request fails for want of money.
    pub async fn watch_helper(&self) {
        let Some(entry) = self.sessions.lock().unwrap().get(HELPER).cloned() else {
            return;
        };
        let st = match self.client.status(&entry.session).await {
            Ok(st) if !st.closed => st,
            Ok(_) => return self.retire_entry(HELPER).await,
            Err(e) if gone(&e) => return self.retire_entry(HELPER).await,
            Err(_) => return,
        };
        let changed = {
            let mut last = self.helper_balance.lock().unwrap();
            let changed = *last != st.balance_usd;
            *last = st.balance_usd.clone();
            changed
        };
        if changed {
            entry.last_used.store(now(), Ordering::SeqCst);
        }
        if unlinkable_core::net::usd_to_cents_floor(&st.balance_usd) < self.settings.funding_cents {
            let mut wallet = self.wallet.lock().await;
            if wallet.balance_cents(entry.session.family) < self.settings.funding_cents {
                drop(wallet);
                self.refill(true).await;
                wallet = self.wallet.lock().await;
            }
            if let Err(e) = self
                .client
                .topup(&mut wallet, &entry.session, self.settings.funding_cents)
                .await
            {
                tracing::warn!("could not top up the helper session: {e:#}");
            }
        }
    }

    /// Stop using a session the server no longer serves and close it, so
    /// its change comes back (an expired session can still be closed; if
    /// closing fails it stays in the wallet for `recover`).
    async fn retire_entry(&self, key: &str) {
        if let Some(old) = self.drop_entry(key) {
            self.close_entry(&old).await;
        }
    }

    fn drop_entry(&self, key: &str) -> Option<Arc<Entry>> {
        self.sessions.lock().unwrap().remove(key)
    }

    async fn close_entry(&self, entry: &Entry) {
        let mut wallet = self.wallet.lock().await;
        match self.client.close(&mut wallet, &entry.session).await {
            Ok(cents) => tracing::info!("closed a session; {} back in the wallet", dollars(cents)),
            Err(e) => tracing::warn!("could not close a session (will retry at next start): {e}"),
        }
    }

    /// Close every session that has been quiet for `idle_close`.
    pub async fn close_idle(&self) {
        let cutoff = now().saturating_sub(self.settings.idle_close.as_secs());
        let idle: Vec<(String, Arc<Entry>)> = {
            let mut sessions = self.sessions.lock().unwrap();
            let keys: Vec<String> = sessions
                .iter()
                .filter(|(_, e)| {
                    e.busy.load(Ordering::SeqCst) == 0 && e.last_used.load(Ordering::SeqCst) <= cutoff
                })
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| sessions.remove(&k).map(|e| (k, e)))
                .collect()
        };
        for (key, entry) in idle {
            self.threads.lock().unwrap().retain(|_, v| *v != key);
            self.close_entry(&entry).await;
        }
    }

    pub async fn close_all(&self) {
        let all: Vec<Arc<Entry>> = self.sessions.lock().unwrap().drain().map(|(_, e)| e).collect();
        self.threads.lock().unwrap().clear();
        for entry in all {
            self.close_entry(&entry).await;
        }
    }

    async fn send(&self, entry: &Entry, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<unlinkable_core::net::Response> {
        let mut inner = Inner {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.to_vec(),
            body: body.to_vec(),
        };
        inner = inner.bearer(&entry.session.secret);
        self.client.transport.send(inner).await
    }

    async fn forward(&self, method: &str, path: &str, headers: HeaderMap, body: bytes::Bytes) -> Response {
        let passed: Vec<(String, String)> = PASSED_HEADERS
            .iter()
            .filter_map(|&h| {
                headers
                    .get(h)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (h.to_string(), v.to_string()))
            })
            .collect();

        // Model lists need no session.
        if method == "GET" && (path == "/v1/models" || path.starts_with("/v1/models/")) {
            let req = Inner {
                method: method.into(),
                path: path.into(),
                headers: passed,
                body: Vec::new(),
            };
            return match self.client.transport.send(req).await {
                Ok(r) => pass_through(r),
                Err(e) => text(StatusCode::BAD_GATEWAY, &format!("{e:#}")),
            };
        }

        self.learn_account_key(&headers);
        let json_body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let key = self.session_key(path, &headers, &json_body);
        let has_thread = json_body["thread"]["rev"].is_string();

        let mut reopened = false;
        let mut topups = 0;
        loop {
            let entry = match self.entry(&key).await {
                Ok(e) => e,
                Err(e) => return text(StatusCode::PAYMENT_REQUIRED, &format!("{e:#}")),
            };
            entry.busy.fetch_add(1, Ordering::SeqCst);
            let result = self.send(&entry, method, path, &passed, &body).await;
            entry.last_used.store(now(), Ordering::SeqCst);
            entry.requests.fetch_add(1, Ordering::SeqCst);
            let response = match result {
                Ok(r) => r,
                Err(e) => {
                    entry.busy.fetch_sub(1, Ordering::SeqCst);
                    return text(StatusCode::BAD_GATEWAY, &format!("{e:#}"));
                }
            };
            match response.status {
                402 if topups < 5 => {
                    // Out of money for this request: add more from the wallet
                    // (the top-up links only to this session) and try again.
                    topups += 1;
                    let cents = self.settings.funding_cents << topups;
                    let result = {
                        let mut wallet = self.wallet.lock().await;
                        self.client.topup(&mut wallet, &entry.session, cents).await
                    };
                    entry.busy.fetch_sub(1, Ordering::SeqCst);
                    if let Err(e) = result {
                        return text(
                            StatusCode::PAYMENT_REQUIRED,
                            &format!("The session ran out and the wallet could not top it up: {e:#}"),
                        );
                    }
                    continue;
                }
                401 if !reopened && !has_thread => {
                    // The session expired: close it for its change, start a new one.
                    entry.busy.fetch_sub(1, Ordering::SeqCst);
                    reopened = true;
                    self.retire_entry(&key).await;
                    continue;
                }
                _ => {}
            }
            if let Some(rev) = response.header("x-obscurify-thread") {
                self.threads
                    .lock()
                    .unwrap()
                    .insert(rev.to_string(), key.clone());
            }
            let out = pass_through_tracked(response, entry.clone());
            return out;
        }
    }

    async fn status_json(&self) -> Value {
        let mut wallet = self.wallet.lock().await;
        let period = unlinkable_core::pass::current_period();
        let passes = wallet.passes(&period);
        let sessions: Vec<Value> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|e| {
                json!({
                    "family": e.session.family,
                    "age_seconds": now() - e.opened_at,
                    "idle_seconds": now() - e.last_used.load(Ordering::SeqCst),
                    "requests": e.requests.load(Ordering::SeqCst),
                })
            })
            .collect();
        let traffic: Vec<Value> = self
            .traffic
            .lock()
            .unwrap()
            .iter()
            .take(40)
            .map(|(at, o)| {
                json!({"at": at, "bytes_sent": o.bytes_sent, "server_sees": o.server_sees})
            })
            .collect();
        json!({
            "server": self.opts.server,
            "keyset": self.client.keyset.fingerprint(),
            "wallet": {
                "paid_cents": wallet.balance_cents(Family::Paid),
                "promo_cents": wallet.balance_cents(Family::Promo),
                "vouchers": wallet.vouchers().len(),
                "passes": passes.len(),
                "pass_tier": passes.first().map(|p| p.tier.clone()),
            },
            "settings": {
                "session_funding_cents": self.settings.funding_cents,
                "idle_close_seconds": self.settings.idle_close.as_secs(),
            },
            "sessions": sessions,
            "traffic": traffic,
        })
    }

    async fn withdraw(&self, api_key: &str, cents: i64) -> Result<i64> {
        let mut wallet = self.wallet.lock().await;
        self.client.withdraw(&mut wallet, api_key, cents).await
    }

    async fn passes(&self, api_key: &str, count: i64) -> Result<usize> {
        let mut wallet = self.wallet.lock().await;
        self.client.get_passes(&mut wallet, api_key, count).await
    }

    async fn import(&self, codes: &[String]) -> Result<i64> {
        let mut added = 0;
        let mut wallet = self.wallet.lock().await;
        for code in codes {
            let voucher = Voucher::parse(code).ok_or_else(|| anyhow!("not a voucher: {code}"))?;
            let family = unlinkable_core::blank::verify(&self.client.keyset, &voucher)
                .ok_or_else(|| anyhow!("this server did not sign {code}"))?;
            added += voucher.denomination_cents;
            wallet.add(family, [voucher]);
        }
        wallet.save()?;
        Ok(added)
    }
}

fn copy_headers(resp: &unlinkable_core::net::Response, out: &mut HeaderMap) {
    for (k, v) in &resp.headers {
        let k = k.to_ascii_lowercase();
        if DROPPED_RESPONSE_HEADERS.contains(&k.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            out.insert(name, value);
        }
    }
}

fn pass_through(resp: unlinkable_core::net::Response) -> Response {
    let mut headers = HeaderMap::new();
    copy_headers(&resp, &mut headers);
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = Body::from_stream(resp.body.map(|r| r.map_err(std::io::Error::other)));
    (status, headers, body).into_response()
}

/// Like [`pass_through`], keeping the session marked busy until the
/// stream ends, so it is never closed mid-answer.
fn pass_through_tracked(resp: unlinkable_core::net::Response, entry: Arc<Entry>) -> Response {
    let mut headers = HeaderMap::new();
    copy_headers(&resp, &mut headers);
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    struct Done(Arc<Entry>);
    impl Drop for Done {
        fn drop(&mut self) {
            self.0.last_used.store(now(), Ordering::SeqCst);
            self.0.busy.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let done = Done(entry);
    let body = resp.body.map(move |r| {
        let _keep = &done;
        r.map_err(std::io::Error::other)
    });
    (status, headers, Body::from_stream(body)).into_response()
}

/// Only local clients, and never a web page: a site you visit must not be
/// able to spend your wallet through this proxy.
fn local_only(headers: &HeaderMap) -> Option<Response> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if !matches!(host_name, "127.0.0.1" | "localhost" | "[::1]" | "") {
        return Some(text(StatusCode::FORBIDDEN, "local clients only"));
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let ok = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| origin.starts_with(p));
        if !ok {
            return Some(text(StatusCode::FORBIDDEN, "web pages cannot use this proxy"));
        }
    }
    None
}

async fn handle(State(proxy): State<Arc<Proxy>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    if let Some(refusal) = local_only(&parts.headers) {
        return refusal;
    }
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let method = parts.method.as_str().to_string();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return text(StatusCode::PAYLOAD_TOO_LARGE, "request too large");
    };

    if path.starts_with("/_unlinkable") {
        return control(&proxy, &method, &path, &parts.headers, &body).await;
    }
    if method == "POST" {
        let json = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if !json {
            return text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send application/json");
        }
    }
    // Clients configured with a base URL without /v1 (some Anthropic
    // setups) still reach the API.
    let path = if path.starts_with("/v1/") {
        path
    } else {
        format!("/v1{path}")
    };
    // Only API calls go out (and only they open sessions): a browser's
    // favicon request or a typo must not spend the wallet.
    let route = path.split('?').next().unwrap_or("");
    let api = match method.as_str() {
        "GET" => route == "/v1/models" || route.starts_with("/v1/models/"),
        "POST" => FORWARDED_POSTS.iter().any(|p| route == *p || route.starts_with(&format!("{p}/"))),
        _ => false,
    };
    if !api {
        return text(StatusCode::NOT_FOUND, "not an API path this proxy forwards");
    }
    proxy.forward(&method, &path, parts.headers, body).await
}

async fn control(proxy: &Proxy, method: &str, path: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    if method == "POST" {
        let json = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        if !json {
            return text(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send application/json");
        }
    }
    let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match (method, path) {
        ("GET", "/_unlinkable") | ("GET", "/_unlinkable/") => Html(PAGE).into_response(),
        ("GET", "/_unlinkable/status") => Json(proxy.status_json().await).into_response(),
        ("GET", "/_unlinkable/key") => match proxy.helper_secret().await {
            Ok(secret) => secret.into_response(),
            Err(e) => text(StatusCode::PAYMENT_REQUIRED, &format!("{e:#}")),
        },
        ("POST", "/_unlinkable/withdraw") => {
            let cents = body["amount_cents"].as_i64().unwrap_or(0);
            let key = body["api_key"].as_str().unwrap_or("");
            match proxy.withdraw(key, cents).await {
                Ok(c) => Json(json!({"withdrawn_cents": c})).into_response(),
                Err(e) => text(StatusCode::BAD_REQUEST, &format!("{e:#}")),
            }
        }
        ("POST", "/_unlinkable/passes") => {
            let count = body["count"].as_i64().unwrap_or(30);
            let key = body["api_key"].as_str().unwrap_or("");
            match proxy.passes(key, count).await {
                Ok(n) => Json(json!({"got": n})).into_response(),
                Err(e) => text(StatusCode::BAD_REQUEST, &format!("{e:#}")),
            }
        }
        ("POST", "/_unlinkable/import") => {
            let codes: Vec<String> = body["vouchers"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            match proxy.import(&codes).await {
                Ok(c) => Json(json!({"added_cents": c})).into_response(),
                Err(e) => text(StatusCode::BAD_REQUEST, &format!("{e:#}")),
            }
        }
        ("POST", "/_unlinkable/close") => {
            proxy.close_all().await;
            Json(json!({"closed": true})).into_response()
        }
        _ => text(StatusCode::NOT_FOUND, "no such control endpoint"),
    }
}

pub fn router(proxy: Arc<Proxy>) -> Router {
    Router::new().fallback(handle).with_state(proxy)
}

/// Serve until `shutdown` resolves, closing idle sessions as it goes and
/// every session at the end.
pub async fn run(
    listener: tokio::net::TcpListener,
    proxy: Arc<Proxy>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let closer = proxy.clone();
    let ticker = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut n: u64 = 0;
        loop {
            tick.tick().await;
            closer.watch_helper().await;
            closer.close_idle().await;
            if n.is_multiple_of(12) {
                closer.refill(false).await;
            }
            n += 1;
        }
    });
    axum::serve(listener, router(proxy.clone()))
        .with_graceful_shutdown(shutdown)
        .await?;
    ticker.abort();
    proxy.close_all().await;
    Ok(())
}

const PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>unlinkable: what leaves this device</title>
<style>
body{font:15px/1.45 system-ui,sans-serif;background:#111;color:#ddd;margin:0;padding:1rem 1rem 6rem}
h1{font-size:1.2rem;margin:.2rem 0 1rem}h2{font-size:1rem;margin:1.5rem 0 .5rem;color:#aaa}
.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;padding:.8rem;margin:.5rem 0}
code{color:#9cf}.peer{color:#fc9}.server{color:#9f9}.warn{color:#f99}
table{border-collapse:collapse;width:100%}td{padding:.35rem .4rem;border-top:1px solid #2a2a2a;vertical-align:top}
.dock{position:fixed;right:1rem;bottom:1rem;display:flex;gap:.5rem;flex-wrap:wrap;justify-content:flex-end}
button,input{font:inherit;border-radius:6px;border:1px solid #444;background:#222;color:#eee;padding:.5rem .8rem}
button{background:#2d4f7c;border-color:#3d6aa5}
</style></head><body>
<h1>What leaves this device</h1>
<div id="summary" class="card">Loading…</div>
<h2>Open sessions</h2><div id="sessions" class="card"></div>
<h2>Last requests</h2><div class="card"><table id="traffic"></table></div>
<div class="dock">
<input id="key" placeholder="account API key" size="18">
<select id="amt"><option value="100">$1</option><option value="500" selected>$5</option><option value="2000">$20</option><option value="5000">$50</option><option value="10000">$100</option></select>
<button onclick="passes()">Get passes</button>
<button onclick="withdraw()">Withdraw into wallet</button>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const usd=c=>'$'+(c/100).toFixed(2);
async function load(){
 const s=await (await fetch('/_unlinkable/status')).json();
 $('summary').innerHTML=`Server <code>${esc(s.server)}</code><br>`+
  `The server sees your IP address unless Tor or a VPN hides it. It never sees your account or how you paid.`+
  `<br>Keyset <code>${esc(s.keyset)}</code><br>Wallet ${usd(s.wallet.paid_cents)} paid, ${usd(s.wallet.promo_cents)} promo, in ${s.wallet.vouchers} vouchers`+
  `<br>Passes this month: ${s.wallet.passes}${s.wallet.pass_tier?' ('+esc(s.wallet.pass_tier)+')':''}. Each new conversation uses one, so it gets your plan's models.`;
 $('sessions').innerHTML=s.sessions.length?s.sessions.map(x=>`${x.requests} request${x.requests==1?'':'s'}, open ${x.age_seconds}s, idle ${x.idle_seconds}s`).join('<br>'):'None. Sessions close after '+s.settings.idle_close_seconds+'s without a request; change goes back to the wallet.';
 $('traffic').innerHTML=s.traffic.map(t=>`<tr><td>${new Date(t.at*1000).toLocaleTimeString()}</td><td><span class="server">server sees</span> ${esc(t.server_sees)}</td></tr>`).join('')||'<tr><td>Nothing sent yet.</td></tr>';
}
async function withdraw(){
 const r=await fetch('/_unlinkable/withdraw',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({api_key:$('key').value.trim(),amount_cents:+$('amt').value})});
 const j=await r.json(); alert(r.ok?'Added '+usd(j.withdrawn_cents)+' to the wallet':j.error.message); $('key').value=''; load();
}
async function passes(){
 const r=await fetch('/_unlinkable/passes',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({api_key:$('key').value.trim(),count:30})});
 const j=await r.json(); alert(r.ok?'Got '+j.got+' passes':j.error.message); $('key').value=''; load();
}
load(); setInterval(load,4000);
</script></body></html>"#;
