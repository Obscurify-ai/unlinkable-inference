//! Reference server: the gateway with an in-memory backend, an echo model
//! that speaks the OpenAI and Anthropic APIs, test accounts instead of real
//! payments, and `GET /debug/db`, which dumps everything the server holds.
//!
//! Run it, use it through the proxy, read the dump, and try to tie
//! a session to the withdrawal that paid for it.

use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use unlinkable_inference::protocol::{ChangeResponse, Issued, PassAllowance, PassResponse, SessionStatus, UnclaimedSession};
use unlinkable_inference::{sha256_hex, Family};
use unlinkable_inference::server::{
    signer::KeyStore,
    Backend, Gateway, GatewayError, IssuedRecord, PassUse, SignChange, Spend,
};

/// Passes each account gets per month.
pub const PASSES_PER_MONTH: i64 = 10;

/// Balances are kept in nanodollars (1e-9 USD).
const NANO_PER_MILLICENT: i64 = 10_000;
/// Echo model price: $2 per million characters in and out.
const NANO_PER_CHAR: i64 = 2_000;

fn usd(nano: i64) -> String {
    let sign = if nano < 0 { "-" } else { "" };
    let nano = nano.abs();
    format!("{sign}{}.{:09}", nano / 1_000_000_000, nano % 1_000_000_000)
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
struct SessionRow {
    family: Family,
    funded_millicents: i64,
    balance_nano: i64,
    /// What the session's requests cost, in nanodollars
    spent_nano: i64,
    tier: Option<String>,
    opened_at: u64,
    closed_at: Option<u64>,
    #[serde(skip)]
    last_used: Instant,
    #[serde(skip)]
    close_answer: Option<(String, ChangeResponse)>,
    /// Which vouchers opened it (`open_digest`): only those make a retry.
    #[serde(skip)]
    open_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct AccountRow {
    balance_cents: i64,
    tier: String,
    /// Passes issued per month
    passes: HashMap<String, i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WithdrawalRow {
    pub account: String,
    pub amount_cents: i64,
    pub at: u64,
    /// Blinded messages the server signed: all it ever sees of the vouchers
    pub blinded_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestRow {
    pub path: String,
    /// Peer address as the app saw it
    pub peer: String,
    /// "session", "account", "none"
    pub credential: String,
    pub had_cookie: bool,
    pub at: u64,
}

#[derive(Default)]
struct Db {
    spent: HashMap<String, u64>,
    spent_passes: HashMap<String, u64>,
    pass_answers: HashMap<String, PassResponse>,
    sessions: HashMap<String, SessionRow>,
    accounts: HashMap<String, AccountRow>,
    answers: HashMap<String, ChangeResponse>,
    withdrawals: Vec<WithdrawalRow>,
    signed_change: Vec<(u64, Vec<String>)>,
    requests: Vec<RequestRow>,
    /// (account key hash, record): seeded withdrawals and passes until done
    issued: Vec<(String, Issued)>,
}

pub struct MemoryBackend {
    db: Mutex<Db>,
    pub idle_timeout: Duration,
    /// An open session is listed as unclaimed after this long unused
    /// (`protocol::UNCLAIMED_AFTER_SECS`; tests shorten it).
    unclaimed_after: Mutex<Duration>,
}

impl MemoryBackend {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            db: Mutex::new(Db::default()),
            idle_timeout,
            unclaimed_after: Mutex::new(Duration::from_secs(unlinkable_inference::protocol::UNCLAIMED_AFTER_SECS)),
        }
    }

    /// How long an open session goes unused before `GET /u/sessions/unclaimed` lists it.
    pub fn set_unclaimed_after(&self, after: Duration) {
        *self.unclaimed_after.lock().unwrap() = after;
    }

    fn status_of(&self, row: &SessionRow) -> SessionStatus {
        SessionStatus {
            balance_usd: usd(row.balance_nano),
            family: row.family,
            idle_timeout_seconds: self.idle_timeout.as_secs(),
            closed: row.closed_at.is_some(),
            tier: row.tier.clone(),
            repeat: false,
        }
    }

    fn spend(db: &mut Db, spends: &[Spend]) -> Result<i64, GatewayError> {
        let spent: Vec<String> = spends
            .iter()
            .filter(|s| db.spent.contains_key(&s.hash))
            .map(|s| s.hash.clone())
            .collect();
        if !spent.is_empty() {
            return Err(GatewayError::Spent(spent));
        }
        let now = unix();
        for s in spends {
            db.spent.insert(s.hash.clone(), now);
        }
        Ok(spends.iter().map(|s| s.millicents).sum())
    }

    /// A usable session for a model request: open and not idle too long.
    /// Returns the tier its pass gave it.
    fn usable(&self, secret_hash: &str) -> Result<Option<String>, GatewayError> {
        let mut db = self.db.lock().unwrap();
        let row = db
            .sessions
            .get_mut(secret_hash)
            .ok_or_else(GatewayError::unauthorized)?;
        if row.closed_at.is_some() || row.last_used.elapsed() > self.idle_timeout {
            return Err(GatewayError::unauthorized());
        }
        if row.balance_nano <= 0 {
            return Err(GatewayError::payment_required(
                "This session has run out. Top it up or open a new one.",
            ));
        }
        row.last_used = Instant::now();
        Ok(row.tier.clone())
    }

    fn charge(&self, secret_hash: &str, nano: i64) {
        if let Some(row) = self.db.lock().unwrap().sessions.get_mut(secret_hash) {
            row.balance_nano -= nano;
            row.spent_nano += nano;
        }
    }

    pub fn create_account(&self, balance_cents: i64, tier: &str) -> String {
        let token = format!("sk-test_{}", unlinkable_inference::b64(rand::random::<[u8; 18]>()));
        self.db.lock().unwrap().accounts.insert(
            sha256_hex(&token),
            AccountRow {
                balance_cents,
                tier: tier.to_string(),
                passes: HashMap::new(),
            },
        );
        token
    }

    pub fn account_balance(&self, token: &str) -> Option<i64> {
        self.db
            .lock()
            .unwrap()
            .accounts
            .get(&sha256_hex(token))
            .map(|a| a.balance_cents)
    }

    fn log(&self, row: RequestRow) {
        self.db.lock().unwrap().requests.push(row);
    }

    /// Everything the server holds.
    pub fn dump(&self) -> Value {
        let db = self.db.lock().unwrap();
        json!({
            "spent_vouchers": db.spent.iter().map(|(h, at)| json!({"hash": h, "at": at})).collect::<Vec<_>>(),
            "spent_passes": db.spent_passes.iter().map(|(h, at)| json!({"hash": h, "at": at})).collect::<Vec<_>>(),
            "sessions": db.sessions.iter().map(|(h, s)| json!({
                "secret_hash": h, "family": s.family, "funded_millicents": s.funded_millicents, "spent_nano": s.spent_nano, "tier": s.tier,
                "balance_usd": usd(s.balance_nano), "opened_at": s.opened_at, "closed_at": s.closed_at,
            })).collect::<Vec<_>>(),
            "accounts": db.accounts.iter().map(|(h, a)| json!({"token_hash": h, "balance_cents": a.balance_cents, "tier": a.tier, "passes_issued": a.passes})).collect::<Vec<_>>(),
            "withdrawals": db.withdrawals,
            "signed_change": db.signed_change.iter().map(|(at, h)| json!({"at": at, "blinded_hashes": h})).collect::<Vec<_>>(),
            "requests": db.requests,
            "issued": db.issued.iter().map(|(a, i)| json!({"account": a, "kind": i.kind, "nonce": i.nonce, "created": i.created})).collect::<Vec<_>>(),
        })
    }
}

fn blinded_hashes(answer: &ChangeResponse) -> Vec<String> {
    answer
        .signed
        .iter()
        .map(|s| sha256_hex(&s.blind_signature))
        .collect()
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn open_session(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
        pass: Option<&PassUse>,
    ) -> Result<SessionStatus, GatewayError> {
        let mut db = self.db.lock().unwrap();
        let digest = unlinkable_inference::server::open_digest(spends);
        if let Some(row) = db.sessions.get(secret_hash) {
            // A retried open presents exactly the vouchers the first one spent. Anything else,
            // even vouchers spent elsewhere (another device's copy of a shared wallet), is a
            // different open with the same secret.
            if row.open_digest == digest {
                return Ok(SessionStatus { repeat: true, ..self.status_of(row) });
            }
            return Err(GatewayError::Status(StatusCode::CONFLICT, "secret_taken", "That session secret is taken; pick another.".into()));
        }
        if let Some(p) = pass {
            if db.spent_passes.contains_key(&p.hash) {
                return Err(GatewayError::Status(
                    StatusCode::CONFLICT,
                    "pass_spent",
                    "That pass was used already.".into(),
                ));
            }
        }
        let cents = Self::spend(&mut db, spends)?;
        if let Some(p) = pass {
            db.spent_passes.insert(p.hash.clone(), unix());
        }
        let row = SessionRow {
            family,
            funded_millicents: cents,
            balance_nano: cents * NANO_PER_MILLICENT,
            spent_nano: 0,
            tier: pass.map(|p| p.tier.clone()),
            opened_at: unix(),
            closed_at: None,
            last_used: Instant::now(),
            close_answer: None,
            open_digest: digest,
        };
        let status = self.status_of(&row);
        db.sessions.insert(secret_hash.to_string(), row);
        Ok(status)
    }

    async fn topup(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
    ) -> Result<SessionStatus, GatewayError> {
        let mut db = self.db.lock().unwrap();
        match db.sessions.get(secret_hash) {
            Some(row) if row.closed_at.is_none() && row.family == family => {}
            Some(row) if row.family != family => {
                return Err(GatewayError::bad_request(
                    "Top up with vouchers of the family that opened the session.",
                ))
            }
            _ => return Err(GatewayError::unauthorized()),
        }
        let cents = Self::spend(&mut db, spends)?;
        let row = db.sessions.get_mut(secret_hash).expect("checked above");
        row.funded_millicents += cents;
        row.balance_nano += cents * NANO_PER_MILLICENT;
        row.last_used = Instant::now();
        let row = row.clone();
        Ok(self.status_of(&row))
    }

    async fn status(&self, secret_hash: &str) -> Result<SessionStatus, GatewayError> {
        let db = self.db.lock().unwrap();
        let row = db
            .sessions
            .get(secret_hash)
            .ok_or_else(GatewayError::unauthorized)?;
        Ok(self.status_of(row))
    }

    async fn close_session(
        &self,
        secret_hash: &str,
        request_digest: &str,
        sign: SignChange,
    ) -> Result<ChangeResponse, GatewayError> {
        let mut db = self.db.lock().unwrap();
        let row = db
            .sessions
            .get(secret_hash)
            .ok_or_else(GatewayError::unauthorized)?;
        if let Some((digest, answer)) = &row.close_answer {
            return if digest == request_digest {
                Ok(answer.clone())
            } else {
                Err(GatewayError::Status(
                    StatusCode::GONE,
                    "session_closed",
                    "This session is already closed.".into(),
                ))
            };
        }
        let balance = row.balance_nano.max(0);
        // Rounded up to the next millicent: never more than the tokens.
        let millicents = (balance + NANO_PER_MILLICENT - 1) / NANO_PER_MILLICENT;
        let answer = sign(row.family, millicents)?;
        db.signed_change.push((unix(), blinded_hashes(&answer)));
        let row = db.sessions.get_mut(secret_hash).expect("present");
        row.balance_nano = 0;
        row.closed_at = Some(unix());
        row.close_answer = Some((request_digest.to_string(), answer.clone()));
        Ok(answer)
    }

    async fn exchange(
        &self,
        request_digest: &str,
        spends: &[Spend],
        answer: &ChangeResponse,
    ) -> Result<ChangeResponse, GatewayError> {
        let mut db = self.db.lock().unwrap();
        if let Some(previous) = db.answers.get(request_digest) {
            return Ok(previous.clone());
        }
        Self::spend(&mut db, spends)?;
        db.signed_change.push((unix(), blinded_hashes(answer)));
        db.answers
            .insert(request_digest.to_string(), answer.clone());
        Ok(answer.clone())
    }

    async fn pass_allowance(
        &self,
        account_token: &str,
        period: &str,
    ) -> Result<PassAllowance, GatewayError> {
        let db = self.db.lock().unwrap();
        let account = db
            .accounts
            .get(&sha256_hex(account_token))
            .ok_or_else(GatewayError::unauthorized)?;
        Ok(PassAllowance {
            tier: account.tier.clone(),
            period: period.to_string(),
            remaining: PASSES_PER_MONTH - account.passes.get(period).copied().unwrap_or(0),
        })
    }

    async fn record_passes(
        &self,
        account_token: &str,
        count: i64,
        request_digest: &str,
        answer: &PassResponse,
        issued: Option<&IssuedRecord>,
    ) -> Result<PassResponse, GatewayError> {
        let mut db = self.db.lock().unwrap();
        if let Some(previous) = db.pass_answers.get(request_digest) {
            return Ok(previous.clone());
        }
        let account = db
            .accounts
            .get_mut(&sha256_hex(account_token))
            .ok_or_else(GatewayError::unauthorized)?;
        let used = account.passes.entry(answer.period.clone()).or_insert(0);
        if *used + count > PASSES_PER_MONTH {
            return Err(GatewayError::Status(
                StatusCode::TOO_MANY_REQUESTS,
                "pass_limit",
                format!("{} passes left this month.", PASSES_PER_MONTH - *used),
            ));
        }
        *used += count;
        let mut answer = answer.clone();
        answer.remaining = PASSES_PER_MONTH - *used;
        db.pass_answers
            .insert(request_digest.to_string(), answer.clone());
        if let Some(i) = issued {
            db.issued.push((sha256_hex(account_token), issued_row(i, &answer)));
        }
        Ok(answer)
    }

    async fn withdraw(
        &self,
        account_token: &str,
        cents: i64,
        request_digest: &str,
        answer: &ChangeResponse,
        issued: Option<&IssuedRecord>,
    ) -> Result<ChangeResponse, GatewayError> {
        let mut db = self.db.lock().unwrap();
        if let Some(previous) = db.answers.get(request_digest) {
            return Ok(previous.clone());
        }
        let key = sha256_hex(account_token);
        let account = db.accounts.get_mut(&key).ok_or_else(|| {
            GatewayError::Status(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Unknown account key.".into(),
            )
        })?;
        if account.balance_cents < cents {
            return Err(GatewayError::unaffordable(
                "Not enough balance to withdraw that much.",
                account.balance_cents,
            ));
        }
        account.balance_cents -= cents;
        db.withdrawals.push(WithdrawalRow {
            account: key.clone(),
            amount_cents: cents,
            at: unix(),
            blinded_hashes: blinded_hashes(answer),
        });
        db.answers
            .insert(request_digest.to_string(), answer.clone());
        if let Some(i) = issued {
            db.issued.push((key, issued_row(i, answer)));
        }
        Ok(answer.clone())
    }

    async fn unclaimed(&self) -> Result<Vec<UnclaimedSession>, GatewayError> {
        let after = *self.unclaimed_after.lock().unwrap();
        let db = self.db.lock().unwrap();
        let mut list: Vec<UnclaimedSession> = db
            .sessions
            .iter()
            .filter(|(_, s)| s.closed_at.is_some() || s.last_used.elapsed() >= after)
            .map(|(h, s)| UnclaimedSession { h: h.clone(), m: s.opened_at / 60 })
            .collect();
        list.sort_by_key(|u| u.m);
        Ok(list)
    }

    async fn session_done(&self, secret_hash: &str) -> Result<(), GatewayError> {
        let mut db = self.db.lock().unwrap();
        if db.sessions.get(secret_hash).is_some_and(|s| s.closed_at.is_some()) {
            db.sessions.remove(secret_hash);
        }
        Ok(())
    }

    async fn issued(&self, account_token: &str) -> Result<Vec<Issued>, GatewayError> {
        let key = sha256_hex(account_token);
        let db = self.db.lock().unwrap();
        if !db.accounts.contains_key(&key) {
            return Err(GatewayError::unauthorized());
        }
        Ok(db.issued.iter().filter(|(a, _)| *a == key).map(|(_, i)| i.clone()).collect())
    }

    async fn issued_done(&self, account_token: &str, nonces: &[String]) -> Result<(), GatewayError> {
        let key = sha256_hex(account_token);
        self.db
            .lock()
            .unwrap()
            .issued
            .retain(|(a, i)| !(*a == key && nonces.contains(&i.nonce)));
        Ok(())
    }

    async fn spent_since(&self, since: u64) -> Result<Vec<String>, GatewayError> {
        let db = self.db.lock().unwrap();
        Ok(db
            .spent
            .iter()
            .chain(db.spent_passes.iter())
            .filter(|(_, at)| **at >= since)
            .map(|(h, _)| h.clone())
            .collect())
    }
}

fn issued_row(i: &IssuedRecord, answer: &impl Serialize) -> Issued {
    Issued {
        kind: i.kind.to_string(),
        nonce: i.nonce.clone(),
        created: unix(),
        request: i.request.clone(),
        answer: serde_json::to_value(answer).expect("answer serialises"),
    }
}

#[derive(Clone)]
struct App {
    backend: Arc<MemoryBackend>,
}

fn session_of(headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))?;
    token
        .starts_with(unlinkable_inference::SESSION_SECRET_PREFIX)
        .then(|| sha256_hex(token.trim()))
}

fn last_user_text(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let last = messages
        .iter()
        .rev()
        .find(|m| m["role"] == "user")
        .cloned()
        .unwrap_or(Value::Null);
    match &last["content"] {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

fn reply_words(body: &Value) -> Vec<String> {
    format!("echo: {}", last_user_text(body))
        .split_inclusive(' ')
        .map(str::to_string)
        .collect()
}

/// Delay between streamed words. `echo-slow` waits long enough that a test
/// can tell a stream from a buffered answer.
fn word_delay(body: &Value) -> Duration {
    if body["model"] == "echo-slow" {
        Duration::from_millis(150)
    } else {
        Duration::from_millis(5)
    }
}

fn price(body: &Value, reply: &[String]) -> i64 {
    let input = serde_json::to_string(&body["messages"]).map(|s| s.len()).unwrap_or(0) as i64;
    let output: i64 = reply.iter().map(|w| w.len() as i64).sum();
    (input + output) * NANO_PER_CHAR
}

fn sse(events: Vec<(Option<&'static str>, Value)>, done: bool, delay: Duration) -> Body {
    let stream = async_stream(events, done, delay);
    Body::from_stream(stream)
}

fn async_stream(
    events: Vec<(Option<&'static str>, Value)>,
    done: bool,
    delay: Duration,
) -> impl futures::Stream<Item = Result<String, std::convert::Infallible>> {
    futures::stream::unfold((events.into_iter(), done, false), move |(mut it, done, first)| async move {
        match it.next() {
            Some((name, data)) => {
                if first {
                    tokio::time::sleep(delay).await;
                }
                let text = match name {
                    Some(n) => format!("event: {n}\ndata: {data}\n\n"),
                    None => format!("data: {data}\n\n"),
                };
                Some((Ok(text), (it, done, true)))
            }
            None if done => Some((Ok("data: [DONE]\n\n".to_string()), (it, false, true))),
            None => None,
        }
    })
}

fn sse_response(body: Body) -> Response {
    Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(body)
        .expect("valid response")
}

async fn chat(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Some(session) = session_of(&headers) else {
        return GatewayError::unauthorized().into_response();
    };
    let tier = match app.backend.usable(&session) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Some(refusal) = plan_check(&body, tier.as_deref()) {
        return refusal;
    }
    let words = reply_words(&body);
    app.backend.charge(&session, price(&body, &words));
    let model = body["model"].as_str().unwrap_or("echo").to_string();
    if body["stream"] == true {
        let mut events: Vec<(Option<&'static str>, Value)> = words
            .iter()
            .map(|w| {
                (None, json!({"object": "chat.completion.chunk", "model": model,
                    "choices": [{"index": 0, "delta": {"content": w}, "finish_reason": null}]}))
            })
            .collect();
        events.push((None, json!({"object": "chat.completion.chunk", "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})));
        return sse_response(sse(events, true, word_delay(&body)));
    }
    Json(json!({
        "object": "chat.completion", "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": words.concat()}, "finish_reason": "stop"}],
    }))
    .into_response()
}

async fn messages(State(app): State<App>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let Some(session) = session_of(&headers) else {
        return GatewayError::unauthorized().into_response();
    };
    let tier = match app.backend.usable(&session) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Some(refusal) = plan_check(&body, tier.as_deref()) {
        return refusal;
    }
    let words = reply_words(&body);
    app.backend.charge(&session, price(&body, &words));
    let model = body["model"].as_str().unwrap_or("echo").to_string();
    if body["stream"] == true {
        let mut events: Vec<(Option<&'static str>, Value)> = vec![
            (Some("message_start"), json!({"type": "message_start", "message": {"id": "msg_echo", "type": "message", "role": "assistant", "model": model, "content": [], "usage": {"input_tokens": 1, "output_tokens": 0}}})),
            (Some("content_block_start"), json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
        ];
        for w in &words {
            events.push((Some("content_block_delta"), json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": w}})));
        }
        events.push((Some("content_block_stop"), json!({"type": "content_block_stop", "index": 0})));
        events.push((Some("message_delta"), json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": words.len()}})));
        events.push((Some("message_stop"), json!({"type": "message_stop"})));
        return sse_response(sse(events, false, word_delay(&body)));
    }
    Json(json!({
        "id": "msg_echo", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": words.concat()}],
        "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": words.len()},
    }))
    .into_response()
}

/// `echo-pro` stands in for a model that needs a plan: only sessions opened
/// with a Pro pass may use it.
fn plan_check(body: &Value, tier: Option<&str>) -> Option<Response> {
    (body["model"] == "echo-pro" && tier != Some("pro")).then(|| {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"error": {"message": "echo-pro needs a Pro pass", "type": "permission_error"}})),
        )
            .into_response()
    })
}

async fn models() -> Json<Value> {
    Json(json!({"object": "list", "data": [
        {"id": "echo", "object": "model"},
        {"id": "echo-slow", "object": "model"},
        {"id": "echo-pro", "object": "model"},
    ]}))
}

#[derive(serde::Deserialize)]
struct NewAccount {
    #[serde(default = "default_balance")]
    balance_cents: i64,
    #[serde(default = "default_tier")]
    tier: String,
}

fn default_tier() -> String {
    "pay_as_you_go".into()
}

fn default_balance() -> i64 {
    10_000
}

/// Test payment: an account with play money.
async fn create_account(State(app): State<App>, Json(req): Json<NewAccount>) -> Json<Value> {
    if !unlinkable_inference::pass::TIERS.contains(&req.tier.as_str()) {
        return Json(json!({"error": {"message": "tier is pay_as_you_go, casual or pro"}}));
    }
    let token = app.backend.create_account(req.balance_cents, &req.tier);
    Json(json!({"api_key": token, "balance_cents": req.balance_cents, "tier": req.tier}))
}

async fn account(State(app): State<App>, headers: HeaderMap) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    match app.backend.account_balance(token) {
        Some(c) => Json(json!({"balance_cents": c})).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn dump(State(app): State<App>) -> Json<Value> {
    Json(app.backend.dump())
}

/// Record what the app could see of each request: the database dump shows
/// it, so the linking exercise has the server's whole view.
async fn record(State(app): State<App>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if !path.starts_with("/debug") {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string())
            .unwrap_or_default();
        let auth = req
            .headers()
            .get("authorization")
            .or_else(|| req.headers().get("x-api-key"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let credential = if auth.contains(unlinkable_inference::SESSION_SECRET_PREFIX) {
            "session"
        } else if auth.is_empty() {
            "none"
        } else {
            "account"
        };
        app.backend.log(RequestRow {
            path,
            peer,
            credential: credential.into(),
            had_cookie: req.headers().contains_key("cookie"),
            at: unix(),
        });
    }
    next.run(req).await
}

pub struct Server {
    pub router: Router,
    pub backend: Arc<MemoryBackend>,
    pub gateway: Arc<Gateway>,
}

/// Build the reference server. `values` are the voucher values to make keys
/// for (all of them in production use; tests can use fewer).
pub fn build(
    keys: KeyStore,
    idle_timeout: Duration,
) -> Server {
    let backend = Arc::new(MemoryBackend::new(idle_timeout));
    let gateway = Gateway::new(backend.clone(), Arc::new(keys));
    let app = App {
        backend: backend.clone(),
    };
    let inner = Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .route("/v1/messages", post(messages))
        .route("/test/accounts", post(create_account))
        .route("/test/account", get(account))
        .route("/debug/db", get(dump))
        .with_state(app.clone())
        .merge(unlinkable_inference::server::router(gateway.clone()))
        .layer(middleware::from_fn_with_state(app, record));
    let router = inner;
    Server {
        router,
        backend,
        gateway,
    }
}
