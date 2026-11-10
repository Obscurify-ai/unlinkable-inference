//! Server side of unlinkable sessions.
//!
//! - [`router`]: the session endpoints (`/u/*`). They read no cookie, no
//!   account key (except `/u/withdraw`, which is the account moving its own
//!   balance into a wallet) and no IP.
//! - [`ohttp::wrap`]: an Oblivious HTTP gateway in front of any axum app.
//!
//! Storage and money live behind [`Backend`], keys behind [`Signer`], so the
//! same code runs in the reference server and in a production server.

pub mod ohttp;
pub mod signer;

pub use unlinkable_core as core;

use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashSet;
use std::sync::Arc;
use unlinkable_core::{
    denominations::{pick_blanks, WITHDRAW_SIZES},
    keyset::{Keyset, VoucherKeyInfo, SCHEME},
    protocol::*,
    Family, Voucher,
};

/// One voucher being spent: the hash of its message and its value.
#[derive(Debug, Clone)]
pub struct Spend {
    pub hash: String,
    pub cents: i64,
}

#[derive(Debug)]
pub enum GatewayError {
    /// These spent-voucher hashes were already spent; nothing was spent.
    Spent(Vec<String>),
    Status(StatusCode, &'static str, String),
}

impl GatewayError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::Status(StatusCode::BAD_REQUEST, "invalid_request_error", message.into())
    }
    pub fn unauthorized() -> Self {
        Self::Status(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "No such session.".into(),
        )
    }
    pub fn payment_required(message: impl Into<String>) -> Self {
        Self::Status(StatusCode::PAYMENT_REQUIRED, "insufficient_balance", message.into())
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Status(StatusCode::INTERNAL_SERVER_ERROR, "api_error", message.into())
    }
    pub fn unavailable() -> Self {
        Self::Status(
            StatusCode::NOT_FOUND,
            "not_found_error",
            "Unlinkable sessions are not available on this server.".into(),
        )
    }
}

impl From<anyhow::Error> for GatewayError {
    fn from(e: anyhow::Error) -> Self {
        Self::internal(e.to_string())
    }
}

/// A gateway error with the spent hashes mapped back to request indexes.
struct Answer(GatewayError, Vec<String>);

impl IntoResponse for Answer {
    fn into_response(self) -> Response {
        let (status, kind, message, spent) = match self.0 {
            GatewayError::Spent(hashes) => {
                let spent: Vec<usize> = self
                    .1
                    .iter()
                    .enumerate()
                    .filter(|(_, h)| hashes.contains(h))
                    .map(|(i, _)| i)
                    .collect();
                (
                    StatusCode::CONFLICT,
                    "voucher_spent",
                    "Some of these vouchers were already spent. Nothing was spent this time."
                        .to_string(),
                    spent,
                )
            }
            GatewayError::Status(status, kind, message) => (status, kind, message, Vec::new()),
        };
        let body = ErrorBody {
            error: ErrorDetail {
                message,
                kind: kind.to_string(),
                spent,
            },
        };
        (status, Json(body)).into_response()
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        Answer(self, Vec::new()).into_response()
    }
}

/// Signs change: given the family and whole cents the session holds, sign
/// the blanks that add up to it.
pub type SignChange =
    Box<dyn FnOnce(Family, i64, String) -> Result<ChangeResponse, GatewayError> + Send>;

/// Storage and money. Every method that spends vouchers or moves balance
/// must do it atomically, and must answer a repeat of a request (same
/// `secret_hash` or `request_digest`) the way it answered the first time,
/// so clients can retry after a lost response.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// Whether sessions are switched on (checked on every request).
    async fn enabled(&self) -> bool {
        true
    }
    /// Spend `spends` and open a session holding their total. If a session
    /// with `secret_hash` exists, return its status and spend nothing.
    async fn open_session(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
    ) -> Result<SessionStatus, GatewayError>;
    async fn topup(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
    ) -> Result<SessionStatus, GatewayError>;
    async fn status(&self, secret_hash: &str) -> Result<SessionStatus, GatewayError>;
    /// Close: lock the session, call `sign` with its whole cents (and the
    /// fraction of a cent forfeited, as a decimal string), store the answer
    /// under `request_digest`, and end the session.
    async fn close_session(
        &self,
        secret_hash: &str,
        request_digest: &str,
        sign: SignChange,
    ) -> Result<ChangeResponse, GatewayError>;
    /// Spend `spends` and record `answer` under `request_digest`, atomically.
    async fn exchange(
        &self,
        request_digest: &str,
        spends: &[Spend],
        answer: &ChangeResponse,
    ) -> Result<ChangeResponse, GatewayError>;
    /// Debit `cents` of withdrawable balance from the account `account_token`
    /// authenticates and record `answer` under `request_digest`, atomically.
    async fn withdraw(
        &self,
        account_token: &str,
        cents: i64,
        request_digest: &str,
        answer: &ChangeResponse,
    ) -> Result<ChangeResponse, GatewayError>;
}

/// Public voucher keys and blind signing.
pub trait Signer: Send + Sync + 'static {
    fn public_keys(&self, family: Family) -> Vec<VoucherKeyInfo>;
    fn sign_blinded(&self, family: Family, cents: i64, blinded: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub struct Gateway {
    pub backend: Arc<dyn Backend>,
    pub signer: Arc<dyn Signer>,
    pub ohttp: Arc<ohttp::OhttpKeys>,
    pub keyset: Keyset,
}

impl Gateway {
    pub fn new(backend: Arc<dyn Backend>, signer: Arc<dyn Signer>, ohttp: ohttp::OhttpKeys) -> Arc<Self> {
        let keyset = Keyset {
            scheme: SCHEME.to_string(),
            paid: signer.public_keys(Family::Paid),
            promo: signer.public_keys(Family::Promo),
            ohttp_key_config: unlinkable_core::b64(ohttp.encoded_config()),
            ohttp_gateway_path: "/ohttp".to_string(),
        };
        Arc::new(Self {
            backend,
            signer,
            ohttp: Arc::new(ohttp),
            keyset,
        })
    }

    /// Parse and check vouchers: valid signatures, one family, no repeats.
    fn spends(&self, codes: &[String]) -> Result<(Family, Vec<Spend>), GatewayError> {
        if codes.is_empty() || codes.len() > 64 {
            return Err(GatewayError::bad_request("Send between 1 and 64 vouchers."));
        }
        let mut family = None;
        let mut seen = HashSet::new();
        let mut spends = Vec::with_capacity(codes.len());
        for (i, code) in codes.iter().enumerate() {
            let voucher = Voucher::parse(code)
                .ok_or_else(|| GatewayError::bad_request(format!("Voucher {i} is not a voucher.")))?;
            let f = unlinkable_core::blank::verify(&self.keyset, &voucher).ok_or_else(|| {
                GatewayError::bad_request(format!("Voucher {i} has no valid signature."))
            })?;
            if *family.get_or_insert(f) != f {
                return Err(GatewayError::bad_request(
                    "Paid and promotional vouchers cannot fund the same session.",
                ));
            }
            let hash = voucher.spent_hash();
            if !seen.insert(hash.clone()) {
                return Err(GatewayError::bad_request(format!("Voucher {i} appears twice.")));
            }
            spends.push(Spend {
                hash,
                cents: voucher.denomination_cents,
            });
        }
        Ok((family.expect("at least one voucher"), spends))
    }

    /// Sign the blanks that hold exactly `cents` of `family` (the standard
    /// split, picked from blanks that can hold any amount up to a limit).
    fn sign_change(
        &self,
        blanks: &[BlindedVoucher],
        family: Family,
        cents: i64,
        forfeited_usd: String,
    ) -> Result<ChangeResponse, GatewayError> {
        let values: Vec<i64> = blanks.iter().map(|b| b.denomination_cents).collect();
        let picked = pick_blanks(&values, cents).ok_or_else(|| {
            GatewayError::bad_request(format!(
                "These blanks cannot hold {cents}¢ of change. Send blanks for any amount up to the balance."
            ))
        })?;
        self.sign_picked(blanks, picked, family, cents, forfeited_usd)
    }

    /// Sign every blank, which must add up to exactly `cents`.
    fn sign_all(
        &self,
        blanks: &[BlindedVoucher],
        family: Family,
        cents: i64,
    ) -> Result<ChangeResponse, GatewayError> {
        let sum: i64 = blanks.iter().map(|b| b.denomination_cents).sum();
        if sum != cents {
            return Err(GatewayError::bad_request(format!(
                "The blanks add up to {sum}¢, not {cents}¢."
            )));
        }
        self.sign_picked(blanks, (0..blanks.len()).collect(), family, cents, "0".into())
    }

    fn sign_picked(
        &self,
        blanks: &[BlindedVoucher],
        picked: Vec<usize>,
        family: Family,
        cents: i64,
        forfeited_usd: String,
    ) -> Result<ChangeResponse, GatewayError> {
        let mut signed = Vec::with_capacity(picked.len());
        for index in picked {
            let blank = &blanks[index];
            let key = self
                .keyset
                .key(family, blank.denomination_cents)
                .ok_or_else(|| GatewayError::bad_request("Unsupported voucher value."))?;
            if key.key_id != blank.key_id {
                return Err(GatewayError::Status(
                    StatusCode::CONFLICT,
                    "keys_changed",
                    "The voucher keys changed; fetch /u/keys and blind again.".into(),
                ));
            }
            let blinded = unlinkable_core::unb64(&blank.blinded_message)
                .ok_or_else(|| GatewayError::bad_request("Invalid blinded message."))?;
            let sig = self
                .signer
                .sign_blinded(family, blank.denomination_cents, &blinded)
                .map_err(|e| GatewayError::bad_request(format!("Cannot sign that blank: {e}")))?;
            signed.push(SignedBlank {
                index,
                blind_signature: unlinkable_core::b64(sig),
            });
        }
        Ok(ChangeResponse {
            change_cents: cents,
            family,
            signed,
            forfeited_usd,
        })
    }
}

/// Digest of a request's blanks, so a repeat is recognised.
fn blanks_digest(kind: &str, blanks: &[BlindedVoucher]) -> String {
    let mut text = kind.to_string();
    for b in blanks {
        text.push('|');
        text.push_str(&b.blinded_message);
    }
    unlinkable_core::sha256_hex(text)
}

fn check_blank_count(blanks: &[BlindedVoucher]) -> Result<(), GatewayError> {
    if blanks.is_empty() || blanks.len() > 128 {
        return Err(GatewayError::bad_request("Send between 1 and 128 blanks."));
    }
    Ok(())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
}

fn session_hash(headers: &HeaderMap) -> Result<String, GatewayError> {
    let token = bearer(headers).ok_or_else(GatewayError::unauthorized)?;
    if !token.starts_with(unlinkable_core::SESSION_SECRET_PREFIX) {
        return Err(GatewayError::unauthorized());
    }
    Ok(unlinkable_core::sha256_hex(token))
}

async fn ensure_enabled(gw: &Gateway) -> Result<(), GatewayError> {
    if gw.backend.enabled().await {
        Ok(())
    } else {
        Err(GatewayError::unavailable())
    }
}

type Gw = State<Arc<Gateway>>;

async fn keys(State(gw): Gw) -> Response {
    if !gw.backend.enabled().await {
        return GatewayError::unavailable().into_response();
    }
    (
        [(http::header::CACHE_CONTROL, "public, max-age=300")],
        Json(gw.keyset.clone()),
    )
        .into_response()
}

async fn open(State(gw): Gw, Json(req): Json<OpenSessionRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        if req.secret_hash.len() != 64 || !req.secret_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GatewayError::bad_request("secret_hash must be SHA-256 hex."));
        }
        let (family, spends) = gw.spends(&req.vouchers)?;
        gw.backend
            .open_session(&req.secret_hash.to_ascii_lowercase(), family, &spends)
            .await
    };
    respond(run.await, &req.vouchers)
}

async fn current(State(gw): Gw, headers: HeaderMap) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        gw.backend.status(&session_hash(&headers)?).await
    };
    respond(run.await, &[])
}

async fn topup(State(gw): Gw, headers: HeaderMap, Json(req): Json<TopupRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        let hash = session_hash(&headers)?;
        let (family, spends) = gw.spends(&req.vouchers)?;
        gw.backend.topup(&hash, family, &spends).await
    };
    respond(run.await, &req.vouchers)
}

async fn close(State(gw): Gw, headers: HeaderMap, Json(req): Json<CloseRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        let hash = session_hash(&headers)?;
        check_blank_count(&req.blanks)?;
        let digest = blanks_digest("close", &req.blanks);
        let signer = gw.clone();
        let blanks = req.blanks.clone();
        gw.backend
            .close_session(
                &hash,
                &digest,
                Box::new(move |family, cents, forfeited| {
                    if cents == 0 {
                        return Ok(ChangeResponse {
                            change_cents: 0,
                            family,
                            signed: Vec::new(),
                            forfeited_usd: forfeited,
                        });
                    }
                    signer.sign_change(&blanks, family, cents, forfeited)
                }),
            )
            .await
    };
    respond(run.await, &[])
}

async fn exchange(State(gw): Gw, Json(req): Json<ExchangeRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        check_blank_count(&req.blanks)?;
        let (family, spends) = gw.spends(&req.vouchers)?;
        let total: i64 = spends.iter().map(|s| s.cents).sum();
        // Signing first is safe: signatures count for nothing until the
        // backend spends the vouchers and records them in one step.
        let answer = gw.sign_all(&req.blanks, family, total)?;
        gw.backend
            .exchange(&blanks_digest("exchange", &req.blanks), &spends, &answer)
            .await
    };
    respond(run.await, &req.vouchers)
}

async fn withdraw(State(gw): Gw, headers: HeaderMap, Json(req): Json<WithdrawRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        let token = bearer(&headers).ok_or_else(|| {
            GatewayError::Status(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Send the account's API key.".into(),
            )
        })?;
        if !WITHDRAW_SIZES.contains(&req.amount_cents) {
            return Err(GatewayError::bad_request(
                "Withdrawals come in fixed sizes: $1, $5, $20, $50 or $100.",
            ));
        }
        check_blank_count(&req.blanks)?;
        let answer = gw.sign_all(&req.blanks, Family::Paid, req.amount_cents)?;
        gw.backend
            .withdraw(
                &token,
                req.amount_cents,
                &blanks_digest("withdraw", &req.blanks),
                &answer,
            )
            .await
    };
    respond(run.await, &[])
}

fn respond<T: serde::Serialize>(result: Result<T, GatewayError>, codes: &[String]) -> Response {
    match result {
        Ok(body) => (
            [(http::header::CACHE_CONTROL, "no-store")],
            Json(body),
        )
            .into_response(),
        Err(e) => {
            let hashes = codes
                .iter()
                .map(|c| Voucher::parse(c).map(|v| v.spent_hash()).unwrap_or_default())
                .collect();
            Answer(e, hashes).into_response()
        }
    }
}

/// The session endpoints. Merge into the app; they need no other state.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/u/keys", get(keys))
        .route("/u/sessions", post(open))
        .route("/u/sessions/current", get(current))
        .route("/u/sessions/topup", post(topup))
        .route("/u/sessions/close", post(close))
        .route("/u/exchange", post(exchange))
        .route("/u/withdraw", post(withdraw))
        .with_state(gateway)
}
