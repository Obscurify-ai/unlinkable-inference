//! Server side of unlinkable sessions.
//!
//! [`router`] serves the session endpoints (`/u/*`). They read no cookie and
//! no account key (except `/u/withdraw`, which is the account moving its own
//! balance into a wallet), and keep no IP.
//!
//! Storage and money live behind [`Backend`], keys behind [`Signer`], so the
//! same code runs in the reference server and in a production server.

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
    denominations::{pick_blanks, pick_dust_blanks, MILLICENTS_PER_CENT, WITHDRAW_SIZES},
    keyset::{Keyset, PassKeyInfo, VoucherKeyInfo, SCHEME},
    pass::{current_period, Pass, TIERS},
    protocol::*,
    Family, Voucher,
};

/// A pass being used to open a session.
#[derive(Debug, Clone)]
pub struct PassUse {
    pub hash: String,
    pub tier: String,
    pub period: String,
}

/// One voucher being spent: the hash of its message and its value.
#[derive(Debug, Clone)]
pub struct Spend {
    pub hash: String,
    /// Value in millicents (1/1000 of a cent)
    pub millicents: i64,
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

/// A withdrawal or pass request made with a nonce (a seeded wallet): kept
/// with its answer, linked to the account, until the account says it is done.
#[derive(Debug, Clone)]
pub struct IssuedRecord {
    /// "withdraw" or "passes"
    pub kind: &'static str,
    pub nonce: String,
    pub request: serde_json::Value,
}

/// Signs change: given the family and the millicents the session holds
/// (its balance rounded up to the next millicent, in the customer's favour),
/// sign/// the blanks that add up to it.
pub type SignChange =
    Box<dyn FnOnce(Family, i64) -> Result<ChangeResponse, GatewayError> + Send>;

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
    /// The smallest total a session can be opened with, in cents.
    async fn min_session_cents(&self) -> i64 {
        10
    }
    /// Spend `spends` (and `pass`, if given: answer 409 `pass_spent` if it was
    /// used before) and open a session holding their total, with the pass's
    /// tier. If a session with `secret_hash` exists, return its status and
    /// spend nothing.
    async fn open_session(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
        pass: Option<&PassUse>,
    ) -> Result<SessionStatus, GatewayError>;
    /// The tier and the passes left this month for the account `account_token`
    /// authenticates.
    async fn pass_allowance(
        &self,
        account_token: &str,
        period: &str,
    ) -> Result<PassAllowance, GatewayError> {
        let _ = (account_token, period);
        Err(GatewayError::unavailable())
    }
    /// Count `count` passes against the account's monthly allowance and record
    /// `answer` under `request_digest`, atomically; a repeat with the same
    /// digest gets the stored answer.
    async fn record_passes(
        &self,
        account_token: &str,
        count: i64,
        request_digest: &str,
        answer: &PassResponse,
        issued: Option<&IssuedRecord>,
    ) -> Result<PassResponse, GatewayError> {
        let _ = (account_token, count, request_digest, answer, issued);
        Err(GatewayError::unavailable())
    }
    /// Sessions still open, or closed and not marked done, oldest first.
    async fn unclaimed(&self) -> Result<Vec<UnclaimedSession>, GatewayError>;
    /// Forget a closed session (its holder has spent all its change). An
    /// open session is left alone.
    async fn session_done(&self, secret_hash: &str) -> Result<(), GatewayError>;
    /// The account's [`IssuedRecord`]s not yet marked done, with answers.
    async fn issued(&self, account_token: &str) -> Result<Vec<Issued>, GatewayError>;
    async fn issued_done(&self, account_token: &str, nonces: &[String]) -> Result<(), GatewayError>;
    /// Hashes of vouchers and passes spent at or after `since` (Unix seconds).
    async fn spent_since(&self, since: u64) -> Result<Vec<String>, GatewayError>;
    async fn topup(
        &self,
        secret_hash: &str,
        family: Family,
        spends: &[Spend],
    ) -> Result<SessionStatus, GatewayError>;
    async fn status(&self, secret_hash: &str) -> Result<SessionStatus, GatewayError>;
    /// Close: lock the session, call `sign` with its balance in millicents,
    /// rounded up (never down: a session must not cost more than its
    /// tokens), store the answer
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
        issued: Option<&IssuedRecord>,
    ) -> Result<ChangeResponse, GatewayError>;
}

/// Public voucher keys and blind signing.
pub trait Signer: Send + Sync + 'static {
    fn public_keys(&self, family: Family) -> Vec<VoucherKeyInfo>;
    fn sign_blinded(&self, family: Family, cents: i64, blinded: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// Dust keys (values in millicents). Without them change below a cent
    /// cannot be returned, so servers should have them.
    fn dust_keys(&self, family: Family) -> Vec<VoucherKeyInfo> {
        let _ = family;
        Vec::new()
    }
    fn sign_dust(&self, family: Family, millicents: i64, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        let _ = (family, millicents, blinded);
        anyhow::bail!("this server has no dust keys")
    }
    /// The pass master key, if this server issues passes.
    fn pass_key(&self) -> Option<PassKeyInfo> {
        None
    }
    /// Sign a blinded pass for `tier` in `period`.
    fn sign_pass(&self, tier: &str, period: &str, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        let _ = (tier, period, blinded);
        anyhow::bail!("this server does not issue passes")
    }
}

pub struct Gateway {
    pub backend: Arc<dyn Backend>,
    pub signer: Arc<dyn Signer>,
    pub keyset: Keyset,
}

impl Gateway {
    pub fn new(backend: Arc<dyn Backend>, signer: Arc<dyn Signer>) -> Arc<Self> {
        let keyset = Keyset {
            scheme: SCHEME.to_string(),
            paid: signer.public_keys(Family::Paid),
            promo: signer.public_keys(Family::Promo),
            dust_paid: signer.dust_keys(Family::Paid),
            dust_promo: signer.dust_keys(Family::Promo),
            pass_key: signer.pass_key(),
        };
        Arc::new(Self {
            backend,
            signer,
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
                millicents: voucher.value_millicents(),
            });
        }
        Ok((family.expect("at least one voucher"), spends))
    }

    /// Sign the blanks that hold exactly `millicents` of `family`: whole
    /// cents the standard way, the rest from dust blanks, each picked from
    /// blanks that can hold any amount up to a limit.
    fn sign_change(
        &self,
        blanks: &[BlindedVoucher],
        family: Family,
        millicents: i64,
    ) -> Result<ChangeResponse, GatewayError> {
        let cents = millicents / MILLICENTS_PER_CENT;
        let dust = millicents % MILLICENTS_PER_CENT;
        let whole: Vec<usize> = (0..blanks.len()).filter(|&i| !blanks[i].dust).collect();
        let small: Vec<usize> = (0..blanks.len()).filter(|&i| blanks[i].dust).collect();
        let values = |idx: &[usize]| idx.iter().map(|&i| blanks[i].denomination_cents).collect::<Vec<_>>();
        let cannot = || {
            GatewayError::bad_request(format!(
                "These blanks cannot hold {cents}¢ and {dust} millicents of change. Send blanks for any amount up to the balance, and dust blanks for any amount below a cent."
            ))
        };
        let mut picked: Vec<usize> = pick_blanks(&values(&whole), cents)
            .ok_or_else(cannot)?
            .into_iter()
            .map(|k| whole[k])
            .collect();
        picked.extend(
            pick_dust_blanks(&values(&small), dust)
                .ok_or_else(cannot)?
                .into_iter()
                .map(|k| small[k]),
        );
        self.sign_picked(blanks, picked, family)
    }

    /// Sign every blank, which must add up to exactly `millicents`.
    fn sign_all(
        &self,
        blanks: &[BlindedVoucher],
        family: Family,
        millicents: i64,
    ) -> Result<ChangeResponse, GatewayError> {
        let sum: i64 = blanks.iter().map(blank_millicents).sum();
        if sum != millicents {
            return Err(GatewayError::bad_request(format!(
                "The blanks add up to {sum} millicents, not {millicents}."
            )));
        }
        self.sign_picked(blanks, (0..blanks.len()).collect(), family)
    }

    fn sign_picked(
        &self,
        blanks: &[BlindedVoucher],
        picked: Vec<usize>,
        family: Family,
    ) -> Result<ChangeResponse, GatewayError> {
        let mut signed = Vec::with_capacity(picked.len());
        let mut total = 0;
        for index in picked {
            let blank = &blanks[index];
            let key = self
                .keyset
                .key_for(family, blank.denomination_cents, blank.dust)
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
            let sig = if blank.dust {
                self.signer.sign_dust(family, blank.denomination_cents, &blinded)
            } else {
                self.signer.sign_blinded(family, blank.denomination_cents, &blinded)
            }
            .map_err(|e| GatewayError::bad_request(format!("Cannot sign that blank: {e}")))?;
            total += blank_millicents(blank);
            signed.push(SignedBlank {
                index,
                blind_signature: unlinkable_core::b64(sig),
            });
        }
        Ok(ChangeResponse {
            change_cents: total / MILLICENTS_PER_CENT,
            dust_millicents: total % MILLICENTS_PER_CENT,
            family,
            signed,
            forfeited_usd: "0".into(),
        })
    }
}

fn blank_millicents(blank: &BlindedVoucher) -> i64 {
    if blank.dust {
        blank.denomination_cents
    } else {
        blank.denomination_cents * MILLICENTS_PER_CENT
    }
}

impl Gateway {
    /// A pass that opens a session: valid signature, this month.
    fn check_pass(&self, code: &str) -> Result<PassUse, GatewayError> {
        let pass = Pass::parse(code).ok_or_else(|| GatewayError::bad_request("That is not a pass."))?;
        if pass.period != current_period() {
            return Err(GatewayError::bad_request(format!(
                "That pass is for {}; passes work in their own month.",
                pass.period
            )));
        }
        if !unlinkable_core::pass::verify(&self.keyset, &pass) {
            return Err(GatewayError::bad_request("That pass has no valid signature."));
        }
        Ok(PassUse {
            hash: pass.spent_hash(),
            tier: pass.tier,
            period: pass.period,
        })
    }
}

fn account_token(headers: &HeaderMap) -> Result<String, GatewayError> {
    bearer(headers)
        .filter(|t| !t.starts_with(unlinkable_core::SESSION_SECRET_PREFIX))
        .ok_or_else(|| {
            GatewayError::Status(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Send the account's API key.".into(),
            )
        })
}

async fn pass_allowance(State(gw): Gw, headers: HeaderMap) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        if gw.keyset.pass_key.is_none() {
            return Err(GatewayError::unavailable());
        }
        gw.backend
            .pass_allowance(&account_token(&headers)?, &current_period())
            .await
    };
    respond(run.await, &[])
}

async fn passes(State(gw): Gw, headers: HeaderMap, Json(req): Json<PassRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        if gw.keyset.pass_key.is_none() {
            return Err(GatewayError::unavailable());
        }
        let token = account_token(&headers)?;
        if req.blinded.is_empty() || req.blinded.len() > 100 {
            return Err(GatewayError::bad_request("Ask for between 1 and 100 passes."));
        }
        if !TIERS.contains(&req.tier.as_str()) || req.period != current_period() {
            return Err(GatewayError::bad_request("Ask for passes for this month."));
        }
        let mut digest = format!("passes|{}|{}", req.tier, req.period);
        for b in &req.blinded {
            digest.push('|');
            digest.push_str(b);
        }
        let digest = unlinkable_core::sha256_hex(digest);
        let allowance = gw.backend.pass_allowance(&token, &req.period).await?;
        if allowance.tier != req.tier {
            return Err(GatewayError::Status(
                StatusCode::FORBIDDEN,
                "permission_error",
                format!("This account gets {} passes.", allowance.tier),
            ));
        }
        // Signing first is safe: nothing counts until record_passes checks the
        // allowance and stores the answer in one step.
        let mut signatures = Vec::with_capacity(req.blinded.len());
        for b in &req.blinded {
            let blinded = unlinkable_core::unb64(b)
                .ok_or_else(|| GatewayError::bad_request("Invalid blinded pass."))?;
            let sig = gw
                .signer
                .sign_pass(&req.tier, &req.period, &blinded)
                .map_err(|e| GatewayError::bad_request(format!("Cannot sign that pass: {e}")))?;
            signatures.push(unlinkable_core::b64(sig));
        }
        let answer = PassResponse {
            tier: req.tier.clone(),
            period: req.period.clone(),
            blind_signatures: signatures,
            remaining: 0,
        };
        let issued = issued_record("passes", req.nonce.as_deref(), &req)?;
        gw.backend
            .record_passes(&token, req.blinded.len() as i64, &digest, &answer, issued.as_ref())
            .await
    };
    respond(run.await, &[])
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
        let total: i64 = spends.iter().map(|s| s.millicents).sum();
        let min = gw.backend.min_session_cents().await;
        if total < min * MILLICENTS_PER_CENT {
            return Err(GatewayError::bad_request(format!(
                "A session needs at least {min}¢ of vouchers."
            )));
        }
        let pass = match &req.pass {
            Some(code) => Some(gw.check_pass(code)?),
            None => None,
        };
        gw.backend
            .open_session(
                &req.secret_hash.to_ascii_lowercase(),
                family,
                &spends,
                pass.as_ref(),
            )
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
                Box::new(move |family, millicents| {
                    signer.sign_change(&blanks, family, millicents.max(0))
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
        let total: i64 = spends.iter().map(|s| s.millicents).sum();
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
        let answer = gw.sign_all(&req.blanks, Family::Paid, req.amount_cents * MILLICENTS_PER_CENT)?;
        let issued = issued_record("withdraw", req.nonce.as_deref(), &req)?;
        gw.backend
            .withdraw(
                &token,
                req.amount_cents,
                &blanks_digest("withdraw", &req.blanks),
                &answer,
                issued.as_ref(),
            )
            .await
    };
    respond(run.await, &[])
}

fn issued_record(
    kind: &'static str,
    nonce: Option<&str>,
    request: &impl serde::Serialize,
) -> Result<Option<IssuedRecord>, GatewayError> {
    let Some(nonce) = nonce else { return Ok(None) };
    if nonce.is_empty() || nonce.len() > 64 {
        return Err(GatewayError::bad_request("Invalid nonce."));
    }
    Ok(Some(IssuedRecord {
        kind,
        nonce: nonce.to_string(),
        request: serde_json::to_value(request).map_err(|e| GatewayError::internal(e.to_string()))?,
    }))
}

async fn unclaimed(State(gw): Gw) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        let mut list = gw.backend.unclaimed().await?;
        for u in &mut list {
            u.h.truncate(HASH_PREFIX);
        }
        Ok(list)
    };
    respond(run.await, &[])
}

async fn session_done(State(gw): Gw, headers: HeaderMap) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        gw.backend.session_done(&session_hash(&headers)?).await?;
        Ok(serde_json::json!({"done": true}))
    };
    respond(run.await, &[])
}

async fn issued(State(gw): Gw, headers: HeaderMap) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        gw.backend.issued(&account_token(&headers)?).await
    };
    respond(run.await, &[])
}

async fn issued_done(State(gw): Gw, headers: HeaderMap, Json(req): Json<DoneRequest>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        if req.nonces.len() > 1000 {
            return Err(GatewayError::bad_request("At most 1000 at a time."));
        }
        gw.backend.issued_done(&account_token(&headers)?, &req.nonces).await?;
        Ok(serde_json::json!({"done": req.nonces.len()}))
    };
    respond(run.await, &[])
}

#[derive(serde::Deserialize)]
struct SpentQuery {
    since: u64,
}

async fn spent(State(gw): Gw, axum::extract::Query(q): axum::extract::Query<SpentQuery>) -> Response {
    let run = async {
        ensure_enabled(&gw).await?;
        let hashes = gw.backend.spent_since(q.since).await?;
        Ok(SpentList {
            hashes: hashes
                .into_iter()
                .map(|h| h.chars().take(HASH_PREFIX).collect())
                .collect(),
        })
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
        .route("/u/passes", get(pass_allowance).post(passes))
        .route("/u/sessions/unclaimed", get(unclaimed))
        .route("/u/sessions/done", post(session_done))
        .route("/u/issued", get(issued))
        .route("/u/issued/done", post(issued_done))
        .route("/u/spent", get(spent))
        .with_state(gateway)
}
