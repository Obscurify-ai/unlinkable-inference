//! Wire types for the session endpoints (`/u/*`). See SPEC.md.

use crate::voucher::Family;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedVoucher {
    /// Cents, or millicents for a dust blank
    pub denomination_cents: i64,
    pub key_id: String,
    /// base64url
    pub blinded_message: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dust: bool,
}

/// `POST /u/sessions`: no cookie, no API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSessionRequest {
    /// Voucher codes (`obv1.…`), all from one family
    pub vouchers: Vec<String>,
    /// SHA-256 (hex) of a session secret the client picked. The secret itself
    /// is only ever sent as the bearer token on later requests.
    pub secret_hash: String,
    /// A pass (`obp1.…`) to present as the session opens (the same as
    /// `POST /u/sessions/pass` straight after)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

/// `POST /u/sessions/pass` (bearer: session secret): present a pass. The
/// session gets whatever the server gives for its label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentPassRequest {
    pub pass: String,
}

/// A request that needs a pass the session has not presented is refused with
/// 403, this response header naming the label, and
/// `{"error": {"type": "pass_required", "pass": "<label>", …}}`. The client
/// presents one (`POST /u/sessions/pass`) and sends the request again.
pub const PASS_REQUIRED_HEADER: &str = "x-pass-required";
/// The error `type` of that refusal.
pub const PASS_REQUIRED: &str = "pass_required";

/// A request header: `1` when the client has nothing left to add to the session, so the server
/// may shorten the reply to what the session can pay for instead of refusing it (402).
pub const REST_HEADER: &str = "x-session-rest";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Remaining balance in USD, as a decimal string (exact)
    pub balance_usd: String,
    pub family: Family,
    /// The session stops working after this long without a request
    pub idle_timeout_seconds: u64,
    pub closed: bool,
    /// Labels of the passes this session has presented
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// 0.1 clients: the label of the pass the session opened with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// `POST /u/sessions` answered an open of a session that already existed (the same secret
    /// and vouchers). After a lost response that is the caller's own open; on a first try it is
    /// another device on the account that made the same choices, so pick another secret.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub repeat: bool,
}

/// `POST /u/passes` (bearer: the account's own API key): blind passes with
/// one label for this month.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassRequest {
    #[serde(default)]
    pub label: String,
    /// 0.1 clients send the label under this name (and get it back so)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub period: String,
    /// base64url blinded messages
    pub blinded: Vec<String>,
    /// As in [`WithdrawRequest::nonce`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl PassRequest {
    pub fn label(&self) -> &str {
        self.tier.as_deref().unwrap_or(&self.label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassResponse {
    #[serde(default)]
    pub label: String,
    /// 0.1 clients (see [`PassRequest::tier`])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub period: String,
    /// Blind signatures, in request order (base64url)
    pub blind_signatures: Vec<String>,
    /// Passes with this label the account can still get this month
    pub remaining: i64,
}

/// One label an account can get passes for, and how many are left this month.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabelAllowance {
    pub label: String,
    pub remaining: i64,
}

/// `GET /u/passes` (bearer: account key): what the account may ask for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassAllowance {
    pub period: String,
    #[serde(default)]
    pub labels: Vec<LabelAllowance>,
    /// 0.1 clients read one label here (`tier`, `remaining`); servers that
    /// never had such clients leave both out
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<i64>,
}

/// `POST /u/sessions/topup` (bearer: session secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopupRequest {
    pub vouchers: Vec<String>,
}

/// `POST /u/sessions/close` (bearer: session secret). The blanks must be able
/// to hold any amount up to the balance; the server signs the ones that add up
/// to the whole cents left and ignores the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseRequest {
    pub blanks: Vec<BlindedVoucher>,
}

/// `POST /u/exchange`: spend vouchers, get the same total back in new ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub vouchers: Vec<String>,
    pub blanks: Vec<BlindedVoucher>,
}

/// `POST /u/withdraw` (bearer: the account's own API key): move a fixed amount
/// of account balance into a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub amount_cents: i64,
    pub blanks: Vec<BlindedVoucher>,
    /// Seeded wallets: the blanks are derived from this, and the server keeps
    /// the request and answer under it until `POST /u/issued/done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlank {
    /// Index into the request's `blanks`
    pub index: usize,
    /// base64url
    pub blind_signature: String,
}

/// Answer to close, exchange and withdraw.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeResponse {
    /// Whole cents signed
    pub change_cents: i64,
    /// Plus this much dust, in millicents (below a cent)
    #[serde(default)]
    pub dust_millicents: i64,
    pub family: Family,
    pub signed: Vec<SignedBlank>,
    /// Fractions of a cent left behind at close (never paid out), USD
    #[serde(default)]
    pub forfeited_usd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Indexes of vouchers that were already spent (nothing was spent then)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spent: Vec<usize>,
    /// A withdrawal larger than the account can cover: what it can (whole cents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_cents: Option<i64>,
    /// With `available_cents`: the account holds more than that, which it can't give yet (a
    /// plan's usage window). Taking all of `available_cents` doesn't leave it empty.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub more_later: bool,
    /// With type [`PASS_REQUIRED`]: the label of the pass that is needed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

/// `GET /u/sessions/unclaimed` lists a session only once it is closed or has gone this long
/// without a request, so a device rebuilding its wallet never closes one another device on the
/// account is using (wallets close their own after five quiet minutes).
pub const UNCLAIMED_AFTER_SECS: u64 = 15 * 60;

/// `GET /u/sessions/unclaimed`: every session still open, or closed with
/// change nobody has confirmed collecting. A seeded wallet finds its own by
/// deriving secrets for those minutes and comparing, on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnclaimedSession {
    /// First 16 hex digits of the secret's hash
    pub h: String,
    /// Unix minute the session was opened
    pub m: u64,
}

/// `GET /u/issued` (bearer: the account's key): withdrawals and passes the
/// account made with a nonce and has not marked done, so a seeded wallet can
/// unblind them again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issued {
    /// "withdraw" or "pass" ("passes": asked for by a 0.1 client)
    pub kind: String,
    pub nonce: String,
    /// Unix time it was made
    pub created: u64,
    pub request: serde_json::Value,
    pub answer: serde_json::Value,
}

/// `POST /u/issued/done` (bearer: the account's key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoneRequest {
    pub nonces: Vec<String>,
}

/// `GET /u/spent?since=<unix>`: the first 16 hex digits of every voucher and
/// pass hash spent since then. Checked on the device, so asking reveals
/// nothing about which vouchers are yours.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentList {
    pub hashes: Vec<String>,
}

/// How much of a hash the recovery lists show.
pub const HASH_PREFIX: usize = 16;
