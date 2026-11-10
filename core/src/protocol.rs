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
    /// A pass (`obp1.…`) for this month: the session gets that tier's models
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    /// Remaining balance in USD, as a decimal string (exact)
    pub balance_usd: String,
    pub family: Family,
    /// The session stops working after this long without a request
    pub idle_timeout_seconds: u64,
    pub closed: bool,
    /// The plan tier a pass gave this session, if any
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

/// `POST /u/passes` (bearer: the account's own API key): blind passes for
/// this month at the account's tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassRequest {
    pub tier: String,
    pub period: String,
    /// base64url blinded messages
    pub blinded: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PassResponse {
    pub tier: String,
    pub period: String,
    /// Blind signatures, in request order (base64url)
    pub blind_signatures: Vec<String>,
    /// Passes this account can still get this month
    pub remaining: i64,
}

/// `GET /u/passes` (bearer: account key): what the account may ask for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassAllowance {
    pub tier: String,
    pub period: String,
    pub remaining: i64,
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
}
