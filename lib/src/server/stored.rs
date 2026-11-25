//! What the server may hand its storage (rule P5 in `spec/RULES.md`).
//!
//! Every value a [`Backend`](super::Backend) is given has a type from this file, and their
//! fields are private: code outside this file can only make one through the functions here,
//! and the compiler checks that. Each function either hashes what it is given, or refuses it
//! when it holds a session secret, a voucher or a pass as they are sent. So a database leak
//! never hands over anything that spends a voucher, uses a pass or takes over a session.
//!
//! This file is locked with the rules: changing it needs a new approval (`spec/APPROVED`).

use std::ops::Deref;

use serde::Serialize;

use super::GatewayError;
use crate::{pass::Pass, Voucher};

/// How a session secret, voucher or pass starts when it is sent; nothing stored may hold one.
const SENT_AS: [&str; 4] = [
    crate::SESSION_SECRET_PREFIX,
    crate::voucher::SENT_PREFIX,
    crate::voucher::SENT_DUST_PREFIX,
    crate::pass::SENT_PREFIX,
];

/// Whether `text` holds a session secret, voucher or pass anywhere in it.
fn holds_a_secret(text: &str) -> bool {
    SENT_AS.iter().any(|p| text.contains(p))
}

macro_rules! text_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }
    };
}

text_type!(
    /// A session, named by the SHA-256 hex of its secret.
    SecretHash
);
text_type!(
    /// A voucher or pass, named by the SHA-256 hex of its message.
    SpentHash
);
text_type!(
    /// A SHA-256 hex digest of a request, so a repeat is recognised.
    Digest
);
text_type!(
    /// The account's API key, as `/u/withdraw`, `/u/passes` and `/u/issued` are sent it:
    /// never a session secret, voucher or pass.
    AccountKey
);
text_type!(
    /// A pass label: 1 to 32 of `a-z`, `0-9`, `_` and `-`.
    Label
);
text_type!(
    /// A month, `YYYY-MM`.
    Period
);
text_type!(
    /// A client's name for a withdrawal or pass request: 1 to 64 characters.
    Nonce
);

impl SecretHash {
    /// The hash of a session secret.
    pub(crate) fn of(secret: &str) -> Self {
        Self(crate::sha256_hex(secret))
    }
    /// The hash a client sends to open a session: 64 hex digits, which a secret never is.
    pub(crate) fn from_hex(hex: &str) -> Option<Self> {
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Self(hex.to_ascii_lowercase()))
    }
}

impl SpentHash {
    pub(crate) fn of_voucher(voucher: &Voucher) -> Self {
        Self(crate::sha256_hex(&voucher.message))
    }
    pub(crate) fn of_pass(pass: &Pass) -> Self {
        Self(crate::sha256_hex(&pass.message))
    }
}

impl Digest {
    pub(crate) fn of(text: impl AsRef<[u8]>) -> Self {
        Self(crate::sha256_hex(text))
    }
}

impl AccountKey {
    pub(crate) fn new(token: &str) -> Option<Self> {
        (!token.is_empty() && !holds_a_secret(token)).then(|| Self(token.to_string()))
    }
}

impl Label {
    pub(crate) fn new(label: &str) -> Option<Self> {
        (crate::pass::valid_label(label) && !holds_a_secret(label)).then(|| Self(label.to_string()))
    }
}

impl Period {
    pub(crate) fn new(period: &str) -> Option<Self> {
        let b = period.as_bytes();
        let ok = b.len() == 7 && b[4] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || c.is_ascii_digit());
        ok.then(|| Self(period.to_string()))
    }
}

impl Nonce {
    pub(crate) fn new(nonce: &str) -> Option<Self> {
        ((1..=64).contains(&nonce.len()) && !holds_a_secret(nonce)).then(|| Self(nonce.to_string()))
    }
}

/// Whether any text in `value` (keys included) holds a secret.
fn json_holds_a_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => holds_a_secret(s),
        serde_json::Value::Array(items) => items.iter().any(json_holds_a_secret),
        serde_json::Value::Object(map) => map.iter().any(|(k, v)| holds_a_secret(k) || json_holds_a_secret(v)),
        _ => false,
    }
}

/// An answer the server signed, checked to hold no secret before storage sees it.
#[derive(Debug, Clone)]
pub struct Checked<T>(T);

impl<T: Serialize> Checked<T> {
    pub(crate) fn new(answer: T) -> Result<Self, GatewayError> {
        let value = serde_json::to_value(&answer).map_err(|e| GatewayError::internal(e.to_string()))?;
        if json_holds_a_secret(&value) {
            return Err(GatewayError::internal("an answer held a secret; not stored"));
        }
        Ok(Self(answer))
    }
}

impl<T> Checked<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Checked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// A withdrawal or pass request made with a nonce (a seeded wallet): kept
/// with its answer, linked to the account, until the account says it is done.
#[derive(Debug, Clone)]
pub struct IssuedRecord {
    kind: &'static str,
    nonce: Nonce,
    request: serde_json::Value,
}

impl IssuedRecord {
    pub(crate) fn new(kind: &'static str, nonce: Nonce, request: &impl Serialize) -> Result<Self, GatewayError> {
        let request = serde_json::to_value(request).map_err(|e| GatewayError::internal(e.to_string()))?;
        if json_holds_a_secret(&request) {
            return Err(GatewayError::bad_request("A request may not hold a secret, voucher or pass."));
        }
        Ok(Self { kind, nonce, request })
    }
    /// "withdraw" or "pass" ("passes": asked for by a 0.1 client)
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
    /// The request as the client sent it (its blanks, amount or label).
    pub fn request(&self) -> &serde_json::Value {
        &self.request
    }
}
