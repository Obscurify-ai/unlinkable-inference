//! The server's public keys, and pinning them.
//!
//! The one real attack on blind vouchers is a server handing one user a
//! signing key (or OHTTP key) nobody else gets, so their vouchers or requests
//! stand out. So clients accept only keysets they have pinned: built into the
//! release, published in the public repo, or (for self-hosted and dev servers)
//! pinned on first use and never silently replaced.

use crate::voucher::Family;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SCHEME: &str = "RSABSSA-SHA384-PSS-Deterministic";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherKeyInfo {
    pub denomination_cents: i64,
    /// First 8 bytes of SHA-256 of the DER key, hex. Part of every voucher.
    pub key_id: String,
    /// DER SubjectPublicKeyInfo, base64url
    pub public_key_der: String,
}

impl VoucherKeyInfo {
    pub fn new(denomination_cents: i64, der: &[u8]) -> Self {
        Self {
            denomination_cents,
            key_id: key_id_for(der),
            public_key_der: crate::b64(der),
        }
    }
}

pub fn key_id_for(der: &[u8]) -> String {
    crate::sha256_hex(der)[..16].to_string()
}

/// Everything a client needs to trust before it talks to a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyset {
    pub scheme: String,
    pub paid: Vec<VoucherKeyInfo>,
    pub promo: Vec<VoucherKeyInfo>,
    /// OHTTP key configuration (RFC 9458 `application/ohttp-keys` entry), base64url
    pub ohttp_key_config: String,
    /// Path of the OHTTP gateway on the server, normally `/ohttp`
    pub ohttp_gateway_path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KeysetError {
    #[error("key {key_id} for {cents}¢ does not match its own key id")]
    BadKeyId { key_id: String, cents: i64 },
    #[error("unsupported scheme {0}")]
    Scheme(String),
    #[error("keyset {0} is not pinned; refusing it")]
    NotPinned(String),
}

impl Keyset {
    /// A short, stable fingerprint of the whole keyset. Pins are these.
    pub fn fingerprint(&self) -> String {
        let mut canonical = self.clone();
        canonical.paid.sort_by_key(|k| k.denomination_cents);
        canonical.promo.sort_by_key(|k| k.denomination_cents);
        let json = serde_json::to_vec(&canonical).expect("keyset serialises");
        format!("ks1-{}", &crate::sha256_hex(json)[..32])
    }

    /// Check that every key id is the hash of its key, so a server cannot list
    /// one key and sign with another.
    pub fn check(&self) -> Result<(), KeysetError> {
        if self.scheme != SCHEME {
            return Err(KeysetError::Scheme(self.scheme.clone()));
        }
        for key in self.paid.iter().chain(&self.promo) {
            let der = crate::unb64(&key.public_key_der).unwrap_or_default();
            if key_id_for(&der) != key.key_id {
                return Err(KeysetError::BadKeyId {
                    key_id: key.key_id.clone(),
                    cents: key.denomination_cents,
                });
            }
        }
        Ok(())
    }

    pub fn key(&self, family: Family, cents: i64) -> Option<&VoucherKeyInfo> {
        let keys = match family {
            Family::Paid => &self.paid,
            Family::Promo => &self.promo,
        };
        keys.iter().find(|k| k.denomination_cents == cents)
    }

    /// Which family a voucher's key belongs to, by key id.
    pub fn family_of(&self, key_id: &str) -> Option<Family> {
        if self.paid.iter().any(|k| k.key_id == key_id) {
            Some(Family::Paid)
        } else if self.promo.iter().any(|k| k.key_id == key_id) {
            Some(Family::Promo)
        } else {
            None
        }
    }

    pub fn ohttp_config_bytes(&self) -> Option<Vec<u8>> {
        crate::unb64(&self.ohttp_key_config)
    }
}

/// Keyset fingerprints a client accepts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pins {
    pub fingerprints: BTreeSet<String>,
}

impl Pins {
    /// Fingerprints built into this release for the public Obscurify server.
    /// Filled in by the release process from `keys/obscurify.ai.json`; a
    /// release never trusts a key that is not in its own source.
    pub fn builtin(host: &str) -> Self {
        let text = match host {
            "obscurify.ai" => include_str!("../../keys/obscurify.ai.pins"),
            _ => "",
        };
        Self {
            fingerprints: text
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with("ks1-"))
                .map(str::to_string)
                .collect(),
        }
    }

    pub fn accepts(&self, keyset: &Keyset) -> bool {
        self.fingerprints.contains(&keyset.fingerprint())
    }

    pub fn require(&self, keyset: &Keyset) -> Result<(), KeysetError> {
        keyset.check()?;
        if self.accepts(keyset) {
            Ok(())
        } else {
            Err(KeysetError::NotPinned(keyset.fingerprint()))
        }
    }
}
