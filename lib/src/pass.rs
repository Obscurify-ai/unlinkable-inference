//! Passes: proof that a session's holder was given something this month,
//! without saying which account.
//!
//! A pass is a partially blind RSA signature (draft-irtf-cfrg-partially-blind-rsa)
//! under one master key, with a label and the month as public metadata. The
//! label is the server's word for what the pass is good for (a group of
//! models, an allowance): this library never reads meaning into it. The
//! account asks for passes while signed in; the server sees the label and
//! month (it decides which labels the account gets) but never the message.
//! A session presents a pass when the server asks for one with that label.
//! Each pass is used once; an account gets a fixed number of each label per
//! month.
//!
//! `obp1.<label>.<period>.<message>.<signature>`, period = `YYYY-MM` (UTC).

use crate::keyset::Keyset;
use anyhow::{anyhow, Context, Result};
use blind_rsa_signatures::pbrsa::PartiallyBlindPublicKeySha384PSSDeterministic as PassPublicKey;
use blind_rsa_signatures::{BlindMessage, BlindSignature, BlindingResult, DefaultRng, Secret};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "obp1";

/// A label is 1 to 32 of `a-z`, `0-9`, `_` and `-`.
pub fn valid_label(label: &str) -> bool {
    (1..=32).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The public metadata a pass is bound to.
pub fn metadata(label: &str, period: &str) -> Vec<u8> {
    format!("unlinkable-inference-pass:v1:{label}:{period}").into_bytes()
}

/// `YYYY-MM` for a Unix time, UTC.
pub fn period_at(unix: u64) -> String {
    // Civil-from-days (Howard Hinnant), enough for any date after 1970.
    let days = (unix / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}")
}

pub fn current_period() -> String {
    period_at(crate::unix_now())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pass {
    /// (`tier` in wallets saved by 0.1)
    #[serde(alias = "tier")]
    pub label: String,
    pub period: String,
    #[serde(with = "crate::voucher::b64bytes")]
    pub message: Vec<u8>,
    #[serde(with = "crate::voucher::b64bytes")]
    pub signature: Vec<u8>,
}

impl Pass {
    pub fn encode(&self) -> String {
        format!(
            "{PREFIX}.{}.{}.{}.{}",
            self.label,
            self.period,
            crate::b64(&self.message),
            crate::b64(&self.signature)
        )
    }

    pub fn parse(code: &str) -> Option<Self> {
        let code = code.trim();
        if code.len() > 1024 {
            return None;
        }
        let mut parts = code.split('.');
        if parts.next()? != PREFIX {
            return None;
        }
        let label = parts.next()?.to_string();
        let period = parts.next()?.to_string();
        let message = crate::unb64(parts.next()?)?;
        let signature = crate::unb64(parts.next()?)?;
        (parts.next().is_none()
            && valid_label(&label)
            && period.len() == 7
            && message.len() == 32)
            .then_some(Self {
                label,
                period,
                message,
                signature,
            })
    }

    /// What the server records once the pass is used.
    pub fn spent_hash(&self) -> String {
        crate::sha256_hex(&self.message)
    }
}

fn master(keyset: &Keyset) -> Result<PassPublicKey> {
    let info = keyset
        .pass_key
        .as_ref()
        .ok_or_else(|| anyhow!("this server does not issue passes"))?;
    let der = crate::unb64(&info.public_key_der).context("pass key is not base64url")?;
    PassPublicKey::from_der(&der).map_err(|e| anyhow!("bad pass key: {e}"))
}

fn derived(keyset: &Keyset, label: &str, period: &str) -> Result<PassPublicKey> {
    master(keyset)?
        .derive_public_key_for_metadata(&metadata(label, period))
        .map_err(|e| anyhow!("pass key for {label} {period}: {e}"))
}

/// A pass message blinded on the device, waiting for the server's signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassBlank {
    #[serde(alias = "tier")]
    pub label: String,
    pub period: String,
    #[serde(with = "crate::voucher::b64bytes")]
    pub message: Vec<u8>,
    #[serde(with = "crate::voucher::b64bytes")]
    pub blinded: Vec<u8>,
    #[serde(with = "crate::voucher::b64bytes")]
    pub secret: Vec<u8>,
}

impl PassBlank {
    pub fn new(keyset: &Keyset, label: &str, period: &str) -> Result<Self> {
        let mut message = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut message);
        Self::build(keyset, label, period, message, &mut DefaultRng)
    }

    /// The `j`th pass blank of operation `op`, derived from the seed (see
    /// [`crate::Blank::seeded`]).
    pub fn seeded(
        keyset: &Keyset,
        label: &str,
        period: &str,
        seed: &crate::seed::Seed,
        op: &[u8],
        j: u32,
    ) -> Result<Self> {
        let j = j.to_be_bytes();
        let message = seed.derive(&[b"pass", op, &j]).to_vec();
        let mut rng = seed.rng(&[b"pass-blinding", op, &j]);
        Self::build(keyset, label, period, message, &mut rng)
    }

    fn build<R: blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized>(
        keyset: &Keyset,
        label: &str,
        period: &str,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self> {
        let pk = derived(keyset, label, period)?;
        let meta = metadata(label, period);
        let blinding = pk
            .blind(rng, &message, Some(&meta))
            .map_err(|e| anyhow!("blinding failed: {e}"))?;
        Ok(Self {
            label: label.to_string(),
            period: period.to_string(),
            message,
            blinded: blinding.blind_message.0,
            secret: blinding.secret.0,
        })
    }

    pub fn finish(&self, keyset: &Keyset, blind_signature: &[u8]) -> Result<Pass> {
        let pk = derived(keyset, &self.label, &self.period)?;
        let blinding = BlindingResult {
            blind_message: BlindMessage(self.blinded.clone()),
            secret: Secret(self.secret.clone()),
            msg_randomizer: None,
        };
        let meta = metadata(&self.label, &self.period);
        let sig = pk
            .finalize(
                &BlindSignature(blind_signature.to_vec()),
                &blinding,
                &self.message,
                Some(&meta),
            )
            .map_err(|e| anyhow!("the server's pass signature does not verify: {e}"))?;
        Ok(Pass {
            label: self.label.clone(),
            period: self.period.clone(),
            message: self.message.clone(),
            signature: sig.0,
        })
    }
}

/// Check a pass's signature for its label and month.
pub fn verify(keyset: &Keyset, pass: &Pass) -> bool {
    let Ok(pk) = derived(keyset, &pass.label, &pass.period) else {
        return false;
    };
    let meta = metadata(&pass.label, &pass.period);
    pk.verify(
        &blind_rsa_signatures::Signature(pass.signature.clone()),
        None,
        &pass.message,
        Some(&meta),
    )
    .is_ok()
}
