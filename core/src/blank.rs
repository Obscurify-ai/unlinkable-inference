//! Blanks: voucher messages blinded on the device, waiting for a signature.
//!
//! The server signs the blinded message without learning the message. When the
//! signature comes back the device unblinds it into a voucher the server has
//! never seen, so spending it later cannot be tied to the signing.

use crate::keyset::Keyset;
use crate::protocol::BlindedVoucher;
use crate::voucher::{Family, Voucher, VOUCHER_MESSAGE_LEN};
use anyhow::{anyhow, Context, Result};
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, BlindMessage, DefaultRng, PublicKeySha384PSSDeterministic,
    Secret,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blank {
    pub family: Family,
    /// Cents, or millicents for dust
    pub denomination_cents: i64,
    #[serde(default)]
    pub dust: bool,
    pub key_id: String,
    #[serde(with = "crate::voucher::b64bytes")]
    pub message: Vec<u8>,
    #[serde(with = "crate::voucher::b64bytes")]
    pub blinded: Vec<u8>,
    /// The blinding factor. Never leaves the device.
    #[serde(with = "crate::voucher::b64bytes")]
    pub secret: Vec<u8>,
}

fn public_key(
    keyset: &Keyset,
    family: Family,
    value: i64,
    dust: bool,
) -> Result<(String, PublicKeySha384PSSDeterministic)> {
    let info = keyset.key_for(family, value, dust).ok_or_else(|| {
        anyhow!(
            "no {} key for {value}{}",
            family.as_str(),
            if dust { " millicents" } else { "¢" }
        )
    })?;
    let der = crate::unb64(&info.public_key_der).context("key is not base64url")?;
    let pk = PublicKeySha384PSSDeterministic::from_der(&der)
        .map_err(|e| anyhow!("bad voucher key: {e}"))?;
    Ok((info.key_id.clone(), pk))
}

impl Blank {
    /// A fresh random voucher message, blinded against the key for `cents`.
    pub fn new(keyset: &Keyset, family: Family, cents: i64) -> Result<Self> {
        Self::make(keyset, family, cents, false)
    }

    /// A dust blank, `millicents` below a cent.
    pub fn new_dust(keyset: &Keyset, family: Family, millicents: i64) -> Result<Self> {
        Self::make(keyset, family, millicents, true)
    }

    fn make(keyset: &Keyset, family: Family, value: i64, dust: bool) -> Result<Self> {
        let mut message = vec![0u8; VOUCHER_MESSAGE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut message);
        Self::build(keyset, family, value, dust, message, &mut DefaultRng)
    }

    /// The `j`th blank of operation `op`, derived from the seed: the same
    /// inputs always give the same message and blinding, so a device that
    /// lost its storage can make it again and unblind the server's stored
    /// answer. Each (op, j) must be used once only.
    pub fn seeded(
        keyset: &Keyset,
        family: Family,
        value: i64,
        dust: bool,
        seed: &crate::seed::Seed,
        op: &[u8],
        j: u32,
    ) -> Result<Self> {
        let j = j.to_be_bytes();
        let message = seed.derive(&[b"voucher", op, &j]).to_vec();
        let mut rng = seed.rng(&[b"blinding", op, &j]);
        Self::build(keyset, family, value, dust, message, &mut rng)
    }

    /// Seeded blanks for `values` (cents, or millicents when `dust`),
    /// numbered from `first`.
    pub fn seeded_many(
        keyset: &Keyset,
        family: Family,
        values: &[i64],
        dust: bool,
        seed: &crate::seed::Seed,
        op: &[u8],
        first: u32,
    ) -> Result<Vec<Self>> {
        values
            .iter()
            .enumerate()
            .map(|(i, &v)| Self::seeded(keyset, family, v, dust, seed, op, first + i as u32))
            .collect()
    }

    fn build<R: blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng + ?Sized>(
        keyset: &Keyset,
        family: Family,
        value: i64,
        dust: bool,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self> {
        let (key_id, pk) = public_key(keyset, family, value, dust)?;
        let blinding = pk
            .blind(rng, &message)
            .map_err(|e| anyhow!("blinding failed: {e}"))?;
        Ok(Self {
            family,
            denomination_cents: value,
            dust,
            key_id,
            message,
            blinded: blinding.blind_message.0,
            secret: blinding.secret.0,
        })
    }

    pub fn many(keyset: &Keyset, family: Family, values: &[i64]) -> Result<Vec<Self>> {
        values.iter().map(|&c| Self::new(keyset, family, c)).collect()
    }

    pub fn many_dust(keyset: &Keyset, family: Family, values: &[i64]) -> Result<Vec<Self>> {
        values
            .iter()
            .map(|&m| Self::new_dust(keyset, family, m))
            .collect()
    }

    /// Blanks for exactly `millicents`: whole cents the standard way, the rest
    /// as dust.
    pub fn for_amount(keyset: &Keyset, family: Family, millicents: i64) -> Result<Vec<Self>> {
        use crate::denominations::{split, split_dust, MILLICENTS_PER_CENT};
        let mut blanks = Self::many(keyset, family, &split(millicents / MILLICENTS_PER_CENT))?;
        blanks.extend(Self::many_dust(
            keyset,
            family,
            &split_dust(millicents % MILLICENTS_PER_CENT),
        )?);
        Ok(blanks)
    }

    /// What is sent to the server: the blinded message only.
    pub fn to_wire(&self) -> BlindedVoucher {
        BlindedVoucher {
            denomination_cents: self.denomination_cents,
            key_id: self.key_id.clone(),
            blinded_message: crate::b64(&self.blinded),
            dust: self.dust,
        }
    }

    /// Unblind the server's signature into a finished voucher, checking it.
    pub fn finish(&self, keyset: &Keyset, blind_signature: &[u8]) -> Result<Voucher> {
        let (_, pk) = public_key(keyset, self.family, self.denomination_cents, self.dust)?;
        let blinding = BlindingResult {
            blind_message: BlindMessage(self.blinded.clone()),
            secret: Secret(self.secret.clone()),
            msg_randomizer: None,
        };
        let signature = pk
            .finalize(&BlindSignature(blind_signature.to_vec()), &blinding, &self.message)
            .map_err(|e| anyhow!("the server's signature does not verify: {e}"))?;
        Ok(Voucher {
            denomination_cents: self.denomination_cents,
            key_id: self.key_id.clone(),
            message: self.message.clone(),
            signature: signature.0,
            dust: self.dust,
        })
    }
}

/// Check a finished voucher against a keyset (used by servers and by the
/// wallet when importing codes).
pub fn verify(keyset: &Keyset, voucher: &Voucher) -> Option<Family> {
    let (family, dust) = keyset.kind_of(&voucher.key_id)?;
    if dust != voucher.dust {
        return None;
    }
    let (key_id, pk) = public_key(keyset, family, voucher.denomination_cents, dust).ok()?;
    (key_id == voucher.key_id
        && voucher.message.len() == VOUCHER_MESSAGE_LEN
        && pk
            .verify(
                &blind_rsa_signatures::Signature(voucher.signature.clone()),
                None,
                &voucher.message,
            )
            .is_ok())
    .then_some(family)
}
