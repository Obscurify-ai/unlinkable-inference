//! Finished vouchers: `obv1.<cents>.<key_id>.<message>.<signature>`.

use serde::{Deserialize, Serialize};

pub const VOUCHER_MESSAGE_LEN: usize = 32;
const PREFIX: &str = "obv1";
/// How a voucher starts when it is sent: nothing the server stores may hold this.
pub(crate) const SENT_PREFIX: &str = "obv1.";
/// Dust vouchers: values in millicents, below a cent.
const DUST_PREFIX: &str = "obd1";
pub(crate) const SENT_DUST_PREFIX: &str = "obd1.";

/// Which key family signed a voucher. Paid vouchers come from money; promo
/// vouchers from promotional credit. They never mix: change comes back in the
/// family that funded the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Paid,
    Promo,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Paid => "paid",
            Family::Promo => "promo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Voucher {
    pub denomination_cents: i64,
    pub key_id: String,
    #[serde(with = "crate::voucher::b64bytes")]
    pub message: Vec<u8>,
    #[serde(with = "crate::voucher::b64bytes")]
    pub signature: Vec<u8>,
    /// A dust voucher: `denomination_cents` is then in millicents.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dust: bool,
}

impl Voucher {
    /// The value in millicents (1/1000 of a cent).
    pub fn value_millicents(&self) -> i64 {
        if self.dust {
            self.denomination_cents
        } else {
            self.denomination_cents * crate::denominations::MILLICENTS_PER_CENT
        }
    }

    /// The text form users copy and servers accept.
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            if self.dust { DUST_PREFIX } else { PREFIX },
            self.denomination_cents,
            self.key_id,
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
        let dust = match parts.next()? {
            PREFIX => false,
            DUST_PREFIX => true,
            _ => return None,
        };
        let denomination_cents: i64 = parts.next()?.parse().ok()?;
        let key_id = parts.next()?.to_string();
        let message = crate::unb64(parts.next()?)?;
        let signature = crate::unb64(parts.next()?)?;
        if parts.next().is_some() || key_id.len() != 16 || message.len() != VOUCHER_MESSAGE_LEN {
            return None;
        }
        Some(Self {
            denomination_cents,
            key_id,
            message,
            signature,
            dust,
        })
    }

    /// What the server stores once the voucher is spent: the hash of the
    /// message, never the message itself.
    pub fn spent_hash(&self) -> String {
        crate::sha256_hex(&self.message)
    }
}

pub(crate) mod b64bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        crate::unb64(&text).ok_or_else(|| serde::de::Error::custom("invalid base64url"))
    }
}
