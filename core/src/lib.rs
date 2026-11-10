//! Client side of unlinkable sessions.
//!
//! A wallet of blind-signed vouchers pays for a session; the session secret,
//! not an account key, authorises requests; and requests travel through an
//! Oblivious HTTP relay so the server never sees the client's IP. See
//! `SPEC.md` for the wire format and `THREAT_MODEL.md` for what this protects.
//!
//! Everything that makes requests unlinkable happens here, on the device: the
//! server only ever sees blinded messages when it signs, and unblinded vouchers
//! it has never seen when they are spent.

pub mod blank;
pub mod denominations;
pub mod keyset;
pub mod pipe;
pub mod protocol;
pub mod voucher;
pub mod wallet;

#[cfg(feature = "net")]
pub mod net;

pub use blank::Blank;
pub use denominations::{split, DENOMINATIONS, WITHDRAW_SIZES};
pub use keyset::{Keyset, Pins};
pub use voucher::{Family, Voucher};
pub use wallet::Wallet;

/// Session secrets look like API keys so OpenAI and Anthropic SDKs accept them.
pub const SESSION_SECRET_PREFIX: &str = "sk-unl1_";

/// SHA-256, hex.
pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data.as_ref()))
}

/// base64url without padding, the encoding used everywhere on the wire.
pub fn b64(data: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
}

/// A new session secret: 32 random bytes. The client picks it and sends only
/// its hash when opening, so a retried open can never hand out a second secret.
pub fn new_session_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    format!("{SESSION_SECRET_PREFIX}{}", b64(bytes))
}
