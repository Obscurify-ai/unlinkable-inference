//! Unlinkable inference: anonymous prepaid API sessions paid for with
//! blind-signed e-cash (David Chaum's scheme).
//!
//! A wallet of blind-signed vouchers pays for a session, and the session
//! secret, not an account key, authorises requests. The client is the
//! default; `server` (feature) is the other end. See `SPEC.md` for the
//! wire format and `THREAT_MODEL.md` for what this protects (not the IP:
//! that is the network's job, Tor or a VPN).
//!
//! Everything that keeps requests from being tied to an account happens on the device: the
//! server only ever sees blinded messages when it signs, and unblinded vouchers
//! it has never seen when they are spent.

pub mod blank;
pub mod denominations;
pub mod keyset;
pub mod pass;
pub mod protocol;
pub mod seed;
pub mod voucher;
pub mod wallet;

#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod manager;
#[cfg(feature = "server")]
pub mod server;

pub use blank::Blank;
pub use denominations::{split, DENOMINATIONS, SMALL_WITHDRAW_SIZES, WITHDRAW_SIZES};
pub use keyset::{Keyset, Pins};
pub use voucher::{Family, Voucher};
pub use wallet::{Spend, Wallet};

/// Session secrets look like API keys so OpenAI and Anthropic SDKs accept them.
pub const SESSION_SECRET_PREFIX: &str = "sk-unl1_";

/// Seconds since 1970 (in a browser, from `Date.now()`: `SystemTime` panics there).
pub fn unix_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

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
