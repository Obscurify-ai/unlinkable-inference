//! Everything a wallet makes, derived from the account number.
//!
//! One slow hash of the number gives a master key. The device sends the
//! server `HMAC(master, "login")` to sign in and keeps `HMAC(master,
//! "wallet")`, the seed, to itself. The server never sees the number, so it
//! cannot compute the seed: it would have to guess the number through the
//! slow hash.
//!
//! Session secrets, voucher messages and blinding factors all come from the
//! seed, so a device that lost its storage (Tor Browser closing, a new phone)
//! rebuilds them from the number and gets back whatever was left: see
//! `Client::restore`.

use blind_rsa_signatures::reexports::hmac_sha256::HMAC;
use blind_rsa_signatures::reexports::rsa::rand_core::{TryCryptoRng, TryRng};

/// Argon2id cost: about a second in a browser, so guessing all 10^16 numbers
/// is out of reach.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_PASSES: u32 = 8;
const MASTER_SALT: &[u8] = b"obscurify-account-v1";

/// The two things the account number gives a device.
#[derive(Clone)]
pub struct AccountKeys {
    /// Sent to the server to sign in (hex). Reveals nothing about `seed`.
    pub login_key: String,
    pub seed: Seed,
}

impl std::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeys(..)")
    }
}

/// Only the digits of an account number; `None` unless there are 16.
pub fn normalize(number: &str) -> Option<String> {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    (digits.len() == 16).then_some(digits)
}

/// Derive the login key and the wallet seed from an account number. Slow on
/// purpose (Argon2id, 64 MiB).
pub fn account_keys(number: &str) -> anyhow::Result<AccountKeys> {
    let digits = normalize(number).ok_or_else(|| anyhow::anyhow!("an account number has 16 digits"))?;
    let params = argon2::Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut master = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(digits.as_bytes(), MASTER_SALT, &mut master)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(AccountKeys {
        login_key: hex::encode(HMAC::mac(b"login", master)),
        seed: Seed(HMAC::mac(b"wallet", master)),
    })
}

/// A new random 16-digit account number, made on the device so the server
/// never learns it.
pub fn new_account_number() -> String {
    let mut digits = String::new();
    while digits.len() < 16 {
        let b: u8 = rand::random();
        // 250..=255 are skipped so every digit is equally likely.
        if b < 250 {
            digits.push(char::from(b'0' + b % 10));
        }
    }
    digits
}

#[derive(Clone, PartialEq, Eq)]
pub struct Seed(pub [u8; 32]);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// Session secrets per minute. A device picks one it isn't using; two devices
/// on one account picking the same one is caught by the server (409
/// `secret_taken`) and the second picks again. Recovery tries each: cheap,
/// it's an HMAC apiece.
pub const SESSIONS_PER_MINUTE: u32 = 64;

impl Seed {
    /// 32 bytes for `parts` (length-prefixed, so parts cannot run together).
    pub fn derive(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut msg = Vec::new();
        for p in parts {
            msg.extend_from_slice(&(p.len() as u32).to_be_bytes());
            msg.extend_from_slice(p);
        }
        HMAC::mac(msg, self.0)
    }

    /// A deterministic random stream for `parts` (blinding factors).
    pub fn rng(&self, parts: &[&[u8]]) -> SeedRng {
        SeedRng {
            key: self.derive(parts),
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }

    /// The secret for the `k`th session opened in Unix minute `minute`.
    pub fn session_secret(&self, minute: u64, k: u32) -> String {
        let bytes = self.derive(&[b"session", &minute.to_be_bytes(), &k.to_be_bytes()]);
        format!("{}{}", crate::SESSION_SECRET_PREFIX, crate::b64(bytes))
    }
}

/// HMAC-SHA256 in counter mode: the same seed and label always give the same
/// bytes, which is the point.
pub struct SeedRng {
    key: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    used: usize,
}

impl TryRng for SeedRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest {
            if self.used == 32 {
                self.buf = HMAC::mac(self.counter.to_be_bytes(), self.key);
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.buf[self.used];
            self.used += 1;
        }
        Ok(())
    }
}

impl TryCryptoRng for SeedRng {}
