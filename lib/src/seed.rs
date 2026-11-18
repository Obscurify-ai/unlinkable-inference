//! Everything a wallet makes, derived from the account number or the account's
//! recovery words.
//!
//! An account is either a 16-digit number (about 53 bits) or 12 recovery words
//! from the BIP-39 English list (128 random bits and a 4-bit checksum). Words
//! are for anything kept on a server under keys from them (synced chats): no
//! one, not even someone holding the server and all its secrets, can guess
//! 128 bits, while 16 digits can be searched by anyone willing to pay.
//!
//! One slow hash of the number (or words) gives a master key. The device sends the
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
/// Words hash under their own salt, so the two kinds can never give the same keys.
const WORDS_SALT: &[u8] = b"obscurify-words-v1";

/// The BIP-39 English word list (2048 words; the first four letters of each are unique).
const WORD_LIST: &str = include_str!("bip39-english.txt");

/// The 2048 words, in order (for suggestions while typing).
pub fn word_list() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| WORD_LIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect())
}

/// What a person typed to sign in, cleaned up.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    /// 16 digits.
    Number(String),
    /// 12 recovery words, lowercase, one space apart.
    Words(String),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self { Credential::Number(_) => "Number(..)", Credential::Words(_) => "Words(..)" })
    }
}

/// 16 digits (spaces and dashes allowed) or 12 recovery words; `None` for
/// anything else, including words whose checksum doesn't hold (a typo).
pub fn normalize_credential(input: &str) -> Option<Credential> {
    if input.len() > 400 {
        return None;
    }
    if input.chars().any(|c| c.is_ascii_alphabetic()) {
        return normalize_words(input).map(Credential::Words);
    }
    normalize(input).map(Credential::Number)
}

/// 12 recovery words as they're kept: lowercase, one space apart. Accepts any
/// separators, numbering ("1. abandon") and words cut to their first four
/// letters or more; `None` unless all 12 are on the list and the checksum holds.
pub fn normalize_words(input: &str) -> Option<String> {
    if input.len() > 400 {
        return None;
    }
    let list = word_list();
    let mut indices = Vec::with_capacity(12);
    for token in input.split(|c: char| !c.is_ascii_alphabetic()).filter(|t| !t.is_empty()) {
        let token = token.to_ascii_lowercase();
        let i = match list.binary_search(&token.as_str()) {
            Ok(i) => i,
            Err(_) if token.len() >= 4 => {
                let mut hits = list.iter().enumerate().filter(|(_, w)| w.starts_with(token.as_str()));
                match (hits.next(), hits.next()) {
                    (Some((i, _)), None) => i,
                    _ => return None,
                }
            }
            Err(_) => return None,
        };
        indices.push(i);
    }
    if indices.len() != 12 {
        return None;
    }
    // 12 x 11 bits = 128 bits of entropy, then the first 4 bits of its SHA-256.
    let mut bits: u128 = 0;
    for &i in &indices[..11] {
        bits = (bits << 11) | i as u128;
    }
    let last = indices[11] as u128;
    let entropy = (bits << 7) | (last >> 4);
    let checksum = (last & 0x0f) as u8;
    let hash = blind_rsa_signatures::reexports::hmac_sha256::Hash::hash(&entropy.to_be_bytes());
    if hash[0] >> 4 != checksum {
        return None;
    }
    Some(indices.iter().map(|&i| list[i]).collect::<Vec<_>>().join(" "))
}

/// 12 new recovery words (128 random bits), made on the device so the server
/// never learns them.
pub fn new_recovery_words() -> String {
    words_from_entropy(rand::random::<[u8; 16]>())
}

/// The 12 words for 16 bytes of entropy (BIP-39).
pub fn words_from_entropy(entropy: [u8; 16]) -> String {
    let list = word_list();
    let hash = blind_rsa_signatures::reexports::hmac_sha256::Hash::hash(&entropy);
    let e = u128::from_be_bytes(entropy);
    let mut words = Vec::with_capacity(12);
    for k in 0..12 {
        // Bits 11k..11k+11 of entropy || checksum (132 bits).
        let start = 11 * k;
        let index = if start + 11 <= 128 {
            ((e >> (128 - start - 11)) & 0x7ff) as usize
        } else {
            // The last word: 7 bits of entropy and the 4 checksum bits.
            (((e & 0x7f) << 4) as usize) | (hash[0] >> 4) as usize
        };
        words.push(list[index]);
    }
    words.join(" ")
}

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

/// Derive the login key and the wallet seed from an account number or 12
/// recovery words. Slow on purpose (Argon2id, 64 MiB).
pub fn account_keys(number_or_words: &str) -> anyhow::Result<AccountKeys> {
    let (input, salt) = match normalize_credential(number_or_words) {
        Some(Credential::Number(digits)) => (digits, MASTER_SALT),
        Some(Credential::Words(words)) => (words, WORDS_SALT),
        None => anyhow::bail!("an account number has 16 digits, and recovery words are 12 words from the list"),
    };
    let params = argon2::Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut master = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(input.as_bytes(), salt, &mut master)
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
