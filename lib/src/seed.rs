//! Everything a wallet makes, derived from the account code or, for accounts
//! made before codes, the account number.
//!
//! An account code is 20 characters (Crockford base 32: digits and letters
//! without I, L, O and U), `RJQDX-WM6PR-2QV5M-8BX5G`: 96 random bits and a 4-bit
//! typo check. No one, not even someone holding the server and all its
//! secrets, can guess 96 bits through the slow hash below; 16 digits (about 53
//! bits) can be searched by anyone willing to pay, so anything kept on a server
//! under keys from them (synced chats) needs a code.
//!
//! One slow hash of the code (or number) gives a master key. The device sends the
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
/// Codes hash under their own salt, so the two kinds can never give the same keys.
const CODE_SALT: &[u8] = b"obscurify-code-v1";

/// Crockford base 32: no I, L, O or U (read as 1, 1, 0; U is left out).
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// What a person typed to sign in, cleaned up.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    /// 16 digits.
    Number(String),
    /// An account code: 20 characters, upper case, no dashes.
    Code(String),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self { Credential::Number(_) => "Number(..)", Credential::Code(_) => "Code(..)" })
    }
}

/// An account code (any case, dashes and spaces anywhere, O for 0, I or L
/// for 1) or 16 digits; `None` for anything else, including a code whose
/// typo check fails.
pub fn normalize_credential(input: &str) -> Option<Credential> {
    if input.len() > 200 {
        return None;
    }
    let bare: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '.').collect();
    if bare.len() == 16 && bare.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Credential::Number(bare));
    }
    normalize_code(input).map(Credential::Code)
}

/// The value of a typed character in the code alphabet.
fn code_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    CODE_ALPHABET.iter().position(|&a| a as char == c).map(|i| i as u8)
}

/// An account code as it's kept: 20 characters, upper case, no dashes;
/// `None` unless it has 20 and its typo check holds.
pub fn normalize_code(input: &str) -> Option<String> {
    if input.len() > 200 {
        return None;
    }
    let mut values = Vec::with_capacity(20);
    for c in input.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '.') {
        values.push(code_value(c)?);
    }
    if values.len() != 20 {
        return None;
    }
    let bits = values.iter().fold(0u128, |acc, &v| (acc << 5) | v as u128); // 100 bits
    let random = bits >> 4; // 96
    let check = (bits & 0x0f) as u8;
    let bytes = random.to_be_bytes();
    if code_check(&bytes[4..]) != check {
        return None;
    }
    Some(values.iter().map(|&v| CODE_ALPHABET[v as usize] as char).collect())
}

/// The typo check: the first 4 bits of SHA-256 of the 12 random bytes.
fn code_check(random: &[u8]) -> u8 {
    blind_rsa_signatures::reexports::hmac_sha256::Hash::hash(random)[0] >> 4
}

/// The code for 12 random bytes.
pub fn code_from_bytes(random: [u8; 12]) -> String {
    let mut wide = [0u8; 16];
    wide[4..].copy_from_slice(&random);
    let bits = (u128::from_be_bytes(wide) << 4) | code_check(&random) as u128;
    (0..20).rev().map(|k| CODE_ALPHABET[((bits >> (5 * k)) & 0x1f) as usize] as char).collect()
}

/// A code as people read it: four groups of five, `RJQDX-WM6PR-2QV5M-8BX5G`.
pub fn format_code(code: &str) -> String {
    code.as_bytes().chunks(5).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// A new account code (96 random bits), made on the device so the server
/// never learns it. Grouped for reading.
pub fn new_account_code() -> String {
    format_code(&code_from_bytes(rand::random::<[u8; 12]>()))
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

/// Derive the login key and the wallet seed from an account code or a 16-digit
/// account number. Slow on purpose (Argon2id, 64 MiB).
pub fn account_keys(code_or_number: &str) -> anyhow::Result<AccountKeys> {
    let (input, salt) = match normalize_credential(code_or_number) {
        Some(Credential::Number(digits)) => (digits, MASTER_SALT),
        Some(Credential::Code(code)) => (code, CODE_SALT),
        None => anyhow::bail!("an account code has 20 characters, and an account number 16 digits"),
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
