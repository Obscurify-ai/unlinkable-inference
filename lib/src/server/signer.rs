//! Voucher signing keys held by this process, one RSA key per value and
//! family, optionally kept in a directory. Production servers can bring
//! their own [`crate::Signer`] instead.

use super::Signer;
use blind_rsa_signatures::pbrsa::{
    PartiallyBlindKeyPairSha384PSSDeterministic as PassKeyPair,
    PartiallyBlindSecretKeySha384PSSDeterministic as PassSecretKey,
};
use std::sync::Mutex;
use crate::keyset::PassKeyInfo;
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSDeterministic, SecretKeySha384PSSDeterministic};
use std::collections::HashMap;
use std::path::Path;
use crate::{keyset::VoucherKeyInfo, Family, DENOMINATIONS};

pub struct KeyStore {
    keys: HashMap<(Family, i64), (VoucherKeyInfo, KeyPairSha384PSSDeterministic)>,
    pass: Option<PassKey>,
    dust: Option<Box<KeyStore>>,
}

/// The pass master key (partially blind RSA, safe primes) and the per-month,
/// per-tier keys derived from it.
pub struct PassKey {
    master: PassKeyPair,
    info: PassKeyInfo,
    derived: Mutex<HashMap<Vec<u8>, PassSecretKey>>,
}

impl PassKey {
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let sk = PassSecretKey::from_pem(pem).map_err(|e| anyhow::anyhow!("pass key: {e}"))?;
        let pk = sk.public_key().map_err(|e| anyhow::anyhow!("pass key: {e}"))?;
        let der = pk.to_der().map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self {
            master: PassKeyPair { pk, sk },
            info: PassKeyInfo::new(&der),
            derived: Mutex::new(HashMap::new()),
        })
    }

    /// Generate a new master key (safe primes: several seconds).
    pub fn generate() -> anyhow::Result<String> {
        let kp = PassKeyPair::generate(&mut DefaultRng, 2048)
            .map_err(|e| anyhow::anyhow!("pass key generation failed: {e}"))?;
        kp.sk.to_pem().map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Load from `path`, creating it on first start.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            tracing::warn!(path = %path.display(), "Creating a pass master key (takes a few seconds); back it up");
            let pem = Self::generate()?;
            std::fs::write(path, &pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Self::from_pem(&std::fs::read_to_string(path)?)
    }

    pub fn info(&self) -> PassKeyInfo {
        self.info.clone()
    }

    pub fn sign(&self, label: &str, period: &str, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(blinded.len() == 256, "blinded pass has the wrong length");
        let meta = crate::pass::metadata(label, period);
        let mut cache = self.derived.lock().unwrap();
        if !cache.contains_key(&meta) {
            let sk = self
                .master
                .derive_secret_key_for_metadata(&meta)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            cache.insert(meta.clone(), sk);
        }
        Ok(cache[&meta]
            .blind_sign(blinded)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .0)
    }
}

fn generate() -> anyhow::Result<KeyPairSha384PSSDeterministic> {
    KeyPairSha384PSSDeterministic::generate(&mut DefaultRng, 2048)
        .map_err(|e| anyhow::anyhow!("RSA key generation failed: {e}"))
}

impl KeyStore {
    /// Keys for `values` in both families, made in parallel. With `dir`, keys
    /// are read from `<family>_<cents>.pem` there and missing ones written.
    pub fn new(values: &[i64], dir: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(dir) = dir {
            std::fs::create_dir_all(dir)?;
        }
        let wanted: Vec<(Family, i64)> = [Family::Paid, Family::Promo]
            .into_iter()
            .flat_map(|f| values.iter().map(move |&c| (f, c)))
            .collect();
        let made: Vec<anyhow::Result<((Family, i64), KeyPairSha384PSSDeterministic)>> =
            std::thread::scope(|scope| {
                let handles: Vec<_> = wanted
                    .iter()
                    .map(|&(family, cents)| {
                        scope.spawn(move || {
                            let path = dir.map(|d| d.join(format!("{}_{cents}.pem", family.as_str())));
                            let pair = match &path {
                                Some(p) if p.exists() => {
                                    let sk = SecretKeySha384PSSDeterministic::from_pem(&std::fs::read_to_string(p)?)
                                        .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
                                    let pk = sk.public_key().map_err(|e| anyhow::anyhow!("{e}"))?;
                                    KeyPairSha384PSSDeterministic { pk, sk }
                                }
                                _ => {
                                    let pair = generate()?;
                                    if let Some(p) = &path {
                                        std::fs::write(p, pair.sk.to_pem().map_err(|e| anyhow::anyhow!("{e}"))?)?;
                                    }
                                    pair
                                }
                            };
                            Ok(((family, cents), pair))
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().expect("keygen thread")).collect()
            });
        let mut keys = HashMap::new();
        for item in made {
            let ((family, cents), pair) = item?;
            let der = pair.pk.to_der().map_err(|e| anyhow::anyhow!("{e}"))?;
            keys.insert((family, cents), (VoucherKeyInfo::new(cents, &der), pair));
        }
        Ok(Self {
            keys,
            pass: None,
            dust: None,
        })
    }

    /// Also give change below a cent, with these keys (values in millicents,
    /// see `DUST_MILLICENTS`).
    pub fn with_dust(mut self, dust: KeyStore) -> Self {
        self.dust = Some(Box::new(dust));
        self
    }

    /// Also issue passes, signed with this master key.
    pub fn with_pass_key(mut self, pass: PassKey) -> Self {
        self.pass = Some(pass);
        self
    }

    /// Every value from 1¢ to $5,000.
    pub fn all(dir: Option<&Path>) -> anyhow::Result<Self> {
        Self::new(&DENOMINATIONS, dir)
    }
}

impl Signer for KeyStore {
    fn public_keys(&self, family: Family) -> Vec<VoucherKeyInfo> {
        let mut keys: Vec<VoucherKeyInfo> = self
            .keys
            .iter()
            .filter(|((f, _), _)| *f == family)
            .map(|(_, (info, _))| info.clone())
            .collect();
        keys.sort_by_key(|k| k.denomination_cents);
        keys
    }

    fn sign_blinded(&self, family: Family, cents: i64, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (_, pair) = self
            .keys
            .get(&(family, cents))
            .ok_or_else(|| anyhow::anyhow!("no key for {cents}¢"))?;
        anyhow::ensure!(blinded.len() == 256, "blinded message has the wrong length");
        Ok(pair
            .sk
            .blind_sign(blinded)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .0)
    }

    fn dust_keys(&self, family: Family) -> Vec<VoucherKeyInfo> {
        self.dust
            .as_ref()
            .map(|d| d.public_keys(family))
            .unwrap_or_default()
    }

    fn sign_dust(&self, family: Family, millicents: i64, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.dust
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no dust keys"))?
            .sign_blinded(family, millicents, blinded)
    }

    fn pass_key(&self) -> Option<PassKeyInfo> {
        self.pass.as_ref().map(PassKey::info)
    }

    fn sign_pass(&self, tier: &str, period: &str, blinded: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pass
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no pass key"))?
            .sign(tier, period, blinded)
    }
}
