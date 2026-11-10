//! Voucher signing keys held by this process, one RSA key per value and
//! family, optionally kept in a directory. Production servers can bring
//! their own [`crate::Signer`] instead.

use crate::Signer;
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSDeterministic, SecretKeySha384PSSDeterministic};
use std::collections::HashMap;
use std::path::Path;
use unlinkable_core::{keyset::VoucherKeyInfo, Family, DENOMINATIONS};

pub struct KeyStore {
    keys: HashMap<(Family, i64), (VoucherKeyInfo, KeyPairSha384PSSDeterministic)>,
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
        Ok(Self { keys })
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
}
