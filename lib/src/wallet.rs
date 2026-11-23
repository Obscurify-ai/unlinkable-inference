//! The wallet: vouchers held on this device, one file per server.
//!
//! Vouchers are bearer credit. Whoever has the file can spend them, and if the
//! file is lost they are gone; `export` exists for backups. The file is
//! written atomically with owner-only permissions. A wallet with no file
//! ([`Wallet::in_memory`]) is for clients that keep the JSON themselves
//! (a browser's storage).

use crate::blank::Blank;
use crate::pass::{Pass, PassBlank};
use crate::voucher::{Family, Voucher};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Held {
    pub family: Family,
    pub voucher: Voucher,
}

/// Blanks sent to the server whose signatures have not come back yet. Kept
/// on disk so a crash or lost response can be retried with the same blanks
/// (the server answers a repeat with the same signatures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub id: String,
    /// "close", "exchange" or "withdraw"
    pub kind: String,
    pub blanks: Vec<Blank>,
    /// For close: the session secret; for exchange: the vouchers spent.
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub vouchers: Vec<String>,
    #[serde(default)]
    pub amount_cents: i64,
    /// For "passes": the blinded passes awaiting signatures
    #[serde(default)]
    pub pass_blanks: Vec<PassBlank>,
}

/// An open session, remembered so it can be closed after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenSession {
    pub secret: String,
    pub family: Family,
    pub opened_at: u64,
    /// What was put in (opening plus top-ups), millicents
    #[serde(default)]
    pub funded_millicents: i64,
    /// Last request, Unix seconds (0: never noted)
    #[serde(default)]
    pub used_at: u64,
    /// What its replies said they cost so far, millicents. Only for showing a balance while it
    /// is open: closing it says exactly.
    #[serde(default)]
    pub noted_millicents: i64,
}

impl OpenSession {
    /// What it still holds, as far as this device knows (asking the server would tie the
    /// sessions asked about to each other).
    pub fn left_millicents(&self) -> i64 {
        (self.funded_millicents - self.noted_millicents).max(0)
    }
}

/// What one closed session cost: what was put in minus the change. Kept
/// only on this device; the server cannot tie it to the account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spend {
    /// When the session was last used, Unix seconds
    pub at: u64,
    pub millicents: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WalletFile {
    #[serde(default)]
    vouchers: Vec<Held>,
    #[serde(default)]
    pending: Vec<Pending>,
    #[serde(default)]
    sessions: Vec<OpenSession>,
    #[serde(default)]
    passes: Vec<Pass>,
    /// Keyset fingerprint pinned on first use (servers without built-in pins)
    #[serde(default)]
    pinned: Option<String>,
    /// Where each voucher came from (hash of its message → `w:<nonce>` for a
    /// withdrawal, `s:<secret hash>` for a session's change). Once nothing
    /// from a source is left, the server can forget it (seeded wallets).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    sources: std::collections::BTreeMap<String, String>,
    /// What closed sessions cost, oldest first (see [`Spend`])
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    spending: Vec<Spend>,
}

pub struct Wallet {
    path: PathBuf,
    file: WalletFile,
}

impl Wallet {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        } else {
            WalletFile::default()
        };
        Ok(Self { path, file })
    }

    /// A wallet with no file: `save` does nothing; keep [`Wallet::to_json`].
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            file: WalletFile::default(),
        }
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Ok(Self {
            path: PathBuf::new(),
            file: serde_json::from_str(text)?,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.file).expect("wallet serialises")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
            restrict(dir, 0o700);
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.file)?)?;
        restrict(&tmp, 0o600);
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Whole cents held (dust below a cent is not counted).
    pub fn balance_cents(&self, family: Family) -> i64 {
        self.balance_millicents(family) / crate::denominations::MILLICENTS_PER_CENT
    }

    pub fn balance_millicents(&self, family: Family) -> i64 {
        self.file
            .vouchers
            .iter()
            .filter(|h| h.family == family)
            .map(|h| h.voucher.value_millicents())
            .sum()
    }

    pub fn vouchers(&self) -> &[Held] {
        &self.file.vouchers
    }

    pub fn add(&mut self, family: Family, vouchers: impl IntoIterator<Item = Voucher>) {
        for voucher in vouchers {
            if !self.file.vouchers.iter().any(|h| h.voucher == voucher) {
                self.file.vouchers.push(Held { family, voucher });
            }
        }
    }

    /// Add vouchers from `source` (see `WalletFile::sources`). With no
    /// vouchers the source is finished straight away.
    pub fn add_from(&mut self, family: Family, vouchers: Vec<Voucher>, source: &str) {
        if vouchers.is_empty() {
            self.file.sources.insert(format!("empty:{source}"), source.to_string());
        }
        for v in &vouchers {
            self.file
                .sources
                .insert(crate::sha256_hex(&v.message), source.to_string());
        }
        self.add(family, vouchers);
    }

    /// Sources none of whose vouchers are held any more.
    pub fn finished_sources(&self) -> Vec<String> {
        let held: std::collections::HashSet<String> = self
            .file
            .vouchers
            .iter()
            .map(|h| crate::sha256_hex(&h.voucher.message))
            .chain(self.file.passes.iter().map(|p| crate::sha256_hex(&p.message)))
            .collect();
        let alive: std::collections::HashSet<&String> = self
            .file
            .sources
            .iter()
            .filter(|(h, _)| held.contains(*h))
            .map(|(_, s)| s)
            .collect();
        let mut done: Vec<String> = self
            .file
            .sources
            .values()
            .filter(|s| !alive.contains(s))
            .cloned()
            .collect();
        done.sort();
        done.dedup();
        done
    }

    /// Remember where passes came from (see [`Wallet::add_from`]).
    pub fn note_pass_source(&mut self, passes: &[Pass], source: &str) {
        if passes.is_empty() {
            self.file.sources.insert(format!("empty:{source}"), source.to_string());
        }
        for p in passes {
            self.file
                .sources
                .insert(crate::sha256_hex(&p.message), source.to_string());
        }
    }

    pub fn forget_sources(&mut self, sources: &[String]) {
        self.file.sources.retain(|_, s| !sources.contains(s));
    }

    /// Take vouchers of one family worth at least `cents` (or everything
    /// there is, if less), largest first, plus all the dust, so leftovers
    /// below a cent are spent instead of piling up. They leave the wallet; put
    /// them back with [`Wallet::add`] if they are not spent.
    pub fn take(&mut self, family: Family, cents: i64) -> Vec<Voucher> {
        let dust: Vec<usize> = (0..self.file.vouchers.len())
            .filter(|&i| self.file.vouchers[i].family == family && self.file.vouchers[i].voucher.dust)
            .collect();
        let mut mine: Vec<usize> = (0..self.file.vouchers.len())
            .filter(|&i| self.file.vouchers[i].family == family && !self.file.vouchers[i].voucher.dust)
            .collect();
        mine.sort_by_key(|&i| std::cmp::Reverse(self.file.vouchers[i].voucher.denomination_cents));
        let mut chosen = dust;
        // Dust always goes along, but counts for nothing towards a session's minimum on the
        // server, so whole cents alone cover what was asked.
        let mut left = cents;
        // Largest that fit first, then the smallest that covers what is left.
        for &i in &mine {
            let v = self.file.vouchers[i].voucher.denomination_cents;
            if left > 0 && v <= left {
                chosen.push(i);
                left -= v;
            }
        }
        if left > 0 {
            if let Some(&i) = mine
                .iter()
                .rev()
                .find(|&&i| !chosen.contains(&i) && self.file.vouchers[i].voucher.denomination_cents >= left)
            {
                chosen.push(i);
                left = 0;
            }
        }
        if left > 0 {
            for &i in &mine {
                if !chosen.contains(&i) {
                    chosen.push(i);
                }
            }
        }
        chosen.sort_unstable_by(|a, b| b.cmp(a));
        chosen
            .into_iter()
            .map(|i| self.file.vouchers.remove(i).voucher)
            .collect()
    }

    /// Remove specific vouchers (already spent elsewhere).
    pub fn forget(&mut self, codes: &[String]) {
        self.file
            .vouchers
            .retain(|h| !codes.contains(&h.voucher.encode()));
    }

    pub fn add_passes(&mut self, passes: impl IntoIterator<Item = Pass>) {
        for pass in passes {
            if !self.file.passes.contains(&pass) {
                self.file.passes.push(pass);
            }
        }
    }

    /// Unused passes for `period`; older ones are dropped (they no longer work).
    pub fn passes(&mut self, period: &str) -> Vec<Pass> {
        self.file.passes.retain(|p| p.period.as_str() >= period);
        self.file
            .passes
            .iter()
            .filter(|p| p.period == period)
            .cloned()
            .collect()
    }

    /// How many unused passes with `label` there are for `period`.
    pub fn passes_of(&self, period: &str, label: &str) -> usize {
        self.file.passes.iter().filter(|p| p.period == period && p.label == label).count()
    }

    /// Take one pass with `label` for `period`.
    pub fn take_pass(&mut self, period: &str, label: &str) -> Option<Pass> {
        let i = self.file.passes.iter().position(|p| p.period == period && p.label == label)?;
        Some(self.file.passes.remove(i))
    }

    pub fn pending(&self) -> &[Pending] {
        &self.file.pending
    }

    pub fn push_pending(&mut self, pending: Pending) {
        self.file.pending.push(pending);
    }

    pub fn finish_pending(&mut self, id: &str) {
        self.file.pending.retain(|p| p.id != id);
    }

    pub fn sessions(&self) -> &[OpenSession] {
        &self.file.sessions
    }

    pub fn remember_session(&mut self, session: OpenSession) {
        self.file.sessions.push(session);
    }

    pub fn forget_session(&mut self, secret: &str) {
        self.file.sessions.retain(|s| s.secret != secret);
    }

    /// More money went into an open session.
    pub fn funded_session(&mut self, secret: &str, millicents: i64) {
        if let Some(s) = self.file.sessions.iter_mut().find(|s| s.secret == secret) {
            s.funded_millicents += millicents;
        }
    }

    /// A request went out on this session at `at` (Unix seconds).
    pub fn used_session(&mut self, secret: &str, at: u64) {
        if let Some(s) = self.file.sessions.iter_mut().find(|s| s.secret == secret) {
            s.used_at = s.used_at.max(at);
        }
    }

    /// A reply on this session said it cost this much.
    pub fn note_cost(&mut self, secret: &str, millicents: i64) {
        if let Some(s) = self.file.sessions.iter_mut().find(|s| s.secret == secret) {
            s.noted_millicents += millicents.max(0);
        }
    }

    /// The session closed and `change_millicents` came back: note what it
    /// cost (when its funding is known) and forget it.
    pub fn closed_session(&mut self, secret: &str, change_millicents: i64) {
        if let Some(s) = self.file.sessions.iter().find(|s| s.secret == secret) {
            if s.funded_millicents > 0 {
                let spent = s.funded_millicents - change_millicents;
                if spent > 0 {
                    self.file.spending.push(Spend { at: s.used_at.max(s.opened_at), millicents: spent });
                }
                // About thirteen months is plenty for a history.
                let cutoff = crate::unix_now().saturating_sub(400 * 86_400);
                self.file.spending.retain(|e| e.at >= cutoff);
            }
        }
        self.forget_session(secret);
    }

    /// What closed sessions cost, oldest first.
    pub fn spending(&self) -> &[Spend] {
        &self.file.spending
    }

    pub fn pinned(&self) -> Option<&str> {
        self.file.pinned.as_deref()
    }

    pub fn pin(&mut self, fingerprint: Option<String>) {
        self.file.pinned = fingerprint;
    }

    /// Every voucher as text, for a backup.
    pub fn export(&self) -> Vec<String> {
        self.file.vouchers.iter().map(|h| h.voucher.encode()).collect()
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) {}
