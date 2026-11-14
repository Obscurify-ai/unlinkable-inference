//! The `unlinkable` proxy: shared setup for the CLI and the local server.

pub mod serve;

use anyhow::{bail, Context as _, Result};
use std::path::PathBuf;
use unlinkable_core::keyset::{Keyset, Pins};
use unlinkable_core::net::{Client, Transport};
use unlinkable_core::Wallet;

/// Where to find the server and how to reach it.
#[derive(Debug, Clone)]
pub struct Options {
    /// Server origin, e.g. `https://obscurify.ai`
    pub server: String,
    pub wallet: Option<PathBuf>,
    /// Extra keyset fingerprints to accept
    pub pins: Vec<String>,
}

impl Options {
    pub fn host(&self) -> String {
        self.server
            .split("://")
            .nth(1)
            .unwrap_or(&self.server)
            .trim_end_matches('/')
            .to_string()
    }

    pub fn wallet_path(&self) -> PathBuf {
        if let Some(p) = &self.wallet {
            return p.clone();
        }
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."));
        let host = self.host().replace([':', '/'], "_");
        base.join("unlinkable").join(host).join("wallet.json")
    }

    pub fn transport(&self) -> Transport {
        Transport::new(&self.server)
    }
}

/// An exclusive hold on the wallet for as long as this lives, so two
/// processes never spend the same vouchers.
pub struct WalletLock(#[allow(dead_code)] std::fs::File);

pub fn lock_wallet(opts: &Options) -> Result<WalletLock> {
    let path = opts.wallet_path().with_extension("lock");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    if file.try_lock().is_err() {
        bail!(
            "another unlinkable process holds the wallet ({}). If the proxy is running, use its page at /_unlinkable or stop it first.",
            path.display()
        );
    }
    Ok(WalletLock(file))
}

/// Fetch the server's keyset and check it against the pins. With no pins at all for this server, pin what we see now and
/// refuse anything different later (trust on first use).
pub async fn trusted_keyset(opts: &Options, wallet: &mut Wallet) -> Result<Keyset> {
    let keyset = opts
        .transport()
        .fetch_keyset()
        .await
        .context("fetching the server's keys")?;
    keyset.check()?;
    let mut pins = Pins::builtin(&opts.host());
    pins.fingerprints.extend(opts.pins.iter().cloned());
    if let Some(p) = wallet.pinned() {
        pins.fingerprints.insert(p.to_string());
    }
    let fingerprint = keyset.fingerprint();
    if pins.fingerprints.is_empty() {
        eprintln!(
            "unlinkable: pinned keyset {fingerprint} for {} on first use",
            opts.host()
        );
        wallet.pin(Some(fingerprint));
        wallet.save()?;
        return Ok(keyset);
    }
    if !pins.accepts(&keyset) {
        bail!(
            "{} is serving keyset {fingerprint}, which is not one you pinned ({}). \
             That is what a server singling you out would look like. If the server \
             announced a key rotation in its public changelog, run `unlinkable keys --trust`.",
            opts.host(),
            pins.fingerprints.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(keyset)
}

pub async fn connect(opts: &Options, wallet: &mut Wallet) -> Result<Client> {
    let keyset = trusted_keyset(opts, wallet).await?;
    Ok(Client::new(opts.transport(), keyset))
}

/// The account's API key, from its login key (the number never leaves this
/// device). Obscurify's `POST /generate_token`.
pub async fn api_key_for(opts: &Options, login_key: &str) -> Result<String> {
    let resp = opts
        .transport()
        .send(unlinkable_core::net::Request::post_json(
            "/generate_token",
            &serde_json::json!({ "account_key": login_key }),
        ))
        .await?;
    let status = resp.status;
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await?).unwrap_or_default();
    match body["token"].as_str() {
        Some(t) if status == 200 => Ok(t.to_string()),
        _ => anyhow::bail!("signing in with the account number failed ({status}): {}", body["error"]),
    }
}

pub fn dollars(cents: i64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}
