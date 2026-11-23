//! What a chat app does with a wallet, so every app does it the same way: one
//! session per conversation, opened on its first request and closed for its
//! change once it has been quiet a while; the wallet topped up from the
//! account at quiet moments; and everything a lost device left behind
//! brought back at start.
//!
//! The app keeps the account number's seed and `Manager::state()` (save it
//! after every call; a crash between saves loses nothing, `start` restores
//! it from the seed) and sends `session(chat)` as `Authorization: Bearer`.
//! On a 402 it calls `ran_out` and retries (with [`REST_HEADER`](crate::protocol::REST_HEADER) when
//! that failed: the server then serves what the session's money still buys); on a 401, `expired` and asks for a
//! new session; on a 403 that names a pass (the `x-pass-required` header),
//! `needs_pass` with that label, then sends the request again: when that said
//! no (none to show), once only, in case the server serves it another way.

use crate::net::{Client, Session, Transport};
use crate::seed::Seed;
use crate::{unix_now, Family, Wallet};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Policy {
    /// What a session starts with: little, so a small balance spreads over many conversations
    /// (a session that runs out is topped up, more each time).
    pub funding_cents: i64,
    /// Top the wallet up when it holds less than this...
    pub keep_cents: i64,
    /// ...by this much: one of `WITHDRAW_SIZES` (fixed, so withdrawals look alike). An account
    /// holding less gives what it has, down to `min_cents`.
    pub refill_cents: i64,
    /// The least to take from the account: less stays there.
    pub min_cents: i64,
    /// After the account refused a top-up, wait this long before asking again.
    pub refused_backoff_secs: u64,
    /// The wallet is shared by every device with the account's code: when low, look for what the
    /// others withdrew or got back as change (at most this often) before taking more from the account.
    pub share_every_secs: u64,
    /// Keep this many of this month's passes of each label the account gets, asking for
    /// `pass_batch` at a time.
    pub keep_passes: usize,
    pub pass_batch: i64,
    /// Ask the account which labels it gets at most this often (a change shows within this).
    pub labels_every_secs: u64,
    /// A session needed a pass the wallet has none of: ask the account at most this often
    /// (per label) whether it gets that label now.
    pub label_retry_secs: u64,
    /// Close a conversation's session after this long without a request.
    pub idle_secs: u64,
    /// The same for a session without money (opened with a pass): it has no change to bring back,
    /// and closing it would waste what its pass still gives. The server's own limit, or less.
    pub idle_free_secs: u64,
    /// When nothing else can fund a conversation, close this device's sessions quiet this long.
    pub quiet_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            funding_cents: 10,
            keep_cents: 50,
            refill_cents: 100,
            min_cents: 1,
            refused_backoff_secs: 600,
            share_every_secs: 10,
            keep_passes: 10,
            pass_batch: 30,
            labels_every_secs: 600,
            label_retry_secs: 60,
            idle_secs: 300,
            idle_free_secs: 6 * 3600,
            quiet_secs: 30,
        }
    }
}

/// See [`Manager::spending`].
#[derive(Debug, Clone, Serialize)]
pub struct Spending {
    /// What each session cost, oldest first (open ones: so far)
    pub spent: Vec<crate::Spend>,
    /// Prepaid money still here: the wallet plus what open sessions hold
    pub prepaid_millicents: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    wallet: Option<serde_json::Value>,
    /// conversation → (session secret, last used, Unix seconds)
    #[serde(default)]
    chats: BTreeMap<String, (String, u64)>,
    /// held reply → the secret of the session that asked for it
    #[serde(default)]
    replies: BTreeMap<String, String>,
    /// When the account last refused a top-up (Unix seconds), so a reload doesn't ask again at once
    #[serde(default)]
    refused_at: u64,
    /// The seed this state was made with (hex), to notice when the account's code changes
    #[serde(default)]
    seed: Option<String>,
    /// Seeds the account had before (its old number, an earlier code): money made with them
    /// (withdrawals, sessions left open) is still the account's, found by rebuilding with each.
    #[serde(default)]
    previous_seeds: Vec<String>,
}

pub struct Manager {
    client: Client,
    wallet: Wallet,
    chats: BTreeMap<String, (String, u64)>,
    replies: BTreeMap<String, String>,
    pub policy: Policy,
    /// The account's API key, used only to top the wallet up. Without it the
    /// wallet spends what it holds.
    pub api_key: Option<String>,
    refused_at: u64,
    shared_at: u64,
    /// The last look in the shared wallet found nothing new
    share_empty: bool,
    /// The labels the account gets and how many of each are left, as last asked, and when
    /// (Unix seconds)
    offered: Option<(crate::protocol::PassAllowance, u64)>,
    /// label → when a session last needed one the account could not give
    refused_labels: BTreeMap<String, u64>,
    /// The label whose passes open a session without money, once asked (`None` inside: none does)
    free_label: Option<Option<String>>,
    server: String,
    seed_hex: String,
    previous_seeds: Vec<String>,
}

impl Manager {
    /// Connect to `server` with the account's seed and the state saved last
    /// time (`None` on a new device). Pins the server's keys on first use and
    /// refuses a server whose keys changed.
    pub async fn connect(server: &str, seed: Seed, state: Option<&str>) -> Result<Self> {
        let st: State = match state.filter(|s| !s.trim().is_empty()) {
            Some(s) => serde_json::from_str(s)?,
            None => State::default(),
        };
        let mut wallet = match &st.wallet {
            Some(w) => Wallet::from_json(&w.to_string())?,
            None => Wallet::in_memory(),
        };
        let transport = Transport::new(server);
        let keyset = transport.fetch_keyset().await?;
        keyset.check()?;
        let fp = keyset.fingerprint();
        match wallet.pinned() {
            Some(p) if p != fp => anyhow::bail!("the server's keys changed ({fp}, pinned {p})"),
            Some(_) => {}
            None => wallet.pin(Some(fp)),
        }
        let seed_hex = hex::encode(seed.0);
        let mut previous_seeds = st.previous_seeds.clone();
        if let Some(old) = st.seed.as_ref().filter(|old| **old != seed_hex && !previous_seeds.contains(old)) {
            // The account got a new code since this state was saved: keep the old seed too.
            previous_seeds.insert(0, old.clone());
            previous_seeds.truncate(4);
        }
        Ok(Manager {
            client: Client::new(transport, keyset).with_seed(seed),
            wallet,
            chats: st.chats,
            replies: st.replies,
            policy: Policy::default(),
            api_key: None,
            refused_at: st.refused_at,
            shared_at: 0,
            share_empty: false,
            offered: None,
            refused_labels: BTreeMap::new(),
            free_label: None,
            server: server.to_string(),
            seed_hex,
            previous_seeds,
        })
    }

    /// Everything to save, as JSON.
    pub fn state(&self) -> String {
        let wallet = serde_json::from_str(&self.wallet.to_json()).ok();
        serde_json::to_string(&State {
            wallet,
            chats: self.chats.clone(),
            replies: self.replies.clone(),
            refused_at: self.refused_at,
            seed: Some(self.seed_hex.clone()),
            previous_seeds: self.previous_seeds.clone(),
        })
        .unwrap_or_default()
    }

    /// At app start: sessions this device opened that no conversation uses
    /// any more are closed for their change; whatever a closed app or another
    /// device left behind (an open session, change not collected, the whole
    /// wallet after a wipe) comes back; then the wallet is topped up.
    /// Resolves to the cents recovered.
    pub async fn start(&mut self) -> Result<i64> {
        let in_use: Vec<String> = self.chats.values().map(|(s, _)| s.clone()).chain(self.replies.values().cloned()).collect();
        for open in self.wallet.sessions().to_vec() {
            if !in_use.contains(&open.secret) {
                let _ = self.client.close(&mut self.wallet, &Session { secret: open.secret, family: open.family }).await;
            }
        }
        let key = self.api_key.clone();
        let got = self.client.restore(&mut self.wallet, key.as_deref()).await?;
        let got = got + self.restore_previous(key.as_deref()).await;
        self.refill().await;
        Ok(got)
    }

    /// Rebuild with the account's earlier seeds too: what was withdrawn, or left in sessions,
    /// before its code changed. Failures wait for the next time.
    async fn restore_previous(&mut self, api_key: Option<&str>) -> i64 {
        let mut got = 0;
        for hex_seed in self.previous_seeds.clone() {
            let Some(seed) = hex::decode(&hex_seed).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { continue };
            let old = Client::new(crate::net::Transport::new(&self.server), self.client.keyset.clone())
                .with_seed(crate::seed::Seed(seed));
            got += old.restore(&mut self.wallet, api_key).await.unwrap_or(0);
        }
        got
    }

    /// Close this device's sessions that have gone quiet (not `keep`) for their change: a small
    /// balance spread over open conversations comes back to fund the one in use.
    async fn free_quiet(&mut self, keep: Option<&str>) {
        let now = unix_now();
        let quiet: Vec<String> = self
            .chats
            .iter()
            .filter(|(_, (secret, used))| Some(secret.as_str()) != keep && now.saturating_sub(*used) >= self.policy.quiet_secs && self.has_money(secret))
            .map(|(k, _)| k.clone())
            .collect();
        for chat in quiet {
            if let Some((secret, _)) = self.chats.remove(&chat) {
                if self.replies.values().any(|s| *s == secret) {
                    self.chats.insert(chat, (secret, now));
                    continue; // a held reply still needs it
                }
                let _ = self.client.close(&mut self.wallet, &Session { secret, family: Family::Paid }).await;
            }
        }
    }

    /// The session secret for conversation `chat`, opening one if it has none.
    pub async fn session(&mut self, chat: &str) -> Result<String> {
        if let Some((secret, used)) = self.chats.get_mut(chat) {
            *used = unix_now();
            self.wallet.used_session(secret, *used);
            return Ok(secret.clone());
        }
        let cents = self.policy.funding_cents;
        let opened = match self.client.open(&mut self.wallet, Family::Paid, cents).await {
            Ok(s) => s,
            Err(_) => {
                self.refill().await;
                match self.client.open(&mut self.wallet, Family::Paid, cents).await {
                    Ok(s) => s,
                    Err(_) => {
                        self.free_quiet(None).await;
                        match self.client.open(&mut self.wallet, Family::Paid, cents).await {
                            Ok(s) => s,
                            // No money anywhere: what costs none still works.
                            Err(e) => self.open_free().await.ok_or(e)?,
                        }
                    }
                }
            }
        };
        self.chats.insert(chat.to_string(), (opened.secret.clone(), unix_now()));
        self.wallet.used_session(&opened.secret, unix_now());
        Ok(opened.secret)
    }

    /// Was money put into this session?
    fn has_money(&self, secret: &str) -> bool {
        self.wallet.sessions().iter().all(|s| s.secret != secret || s.funded_millicents > 0)
    }

    /// A session without money, opened with one of the passes the server takes for that.
    async fn open_free(&mut self) -> Option<Session> {
        if self.free_label.is_none() {
            self.free_label = Some(self.client.free_open_label().await.ok()?);
        }
        let label = self.free_label.clone()??;
        if let Ok(Some(s)) = self.client.open_with_pass(&mut self.wallet, &label).await {
            return Some(s);
        }
        if !self.fetch_passes(&label).await {
            return None;
        }
        self.client.open_with_pass(&mut self.wallet, &label).await.ok().flatten()
    }

    /// Money was just added to the account: the next top-up asks it again, however lately it
    /// refused one.
    pub fn ask_again(&mut self) {
        self.refused_at = 0;
    }

    /// The secret of the session that asked for held reply `id`.
    pub fn reply(&self, id: &str) -> Option<String> {
        self.replies.get(id).cloned()
    }

    /// The server is holding a reply for this session: reading it later needs the same secret.
    pub fn note_reply(&mut self, id: &str, secret: &str) {
        self.replies.insert(id.to_string(), secret.to_string());
    }

    /// The session ran out of money (402): add more, doubling with each `attempt`. An error:
    /// there is nothing more to add.
    pub async fn ran_out(&mut self, secret: &str, attempt: u32) -> Result<()> {
        let session = Session { secret: secret.to_string(), family: Family::Paid };
        let cents = self.policy.funding_cents << attempt.min(8);
        if self.client.topup(&mut self.wallet, &session, cents).await.is_err() {
            self.refill().await;
            if self.client.topup(&mut self.wallet, &session, cents).await.is_err() {
                self.free_quiet(Some(secret)).await;
                self.client.topup(&mut self.wallet, &session, cents).await?;
            }
        }
        Ok(())
    }

    /// The server asked this session for a pass with `label` (403 with the
    /// `x-pass-required` header). Presents one from the wallet. With none held, what the
    /// account was last told decides: a label it gets and has used up for the month means no,
    /// with no word to the account (a request from the account right before this session's
    /// next one would tie the two by their timing); a label it wasn't offered may be new (its
    /// plan just changed), so the account is asked once (then at most every
    /// `label_retry_secs`) and some are fetched.
    /// True: the session has it, send the request again. False: the account has none to
    /// give; send the request once more as it was (the server may serve it another way),
    /// and show its error if it refuses again.
    pub async fn needs_pass(&mut self, secret: &str, label: &str) -> Result<bool> {
        let session = Session { secret: secret.to_string(), family: Family::Paid };
        if self.client.present_pass(&mut self.wallet, &session, label).await? {
            return Ok(true);
        }
        if !self.fetch_passes(label).await {
            return Ok(false);
        }
        self.client.present_pass(&mut self.wallet, &session, label).await
    }

    /// The wallet has no `label` pass: fetch some if what the account was last told allows it
    /// (see [`Manager::needs_pass`]). False: there are none to have.
    async fn fetch_passes(&mut self, label: &str) -> bool {
        let Some(key) = self.api_key.clone() else { return false };
        let now = unix_now();
        let known = self
            .offered
            .as_ref()
            .filter(|(_, at)| now.saturating_sub(*at) < self.policy.labels_every_secs)
            .and_then(|(a, _)| a.labels.iter().find(|l| l.label == label))
            .map(|l| l.remaining);
        match known {
            // Used up: nothing to ask.
            Some(left) if left <= 0 => return false,
            // Offered, and the stock ran out between two looks: fetch more.
            Some(_) => {}
            // Not offered when last asked (or never asked): it may be new.
            None => {
                let asked = self.refused_labels.get(label).copied().unwrap_or(0);
                if now.saturating_sub(asked) < self.policy.label_retry_secs {
                    return false;
                }
                self.refused_labels.insert(label.to_string(), now);
                self.offered = None;
            }
        }
        self.stock(&key, Some(label)).await;
        true
    }

    /// Keep `keep_passes` of each label the account gets (just `only`, when given).
    async fn stock(&mut self, key: &str, only: Option<&str>) {
        if self.client.keyset.pass_key.is_none() {
            return;
        }
        let now = unix_now();
        if self.offered.as_ref().is_none_or(|(_, at)| now.saturating_sub(*at) >= self.policy.labels_every_secs) {
            match self.client.pass_allowance(key).await {
                Ok(a) => self.offered = Some((a, now)),
                Err(_) => return,
            }
        }
        if let Some((allowance, _)) = self.offered.as_mut() {
            self.client
                .stock_passes(&mut self.wallet, key, allowance, self.policy.keep_passes, self.policy.pass_batch, only)
                .await;
        }
    }

    /// The server no longer takes this session (401): its conversation gets a new one.
    pub fn expired(&mut self, secret: &str) {
        self.chats.retain(|_, (s, _)| s != secret);
    }

    /// Call every 30 s or so: closes conversations' sessions that have been
    /// quiet for `idle_secs` (their change comes back) and tops the wallet up.
    pub async fn tick(&mut self) {
        let now = unix_now();
        let idle: Vec<String> = self
            .chats
            .iter()
            .filter(|(_, (secret, used))| {
                let idle = if self.has_money(secret) { self.policy.idle_secs } else { self.policy.idle_free_secs };
                now.saturating_sub(*used) >= idle
            })
            .map(|(k, _)| k.clone())
            .collect();
        for chat in idle {
            if let Some((secret, _)) = self.chats.remove(&chat) {
                self.replies.retain(|_, s| *s != secret);
                // On failure the session stays in the wallet; `start` closes it next time.
                let _ = self.client.close(&mut self.wallet, &Session { secret, family: Family::Paid }).await;
            }
        }
        self.top_up(false).await;
    }

    /// Top the wallet and passes up, and let the server forget records whose
    /// money is fully spent. Failures wait for the next tick.
    pub async fn refill(&mut self) {
        self.top_up(true).await;
    }

    /// `refill`; `urgent` when a conversation is waiting for money. In the background (`tick`),
    /// a wallet that stays low after a look found nothing looks again only after
    /// `refused_backoff_secs`: an idle device on an empty account asks a few times an hour.
    async fn top_up(&mut self, urgent: bool) {
        let Some(key) = self.api_key.clone() else { return };
        let now = unix_now();
        let low = |m: &Self| m.wallet.balance_cents(Family::Paid) < m.policy.keep_cents;
        // The wallet is the account's, not this device's: what another device withdrew, or got
        // back as change from a session it closed, is found from the shared seed first. Nothing
        // here names a chat: the lookups are the account's own records and anonymous lists.
        let every = if urgent || !self.share_empty { self.policy.share_every_secs } else { self.policy.refused_backoff_secs };
        if low(self) && now.saturating_sub(self.shared_at) >= every {
            self.shared_at = now;
            let before = self.wallet.balance_millicents(Family::Paid);
            let _ = self.client.restore(&mut self.wallet, Some(&key)).await;
            self.restore_previous(Some(&key)).await;
            self.share_empty = self.wallet.balance_millicents(Family::Paid) <= before;
        }
        if low(self) && now.saturating_sub(self.refused_at) >= self.policy.refused_backoff_secs {
            let min = self.policy.min_cents.min(self.policy.refill_cents);
            match self.client.withdraw_up_to(&mut self.wallet, &key, self.policy.refill_cents, min).await {
                Ok(_) => self.refused_at = 0,
                // Refused (402: not enough in the account): wait. A network failure retries next tick.
                Err(e) if matches!(e.downcast_ref::<crate::net::ApiError>(), Some(crate::net::ApiError::Server { status: 402, .. })) => {
                    self.refused_at = now
                }
                Err(_) => {}
            }
        }
        self.stock(&key, None).await;
        let _ = self.client.flush_done(&mut self.wallet, Some(&key)).await;
    }

    /// (cents in the wallet, this month's passes)
    pub fn summary(&mut self) -> (i64, usize) {
        let passes = self.wallet.passes(&crate::pass::current_period()).len();
        (self.wallet.balance_cents(Family::Paid), passes)
    }

    /// What private use cost on this device, and what it still holds. All from what the device
    /// knows, with no requests: asking the server about every open session at once, next to the
    /// account's own requests, would tie them together by timing and address. An open session
    /// counts what its replies said they cost ([`Manager::note_cost`]); closing it says exactly.
    pub async fn spending(&self) -> Spending {
        let mut spent = self.wallet.spending().to_vec();
        let mut prepaid_millicents = self.wallet.balance_millicents(Family::Paid);
        for open in self.wallet.sessions() {
            prepaid_millicents += open.left_millicents();
            let used = open.funded_millicents - open.left_millicents();
            if used > 0 {
                spent.push(crate::Spend { at: open.used_at.max(open.opened_at), millicents: used });
            }
        }
        Spending { spent, prepaid_millicents }
    }

    /// A reply in conversation `chat` said it cost this much (millicents).
    pub fn note_cost(&mut self, chat: &str, millicents: i64) {
        if let Some((secret, _)) = self.chats.get(chat) {
            self.wallet.note_cost(secret, millicents);
        }
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
}
