//! What a chat app does with a wallet, so every app does it the same way: one
//! session per conversation, opened on its first request and closed for its
//! change once it has been quiet a while; the wallet topped up from the
//! account at quiet moments; and everything a lost device left behind
//! brought back at start.
//!
//! The app keeps the account number's seed and `Manager::state()` (save it
//! after every call; a crash between saves loses nothing, `start` restores
//! it from the seed) and sends `session(chat)` as `Authorization: Bearer`.
//! On a 402 it calls `ran_out` and retries; on a 401, `expired` and asks for a
//! new session.

use crate::net::{Client, Session, Transport};
use crate::seed::Seed;
use crate::{unix_now, Family, Wallet};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Policy {
    /// What a session starts with.
    pub funding_cents: i64,
    /// Top the wallet up when it holds less than this...
    pub keep_cents: i64,
    /// ...by this much: one of `WITHDRAW_SIZES` (fixed, so withdrawals look alike). An account
    /// holding less gives what it has, down to `min_session_cents`.
    pub refill_cents: i64,
    /// The least a session can open with (the server's minimum): less stays in the account.
    pub min_session_cents: i64,
    /// After the account refused a top-up, wait this long before asking again.
    pub refused_backoff_secs: u64,
    /// The wallet is shared by every device with the account's code: when low, look for what the
    /// others withdrew or got back as change (at most this often) before taking more from the account.
    pub share_every_secs: u64,
    /// Keep this many of this month's passes (on a plan), getting `pass_batch` at a time.
    pub keep_passes: usize,
    pub pass_batch: i64,
    /// Close a conversation's session after this long without a request.
    pub idle_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            funding_cents: 50,
            keep_cents: 50,
            refill_cents: 100,
            min_session_cents: 10,
            refused_backoff_secs: 600,
            share_every_secs: 10,
            keep_passes: 10,
            pass_batch: 30,
            idle_secs: 300,
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
        Ok(Manager {
            client: Client::new(transport, keyset).with_seed(seed),
            wallet,
            chats: st.chats,
            replies: st.replies,
            policy: Policy::default(),
            api_key: None,
            refused_at: st.refused_at,
            shared_at: 0,
        })
    }

    /// Everything to save, as JSON.
    pub fn state(&self) -> String {
        let wallet = serde_json::from_str(&self.wallet.to_json()).ok();
        serde_json::to_string(&State { wallet, chats: self.chats.clone(), replies: self.replies.clone(), refused_at: self.refused_at })
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
        let got = self.client.restore(&mut self.wallet, self.api_key.as_deref()).await?;
        self.refill().await;
        Ok(got)
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
                self.client.open(&mut self.wallet, Family::Paid, cents).await?
            }
        };
        self.chats.insert(chat.to_string(), (opened.secret.clone(), unix_now()));
        self.wallet.used_session(&opened.secret, unix_now());
        Ok(opened.secret)
    }

    /// The secret of the session that asked for held reply `id`.
    pub fn reply(&self, id: &str) -> Option<String> {
        self.replies.get(id).cloned()
    }

    /// The server is holding a reply for this session: reading it later needs the same secret.
    pub fn note_reply(&mut self, id: &str, secret: &str) {
        self.replies.insert(id.to_string(), secret.to_string());
    }

    /// The session ran out of money (402): add more, doubling with each `attempt`.
    pub async fn ran_out(&mut self, secret: &str, attempt: u32) -> Result<()> {
        let session = Session { secret: secret.to_string(), family: Family::Paid };
        let cents = self.policy.funding_cents << attempt.min(8);
        if self.client.topup(&mut self.wallet, &session, cents).await.is_err() {
            self.refill().await;
            self.client.topup(&mut self.wallet, &session, cents).await?;
        }
        Ok(())
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
            .filter(|(_, (_, used))| now.saturating_sub(*used) >= self.policy.idle_secs)
            .map(|(k, _)| k.clone())
            .collect();
        for chat in idle {
            if let Some((secret, _)) = self.chats.remove(&chat) {
                self.replies.retain(|_, s| *s != secret);
                // On failure the session stays in the wallet; `start` closes it next time.
                let _ = self.client.close(&mut self.wallet, &Session { secret, family: Family::Paid }).await;
            }
        }
        self.refill().await;
    }

    /// Top the wallet and passes up, and let the server forget records whose
    /// money is fully spent. Failures wait for the next tick.
    pub async fn refill(&mut self) {
        let Some(key) = self.api_key.clone() else { return };
        let now = unix_now();
        let low = |m: &Self| m.wallet.balance_cents(Family::Paid) < m.policy.keep_cents;
        // The wallet is the account's, not this device's: what another device withdrew, or got
        // back as change from a session it closed, is found from the shared seed first. Nothing
        // here names a chat: the lookups are the account's own records and anonymous lists.
        if low(self) && now.saturating_sub(self.shared_at) >= self.policy.share_every_secs {
            self.shared_at = now;
            let _ = self.client.restore(&mut self.wallet, Some(&key)).await;
        }
        if low(self) && now.saturating_sub(self.refused_at) >= self.policy.refused_backoff_secs {
            let min = self.policy.min_session_cents.min(self.policy.refill_cents);
            match self.client.withdraw_up_to(&mut self.wallet, &key, self.policy.refill_cents, min).await {
                Ok(_) => self.refused_at = 0,
                // Refused (402: not enough in the account): wait. A network failure retries next tick.
                Err(e) if matches!(e.downcast_ref::<crate::net::ApiError>(), Some(crate::net::ApiError::Server { status: 402, .. })) => {
                    self.refused_at = now
                }
                Err(_) => {}
            }
        }
        if self.wallet.passes(&crate::pass::current_period()).len() < self.policy.keep_passes {
            let _ = self.client.get_passes(&mut self.wallet, &key, self.policy.pass_batch).await;
        }
        let _ = self.client.flush_done(&mut self.wallet, Some(&key)).await;
    }

    /// (cents in the wallet, this month's passes)
    pub fn summary(&mut self) -> (i64, usize) {
        let passes = self.wallet.passes(&crate::pass::current_period()).len();
        (self.wallet.balance_cents(Family::Paid), passes)
    }

    /// What private use cost, for an app's history. Closed sessions come
    /// from the wallet's log; open ones are asked from the server with each
    /// session's own secret. Changes nothing.
    pub async fn spending(&self) -> Spending {
        let mut spent = self.wallet.spending().to_vec();
        let mut prepaid_millicents = self.wallet.balance_millicents(Family::Paid);
        for open in self.wallet.sessions() {
            if open.funded_millicents <= 0 {
                continue;
            }
            let session = Session { secret: open.secret.clone(), family: open.family };
            if let Ok(status) = self.client.status(&session).await {
                let left = crate::net::usd_to_millicents_ceil(&status.balance_usd);
                prepaid_millicents += left;
                if open.funded_millicents > left {
                    spent.push(crate::Spend { at: open.used_at.max(open.opened_at), millicents: open.funded_millicents - left });
                }
            }
        }
        Spending { spent, prepaid_millicents }
    }

    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
}
