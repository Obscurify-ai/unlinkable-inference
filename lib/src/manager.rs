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
//!
//! **Nothing a conversation does makes a request with the account's key.** A withdrawal a
//! second before a session opens (or tops up) ties the two together by timing alone, whatever
//! the amounts. So the account is asked only at moments of its own: `start` (the app opening,
//! a sign-in), `money_added`, and at random times (`contact_min_secs`..`contact_max_secs` apart)
//! from `tick`. When a conversation needs money or a pass the wallet doesn't hold, the call fails
//! with [`Refilling`]: the app holds the request ("the private wallet is refilling") until
//! `refilling()` is `None` again, and the next contact is brought forward to a random moment
//! `wait_min_secs`..`wait_max_secs` away, never to now.

use crate::net::{Client, Session, Transport};
use crate::seed::Seed;
use crate::{unix_now, Family, Wallet};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A conversation needs money or a pass the wallet doesn't hold, and the account may have it:
/// the wallet asks the account at a random moment, about Unix time `at`. Hold the request until
/// [`Manager::refilling`] is `None`, then send it again.
#[derive(Debug, Clone, Copy)]
pub struct Refilling {
    pub at: u64,
}

impl std::fmt::Display for Refilling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the private wallet is refilling")
    }
}

impl std::error::Error for Refilling {}

/// A random whole number of seconds in `min..=max`.
pub fn random_secs(min: u64, max: u64) -> u64 {
    use rand::Rng;
    if max <= min {
        return min;
    }
    rand::rngs::OsRng.gen_range(min..=max)
}

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
    /// Unused since 0.3 (the account is asked only at contacts); kept for apps that set it.
    pub refused_backoff_secs: u64,
    /// Unused since 0.3 (other devices' withdrawals and change are looked for at contacts).
    pub share_every_secs: u64,
    /// The account is asked (for money, passes, other devices' leftovers) at random times this
    /// far apart, whether or not anything is needed, so when it is asked says nothing about
    /// what a conversation did.
    pub contact_min_secs: u64,
    pub contact_max_secs: u64,
    /// A conversation waiting for money brings the next contact forward to a random moment this
    /// far away (never sooner: a withdrawal right after a request ran dry would point at it), and
    /// goes on a random while this long after it (a top-up right after the withdrawal would too).
    pub wait_min_secs: u64,
    pub wait_max_secs: u64,
    /// Keep this many of this month's passes of each label the account gets, asking for
    /// `pass_batch` at a time.
    pub keep_passes: usize,
    pub pass_batch: i64,
    /// Ask the account which labels it gets at most this often (a change shows within this).
    pub labels_every_secs: u64,
    /// Unused since 0.3 (a label the wallet lacks is asked for at the next contact).
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
            // A pricey model's reply ($1 held, plus its prompt) fits in what the wallet keeps, so
            // a conversation rarely has to wait for the account.
            keep_cents: 200,
            refill_cents: 500,
            min_cents: 1,
            refused_backoff_secs: 600,
            share_every_secs: 10,
            contact_min_secs: 5 * 60,
            contact_max_secs: 30 * 60,
            // Before the contact and again after it: a few minutes in all, on average.
            wait_min_secs: 30,
            wait_max_secs: 300,
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
    /// When the account last refused a top-up (Unix seconds). Kept for older states.
    #[serde(default)]
    refused_at: u64,
    /// The account had nothing to give at the last contact (until `money_added` or a later contact)
    #[serde(default)]
    account_empty: bool,
    /// When the account is asked next (Unix seconds; 0: at the first `tick`)
    #[serde(default)]
    next_contact: u64,
    /// A conversation was waiting for the account, and when the hold-back after the contact
    /// ends: kept, so reopening the app doesn't ask the account at once (see `start`)
    #[serde(default)]
    waiting: bool,
    #[serde(default)]
    release_at: u64,
    /// What the account said when it last refused a top-up (see `Manager::account_note`)
    #[serde(default)]
    account_note: Option<String>,
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
    /// See `State::account_empty`
    account_empty: bool,
    /// When the account is asked next (Unix seconds)
    next_contact: u64,
    /// A conversation is waiting for what only the account can give
    waiting: bool,
    /// After the contact a waiting conversation needed, it waits this long more (Unix seconds),
    /// so the wallet's top-up and the session's are not seconds apart either
    release_at: u64,
    /// Labels a session asked for that the wallet had none of: asked for at the next contact
    wanted: std::collections::BTreeSet<String>,
    /// See `State::account_note`
    account_note: Option<String>,
    /// The labels the account gets and how many of each are left, as last asked, and when
    /// (Unix seconds)
    offered: Option<(crate::protocol::PassAllowance, u64)>,
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
            account_empty: st.account_empty,
            next_contact: st.next_contact,
            waiting: st.waiting,
            release_at: st.release_at,
            wanted: Default::default(),
            account_note: st.account_note.clone(),
            offered: None,
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
            account_empty: self.account_empty,
            next_contact: self.next_contact,
            waiting: self.waiting,
            release_at: self.release_at,
            account_note: self.account_note.clone(),
            seed: Some(self.seed_hex.clone()),
            previous_seeds: self.previous_seeds.clone(),
        })
        .unwrap_or_default()
    }

    /// At app start (or sign-in), a moment of the account's own: sessions this device opened
    /// that no conversation uses any more are closed for their change; whatever a closed app or
    /// another device left behind (an open session, change not collected, the whole wallet after
    /// a wipe) comes back; then the account is asked for what the wallet lacks.
    /// Resolves to the cents recovered.
    ///
    /// Not while a conversation waits for the wallet (or holds back after it was filled): an app
    /// reopened then, often to get a chat going, would otherwise ask the account seconds before
    /// that chat goes on. The scheduled contact (and hold-back) stand; `tick` makes it.
    pub async fn start(&mut self) -> Result<i64> {
        if self.refilling().is_some() {
            return Ok(0);
        }
        let in_use: Vec<String> = self.chats.values().map(|(s, _)| s.clone()).chain(self.replies.values().cloned()).collect();
        for open in self.wallet.sessions().to_vec() {
            if !in_use.contains(&open.secret) {
                let _ = self.client.close(&mut self.wallet, &Session { secret: open.secret, family: open.family }).await;
            }
        }
        let key = self.api_key.clone();
        let got = self.client.restore(&mut self.wallet, key.as_deref()).await?;
        let got = got + self.restore_previous(key.as_deref()).await;
        self.contact().await;
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

    /// The session secret for conversation `chat`, opening one if it has none. Paid from the
    /// wallet, or from this device's quiet sessions' change; never from the account at this
    /// moment. With nothing here: [`Refilling`] when the account may have money (hold the
    /// request), else a session without money if the server has those (free models), else an
    /// error.
    pub async fn session(&mut self, chat: &str) -> Result<String> {
        if let Some((secret, used)) = self.chats.get_mut(chat) {
            *used = unix_now();
            self.wallet.used_session(secret, *used);
            return Ok(secret.clone());
        }
        // Just filled for a conversation that waited: nothing opens until the hold-back is over.
        if let Some(at) = self.held_back() {
            return Err(Refilling { at }.into());
        }
        let cents = self.policy.funding_cents;
        let opened = match self.client.open(&mut self.wallet, Family::Paid, cents).await {
            Ok(s) => s,
            Err(_) => {
                self.free_quiet(None).await;
                match self.client.open(&mut self.wallet, Family::Paid, cents).await {
                    Ok(s) => s,
                    Err(e) => {
                        if let Some(waiting) = self.wait() {
                            return Err(waiting.into());
                        }
                        // No money anywhere: what costs none still works.
                        self.open_free().await.ok_or(e)?
                    }
                }
            }
        };
        self.chats.insert(chat.to_string(), (opened.secret.clone(), unix_now()));
        self.wallet.used_session(&opened.secret, unix_now());
        Ok(opened.secret)
    }

    /// A conversation needs what only the account can give. `None` when it has nothing to give
    /// (or there is no account key); else the next contact is brought forward to a random moment
    /// `wait_min_secs`..`wait_max_secs` away (unless one is due sooner).
    fn wait(&mut self) -> Option<Refilling> {
        if self.api_key.is_none() || self.account_empty {
            return None;
        }
        if let Some(at) = self.refilling() {
            // Already waiting, or just filled and holding back.
            return Some(Refilling { at });
        }
        let at = unix_now() + random_secs(self.policy.wait_min_secs, self.policy.wait_max_secs);
        self.next_contact = self.next_contact.min(at);
        self.waiting = true;
        Some(Refilling { at: self.next_contact })
    }

    /// Just filled for a conversation that waited: `Some(until)` while sessions are neither
    /// opened nor topped up (a session funded a second after the withdrawal points at it).
    fn held_back(&self) -> Option<u64> {
        (!self.waiting && unix_now() < self.release_at).then_some(self.release_at)
    }

    /// What the account said when it last refused to fill the wallet (a plan's limit used up and
    /// when it starts over, say), for an app to word a refusal with: asking the account again
    /// right after a conversation was refused would tie the two together. `None` after a top-up.
    pub fn account_note(&self) -> Option<&str> {
        self.account_note.as_deref()
    }

    /// `Some(when)` (Unix seconds) while a conversation waits for the account (see
    /// [`Refilling`]); `None` once the contact has been made: send the held request again.
    pub fn refilling(&self) -> Option<u64> {
        if self.waiting {
            return Some(self.next_contact.max(self.release_at));
        }
        (unix_now() < self.release_at).then_some(self.release_at)
    }

    /// Was money put into this session?
    fn has_money(&self, secret: &str) -> bool {
        self.wallet.sessions().iter().all(|s| s.secret != secret || s.funded_millicents > 0)
    }

    /// A session without money, opened with one of the passes the server takes for that, from
    /// the wallet's stock (asking which label is anonymous; asking the account for passes waits
    /// for the next contact).
    async fn open_free(&mut self) -> Option<Session> {
        if self.free_label.is_none() {
            self.free_label = Some(self.client.free_open_label().await.ok()?);
        }
        let label = self.free_label.clone()??;
        if let Ok(Some(s)) = self.client.open_with_pass(&mut self.wallet, &label).await {
            return Some(s);
        }
        if self.api_key.is_some() {
            self.wanted.insert(label);
        }
        None
    }

    /// Money was just added to the account, or its plan changed (a moment of its own, e.g. a
    /// payment went through in the app): ask it at the next `tick`, labels included.
    pub fn ask_again(&mut self) {
        self.account_empty = false;
        self.account_note = None;
        self.refused_at = 0;
        self.offered = None;
        self.next_contact = unix_now();
    }

    /// [`Manager::ask_again`], then ask the account at once.
    pub async fn money_added(&mut self) {
        self.ask_again();
        self.contact().await;
    }

    /// The secret of the session that asked for held reply `id`.
    pub fn reply(&self, id: &str) -> Option<String> {
        self.replies.get(id).cloned()
    }

    /// The server is holding a reply for this session: reading it later needs the same secret.
    pub fn note_reply(&mut self, id: &str, secret: &str) {
        self.replies.insert(id.to_string(), secret.to_string());
    }

    /// The session ran out of money (402): add more, doubling with each `attempt`, from the
    /// wallet or this device's quiet sessions. [`Refilling`]: the account may have more, hold the
    /// request. Another error: there is nothing more to add (send the rest of the session's
    /// money with [`REST_HEADER`](crate::protocol::REST_HEADER)).
    pub async fn ran_out(&mut self, secret: &str, attempt: u32) -> Result<()> {
        if let Some(at) = self.held_back() {
            return Err(Refilling { at }.into());
        }
        let session = Session { secret: secret.to_string(), family: Family::Paid };
        let cents = self.policy.funding_cents << attempt.min(8);
        if self.client.topup(&mut self.wallet, &session, cents).await.is_ok() {
            return Ok(());
        }
        self.free_quiet(Some(secret)).await;
        match self.client.topup(&mut self.wallet, &session, cents).await {
            Ok(_) => Ok(()),
            Err(e) => match self.wait() {
                Some(waiting) => Err(waiting.into()),
                None => Err(e),
            },
        }
    }

    /// The server asked this session for a pass with `label` (403 with the
    /// `x-pass-required` header). Presents one from the wallet. True: the session has it, send
    /// the request again. False: the account has none to give (it wasn't offered that label at
    /// the last contact, or used it up this month, or there is no key); send the request once
    /// more as it was (the server may serve it another way), and show its error if it refuses
    /// again. [`Refilling`]: the account gets that label and the wallet's stock ran out (or the
    /// account hasn't been asked yet); it is asked at the next contact, never right now, which
    /// would tie this session to it by timing.
    pub async fn needs_pass(&mut self, secret: &str, label: &str) -> Result<bool> {
        let session = Session { secret: secret.to_string(), family: Family::Paid };
        if self.client.present_pass(&mut self.wallet, &session, label).await? {
            return Ok(true);
        }
        if self.api_key.is_none() {
            return Ok(false);
        }
        // What the account was told at the last contact. A label it wasn't offered: no (a plan
        // bought since is a moment of the account's own: the app calls `money_added`).
        let known = self.offered.as_ref().map(|(a, _)| a.labels.iter().find(|l| l.label == label).map(|l| l.remaining));
        match known {
            Some(None) => return Ok(false),
            Some(Some(left)) if left <= 0 => return Ok(false),
            _ => {}
        }
        if self.wanted.contains(label) && !self.waiting {
            // Asked for at the last contact and still none: the account doesn't give it.
            self.wanted.remove(label);
            return Ok(false);
        }
        self.wanted.insert(label.to_string());
        match self.wait() {
            Some(waiting) => Err(waiting.into()),
            None => Ok(false),
        }
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

    /// Call every 30 s or so: closes conversations' sessions that have been quiet for
    /// `idle_secs` (their change comes back), and asks the account for what the wallet lacks
    /// when the next contact is due (random times, see [`Policy::contact_min_secs`]).
    pub async fn tick(&mut self) {
        let now = unix_now();
        // A conversation waiting for the wallet makes no requests: its session isn't idle.
        let waiting = self.refilling().is_some();
        let idle: Vec<String> = self
            .chats
            .iter()
            .filter(|_| !waiting)
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
        if now >= self.next_contact {
            self.contact().await;
        }
    }

    /// Ask the account now. For a moment of its own (a payment, a sign-in); a conversation's
    /// need waits for `tick` (see [`Refilling`]).
    pub async fn refill(&mut self) {
        self.contact().await;
    }

    /// One contact with the account: other devices' leftovers (when low), a top-up (when low),
    /// passes, and letting the server forget what is fully spent. Then the next one is set at
    /// random. A wallet that is still short and an account with nothing: `account_empty`.
    async fn contact(&mut self) {
        let now = unix_now();
        self.next_contact = now + random_secs(self.policy.contact_min_secs, self.policy.contact_max_secs);
        let Some(key) = self.api_key.clone() else {
            self.waiting = false;
            return;
        };
        let low = |m: &Self| m.wallet.balance_cents(Family::Paid) < m.policy.keep_cents;
        // The wallet is the account's, not this device's: what another device withdrew, or got
        // back as change from a session it closed, is found from the shared seed first. Nothing
        // here names a chat: the lookups are the account's own records and anonymous lists.
        if low(self) {
            let _ = self.client.restore(&mut self.wallet, Some(&key)).await;
            self.restore_previous(Some(&key)).await;
        }
        if low(self) {
            let min = self.policy.min_cents.min(self.policy.refill_cents);
            match self.client.withdraw_up_to_left(&mut self.wallet, &key, self.policy.refill_cents, min).await {
                Ok((_, left)) => {
                    self.refused_at = 0;
                    self.account_note = None;
                    // It gave its last cents: a conversation that runs short doesn't wait for it.
                    self.account_empty = left == Some(0);
                }
                // Refused (402: not enough in the account). A network failure tries again next time.
                Err(e) if matches!(e.downcast_ref::<crate::net::ApiError>(), Some(crate::net::ApiError::Server { status: 402, .. })) => {
                    self.refused_at = now;
                    self.account_empty = true;
                    if let Some(crate::net::ApiError::Server { body, .. }) = e.downcast_ref::<crate::net::ApiError>() {
                        self.account_note = Some(body.error.message.clone());
                    }
                }
                Err(_) => {}
            }
        }
        // Labels a session asked for: ask the account again which it gets (a plan may have changed).
        if !self.wanted.is_empty() {
            self.offered = None;
        }
        self.stock(&key, None).await;
        let wanted: Vec<String> = self.wanted.iter().cloned().collect();
        for label in wanted {
            let left = self.wallet.passes_of(&crate::pass::current_period(), &label);
            if left > 0 {
                self.wanted.remove(&label);
            }
        }
        let _ = self.client.flush_done(&mut self.wallet, Some(&key)).await;
        if self.waiting {
            // The conversation that waited goes on a random while later, not at once: a session
            // topped up a second after the account's withdrawal points at it just the same.
            self.release_at = unix_now() + random_secs(self.policy.wait_min_secs, self.policy.wait_max_secs);
            // The conversations made no requests while they waited: none is idle before it may go on.
            let until = self.release_at;
            for (_, used) in self.chats.values_mut() {
                *used = (*used).max(until);
            }
        }
        self.waiting = false;
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
