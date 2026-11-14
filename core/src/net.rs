//! Talking to a server over HTTPS.
//!
//! Hiding this device's IP address is left to the network it runs on (Tor, a
//! VPN): nothing here depends on a third party. What this layer guarantees is
//! that requests carry a session secret, never an account key or a cookie.

use crate::blank::Blank;
use crate::denominations::{
    blanks_for_any_amount_up_to, dust_blanks_for_any, split, MILLICENTS_PER_CENT, WITHDRAW_SIZES,
};
use crate::keyset::Keyset;
use crate::pass::{Pass, PassBlank};
use crate::protocol::*;
use crate::voucher::{Family, Voucher};
use crate::wallet::{OpenSession, Pending, Wallet};
use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// One request as the server will see it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Path and query, e.g. `/v1/chat/completions`
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn get(path: &str) -> Self {
        Self {
            method: "GET".into(),
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn post_json(path: &str, body: &impl serde::Serialize) -> Self {
        Self {
            method: "POST".into(),
            path: path.into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(body).expect("request serialises"),
        }
    }

    pub fn bearer(mut self, token: &str) -> Self {
        self.headers
            .push(("authorization".into(), format!("Bearer {token}")));
        self
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: BoxStream<'static, Result<Bytes>>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub async fn bytes(self) -> Result<Vec<u8>> {
        let chunks: Vec<Bytes> = self.body.try_collect().await?;
        Ok(chunks.concat())
    }
}

/// What the server received for one request, for the "what leaves this
/// device" view.
#[derive(Debug, Clone)]
pub struct Observed {
    pub server: String,
    pub bytes_sent: usize,
    /// Method, path, headers (credentials named, not shown) and body size
    pub server_sees: String,
}

pub type Observer = Arc<dyn Fn(&Observed) + Send + Sync>;

#[derive(Clone)]
pub struct Transport {
    #[cfg(not(target_arch = "wasm32"))]
    http: reqwest::Client,
    /// Server origin, e.g. `https://obscurify.ai`
    pub server: String,
    observer: Option<Observer>,
}

impl Transport {
    /// Requests go out with no cookies and a generic user agent. Standard
    /// proxy variables (`HTTPS_PROXY`, `ALL_PROXY`) are honoured.
    pub fn new(server: &str) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            http: reqwest::Client::builder()
                .user_agent("unlinkable")
                .build()
                .expect("http client"),
            server: server.trim_end_matches('/').to_string(),
            observer: None,
        }
    }

    pub fn observe(mut self, observer: Observer) -> Self {
        self.observer = Some(observer);
        self
    }

    fn describe(req: &Request) -> String {
        let headers: Vec<String> = req
            .headers
            .iter()
            .map(|(k, v)| {
                if k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("x-api-key") {
                    let kind = if v.contains(crate::SESSION_SECRET_PREFIX) {
                        "session secret"
                    } else {
                        "ACCOUNT KEY"
                    };
                    format!("{k}: <{kind}>")
                } else {
                    format!("{k}: {v}")
                }
            })
            .collect();
        format!(
            "{} {} [{}] body {} bytes",
            req.method,
            req.path,
            headers.join(", "),
            req.body.len()
        )
    }

    pub async fn send(&self, req: Request) -> Result<Response> {
        if let Some(observer) = &self.observer {
            observer(&Observed {
                server: self.server.clone(),
                bytes_sent: req.body.len(),
                server_sees: Self::describe(&req),
            });
        }
        self.fetch(req).await
    }

    /// In a browser: `fetch` with credentials "omit", so the site's cookies
    /// (the account's sign-in) never go with a session request.
    #[cfg(target_arch = "wasm32")]
    async fn fetch(&self, req: Request) -> Result<Response> {
        use wasm_bindgen::JsCast;
        let js = |e: wasm_bindgen::JsValue| anyhow!("fetch: {e:?}");
        let init = web_sys::RequestInit::new();
        init.set_method(&req.method);
        init.set_credentials(web_sys::RequestCredentials::Omit);
        let headers = web_sys::Headers::new().map_err(js)?;
        for (k, v) in &req.headers {
            headers.set(k, v).map_err(js)?;
        }
        init.set_headers(&headers);
        if !req.body.is_empty() {
            init.set_body(&js_sys::Uint8Array::from(&req.body[..]));
        }
        let url = format!("{}{}", self.server, req.path);
        let request = web_sys::Request::new_with_str_and_init(&url, &init).map_err(js)?;
        let global = js_sys::global();
        let promise = match global.dyn_ref::<web_sys::Window>() {
            Some(window) => window.fetch_with_request(&request),
            None => global.unchecked_ref::<web_sys::WorkerGlobalScope>().fetch_with_request(&request),
        };
        let resp: web_sys::Response = wasm_bindgen_futures::JsFuture::from(promise).await.map_err(js)?.unchecked_into();
        let buf = wasm_bindgen_futures::JsFuture::from(resp.array_buffer().map_err(js)?)
            .await
            .map_err(js)?;
        let body = Bytes::from(js_sys::Uint8Array::new(&buf).to_vec());
        Ok(Response {
            status: resp.status(),
            headers: Vec::new(),
            body: futures::stream::once(async move { Ok(body) }).boxed(),
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = format!("{}{}", self.server, req.path);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())?;
        let mut builder = self.http.request(method, &url);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        let resp = builder.body(req.body).send().await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        Ok(Response {
            status,
            headers,
            body: resp.bytes_stream().map_err(anyhow::Error::from).boxed(),
        })
    }

    pub async fn json<T: DeserializeOwned>(&self, req: Request) -> Result<T, ApiError> {
        let resp = self.send(req).await.map_err(ApiError::Network)?;
        let status = resp.status;
        let body = resp.bytes().await.map_err(ApiError::Network)?;
        if (200..300).contains(&status) {
            serde_json::from_slice(&body).map_err(|e| ApiError::Network(e.into()))
        } else {
            Err(ApiError::Server {
                status,
                body: serde_json::from_slice(&body).unwrap_or(ErrorBody {
                    error: ErrorDetail {
                        message: String::from_utf8_lossy(&body).chars().take(300).collect(),
                        kind: "unknown".into(),
                        spent: Vec::new(),
                    },
                }),
            })
        }
    }

    pub async fn fetch_keyset(&self) -> Result<Keyset> {
        Ok(self.json(Request::get("/u/keys")).await?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Network(anyhow::Error),
    #[error("server answered {status}: {}", body.error.message)]
    Server { status: u16, body: ErrorBody },
}

/// A session as the client holds it.
#[derive(Debug, Clone)]
pub struct Session {
    pub secret: String,
    pub family: Family,
}

/// Session operations against one server, with one wallet.
pub struct Client {
    pub transport: Transport,
    pub keyset: Keyset,
    /// With a seed (from the account number) everything the wallet makes is
    /// derived, so [`Client::restore`] can rebuild it on a device that lost
    /// its storage. Without one, it is random and lives only in the wallet.
    pub seed: Option<crate::seed::Seed>,
}

/// A close sends blanks for any change up to this (cents) in seeded wallets,
/// the same set every time, so a repeated close matches the first.
const SEEDED_CLOSE_MAX_CENTS: i64 = 100_000;

/// Withdrawals arrive in pieces of this size (seeded wallets), so a session
/// never needs an exchange to get started.
const PIECE_CENTS: i64 = 50;

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    crate::b64(bytes)
}

fn prefix(hash: &str) -> &str {
    &hash[..HASH_PREFIX.min(hash.len())]
}

fn now() -> u64 {
    crate::unix_now()
}

/// Whole cents in a decimal USD string, rounded down.
pub fn usd_to_cents_floor(usd: &str) -> i64 {
    let usd = usd.trim();
    let negative = usd.starts_with('-');
    let usd = usd.trim_start_matches('-');
    let (whole, frac) = usd.split_once('.').unwrap_or((usd, ""));
    let whole: i64 = whole.parse().unwrap_or(0);
    let mut frac2: String = frac.chars().take(2).collect();
    while frac2.len() < 2 {
        frac2.push('0');
    }
    let cents = whole * 100 + frac2.parse::<i64>().unwrap_or(0);
    if negative {
        0
    } else {
        cents
    }
}

impl Client {
    pub fn new(transport: Transport, keyset: Keyset) -> Self {
        Self {
            transport,
            keyset,
            seed: None,
        }
    }

    pub fn with_seed(mut self, seed: crate::seed::Seed) -> Self {
        self.seed = Some(seed);
        self
    }

    /// A secret for a new session: derived from (this minute, k) when seeded.
    /// A secret for a new session: from the seed, one of this minute's that
    /// the wallet isn't already using.
    fn new_secret(&self, wallet: &Wallet) -> String {
        match &self.seed {
            Some(seed) => {
                let minute = now() / 60;
                let free: Vec<String> = (0..crate::seed::SESSIONS_PER_MINUTE)
                    .map(|k| seed.session_secret(minute, k))
                    .filter(|s| !wallet.sessions().iter().any(|o| &o.secret == s))
                    .collect();
                match free.len() {
                    0 => seed.session_secret(minute, rand::random::<u32>() % crate::seed::SESSIONS_PER_MINUTE),
                    n => free[rand::random::<usize>() % n].clone(),
                }
            }
            None => crate::new_session_secret(),
        }
    }

    /// The blanks a close sends.
    fn close_blanks(&self, secret: &str, family: Family, max_cents: i64) -> Result<Vec<Blank>> {
        let dust = !self.keyset.dust_paid.is_empty();
        Ok(match &self.seed {
            Some(seed) => {
                let op = format!("change:{}", crate::sha256_hex(secret));
                let mut values = blanks_for_any_amount_up_to(SEEDED_CLOSE_MAX_CENTS);
                values.retain(|&v| self.keyset.key_for(family, v, false).is_some());
                let mut blanks = Blank::seeded_many(
                    &self.keyset,
                    family,
                    &values,
                    false,
                    seed,
                    op.as_bytes(),
                    0,
                )?;
                if dust {
                    blanks.extend(Blank::seeded_many(
                        &self.keyset,
                        family,
                        &dust_blanks_for_any(),
                        true,
                        seed,
                        op.as_bytes(),
                        1000,
                    )?);
                }
                blanks
            }
            None => {
                let mut blanks = Blank::many(&self.keyset, family, &blanks_for_any_amount_up_to(max_cents))?;
                if dust {
                    blanks.extend(Blank::many_dust(&self.keyset, family, &dust_blanks_for_any())?);
                }
                blanks
            }
        })
    }

    fn finish(&self, blanks: &[Blank], change: &ChangeResponse) -> Result<Vec<Voucher>> {
        change
            .signed
            .iter()
            .map(|s| {
                let blank = blanks
                    .get(s.index)
                    .ok_or_else(|| anyhow!("server signed a blank we did not send"))?;
                let sig = crate::unb64(&s.blind_signature)
                    .ok_or_else(|| anyhow!("signature is not base64url"))?;
                blank.finish(&self.keyset, &sig)
            })
            .collect()
    }

    /// If only vouchers much bigger than `cents` are left, trade the smallest
    /// of them (anonymously, no account involved) for session-sized pieces,
    /// so one session does not lock up the whole wallet.
    async fn break_up(&self, wallet: &mut Wallet, family: Family, cents: i64) -> Result<()> {
        let mine: Vec<i64> = wallet
            .vouchers()
            .iter()
            .filter(|h| h.family == family && !h.voucher.dust)
            .map(|h| h.voucher.denomination_cents)
            .collect();
        let small: i64 = mine.iter().filter(|&&v| v <= cents).sum();
        if small >= cents {
            return Ok(());
        }
        let Some(&big) = mine.iter().filter(|&&v| v > cents).min() else {
            return Ok(());
        };
        let pieces = (big / cents).min(8);
        let mut values: Vec<i64> = (0..pieces).flat_map(|_| split(cents)).collect();
        values.extend(split(big - pieces * cents));
        let voucher = wallet
            .vouchers()
            .iter()
            .find(|h| h.family == family && !h.voucher.dust && h.voucher.denomination_cents == big)
            .map(|h| h.voucher.clone())
            .expect("found above");
        wallet.forget(&[voucher.encode()]);
        self.exchange_vouchers(wallet, family, vec![voucher], &values).await?;
        Ok(())
    }

    /// Open a session worth at least `cents` from the wallet.
    pub async fn open(&self, wallet: &mut Wallet, family: Family, cents: i64) -> Result<Session> {
        if self.seed.is_none() {
            self.break_up(wallet, family, cents).await?;
        }
        let period = crate::pass::current_period();
        for _attempt in 0..3 {
            // A pass, if we hold one for this month, gives the session our
            // plan's models. It is spent with the session.
            let pass = if self.keyset.pass_key.is_some() {
                wallet.take_pass(&period)
            } else {
                None
            };
            let put_back = |wallet: &mut Wallet, pass: &Option<Pass>| {
                if let Some(p) = pass {
                    wallet.add_passes([p.clone()]);
                }
            };
            let vouchers = wallet.take(family, cents);
            if vouchers.is_empty() {
                put_back(wallet, &pass);
                wallet.save()?;
                bail!(
                    "the wallet has no {} vouchers; withdraw or import some first",
                    family.as_str()
                );
            }
            let codes: Vec<String> = vouchers.iter().map(Voucher::encode).collect();
            let secret = self.new_secret(wallet);
            wallet.remember_session(OpenSession {
                secret: secret.clone(),
                family,
                opened_at: now(),
            });
            wallet.save()?;
            let req = OpenSessionRequest {
                vouchers: codes.clone(),
                secret_hash: crate::sha256_hex(&secret),
                pass: pass.as_ref().map(Pass::encode),
            };
            match self
                .transport
                .json::<SessionStatus>(Request::post_json("/u/sessions", &req))
                .await
            {
                Ok(_) => {
                    wallet.save()?;
                    return Ok(Session { secret, family });
                }
                Err(ApiError::Server { status: 409, body }) if body.error.kind == "secret_taken" => {
                    // Another device on this account opened a session with
                    // this secret: nothing was spent, pick another.
                    put_back(wallet, &pass);
                    wallet.add(family, vouchers);
                    wallet.forget_session(&secret);
                    wallet.save()?;
                }
                Err(ApiError::Server { status: 409, body }) if body.error.kind == "pass_spent" => {
                    // That pass was used already: drop it, nothing else was spent.
                    wallet.add(family, vouchers);
                    wallet.forget_session(&secret);
                    wallet.save()?;
                }
                Err(ApiError::Server { status: 409, body }) if !body.error.spent.is_empty() => {
                    put_back(wallet, &pass);
                    // Some were spent already (another device, an old backup).
                    // Nothing was spent this time: drop those, keep the rest.
                    let spent: Vec<String> = body
                        .error
                        .spent
                        .iter()
                        .filter_map(|&i| codes.get(i).cloned())
                        .collect();
                    let keep = vouchers.into_iter().filter(|v| !spent.contains(&v.encode()));
                    wallet.add(family, keep);
                    wallet.forget_session(&secret);
                    wallet.save()?;
                }
                Err(e @ ApiError::Server { .. }) => {
                    put_back(wallet, &pass);
                    wallet.add(family, vouchers);
                    wallet.forget_session(&secret);
                    wallet.save()?;
                    return Err(e.into());
                }
                Err(ApiError::Network(e)) => {
                    // Unknown outcome: retry with the same secret and vouchers.
                    // The server answers a repeat open with the same session.
                    match self
                        .transport
                        .json::<SessionStatus>(Request::post_json("/u/sessions", &req))
                        .await
                    {
                        Ok(_) => return Ok(Session { secret, family }),
                        Err(_) => {
                            put_back(wallet, &pass);
                            wallet.add(family, vouchers);
                            wallet.forget_session(&secret);
                            wallet.save()?;
                            return Err(e.context("opening a session"));
                        }
                    }
                }
            }
        }
        bail!("could not open a session: vouchers kept turning out spent")
    }

    pub async fn status(&self, session: &Session) -> Result<SessionStatus> {
        Ok(self
            .transport
            .json(Request::get("/u/sessions/current").bearer(&session.secret))
            .await?)
    }

    /// Add at least `cents` more from the wallet to an open session.
    pub async fn topup(&self, wallet: &mut Wallet, session: &Session, cents: i64) -> Result<SessionStatus> {
        let vouchers = wallet.take(session.family, cents);
        if vouchers.is_empty() {
            bail!("the wallet is empty");
        }
        wallet.save()?;
        let codes: Vec<String> = vouchers.iter().map(Voucher::encode).collect();
        match self
            .transport
            .json::<SessionStatus>(
                Request::post_json("/u/sessions/topup", &TopupRequest { vouchers: codes })
                    .bearer(&session.secret),
            )
            .await
        {
            Ok(status) => Ok(status),
            Err(e) => {
                if !matches!(e, ApiError::Server { status: 409, .. }) {
                    wallet.add(session.family, vouchers);
                    wallet.save()?;
                }
                Err(e.into())
            }
        }
    }

    /// Close a session and put its change in the wallet. Returns the change in cents.
    pub async fn close(&self, wallet: &mut Wallet, session: &Session) -> Result<i64> {
        // Change is the balance rounded up to the next 0.001¢: whole cents
        // the standard way, the rest as dust. One cent more of whole-cent
        // blanks covers the rounding.
        let max = if self.seed.is_some() {
            0
        } else {
            usd_to_cents_floor(&self.status(session).await?.balance_usd) + 1
        };
        let blanks = self.close_blanks(&session.secret, session.family, max)?;
        let id = crate::new_session_secret();
        wallet.push_pending(Pending {
            id: id.clone(),
            kind: "close".into(),
            blanks: blanks.clone(),
            secret: Some(session.secret.clone()),
            vouchers: Vec::new(),
            amount_cents: 0,
            pass_blanks: Vec::new(),
        });
        wallet.save()?;
        let change = self.close_with(&session.secret, &blanks).await?;
        let vouchers = self.finish(&blanks, &change)?;
        if self.seed.is_some() {
            wallet.add_from(change.family, vouchers, &format!("s:{}", session.secret));
        } else {
            wallet.add(change.family, vouchers);
        }
        wallet.finish_pending(&id);
        wallet.forget_session(&session.secret);
        wallet.save()?;
        Ok(change.change_cents)
    }

    async fn close_with(&self, secret: &str, blanks: &[Blank]) -> Result<ChangeResponse> {
        let req = CloseRequest {
            blanks: blanks.iter().map(Blank::to_wire).collect(),
        };
        Ok(self
            .transport
            .json(Request::post_json("/u/sessions/close", &req).bearer(secret))
            .await?)
    }

    /// Move a fixed amount of account balance into the wallet.
    pub async fn withdraw(&self, wallet: &mut Wallet, api_key: &str, cents: i64) -> Result<i64> {
        if !WITHDRAW_SIZES.contains(&cents) {
            bail!(
                "withdrawals come in fixed sizes: {}",
                WITHDRAW_SIZES
                    .iter()
                    .map(|c| format!("${}", c / 100))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let nonce = self.seed.as_ref().map(|_| random_nonce());
        let blanks = match (&self.seed, &nonce) {
            (Some(seed), Some(nonce)) => {
                let pieces = (cents / PIECE_CENTS).min(20);
                let mut values = vec![PIECE_CENTS; pieces as usize];
                values.extend(split(cents - pieces * PIECE_CENTS));
                let op = format!("withdraw:{nonce}");
                Blank::seeded_many(&self.keyset, Family::Paid, &values, false, seed, op.as_bytes(), 0)?
            }
            _ => Blank::many(&self.keyset, Family::Paid, &split(cents))?,
        };
        let id = nonce.clone().unwrap_or_else(crate::new_session_secret);
        wallet.push_pending(Pending {
            id: id.clone(),
            kind: "withdraw".into(),
            blanks: blanks.clone(),
            secret: Some(api_key.to_string()),
            vouchers: Vec::new(),
            amount_cents: cents,
            pass_blanks: Vec::new(),
        });
        wallet.save()?;
        let change = self.withdraw_with(api_key, cents, &blanks, nonce.as_deref()).await?;
        let vouchers = self.finish(&blanks, &change)?;
        match &nonce {
            Some(nonce) => wallet.add_from(Family::Paid, vouchers, &format!("w:{nonce}")),
            None => wallet.add(Family::Paid, vouchers),
        }
        wallet.finish_pending(&id);
        wallet.save()?;
        Ok(change.change_cents)
    }

    async fn withdraw_with(
        &self,
        api_key: &str,
        cents: i64,
        blanks: &[Blank],
        nonce: Option<&str>,
    ) -> Result<ChangeResponse> {
        let req = WithdrawRequest {
            nonce: nonce.map(str::to_string),
            amount_cents: cents,
            blanks: blanks.iter().map(Blank::to_wire).collect(),
        };
        Ok(self
            .transport
            .json(Request::post_json("/u/withdraw", &req).bearer(api_key))
            .await?)
    }

    /// Trade every voucher of a family for a fresh set with the same total,
    /// split the standard way. Useful after many small change vouchers pile up.
    pub async fn exchange(&self, wallet: &mut Wallet, family: Family) -> Result<i64> {
        let total = wallet.balance_millicents(family);
        if total == 0 {
            return Ok(0);
        }
        let vouchers = wallet.take(family, (total + MILLICENTS_PER_CENT - 1) / MILLICENTS_PER_CENT);
        let blanks = Blank::for_amount(&self.keyset, family, total)?;
        self.exchange_blanks(wallet, family, vouchers, blanks).await?;
        Ok(total / MILLICENTS_PER_CENT)
    }

    /// Spend `vouchers` (already out of the wallet) for fresh ones of
    /// `values`, which must add up to the same total.
    async fn exchange_vouchers(
        &self,
        wallet: &mut Wallet,
        family: Family,
        vouchers: Vec<Voucher>,
        values: &[i64],
    ) -> Result<i64> {
        let blanks = Blank::many(&self.keyset, family, values)?;
        self.exchange_blanks(wallet, family, vouchers, blanks).await
    }

    async fn exchange_blanks(
        &self,
        wallet: &mut Wallet,
        family: Family,
        vouchers: Vec<Voucher>,
        blanks: Vec<Blank>,
    ) -> Result<i64> {
        let total: i64 = vouchers.iter().map(Voucher::value_millicents).sum();
        let made: i64 = blanks
            .iter()
            .map(|b| if b.dust { b.denomination_cents } else { b.denomination_cents * MILLICENTS_PER_CENT })
            .sum();
        anyhow::ensure!(made == total, "exchange must keep the total");
        let codes: Vec<String> = vouchers.iter().map(Voucher::encode).collect();
        let id = crate::new_session_secret();
        wallet.push_pending(Pending {
            id: id.clone(),
            kind: "exchange".into(),
            blanks: blanks.clone(),
            secret: None,
            vouchers: codes.clone(),
            amount_cents: total,
            pass_blanks: Vec::new(),
        });
        wallet.save()?;
        match self.exchange_with(&codes, &blanks).await {
            Ok(change) => {
                let fresh = self.finish(&blanks, &change)?;
                wallet.add(change.family, fresh);
                wallet.finish_pending(&id);
                wallet.save()?;
                Ok(change.change_cents)
            }
            Err(e) => {
                if let Some(ApiError::Server { status, .. }) = e.downcast_ref::<ApiError>() {
                    if *status != 409 {
                        wallet.add(family, vouchers);
                        wallet.finish_pending(&id);
                        wallet.save()?;
                    }
                }
                Err(e)
            }
        }
    }

    async fn exchange_with(&self, codes: &[String], blanks: &[Blank]) -> Result<ChangeResponse> {
        let req = ExchangeRequest {
            vouchers: codes.to_vec(),
            blanks: blanks.iter().map(Blank::to_wire).collect(),
        };
        Ok(self
            .transport
            .json(Request::post_json("/u/exchange", &req))
            .await?)
    }

    /// How many passes the account can still get this month, at which tier.
    pub async fn pass_allowance(&self, api_key: &str) -> Result<PassAllowance> {
        Ok(self
            .transport
            .json(Request::get("/u/passes").bearer(api_key))
            .await?)
    }

    /// Get up to `count` passes for this month into the wallet. Do it ahead
    /// of time: the server sees when the account asks.
    pub async fn get_passes(&self, wallet: &mut Wallet, api_key: &str, count: i64) -> Result<usize> {
        let allowance = self.pass_allowance(api_key).await?;
        let count = count.min(allowance.remaining).max(0);
        if count == 0 {
            return Ok(0);
        }
        let nonce = self.seed.as_ref().map(|_| random_nonce());
        let blanks: Vec<PassBlank> = (0..count)
            .map(|j| match (&self.seed, &nonce) {
                (Some(seed), Some(nonce)) => PassBlank::seeded(
                    &self.keyset,
                    &allowance.tier,
                    &allowance.period,
                    seed,
                    format!("passes:{nonce}").as_bytes(),
                    j as u32,
                ),
                _ => PassBlank::new(&self.keyset, &allowance.tier, &allowance.period),
            })
            .collect::<Result<_>>()?;
        let id = nonce.clone().unwrap_or_else(crate::new_session_secret);
        wallet.push_pending(Pending {
            id: id.clone(),
            kind: "passes".into(),
            blanks: Vec::new(),
            secret: Some(api_key.to_string()),
            vouchers: Vec::new(),
            amount_cents: 0,
            pass_blanks: blanks.clone(),
        });
        wallet.save()?;
        let answer = self.passes_with(api_key, &blanks, nonce.as_deref()).await?;
        let passes = self.finish_passes(&blanks, &answer)?;
        let got = passes.len();
        if let Some(nonce) = &nonce {
            wallet.note_pass_source(&passes, &format!("p:{nonce}"));
        }
        wallet.add_passes(passes);
        wallet.finish_pending(&id);
        wallet.save()?;
        Ok(got)
    }

    async fn passes_with(&self, api_key: &str, blanks: &[PassBlank], nonce: Option<&str>) -> Result<PassResponse> {
        let first = blanks.first().ok_or_else(|| anyhow!("no passes asked for"))?;
        let req = PassRequest {
            nonce: nonce.map(str::to_string),
            tier: first.tier.clone(),
            period: first.period.clone(),
            blinded: blanks.iter().map(|b| crate::b64(&b.blinded)).collect(),
        };
        Ok(self
            .transport
            .json(Request::post_json("/u/passes", &req).bearer(api_key))
            .await?)
    }

    fn finish_passes(&self, blanks: &[PassBlank], answer: &PassResponse) -> Result<Vec<Pass>> {
        anyhow::ensure!(
            answer.blind_signatures.len() == blanks.len(),
            "the server signed a different number of passes"
        );
        blanks
            .iter()
            .zip(&answer.blind_signatures)
            .map(|(b, sig)| {
                b.finish(
                    &self.keyset,
                    &crate::unb64(sig).ok_or_else(|| anyhow!("signature is not base64url"))?,
                )
            })
            .collect()
    }

    /// Retry anything a crash or a lost response left half done, and close
    /// sessions a previous run left open. Returns cents recovered.
    pub async fn recover(&self, wallet: &mut Wallet) -> Result<i64> {
        let mut recovered = 0;
        for pending in wallet.pending().to_vec() {
            if pending.kind == "passes" {
                let answer = self
                    .passes_with(
                        pending.secret.as_deref().unwrap_or(""),
                        &pending.pass_blanks,
                        self.seed.as_ref().map(|_| pending.id.as_str()),
                    )
                    .await;
                match answer {
                    Ok(answer) => {
                        let passes = self.finish_passes(&pending.pass_blanks, &answer)?;
                        wallet.add_passes(passes);
                        wallet.finish_pending(&pending.id);
                    }
                    Err(e) => match e.downcast_ref::<ApiError>() {
                        Some(ApiError::Server { status: 400..=499, .. }) => {
                            wallet.finish_pending(&pending.id);
                        }
                        _ => return Err(e),
                    },
                }
                wallet.save()?;
                continue;
            }
            let result = match pending.kind.as_str() {
                "close" => {
                    self.close_with(pending.secret.as_deref().unwrap_or(""), &pending.blanks)
                        .await
                }
                "withdraw" => {
                    self.withdraw_with(
                        pending.secret.as_deref().unwrap_or(""),
                        pending.amount_cents,
                        &pending.blanks,
                        self.seed.as_ref().map(|_| pending.id.as_str()),
                    )
                    .await
                }
                "exchange" => self.exchange_with(&pending.vouchers, &pending.blanks).await,
                _ => continue,
            };
            match result {
                Ok(change) => {
                    let vouchers = self.finish(&pending.blanks, &change)?;
                    wallet.add(change.family, vouchers);
                    recovered += change.change_cents;
                    wallet.finish_pending(&pending.id);
                    if let Some(secret) = &pending.secret {
                        wallet.forget_session(secret);
                    }
                }
                Err(e) => match e.downcast_ref::<ApiError>() {
                    // The server has no record of it: nothing to recover.
                    Some(ApiError::Server { status: 404 | 410, .. }) => {
                        wallet.finish_pending(&pending.id);
                    }
                    _ => return Err(e),
                },
            }
            wallet.save()?;
        }
        let pending_secrets: Vec<String> = wallet
            .pending()
            .iter()
            .filter_map(|p| p.secret.clone())
            .collect();
        for open in wallet.sessions().to_vec() {
            if pending_secrets.contains(&open.secret) {
                continue;
            }
            let session = Session {
                secret: open.secret.clone(),
                family: open.family,
            };
            match self.close(wallet, &session).await {
                Ok(cents) => recovered += cents,
                Err(e) => match e.downcast_ref::<ApiError>() {
                    Some(ApiError::Server { status: 401 | 404 | 410, .. }) => {
                        wallet.forget_session(&open.secret);
                        wallet.save()?;
                    }
                    _ => return Err(e),
                },
            }
        }
        Ok(recovered)
    }

    /// Tell the server which withdrawals, passes and sessions this wallet has
    /// spent everything from, so it can delete them (seeded wallets). The
    /// account key is needed for withdrawals and passes; sessions use their
    /// own secret. Call it at a quiet moment, not right after a session
    /// opens, so its timing says little.
    pub async fn flush_done(&self, wallet: &mut Wallet, api_key: Option<&str>) -> Result<()> {
        let finished = wallet.finished_sources();
        let mut done = Vec::new();
        let nonces: Vec<String> = finished
            .iter()
            .filter_map(|s| s.strip_prefix("w:").or_else(|| s.strip_prefix("p:")))
            .map(str::to_string)
            .collect();
        if let (Some(key), false) = (api_key, nonces.is_empty()) {
            let _: serde_json::Value = self
                .transport
                .json(Request::post_json("/u/issued/done", &DoneRequest { nonces }).bearer(key))
                .await?;
            done.extend(finished.iter().filter(|s| !s.starts_with("s:")).cloned());
        }
        for source in finished.iter().filter(|s| s.starts_with("s:")) {
            let secret = &source[2..];
            match self
                .transport
                .json::<serde_json::Value>(Request::post_json("/u/sessions/done", &serde_json::json!({})).bearer(secret))
                .await
            {
                Ok(_) | Err(ApiError::Server { status: 401 | 404 | 410, .. }) => done.push(source.clone()),
                Err(e) => return Err(e.into()),
            }
        }
        wallet.forget_sources(&done);
        wallet.save()
    }

    /// Rebuild a seeded wallet from the server's records: withdrawals and
    /// passes the account has not marked done (needs its key), and sessions
    /// left open or with change not yet collected (found by comparing hash
    /// prefixes on this device). Then drop whatever was spent since. Returns
    /// the cents recovered into the wallet.
    pub async fn restore(&self, wallet: &mut Wallet, api_key: Option<&str>) -> Result<i64> {
        let seed = self
            .seed
            .clone()
            .ok_or_else(|| anyhow!("restoring needs the seed from the account number"))?;
        // (family, vouchers, source)
        let mut found: Vec<(Family, Vec<Voucher>, String)> = Vec::new();
        let mut passes: Vec<(Vec<Pass>, String)> = Vec::new();
        let mut since = now();

        if let Some(key) = api_key {
            let issued: Vec<Issued> = self.transport.json(Request::get("/u/issued").bearer(key)).await?;
            for it in issued {
                since = since.min(it.created);
                match it.kind.as_str() {
                    "withdraw" => {
                        let req: WithdrawRequest = serde_json::from_value(it.request)?;
                        let answer: ChangeResponse = serde_json::from_value(it.answer)?;
                        let op = format!("withdraw:{}", it.nonce);
                        let blanks = req
                            .blanks
                            .iter()
                            .enumerate()
                            .map(|(j, b)| {
                                Blank::seeded(&self.keyset, Family::Paid, b.denomination_cents, b.dust, &seed, op.as_bytes(), j as u32)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        if !same_blinded(&blanks, &req.blanks) {
                            continue; // not made with this seed
                        }
                        found.push((Family::Paid, self.finish(&blanks, &answer)?, format!("w:{}", it.nonce)));
                    }
                    "passes" => {
                        let req: PassRequest = serde_json::from_value(it.request)?;
                        let answer: PassResponse = serde_json::from_value(it.answer)?;
                        let op = format!("passes:{}", it.nonce);
                        let blanks = (0..req.blinded.len())
                            .map(|j| PassBlank::seeded(&self.keyset, &req.tier, &req.period, &seed, op.as_bytes(), j as u32))
                            .collect::<Result<Vec<_>>>()?;
                        if blanks.iter().zip(&req.blinded).any(|(b, w)| crate::b64(&b.blinded) != *w) {
                            continue;
                        }
                        passes.push((self.finish_passes(&blanks, &answer)?, format!("p:{}", it.nonce)));
                    }
                    _ => {}
                }
            }
        }

        let unclaimed: Vec<UnclaimedSession> = self.transport.json(Request::get("/u/sessions/unclaimed")).await?;
        let wanted: std::collections::HashSet<&str> = unclaimed.iter().map(|u| u.h.as_str()).collect();
        let mut minutes: Vec<u64> = unclaimed
            .iter()
            .flat_map(|u| u.m.saturating_sub(2)..=u.m + 2)
            .collect();
        minutes.sort_unstable();
        minutes.dedup();
        for m in minutes {
            for k in 0..crate::seed::SESSIONS_PER_MINUTE {
                let secret = seed.session_secret(m, k);
                let hash = crate::sha256_hex(&secret);
                // A session this device still knows is in use, not stranded.
                if !wanted.contains(prefix(&hash)) || wallet.sessions().iter().any(|s| s.secret == secret) {
                    continue;
                }
                let status = match self.status(&Session { secret: secret.clone(), family: Family::Paid }).await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                since = since.min(m * 60);
                let blanks = self.close_blanks(&secret, status.family, 0)?;
                let change = self.close_with(&secret, &blanks).await?;
                found.push((change.family, self.finish(&blanks, &change)?, format!("s:{secret}")));
                wallet.forget_session(&secret);
            }
        }

        let spent: SpentList = self
            .transport
            .json(Request::get(&format!("/u/spent?since={}", since.saturating_sub(120))))
            .await?;
        let spent: std::collections::HashSet<String> = spent.hashes.into_iter().collect();
        let unspent = |message: &[u8]| !spent.contains(prefix(&crate::sha256_hex(message)));

        let mut cents = 0;
        let held: std::collections::HashSet<String> = wallet.vouchers().iter().map(|h| h.voucher.encode()).collect();
        for (family, vouchers, source) in found {
            let keep: Vec<Voucher> = vouchers
                .into_iter()
                .filter(|v| unspent(&v.message) && !held.contains(&v.encode()))
                .collect();
            cents += keep.iter().map(Voucher::value_millicents).sum::<i64>();
            wallet.add_from(family, keep, &source);
        }
        for (list, source) in passes {
            let keep: Vec<Pass> = list.into_iter().filter(|p| unspent(&p.message)).collect();
            wallet.note_pass_source(&keep, &source);
            wallet.add_passes(keep);
        }
        wallet.save()?;
        Ok(cents / MILLICENTS_PER_CENT)
    }
}

fn same_blinded(blanks: &[Blank], wire: &[BlindedVoucher]) -> bool {
    blanks.len() == wire.len()
        && blanks
            .iter()
            .zip(wire)
            .all(|(b, w)| crate::b64(&b.blinded) == w.blinded_message)
}
