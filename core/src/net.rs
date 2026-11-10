//! Talking to a server over HTTPS.
//!
//! Hiding this device's IP address is left to the network it runs on (Tor, a
//! VPN): nothing here depends on a third party. What this layer guarantees is
//! that requests carry a session secret, never an account key or a cookie.

use crate::blank::Blank;
use crate::denominations::{blanks_for_any_amount_up_to, split, WITHDRAW_SIZES};
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
        let url = format!("{}{}", self.server, req.path);
        let method = reqwest::Method::from_bytes(req.method.as_bytes())?;
        let mut builder = self.http.request(method, &url);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(observer) = &self.observer {
            observer(&Observed {
                server: self.server.clone(),
                bytes_sent: req.body.len(),
                server_sees: Self::describe(&req),
            });
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
        let url = format!("{}/u/keys", self.server);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            bail!("{url} answered {}", resp.status());
        }
        Ok(resp.json().await?)
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
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        Self { transport, keyset }
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
            .filter(|h| h.family == family)
            .map(|h| h.voucher.denomination_cents)
            .collect();
        let small: i64 = mine.iter().filter(|&&v| v <= cents).sum();
        if small >= cents {
            return Ok(());
        }
        let Some(&big) = mine.iter().filter(|&&v| v > 2 * cents).min() else {
            return Ok(());
        };
        let pieces = (big / cents).min(8);
        let mut values: Vec<i64> = (0..pieces).flat_map(|_| split(cents)).collect();
        values.extend(split(big - pieces * cents));
        let voucher = wallet
            .vouchers()
            .iter()
            .find(|h| h.family == family && h.voucher.denomination_cents == big)
            .map(|h| h.voucher.clone())
            .expect("found above");
        wallet.forget(&[voucher.encode()]);
        self.exchange_vouchers(wallet, family, vec![voucher], &values).await?;
        Ok(())
    }

    /// Open a session worth at least `cents` from the wallet.
    pub async fn open(&self, wallet: &mut Wallet, family: Family, cents: i64) -> Result<Session> {
        self.break_up(wallet, family, cents).await?;
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
            let secret = crate::new_session_secret();
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
        let status = self.status(session).await?;
        let max = usd_to_cents_floor(&status.balance_usd);
        let blanks = Blank::many(&self.keyset, session.family, &blanks_for_any_amount_up_to(max))?;
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
        wallet.add(change.family, vouchers);
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
        let blanks = Blank::many(&self.keyset, Family::Paid, &split(cents))?;
        let id = crate::new_session_secret();
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
        let change = self.withdraw_with(api_key, cents, &blanks).await?;
        let vouchers = self.finish(&blanks, &change)?;
        wallet.add(Family::Paid, vouchers);
        wallet.finish_pending(&id);
        wallet.save()?;
        Ok(change.change_cents)
    }

    async fn withdraw_with(&self, api_key: &str, cents: i64, blanks: &[Blank]) -> Result<ChangeResponse> {
        let req = WithdrawRequest {
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
        let total = wallet.balance_cents(family);
        if total == 0 {
            return Ok(0);
        }
        let vouchers = wallet.take(family, total);
        self.exchange_vouchers(wallet, family, vouchers, &split(total)).await
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
        let total: i64 = vouchers.iter().map(|v| v.denomination_cents).sum();
        anyhow::ensure!(values.iter().sum::<i64>() == total, "exchange must keep the total");
        let codes: Vec<String> = vouchers.iter().map(Voucher::encode).collect();
        let blanks = Blank::many(&self.keyset, family, values)?;
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
        let blanks: Vec<PassBlank> = (0..count)
            .map(|_| PassBlank::new(&self.keyset, &allowance.tier, &allowance.period))
            .collect::<Result<_>>()?;
        let id = crate::new_session_secret();
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
        let answer = self.passes_with(api_key, &blanks).await?;
        let passes = self.finish_passes(&blanks, &answer)?;
        let got = passes.len();
        wallet.add_passes(passes);
        wallet.finish_pending(&id);
        wallet.save()?;
        Ok(got)
    }

    async fn passes_with(&self, api_key: &str, blanks: &[PassBlank]) -> Result<PassResponse> {
        let first = blanks.first().ok_or_else(|| anyhow!("no passes asked for"))?;
        let req = PassRequest {
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
                    .passes_with(pending.secret.as_deref().unwrap_or(""), &pending.pass_blanks)
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
}
