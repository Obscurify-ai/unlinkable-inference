//! The core client for a web page. The page keeps the wallet JSON (e.g. in
//! localStorage) and the seed; this module makes every request, with no
//! cookies, and returns session secrets for the page to send as
//! `Authorization: Bearer`.

use futures::lock::Mutex;
use std::rc::Rc;
use unlinkable_core::net::{Client, Session, Transport};
use unlinkable_core::{Family, Wallet};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// `{login_key, seed}` (hex) for an account number. Slow on purpose.
#[wasm_bindgen(js_name = accountKeys)]
pub fn account_keys(number: &str) -> Result<JsValue, JsValue> {
    let keys = unlinkable_core::seed::account_keys(number).map_err(err)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"login_key".into(), &keys.login_key.into())?;
    js_sys::Reflect::set(&obj, &"seed".into(), &hex::encode(keys.seed.0).into())?;
    Ok(obj.into())
}

/// A fresh random 16-digit account number, made on the device.
#[wasm_bindgen(js_name = newAccountNumber)]
pub fn new_account_number() -> String {
    let mut digits = String::new();
    while digits.len() < 16 {
        let secret = unlinkable_core::new_session_secret();
        let raw = unlinkable_core::unb64(&secret[unlinkable_core::SESSION_SECRET_PREFIX.len()..]).unwrap_or_default();
        // Bytes 250..=255 are skipped so every digit is equally likely.
        for b in raw.into_iter().filter(|b| *b < 250) {
            if digits.len() < 16 {
                digits.push(char::from(b'0' + b % 10));
            }
        }
    }
    digits
}

struct Inner {
    client: Client,
    wallet: Mutex<Wallet>,
}

#[wasm_bindgen]
pub struct Unlinkable {
    inner: Rc<Inner>,
}

macro_rules! promise {
    ($self:ident, |$inner:ident| $body:expr) => {{
        let $inner = $self.inner.clone();
        wasm_bindgen_futures::future_to_promise(async move { $body })
    }};
}

#[wasm_bindgen]
impl Unlinkable {
    /// Connect to `server` (origin) with the seed (hex) and the saved wallet
    /// JSON, if any. Refuses a server whose keys changed since they were pinned.
    pub async fn connect(server: String, seed_hex: String, wallet_json: Option<String>) -> Result<Unlinkable, JsValue> {
        let seed: [u8; 32] = hex::decode(seed_hex.trim())
            .map_err(err)?
            .try_into()
            .map_err(|_| err("the seed is 32 bytes"))?;
        let mut wallet = match wallet_json.filter(|j| !j.is_empty()) {
            Some(j) => Wallet::from_json(&j).map_err(err)?,
            None => Wallet::in_memory(),
        };
        let transport = Transport::new(&server);
        let keyset = transport.fetch_keyset().await.map_err(err)?;
        keyset.check().map_err(err)?;
        let fp = keyset.fingerprint();
        match wallet.pinned() {
            Some(p) if p != fp => return Err(err(format!("the server's keys changed ({fp}, pinned {p})"))),
            Some(_) => {}
            None => wallet.pin(Some(fp)),
        }
        let client = Client::new(transport, keyset).with_seed(unlinkable_core::seed::Seed(seed));
        Ok(Unlinkable {
            inner: Rc::new(Inner {
                client,
                wallet: Mutex::new(wallet),
            }),
        })
    }

    /// The wallet as JSON, for the page to save. `null` while an operation runs.
    #[wasm_bindgen(js_name = walletJson)]
    pub fn wallet_json(&self) -> Option<String> {
        self.inner.wallet.try_lock().map(|w| w.to_json())
    }

    /// `{paid_cents, passes}`, or `null` while an operation runs.
    pub fn summary(&self) -> JsValue {
        let Some(mut w) = self.inner.wallet.try_lock() else { return JsValue::NULL };
        let obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&obj, &"paid_cents".into(), &(w.balance_cents(Family::Paid) as f64).into());
        let passes = w.passes(&unlinkable_core::pass::current_period()).len();
        let _ = js_sys::Reflect::set(&obj, &"passes".into(), &(passes as f64).into());
        obj.into()
    }

    /// Open a session worth at least `cents`; resolves to its secret.
    pub fn open(&self, cents: i32) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let s = inner.client.open(&mut w, Family::Paid, cents as i64).await.map_err(err)?;
            Ok(s.secret.into())
        })
    }

    pub fn topup(&self, secret: String, cents: i32) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let session = Session { secret, family: Family::Paid };
            inner.client.topup(&mut w, &session, cents as i64).await.map_err(err)?;
            Ok(JsValue::TRUE)
        })
    }

    /// Close a session; resolves to the change in cents.
    pub fn close(&self, secret: String) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let family = w.sessions().iter().find(|s| s.secret == secret).map(|s| s.family).unwrap_or(Family::Paid);
            let cents = inner.client.close(&mut w, &Session { secret, family }).await.map_err(err)?;
            Ok((cents as f64).into())
        })
    }

    pub fn withdraw(&self, api_key: String, cents: i32) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let got = inner.client.withdraw(&mut w, &api_key, cents as i64).await.map_err(err)?;
            Ok((got as f64).into())
        })
    }

    #[wasm_bindgen(js_name = getPasses)]
    pub fn get_passes(&self, api_key: String, count: i32) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let got = inner.client.get_passes(&mut w, &api_key, count as i64).await.map_err(err)?;
            Ok((got as f64).into())
        })
    }

    /// Rebuild the wallet from the server's records (a fresh browser, Tor
    /// Browser after closing). Resolves to the cents recovered.
    pub fn restore(&self, api_key: Option<String>) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            let cents = inner.client.restore(&mut w, api_key.as_deref()).await.map_err(err)?;
            Ok((cents as f64).into())
        })
    }

    /// Let the server forget records whose money is fully spent.
    pub fn flush(&self, api_key: Option<String>) -> js_sys::Promise {
        promise!(self, |inner| {
            let mut w = inner.wallet.lock().await;
            inner.client.flush_done(&mut w, api_key.as_deref()).await.map_err(err)?;
            Ok(JsValue::TRUE)
        })
    }
}
