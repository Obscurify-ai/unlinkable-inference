//! Unlinkable inference in a web page: `unlinkable_inference::manager` as a
//! WebAssembly module. `js/index.js` wraps it in a `fetch` that sends each
//! conversation's session secret instead of the page's cookie.

use futures::lock::Mutex;
use std::rc::Rc;
use unlinkable_inference::manager;
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// `{login_key, seed}` (hex) for an account number. Slow on purpose.
#[wasm_bindgen(js_name = accountKeys)]
pub fn account_keys(number: &str) -> Result<JsValue, JsValue> {
    let keys = unlinkable_inference::seed::account_keys(number).map_err(err)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"login_key".into(), &keys.login_key.into())?;
    js_sys::Reflect::set(&obj, &"seed".into(), &hex::encode(keys.seed.0).into())?;
    Ok(obj.into())
}

/// A fresh random 16-digit account number, made on the device.
#[wasm_bindgen(js_name = newAccountNumber)]
pub fn new_account_number() -> String {
    unlinkable_inference::seed::new_account_number()
}

/// A fresh account code (20 characters, 96 random bits), made on the device.
#[wasm_bindgen(js_name = newAccountCode)]
pub fn new_account_code() -> String {
    unlinkable_inference::seed::new_account_code()
}

/// What `input` is: "code" (an account code whose typo check holds), "number"
/// (16 digits) or "" (neither yet).
#[wasm_bindgen(js_name = credentialKind)]
pub fn credential_kind(input: &str) -> String {
    match unlinkable_inference::seed::normalize_credential(input) {
        Some(unlinkable_inference::seed::Credential::Number(_)) => "number",
        Some(unlinkable_inference::seed::Credential::Code(_)) => "code",
        None => "",
    }
    .into()
}

#[wasm_bindgen]
pub struct Manager {
    inner: Rc<Mutex<manager::Manager>>,
}

macro_rules! promise {
    ($self:ident, |$m:ident| $body:expr) => {{
        let inner = $self.inner.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            #[allow(unused_mut)]
            let mut $m = inner.lock().await;
            $body
        })
    }};
}

#[wasm_bindgen]
impl Manager {
    /// Connect to `server` (origin) with the seed (hex) and the state saved
    /// last time, if any. Refuses a server whose keys changed since they were
    /// pinned. `api_key` tops the wallet up; without it the wallet spends what
    /// it holds.
    pub async fn connect(server: String, seed_hex: String, state: Option<String>, api_key: Option<String>) -> Result<Manager, JsValue> {
        let seed: [u8; 32] = hex::decode(seed_hex.trim())
            .map_err(err)?
            .try_into()
            .map_err(|_| err("the seed is 32 bytes"))?;
        let mut m = manager::Manager::connect(&server, unlinkable_inference::seed::Seed(seed), state.as_deref()).await.map_err(err)?;
        m.api_key = api_key;
        Ok(Manager { inner: Rc::new(Mutex::new(m)) })
    }

    /// Everything to save, as JSON. `null` while a call runs (save after it).
    pub fn state(&self) -> Option<String> {
        self.inner.try_lock().map(|m| m.state())
    }

    /// `{paid_cents, passes}`, or `null` while a call runs.
    pub fn summary(&self) -> JsValue {
        let Some(mut m) = self.inner.try_lock() else { return JsValue::NULL };
        let (cents, passes) = m.summary();
        let obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&obj, &"paid_cents".into(), &(cents as f64).into());
        let _ = js_sys::Reflect::set(&obj, &"passes".into(), &(passes as f64).into());
        obj.into()
    }

    /// What private use cost: `{spent: [{at, millicents}], prepaid_millicents}`
    /// (`at` in Unix seconds; 100000 millicents = $1). Changes nothing.
    pub fn spending(&self) -> js_sys::Promise {
        promise!(self, |m| {
            let s = m.spending().await;
            js_sys::JSON::parse(&serde_json::to_string(&s).map_err(err)?)
        })
    }

    /// A reply in conversation `chat` said it cost `usd`.
    #[wasm_bindgen(js_name = noteCost)]
    pub fn note_cost(&self, chat: String, usd: f64) -> js_sys::Promise {
        promise!(self, |m| {
            m.note_cost(&chat, (usd * 100_000.0).round() as i64);
            Ok(JsValue::TRUE)
        })
    }

    /// Close sessions no conversation uses, bring back what a lost browser
    /// left behind, top up. Resolves to the cents recovered.
    pub fn start(&self) -> js_sys::Promise {
        promise!(self, |m| Ok((m.start().await.map_err(err)? as f64).into()))
    }

    /// The session secret for conversation `chat` (opening one if needed).
    pub fn session(&self, chat: String) -> js_sys::Promise {
        promise!(self, |m| Ok(m.session(&chat).await.map_err(err)?.into()))
    }

    /// The secret of the session that asked for held reply `id`.
    pub fn reply(&self, id: String) -> js_sys::Promise {
        promise!(self, |m| Ok(m.reply(&id).map(JsValue::from).unwrap_or(JsValue::NULL)))
    }

    #[wasm_bindgen(js_name = noteReply)]
    pub fn note_reply(&self, id: String, secret: String) -> js_sys::Promise {
        promise!(self, |m| {
            m.note_reply(&id, &secret);
            Ok(JsValue::TRUE)
        })
    }

    /// A 402: add more to the session, doubling with each attempt. Rejects when there is nothing more to add.
    #[wasm_bindgen(js_name = ranOut)]
    pub fn ran_out(&self, secret: String, attempt: u32) -> js_sys::Promise {
        promise!(self, |m| {
            m.ran_out(&secret, attempt).await.map_err(err)?;
            Ok(JsValue::TRUE)
        })
    }

    /// `null` when nothing waits; else the Unix time (seconds) a conversation may go on about
    /// (it waits for the wallet: hold its request, keep calling `tick`, ask again).
    /// `undefined` while a call runs.
    pub fn refilling(&self) -> JsValue {
        let Some(m) = self.inner.try_lock() else { return JsValue::UNDEFINED };
        match m.refilling() {
            Some(at) => (at as f64).into(),
            None => JsValue::NULL,
        }
    }

    /// Money was just added to the account, or its plan changed (in this app): ask it now.
    #[wasm_bindgen(js_name = moneyAdded)]
    pub fn money_added(&self) -> js_sys::Promise {
        promise!(self, |m| {
            m.money_added().await;
            Ok(JsValue::TRUE)
        })
    }

    /// Money was just added to the account: the next top-up asks it again.
    #[wasm_bindgen(js_name = askAgain)]
    pub fn ask_again(&self) -> js_sys::Promise {
        promise!(self, |m| {
            m.ask_again();
            Ok(JsValue::TRUE)
        })
    }

    /// A 403 with the `x-pass-required` header: present a pass with that label for this
    /// session. True: it has one now, send the request again.
    #[wasm_bindgen(js_name = needsPass)]
    pub fn needs_pass(&self, secret: String, label: String) -> js_sys::Promise {
        promise!(self, |m| {
            let retry = m.needs_pass(&secret, &label).await.map_err(err)?;
            Ok(JsValue::from_bool(retry))
        })
    }

    /// A 401: the conversation gets a new session next time.
    pub fn expired(&self, secret: String) -> js_sys::Promise {
        promise!(self, |m| {
            m.expired(&secret);
            Ok(JsValue::TRUE)
        })
    }

    /// Every 30 s or so: close quiet sessions for their change, top up.
    pub fn tick(&self) -> js_sys::Promise {
        promise!(self, |m| {
            m.tick().await;
            Ok(JsValue::TRUE)
        })
    }
}
