//! End to end: reference server, a real relay and the proxy, over real
//! sockets. Buy (test money) → withdraw → open → stream → close → change,
//! then read the server's whole database and try to link.

use futures::StreamExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use unlinkable_core::{Family, Wallet};
use unlinkable_gateway::{ohttp::OhttpKeys, signer::KeyStore};
use unlinkable_proxy::serve::{Proxy, Settings};
use unlinkable_proxy::{connect, Options};

const VALUES: [i64; 10] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

struct Stack {
    server: String,
    relay: String,
    backend: Arc<unlinkable_reference_server::MemoryBackend>,
}

async fn listen() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, format!("http://{addr}"))
}

async fn start_stack() -> Stack {
    let keys = KeyStore::new(&VALUES, None).unwrap();
    let ref_server = unlinkable_reference_server::build(keys, OhttpKeys::ephemeral(), Duration::from_secs(3600));
    let backend = ref_server.backend.clone();
    let (l, server) = listen().await;
    tokio::spawn(async move {
        axum::serve(l, ref_server.router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    let relay = unlinkable_relay::Relay::from_specs(&[format!("ref={server}")]).unwrap();
    let (l, relay_origin) = listen().await;
    tokio::spawn(async move { axum::serve(l, relay.router()).await.unwrap() });
    Stack {
        server,
        relay: format!("{relay_origin}/ref"),
        backend,
    }
}

fn temp_wallet() -> PathBuf {
    std::env::temp_dir()
        .join(format!("unlinkable-e2e-{}", rand_id()))
        .join("wallet.json")
}

fn rand_id() -> String {
    unlinkable_core::sha256_hex(format!("{:?}{:?}", Instant::now(), std::thread::current().id()))[..12].to_string()
}

async fn new_account(server: &str, cents: i64) -> String {
    let v: Value = reqwest::Client::new()
        .post(format!("{server}/test/accounts"))
        .json(&json!({"balance_cents": cents}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["api_key"].as_str().unwrap().to_string()
}

async fn start_proxy(opts: &Options, settings: Settings) -> (Arc<Proxy>, String) {
    let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
    let client = connect(opts, &mut wallet).await.unwrap();
    let proxy = Proxy::new(client, wallet, settings, opts.clone());
    let (l, url) = listen().await;
    let p = proxy.clone();
    tokio::spawn(async move { unlinkable_proxy::serve::run(l, p, std::future::pending()).await.unwrap() });
    (proxy, url)
}

async fn status(proxy_url: &str) -> Value {
    reqwest::get(format!("{proxy_url}/_unlinkable/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Read an SSE stream, returning the concatenated data lines and how long
/// passed between the first content and the end of the stream.
async fn read_stream(resp: reqwest::Response) -> (String, Duration) {
    let mut stream = resp.bytes_stream();
    let mut text = String::new();
    let mut first: Option<Instant> = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        let s = String::from_utf8_lossy(&chunk).to_string();
        if first.is_none() && s.contains("echo") {
            first = Some(Instant::now());
        }
        text.push_str(&s);
    }
    (text, first.map(|f| f.elapsed()).unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chat_through_the_relay_cannot_be_tied_to_the_account_that_paid_for_it() {
    let stack = start_stack().await;
    let api_key = new_account(&stack.server, 2_000).await;
    let opts = Options {
        server: stack.server.clone(),
        relay: Some(stack.relay.clone()),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };

    // Withdraw $5 into the wallet, through the relay.
    {
        let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
        let client = connect(&opts, &mut wallet).await.unwrap();
        assert!(wallet.pinned().is_some(), "keys are pinned on first use");
        let got = client.withdraw(&mut wallet, &api_key, 500).await.unwrap();
        assert_eq!(got, 500);
        assert_eq!(wallet.balance_cents(Family::Paid), 500);
        // Odd amounts are refused: fixed sizes only.
        assert!(client.withdraw(&mut wallet, &api_key, 300).await.is_err());
    }
    assert_eq!(stack.backend.account_balance(&api_key), Some(1_500));

    let (proxy, url) = start_proxy(
        &opts,
        Settings {
            funding_cents: 100,
            ..Settings::default()
        },
    )
    .await;
    let http = reqwest::Client::new();

    // OpenAI, streamed, slow enough to tell a stream from a buffered answer.
    let resp = http
        .post(format!("{url}/v1/chat/completions"))
        .header("authorization", "Bearer whatever-the-agent-sends")
        .json(&json!({"model": "echo-slow", "stream": true,
            "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "one two three four"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (text, spread) = read_stream(resp).await;
    assert!(text.contains("\"content\":\"four\""), "{text}");
    assert!(text.contains("[DONE]"));
    assert!(
        spread >= Duration::from_millis(400),
        "words should arrive as they are made, not all at the end (spread {spread:?})"
    );

    // Same conversation, next turn: same session.
    let resp = http
        .post(format!("{url}/v1/chat/completions"))
        .header("authorization", "Bearer whatever-the-agent-sends")
        .json(&json!({"model": "echo", "messages": [
            {"role": "system", "content": "be brief"}, {"role": "user", "content": "one two three four"},
            {"role": "assistant", "content": "echo: one two three four"}, {"role": "user", "content": "again"}]}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "echo: again");
    assert_eq!(status(&url).await["sessions"].as_array().unwrap().len(), 1);

    // Anthropic Messages (Claude Code's API), streamed: a new conversation,
    // so a second session.
    let resp = http
        .post(format!("{url}/v1/messages"))
        .header("x-api-key", "claude-code")
        .header("anthropic-version", "2023-06-01")
        .json(&json!({"model": "echo", "max_tokens": 50, "stream": true,
            "messages": [{"role": "user", "content": "hello there"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (text, _) = read_stream(resp).await;
    assert!(text.contains("event: message_stop"), "{text}");
    assert!(text.contains("there"));
    let st = status(&url).await;
    assert_eq!(st["sessions"].as_array().unwrap().len(), 2);
    assert!(st["traffic"][0]["server_sees"].as_str().unwrap().contains("session secret"));
    assert!(!st["traffic"][0]["server_sees"].as_str().unwrap().contains("claude-code"));

    // A web page cannot spend the wallet.
    let refused = http
        .post(format!("{url}/v1/chat/completions"))
        .header("origin", "https://evil.example")
        .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "x"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);

    // A browser's favicon request is answered here and opens no session.
    let favicon = http.get(format!("{url}/favicon.ico")).send().await.unwrap();
    assert_eq!(favicon.status(), 404);
    assert_eq!(status(&url).await["sessions"].as_array().unwrap().len(), 2);

    // Close everything: change comes back to the wallet.
    proxy.close_all().await;
    let st = status(&url).await;
    let left = st["wallet"]["paid_cents"].as_i64().unwrap();
    assert!(st["sessions"].as_array().unwrap().is_empty());
    assert!(left > 400 && left < 500, "spent a little, kept the rest: {left}");

    // Now read everything the server has and try to link.
    let db = stack.backend.dump();
    let requests = db["requests"].as_array().unwrap();
    let session_requests: Vec<&Value> = requests.iter().filter(|r| r["credential"] == "session").collect();
    assert!(session_requests.len() >= 5, "{requests:?}");
    for r in &session_requests {
        assert_eq!(r["via_ohttp"], true, "every session request came through the relay: {r}");
        assert_eq!(r["peer"], "0.0.0.0", "no client address reached the app: {r}");
        assert_eq!(r["had_cookie"], false);
    }
    for r in requests.iter().filter(|r| r["credential"] == "account") {
        assert_eq!(r["path"], "/u/withdraw", "the account key is only ever used to withdraw: {r}");
    }
    // What the server keeps from the withdrawal (hashes of what it signed)
    // shares nothing with what it keeps when vouchers are spent.
    let withdrawn: Vec<&str> = db["withdrawals"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|w| w["blinded_hashes"].as_array().unwrap().iter().map(|h| h.as_str().unwrap()))
        .collect();
    let spent: Vec<&str> = db["spent_vouchers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["hash"].as_str().unwrap())
        .collect();
    assert!(!withdrawn.is_empty() && !spent.is_empty());
    assert!(withdrawn.iter().all(|w| !spent.contains(w)));
    let dump_text = db.to_string();
    let sessions = db["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    for s in sessions {
        let keys: Vec<&String> = s.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["balance_usd", "closed_at", "family", "funded_cents", "opened_at", "secret_hash"],
            "a session row holds nothing about who opened it"
        );
    }
    // The account's token hash appears only in the account and withdrawal rows.
    let account_hash = unlinkable_core::sha256_hex(&api_key);
    assert_eq!(dump_text.matches(&account_hash).count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_changes_its_keys_is_refused() {
    let stack = start_stack().await;
    let wallet_path = temp_wallet();
    let opts = Options {
        server: stack.server.clone(),
        relay: Some(stack.relay.clone()),
        wallet: Some(wallet_path.clone()),
        pins: Vec::new(),
    };
    let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
    connect(&opts, &mut wallet).await.unwrap();

    // Another server (other keys) at a new address, same wallet: as if the
    // server swapped in a key just for this user.
    let other = start_stack().await;
    let opts2 = Options {
        server: other.server.clone(),
        relay: Some(other.relay.clone()),
        wallet: Some(wallet_path),
        pins: Vec::new(),
    };
    let mut wallet = Wallet::open(opts2.wallet_path()).unwrap();
    let err = match connect(&opts2, &mut wallet).await {
        Ok(_) => panic!("a different keyset must not be accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("not one you pinned"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_answers_are_retried_safely_and_spent_vouchers_are_dropped() {
    let stack = start_stack().await;
    let api_key = new_account(&stack.server, 1_000).await;
    let opts = Options {
        server: stack.server.clone(),
        relay: Some(stack.relay.clone()),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };
    let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
    let client = connect(&opts, &mut wallet).await.unwrap();
    client.withdraw(&mut wallet, &api_key, 100).await.unwrap();
    let backup = wallet.export();

    // Spend everything in a session and close it.
    let session = client.open(&mut wallet, Family::Paid, 100).await.unwrap();
    let change = client.close(&mut wallet, &session).await.unwrap();
    assert_eq!(change, 100, "nothing used, everything back");

    // Restore the old backup: those vouchers are spent now. Opening with
    // them is refused, nothing is spent, and the wallet forgets them.
    let mut restored = Wallet::open(temp_wallet()).unwrap();
    for code in &backup {
        let v = unlinkable_core::Voucher::parse(code).unwrap();
        restored.add(Family::Paid, [v]);
    }
    let err = client.open(&mut restored, Family::Paid, 100).await.unwrap_err();
    assert!(err.to_string().contains("no paid vouchers"), "{err}");
    assert_eq!(restored.balance_cents(Family::Paid), 0);

    // Exchange: the same total comes back as a standard set.
    let before = wallet.balance_cents(Family::Paid);
    let exchanged = client.exchange(&mut wallet, Family::Paid).await.unwrap();
    assert_eq!(exchanged, before);
    assert_eq!(wallet.balance_cents(Family::Paid), before);

    // A crash after sending close but before the answer: recover() finishes
    // it with the same blanks and the server answers the same way.
    let session = client.open(&mut wallet, Family::Paid, 100).await.unwrap();
    assert_eq!(wallet.balance_cents(Family::Paid), 0);
    let status = client.status(&session).await.unwrap();
    assert_eq!(status.balance_usd, "1.000000000");
    let recovered = client.recover(&mut wallet).await.unwrap();
    assert_eq!(recovered, 100);
    assert_eq!(wallet.balance_cents(Family::Paid), 100);
    assert!(wallet.sessions().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_relay_the_server_sees_the_address_but_still_not_the_account() {
    let stack = start_stack().await;
    let api_key = new_account(&stack.server, 1_000).await;
    let opts = Options {
        server: stack.server.clone(),
        relay: None,
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };
    {
        let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
        let client = connect(&opts, &mut wallet).await.unwrap();
        client.withdraw(&mut wallet, &api_key, 100).await.unwrap();
    }
    let (proxy, url) = start_proxy(&opts, Settings::default()).await;
    let resp: Value = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["choices"][0]["message"]["content"], "echo: hi");
    proxy.close_all().await;
    let db = stack.backend.dump();
    let chat = db["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == "/v1/chat/completions")
        .unwrap()
        .clone();
    assert_eq!(chat["via_ohttp"], false);
    assert_eq!(chat["peer"], "127.0.0.1");
    assert_eq!(chat["credential"], "session");
}
