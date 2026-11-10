//! End to end: reference server and the proxy, over real sockets. Buy (test money) → withdraw → open → stream → close → change,
//! then read the server's whole database and try to link.

use futures::StreamExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use unlinkable_core::{Family, Wallet};
use unlinkable_gateway::signer::{KeyStore, PassKey};
use unlinkable_proxy::serve::{Proxy, Settings};
use unlinkable_proxy::{connect, Options};

const VALUES: [i64; 10] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

struct Stack {
    server: String,
    backend: Arc<unlinkable_reference_server::MemoryBackend>,
}

async fn listen() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, format!("http://{addr}"))
}

async fn start_stack() -> Stack {
    // A fixed test pass key: generating one (safe primes) takes seconds.
    let pass = PassKey::from_pem(include_str!("../../reference-server/testdata/test_pass_key.pem")).unwrap();
    let keys = KeyStore::new(&VALUES, None).unwrap().with_pass_key(pass);
    let ref_server = unlinkable_reference_server::build(keys, Duration::from_secs(3600));
    let backend = ref_server.backend.clone();
    let (l, server) = listen().await;
    tokio::spawn(async move {
        axum::serve(l, ref_server.router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap()
    });
    Stack { server, backend }
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
    new_account_on(server, cents, "pay_as_you_go").await
}

async fn new_account_on(server: &str, cents: i64, tier: &str) -> String {
    let v: Value = reqwest::Client::new()
        .post(format!("{server}/test/accounts"))
        .json(&json!({"balance_cents": cents, "tier": tier}))
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
async fn a_chat_cannot_be_tied_to_the_account_that_paid_for_it() {
    let stack = start_stack().await;
    let api_key = new_account(&stack.server, 2_000).await;
    let opts = Options {
        server: stack.server.clone(),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };

    // Withdraw $5 into the wallet.
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
        assert_eq!(r["had_cookie"], false, "{r}");
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
            ["balance_usd", "closed_at", "family", "funded_cents", "opened_at", "secret_hash", "tier"],
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

async fn chat(url: &str, model: &str, text: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .json(&json!({"model": model, "messages": [{"role": "user", "content": text}]}))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_gives_a_session_the_plan_models_without_naming_the_account() {
    let stack = start_stack().await;
    let pro = new_account_on(&stack.server, 2_000, "pro").await;
    let opts = Options {
        server: stack.server.clone(),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };
    let period = unlinkable_core::pass::current_period();
    {
        let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
        let client = connect(&opts, &mut wallet).await.unwrap();
        client.withdraw(&mut wallet, &pro, 500).await.unwrap();
        // Asking for more than the month allows gets what is left.
        let got = client.get_passes(&mut wallet, &pro, 3).await.unwrap();
        assert_eq!(got, 3);
        let got = client.get_passes(&mut wallet, &pro, 100).await.unwrap();
        assert_eq!(got as i64, unlinkable_reference_server::PASSES_PER_MONTH - 3);
        assert_eq!(client.get_passes(&mut wallet, &pro, 1).await.unwrap(), 0);
        assert_eq!(wallet.passes(&period).len() as i64, unlinkable_reference_server::PASSES_PER_MONTH);
        assert!(wallet.passes(&period).iter().all(|p| p.tier == "pro"));

        // A pass opens one session. Putting a used one back (an old backup)
        // gets it refused; the client drops it and uses the next one.
        let before = wallet.passes(&period);
        let session = client.open(&mut wallet, Family::Paid, 50).await.unwrap();
        assert_eq!(client.status(&session).await.unwrap().tier.as_deref(), Some("pro"));
        client.close(&mut wallet, &session).await.unwrap();
        let after = wallet.passes(&period);
        let spent: Vec<_> = before.into_iter().filter(|p| !after.contains(p)).collect();
        assert_eq!(spent.len(), 1);
        // Put the spent pass back, as if from an old backup, and make it the
        // only one: the server refuses it and the session opens without a pass.
        let mut solo = Wallet::open(temp_wallet()).unwrap();
        solo.add(Family::Paid, wallet.take(Family::Paid, 50));
        solo.add_passes(spent.clone());
        let session = client.open(&mut solo, Family::Paid, 50).await.unwrap();
        assert!(solo.passes(&period).is_empty(), "the spent pass was dropped");
        assert_eq!(client.status(&session).await.unwrap().tier, None);
        client.close(&mut solo, &session).await.unwrap();
        wallet.add(Family::Paid, solo.take(Family::Paid, 1000));
        assert_eq!(stack.backend.dump()["spent_passes"].as_array().unwrap().len(), 1);
        wallet.save().unwrap();
    }

    let (proxy, url) = start_proxy(&opts, Settings::default()).await;
    // A Pro-only model works in a session opened with a Pro pass.
    let resp = chat(&url, "echo-pro", "plan model please").await;
    assert_eq!(resp.status(), 200);
    let st = status(&url).await;
    assert_eq!(st["wallet"]["passes"], unlinkable_reference_server::PASSES_PER_MONTH - 2);
    proxy.close_all().await;

    // A pass works once.
    let db = stack.backend.dump();
    assert_eq!(db["spent_passes"].as_array().unwrap().len(), 2);
    let tiers: Vec<&Value> = db["sessions"].as_array().unwrap().iter().map(|s| &s["tier"]).collect();
    assert_eq!(tiers.iter().filter(|t| **t == "pro").count(), 2);
    // The account row records how many passes it got, nothing about which
    // sessions used them; the session row records the tier, nothing else.
    let account_hash = unlinkable_core::sha256_hex(&pro);
    assert_eq!(db.to_string().matches(&account_hash).count(), 2);
    for p in db["spent_passes"].as_array().unwrap() {
        let hash = p["hash"].as_str().unwrap();
        assert_eq!(db.to_string().matches(hash).count(), 1, "a spent pass appears nowhere else");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_pass_plan_models_are_refused_and_tiny_sessions_are_too() {
    let stack = start_stack().await;
    let payg = new_account(&stack.server, 1_000).await;
    let opts = Options {
        server: stack.server.clone(),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };
    let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
    let client = connect(&opts, &mut wallet).await.unwrap();
    client.withdraw(&mut wallet, &payg, 100).await.unwrap();

    // A session must hold at least 10¢: one of 5¢ is refused, and the
    // vouchers come back.
    let err = client.open(&mut wallet, Family::Paid, 5).await.unwrap_err();
    assert!(err.to_string().contains("at least 10¢"), "{err}");
    assert_eq!(wallet.balance_cents(Family::Paid), 100);

    wallet.save().unwrap();
    drop(wallet);
    let (_proxy, url) = start_proxy(&opts, Settings { funding_cents: 20, ..Settings::default() }).await;
    assert_eq!(chat(&url, "echo-pro", "x").await.status(), 403);
    assert_eq!(chat(&url, "echo", "x").await.status(), 200);
}
