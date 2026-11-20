//! End to end: reference server and the proxy, over real sockets. Buy (test money) → withdraw → open → stream → close → change,
//! then read the server's whole database and try to link.

use futures::StreamExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use unlinkable_inference::{Family, Wallet};
use unlinkable_inference::server::signer::{KeyStore, PassKey};
use unlinkable_inference_cli::serve::{Proxy, Settings};
use unlinkable_inference_cli::{connect, Options};

const VALUES: [i64; 10] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

struct Stack {
    server: String,
    backend: Arc<unlinkable_inference_reference_server::MemoryBackend>,
}

async fn listen() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, format!("http://{addr}"))
}

async fn start_stack() -> Stack {
    // A fixed test pass key: generating one (safe primes) takes seconds.
    let pass = PassKey::from_pem(include_str!("../../reference-server/testdata/test_pass_key.pem")).unwrap();
    let dust = KeyStore::new(&unlinkable_inference::denominations::DUST_MILLICENTS, None).unwrap();
    let keys = KeyStore::new(&VALUES, None)
        .unwrap()
        .with_pass_key(pass)
        .with_dust(dust);
    let ref_server = unlinkable_inference_reference_server::build(keys, Duration::from_secs(3600));
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
        .join(format!("unlinkable-inference-e2e-{}", rand_id()))
        .join("wallet.json")
}

fn rand_id() -> String {
    unlinkable_inference::sha256_hex(format!("{:?}{:?}", Instant::now(), std::thread::current().id()))[..12].to_string()
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
    tokio::spawn(async move { unlinkable_inference_cli::serve::run(l, p, std::future::pending()).await.unwrap() });
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
    // Exactly the tokens, never more: what left the wallet is what the
    // requests cost, rounded down to the millicent in the customer's favour.
    let wallet_mc = Wallet::open(opts.wallet_path()).unwrap().balance_millicents(Family::Paid);
    let charged_mc: i64 = stack.backend.dump()["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["spent_nano"].as_i64().unwrap() / 10_000)
        .sum();
    assert!(charged_mc > 0);
    assert_eq!(500_000 - wallet_mc, charged_mc, "the wallet paid exactly for the tokens");
    // The proxy's page shows the same total as spent (kept on this device only).
    let spending: Value = http.get(format!("{url}/_unlinkable/spending")).send().await.unwrap().json().await.unwrap();
    let shown: i64 = spending["spent"].as_array().unwrap().iter().map(|e| e["millicents"].as_i64().unwrap()).sum();
    assert_eq!(shown, charged_mc, "spent, as the proxy shows it: {spending}");

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
            ["balance_usd", "closed_at", "family", "funded_millicents", "opened_at", "secret_hash", "spent_nano", "tier"],
            "a session row holds nothing about who opened it"
        );
    }
    // The account's token hash appears only in the account and withdrawal rows.
    let account_hash = unlinkable_inference::sha256_hex(&api_key);
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
        let v = unlinkable_inference::Voucher::parse(code).unwrap();
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
    let period = unlinkable_inference::pass::current_period();
    {
        let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
        let client = connect(&opts, &mut wallet).await.unwrap();
        client.withdraw(&mut wallet, &pro, 500).await.unwrap();
        // Asking for more than the month allows gets what is left.
        let got = client.get_passes(&mut wallet, &pro, 3).await.unwrap();
        assert_eq!(got, 3);
        let got = client.get_passes(&mut wallet, &pro, 100).await.unwrap();
        assert_eq!(got as i64, unlinkable_inference_reference_server::PASSES_PER_MONTH - 3);
        assert_eq!(client.get_passes(&mut wallet, &pro, 1).await.unwrap(), 0);
        assert_eq!(wallet.passes(&period).len() as i64, unlinkable_inference_reference_server::PASSES_PER_MONTH);
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
    assert_eq!(st["wallet"]["passes"], unlinkable_inference_reference_server::PASSES_PER_MONTH - 2);
    proxy.close_all().await;

    // A pass works once.
    let db = stack.backend.dump();
    assert_eq!(db["spent_passes"].as_array().unwrap().len(), 2);
    let tiers: Vec<&Value> = db["sessions"].as_array().unwrap().iter().map(|s| &s["tier"]).collect();
    assert_eq!(tiers.iter().filter(|t| **t == "pro").count(), 2);
    // The account row records how many passes it got, nothing about which
    // sessions used them; the session row records the tier, nothing else.
    let account_hash = unlinkable_inference::sha256_hex(&pro);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_customer_just_uses_their_key_and_the_server_never_sees_it_with_a_chat() {
    let stack = start_stack().await;
    let key = new_account_on(&stack.server, 2_000, "pro").await;
    let opts = Options {
        server: stack.server.clone(),
        wallet: Some(temp_wallet()),
        pins: Vec::new(),
    };
    // Empty wallet, no setup: the client sends its usual key, as it would to
    // the API directly.
    let settings = Settings {
        account_key_prefix: "sk-test_".into(),
        ..Settings::default()
    };
    let (_proxy, url) = start_proxy(&opts, settings).await;
    let resp = reqwest::Client::new()
        .post(format!("{url}/v1/chat/completions"))
        .header("authorization", format!("Bearer {key}"))
        .json(&json!({"model": "echo-pro", "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the plan model works, with nothing set up");
    let st = status(&url).await;
    assert!(st["wallet"]["paid_cents"].as_i64().unwrap() > 0, "{st}");
    assert!(st["wallet"]["passes"].as_i64().unwrap() > 0);
    assert_eq!(stack.backend.account_balance(&key), Some(1_900), "one $1 top-up");

    let db = stack.backend.dump();
    for r in db["requests"].as_array().unwrap() {
        if r["credential"] == "account" {
            assert!(
                r["path"].as_str().unwrap().starts_with("/u/withdraw")
                    || r["path"].as_str().unwrap().starts_with("/u/passes"),
                "the account key only moves money and fetches passes: {r}"
            );
        }
        if r["path"].as_str().unwrap().starts_with("/v1/") {
            assert_eq!(r["credential"], "session", "{r}");
        }
    }
}

/// Claude Code without a base URL change: `unlinkable-inference mcp` runs as one of the
/// agent's MCP servers, `unlinkable-inference key` is its apiKeyHelper, and the agent
/// sends the session secret straight to the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_attaches_the_mcp_server_and_talks_to_the_server_with_a_session_secret() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let stack = start_stack().await;
    let key = new_account(&stack.server, 2_000).await;
    let wallet = temp_wallet();
    let listen = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let bin = env!("CARGO_BIN_EXE_unlinkable-inference");
    let mut mcp = tokio::process::Command::new(bin)
        .args(["mcp", "--listen", &listen, "--api-key", &key])
        .env("UNLINKABLE_SERVER", &stack.server)
        .env("UNLINKABLE_WALLET", &wallet)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // The agent's MCP handshake: no tools.
    let mut stdin = mcp.stdin.take().unwrap();
    let mut lines = tokio::io::BufReader::new(mcp.stdout.take().unwrap()).lines();
    for msg in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ] {
        stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
    }
    let init: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "unlinkable-inference");
    let tools: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(tools["result"]["tools"], json!([]));

    let get_key = || async {
        let out = tokio::process::Command::new(bin)
            .args(["key", "--listen", &listen])
            .output()
            .await
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let secret = get_key().await;
    assert!(secret.starts_with(unlinkable_inference::SESSION_SECRET_PREFIX), "{secret}");

    // Straight to the server, no proxy in the way. 150k characters cost 30¢
    // of the session's 50¢.
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/v1/chat/completions", stack.server))
        .bearer_auth(&secret)
        .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "x".repeat(150_000)}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let balance = || async {
        let st: Value = http
            .get(format!("{}/u/sessions/current", stack.server))
            .bearer_auth(&secret)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        unlinkable_inference::net::usd_to_cents_floor(st["balance_usd"].as_str().unwrap())
    };
    assert!(balance().await < 50);
    // The MCP server sees the balance drop and tops the session up before a
    // request runs short.
    let deadline = Instant::now() + Duration::from_secs(20);
    while balance().await < 50 {
        assert!(Instant::now() < deadline, "the session was never topped up");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(get_key().await, secret, "the same session until it goes idle");

    // The agent exits: the session closes and its change is back in the wallet.
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(30), mcp.wait()).await.unwrap().unwrap();
    assert!(status.success());
    let w = Wallet::open(wallet).unwrap();
    assert!(w.sessions().is_empty(), "no session left open");
    assert!(w.balance_cents(Family::Paid) > 0);

    let db = stack.backend.dump();
    assert!(db["sessions"].as_array().unwrap().iter().all(|s| !s["closed_at"].is_null()));
    for r in db["requests"].as_array().unwrap() {
        if r["path"].as_str().unwrap().starts_with("/v1/") {
            assert_eq!(r["credential"], "session", "{r}");
        }
        if r["credential"] == "account" {
            let path = r["path"].as_str().unwrap();
            assert!(path.starts_with("/u/withdraw") || path.starts_with("/u/passes"), "{r}");
        }
    }
}

/// Tor Browser closing, a lost phone: a seeded wallet is rebuilt from the
/// account number alone, to the millicent, and records the device has
/// finished with are deleted from the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_loses_everything_gets_it_all_back_from_the_account_number() {
    use unlinkable_inference::net::{Client, Session, Transport};
    let stack = start_stack().await;
    // The dead device's open session counts as abandoned at once (normally after 15 quiet minutes).
    stack.backend.set_unclaimed_after(Duration::ZERO);
    let key = new_account(&stack.server, 2_000).await;
    let keys = unlinkable_inference::seed::account_keys("4821 0937 5512 8846").unwrap();
    let keyset = Transport::new(&stack.server).fetch_keyset().await.unwrap();
    let client = || Client::new(Transport::new(&stack.server), keyset.clone()).with_seed(keys.seed.clone());
    let a = client();
    let mut wallet = Wallet::in_memory();

    a.withdraw(&mut wallet, &key, 100).await.unwrap();
    assert_eq!(a.get_passes(&mut wallet, &key, 3).await.unwrap(), 3);
    let chat = |secret: String| {
        let server = stack.server.clone();
        async move {
            let r = reqwest::Client::new()
                .post(format!("{server}/v1/chat/completions"))
                .bearer_auth(secret)
                .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "x".repeat(20_000)}]}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200);
        }
    };
    // One session used and closed (its change is in the wallet), one used
    // and left open: the device dies before it can close it.
    let s1 = a.open(&mut wallet, Family::Paid, 50).await.unwrap();
    chat(s1.secret.clone()).await;
    a.close(&mut wallet, &s1).await.unwrap();
    let s2 = a.open(&mut wallet, Family::Paid, 50).await.unwrap();
    chat(s2.secret.clone()).await;
    let left_in_s2 = {
        let st = a.status(&s2).await.unwrap();
        // Close rounds up to the next millicent.
        let (whole, frac) = st.balance_usd.split_once('.').unwrap();
        let frac = format!("{frac:0<8}");
        let nano: i64 = whole.parse::<i64>().unwrap() * 100_000_000 + frac[..8].parse::<i64>().unwrap();
        (nano + 999) / 1000
    };
    let had = wallet.balance_millicents(Family::Paid) + left_in_s2;
    let passes_had = wallet.passes(&unlinkable_inference::pass::current_period()).len();
    assert_eq!(passes_had, 1, "two of three passes went into sessions");
    drop(wallet);

    // A new device: nothing but the account number (and the key it gives).
    let b = client();
    let mut fresh = Wallet::in_memory();
    b.restore(&mut fresh, Some(&key)).await.unwrap();
    assert_eq!(fresh.balance_millicents(Family::Paid), had, "every millicent is back");
    assert_eq!(fresh.passes(&unlinkable_inference::pass::current_period()).len(), passes_had);
    assert!(b.status(&Session { secret: s2.secret.clone(), family: Family::Paid }).await.unwrap().closed);
    // Restoring again finds nothing new.
    b.restore(&mut fresh, Some(&key)).await.unwrap();
    assert_eq!(fresh.balance_millicents(Family::Paid), had);

    // Once everything the withdrawal and the sessions gave is spent, the server forgets them;
    // only the session whose change is still held stays.
    b.flush_done(&mut fresh, Some(&key)).await.unwrap();
    assert_eq!(stack.backend.dump()["sessions"].as_array().unwrap().len(), 2);
    let s3 = b.open(&mut fresh, Family::Paid, had / 1000 + 1).await.unwrap();
    assert_eq!(fresh.vouchers().iter().filter(|h| !h.voucher.dust).count(), 0, "everything went into s3");
    b.close(&mut fresh, &s3).await.unwrap();
    b.flush_done(&mut fresh, Some(&key)).await.unwrap();
    let db = stack.backend.dump();
    assert!(db["issued"].as_array().unwrap().iter().all(|i| i["kind"] == "passes"), "{}", db["issued"]);
    let hashes: Vec<&str> = db["sessions"].as_array().unwrap().iter().map(|s| s["secret_hash"].as_str().unwrap()).collect();
    assert_eq!(hashes, vec![unlinkable_inference::sha256_hex(&s3.secret)], "only the session whose change is still held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_app_using_the_manager_gives_each_conversation_its_own_session_and_loses_nothing() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 2_000).await;
    let seed = unlinkable_inference::seed::account_keys("7730 1945 2286 0413").unwrap().seed;
    let chat = |secret: String| {
        let server = stack.server.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{server}/v1/chat/completions"))
                .bearer_auth(secret)
                .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "x".repeat(20_000)}]}))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    let mut m = Manager::connect(&stack.server, seed.clone(), None).await.unwrap();
    m.api_key = Some(key.clone());
    m.start().await.unwrap();
    assert!(m.summary().0 >= 50, "topped up at start");
    let a = m.session("chat-a").await.unwrap();
    let b = m.session("chat-b").await.unwrap();
    assert_ne!(a, b, "one session per conversation");
    assert_eq!(m.session("chat-a").await.unwrap(), a, "and it stays with the conversation");
    assert_eq!(chat(a.clone()).await, 200);
    assert_eq!(chat(b.clone()).await, 200);

    // Saved state carries on in a restarted app: same conversation, same session.
    let saved = m.state();
    drop(m);
    let mut m = Manager::connect(&stack.server, seed.clone(), Some(&saved)).await.unwrap();
    m.api_key = Some(key.clone());
    m.start().await.unwrap();
    assert_eq!(m.session("chat-a").await.unwrap(), a);

    // What the chats cost shows while their sessions are still open...
    let charged = || -> i64 {
        stack.backend.dump()["sessions"].as_array().unwrap().iter().map(|s| s["spent_nano"].as_i64().unwrap() / 10_000).sum()
    };
    let live = m.spending().await.spent;
    assert_eq!(live.len(), 2, "both conversations' sessions: {live:?}");
    assert!(live.iter().map(|e| e.millicents).sum::<i64>() >= charged());

    // Quiet conversations are closed for their change.
    m.policy.idle_secs = 0;
    m.tick().await;
    let db = stack.backend.dump();
    assert!(db["sessions"].as_array().unwrap().iter().all(|s| !s["closed_at"].is_null()), "{}", db["sessions"]);
    // ...and stays on this device once they close: what was paid in minus the change.
    let log = m.wallet().spending().to_vec();
    assert_eq!(log.len(), 2, "{log:?}");
    assert_eq!(log.iter().map(|e| e.millicents).sum::<i64>(), charged(), "the log matches what the server charged");
    let after = m.spending().await;
    assert_eq!(after.spent.len(), 2, "closed sessions are not counted twice");
    assert_eq!(after.prepaid_millicents, m.wallet().balance_millicents(Family::Paid));
    let saved = m.state();
    assert!(saved.contains("\"spending\""), "the log is saved with the wallet");

    // A new device with nothing saved ends up with the same money.
    let had = m.wallet().balance_millicents(Family::Paid);
    let mut fresh = Manager::connect(&stack.server, seed, None).await.unwrap();
    fresh.api_key = Some(key);
    fresh.policy.keep_cents = 0; // no top-up, to compare
    fresh.start().await.unwrap();
    assert_eq!(fresh.wallet().balance_millicents(Family::Paid), had);
    two_devices_never_share_a_session(&stack.server, &new_account(&stack.server, 2_000).await).await;
}

/// Two devices on one account opening many sessions in the same minute pick
/// some of the same secrets (64 a minute); the server refuses the second
/// (`secret_taken`) and it picks again, so none is shared and nothing is lost.
async fn two_devices_never_share_a_session(server: &str, key: &str) {
    use unlinkable_inference::manager::Manager;
    let seed = unlinkable_inference::seed::account_keys("1188 6021 4459 3307").unwrap().seed;
    let mut phone = Manager::connect(server, seed.clone(), None).await.unwrap();
    let mut laptop = Manager::connect(server, seed, None).await.unwrap();
    let mut secrets = std::collections::HashSet::new();
    for m in [&mut phone, &mut laptop] {
        m.api_key = Some(key.to_string());
        m.policy.funding_cents = 10;
        m.policy.refill_cents = 500; // a fixed withdrawal size
        // Both spend one shared wallet, faster than any person: look in it every time it runs low.
        m.policy.share_every_secs = 0;
    }
    for i in 0..20 {
        for m in [&mut phone, &mut laptop] {
            let s = m.session(&format!("chat-{i}")).await.unwrap();
            assert!(secrets.insert(s), "a secret was handed out twice");
        }
    }
    let held = |m: &Manager| m.wallet().balance_millicents(Family::Paid);
    for m in [&mut phone, &mut laptop] {
        let before = held(m);
        m.policy.idle_secs = 0;
        m.policy.keep_cents = 0;
        m.tick().await;
        // Sessions are funded with whole vouchers (50¢ pieces), at least 10¢ each.
        assert!(held(m) >= before + 20 * 10_000, "every unused session's money comes back");
        assert!(m.wallet().sessions().is_empty());
    }
}

/// The same against a real server (spends nothing for good: every session closes unused):
///   UNLINKABLE_SERVER=http://127.0.0.1:8230 UNLINKABLE_KEY=sk-obs1_… cargo test -p unlinkable-inference-cli --test e2e -- --ignored
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn against_a_real_server_two_devices_never_share_a_session() {
    let server = std::env::var("UNLINKABLE_SERVER").expect("UNLINKABLE_SERVER");
    let key = std::env::var("UNLINKABLE_KEY").expect("UNLINKABLE_KEY");
    two_devices_never_share_a_session(&server, &key).await;
}


async fn echo(server: &str, secret: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("{server}/v1/chat/completions"))
        .bearer_auth(secret)
        .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "x".repeat(20_000)}]}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn balance_cents(server: &str, key: &str) -> i64 {
    let v: Value = reqwest::Client::new().get(format!("{server}/test/account")).bearer_auth(key).send().await.unwrap().json().await.unwrap();
    v["balance_cents"].as_i64().unwrap()
}

fn withdraw_requests(stack: &Stack) -> usize {
    stack.backend.dump()["requests"].as_array().unwrap().iter().filter(|r| r["path"] == "/u/withdraw").count()
}

/// The wallet belongs to the account, not the device: a second device spends what the first
/// withdrew, collects the change of a session the first closed, and never closes one the first
/// is still using. When the shared wallet runs dry the account's last cents (under $1) are taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_on_one_account_share_one_wallet() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 150).await;
    let seed = unlinkable_inference::seed::account_keys("2207 6634 9015 4482").unwrap().seed;
    let device = || async {
        let mut m = Manager::connect(&stack.server, seed.clone(), None).await.unwrap();
        m.api_key = Some(key.clone());
        m
    };

    // The browser starts first and takes $1 from the account; 50¢ stay.
    let mut browser = device().await;
    browser.start().await.unwrap();
    assert_eq!(browser.wallet().balance_cents(Family::Paid), 100);
    assert_eq!(balance_cents(&stack.server, &key).await, 50);
    let b1 = browser.session("browser-chat").await.unwrap();
    assert_eq!(echo(&stack.server, &b1).await, 200);

    // The phone starts with nothing of its own: it finds the browser's withdrawal, without
    // taking more from the account, and leaves the browser's open session alone.
    let mut phone = device().await;
    phone.start().await.unwrap();
    assert!(phone.wallet().balance_cents(Family::Paid) >= 50, "the phone sees what the browser holds");
    assert_eq!(balance_cents(&stack.server, &key).await, 50, "nothing more taken from the account");
    let p1 = phone.session("phone-chat").await.unwrap();
    assert_eq!(echo(&stack.server, &p1).await, 200, "the phone chats on the shared wallet");
    assert_eq!(echo(&stack.server, &b1).await, 200, "the browser's session was never closed");

    // Another conversation on the browser: sessions start small, so the shared dollar still
    // covers it, with nothing more from the account.
    let b2 = browser.session("browser-chat-2").await.unwrap();
    assert_eq!(echo(&stack.server, &b2).await, 200);
    assert_eq!(balance_cents(&stack.server, &key).await, 50, "the shared wallet covered it");

    // The browser goes quiet and closes its sessions: their change is the phone's to spend too.
    browser.policy.idle_secs = 0;
    browser.policy.keep_cents = 0;
    let held_before: Vec<String> = browser.wallet().vouchers().iter().map(|h| h.voucher.encode()).collect();
    browser.tick().await;
    let change: Vec<String> = browser
        .wallet()
        .vouchers()
        .iter()
        .map(|h| h.voucher.encode())
        .filter(|c| !held_before.contains(c))
        .collect();
    assert!(!change.is_empty(), "the browser got change back");
    phone.policy.idle_secs = 0;
    phone.policy.keep_cents = 0;
    phone.tick().await; // closes the phone's own session for its change
    phone.policy.keep_cents = 10_000; // low: look in the shared wallet
    phone.policy.share_every_secs = 0;
    phone.refill().await;
    let held: Vec<String> = phone.wallet().vouchers().iter().map(|h| h.voucher.encode()).collect();
    let missing = change.iter().filter(|c| !held.contains(c)).count();
    assert_eq!(missing, 0, "the browser's change is the phone's to spend too ({missing} of {} missing)", change.len());
}

/// No balance is stranded: 73¢ is spent privately, and 7¢ (below the 10¢ a session needs) stays
/// in the account for the app to spend there, without asking again on every tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_balance_under_a_dollar_is_spent_privately_and_crumbs_stay_in_the_account() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 73).await;
    let seed = unlinkable_inference::seed::account_keys("6650 1123 8094 2271").unwrap().seed;
    let mut m = Manager::connect(&stack.server, seed, None).await.unwrap();
    m.api_key = Some(key.clone());
    m.start().await.unwrap();
    assert_eq!(m.wallet().balance_cents(Family::Paid), 73, "all 73¢ moved");
    assert_eq!(balance_cents(&stack.server, &key).await, 0);
    let s = m.session("chat").await.unwrap();
    assert_eq!(echo(&stack.server, &s).await, 200);

    let key = new_account(&stack.server, 7).await;
    let seed = unlinkable_inference::seed::account_keys("3381 0067 5529 4410").unwrap().seed;
    let mut m = Manager::connect(&stack.server, seed.clone(), None).await.unwrap();
    m.api_key = Some(key.clone());
    m.start().await.unwrap();
    assert_eq!(m.wallet().balance_cents(Family::Paid), 0);
    assert_eq!(balance_cents(&stack.server, &key).await, 7, "crumbs stay in the account");
    assert!(m.session("chat").await.is_err(), "no session: the app pays from the account");
    let asked = withdraw_requests(&stack);
    for _ in 0..5 {
        m.tick().await;
    }
    assert_eq!(withdraw_requests(&stack), asked, "a refusal isn't repeated every tick");
    // A reload keeps the back-off too.
    let saved = m.state();
    let mut again = Manager::connect(&stack.server, seed, Some(&saved)).await.unwrap();
    again.api_key = Some(key);
    again.tick().await;
    assert_eq!(withdraw_requests(&stack), asked);
}

/// Topping a session up with vouchers another device spent already: the server refuses (409,
/// naming them) and nothing is spent, so the rest go back into the wallet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_top_up_keeps_the_vouchers_that_were_not_spent() {
    use unlinkable_inference::net::{Client, Transport};
    let stack = start_stack().await;
    let key = new_account(&stack.server, 500).await;
    let keys = unlinkable_inference::seed::account_keys("9012 4471 3368 5520").unwrap();
    let keyset = Transport::new(&stack.server).fetch_keyset().await.unwrap();
    let client = Client::new(Transport::new(&stack.server), keyset).with_seed(keys.seed);
    let mut wallet = Wallet::in_memory();
    client.withdraw(&mut wallet, &key, 500).await.unwrap();
    let session = client.open(&mut wallet, Family::Paid, 50).await.unwrap();
    // Another device spends one of this wallet's vouchers.
    let mut copy = Wallet::from_json(&wallet.to_json()).unwrap();
    let elsewhere = client.open(&mut copy, Family::Paid, 10).await.unwrap();
    assert_ne!(elsewhere.secret, session.secret);
    let before = wallet.balance_millicents(Family::Paid);
    assert!(client.topup(&mut wallet, &session, 30).await.is_err(), "refused: some were spent");
    let after = wallet.balance_millicents(Family::Paid);
    assert!(after > 0 && after >= before - 50_000, "only the spent ones went: {before} -> {after}");
    // And the rest still top the session up.
    client.topup(&mut wallet, &session, 50).await.unwrap();
}


/// A dollar is many conversations: sessions start at 10¢ and grow as they are used, so two
/// devices with four conversations open between them all chat on a $1 account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dollar_spreads_over_many_open_conversations_on_two_devices() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 100).await;
    let seed = unlinkable_inference::seed::account_keys("5012 7743 1186 2209").unwrap().seed;
    let mut phone = Manager::connect(&stack.server, seed.clone(), None).await.unwrap();
    let mut browser = Manager::connect(&stack.server, seed, None).await.unwrap();
    for m in [&mut phone, &mut browser] {
        m.api_key = Some(key.clone());
        m.start().await.unwrap();
    }
    for i in 0..4 {
        let m = if i % 2 == 0 { &mut phone } else { &mut browser };
        let s = m.session(&format!("chat-{i}")).await.expect("every conversation gets a session");
        assert_eq!(echo(&stack.server, &s).await, 200, "chat {i}");
    }
}

/// Money from before the account's code changed stays the account's: a device that knew the old
/// number keeps its seed after entering the new code and still finds what was withdrawn under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn money_from_before_a_new_account_code_is_still_found() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 100).await;
    let number = unlinkable_inference::seed::account_keys("7120 4433 0918 6652").unwrap().seed;
    let code = unlinkable_inference::seed::account_keys("Q3RTN-8XW1K-ZD4PM-07HJ2").map(|k| k.seed).unwrap_or_else(|_| {
        unlinkable_inference::seed::account_keys(&unlinkable_inference::seed::new_account_code()).unwrap().seed
    });
    // The phone, on the number, takes the dollar and spends 10¢ of it.
    let mut phone = Manager::connect(&stack.server, number.clone(), None).await.unwrap();
    phone.api_key = Some(key.clone());
    phone.start().await.unwrap();
    let s = phone.session("chat").await.unwrap();
    assert_eq!(echo(&stack.server, &s).await, 200);
    assert_eq!(balance_cents(&stack.server, &key).await, 0);
    // The browser was signed in with the number too, then enters the new code.
    let browser = Manager::connect(&stack.server, number, None).await.unwrap();
    let saved = browser.state();
    drop(browser);
    let mut browser = Manager::connect(&stack.server, code, Some(&saved)).await.unwrap();
    browser.api_key = Some(key.clone());
    browser.policy.keep_cents = 100;
    browser.start().await.unwrap();
    assert!(browser.wallet().balance_cents(Family::Paid) >= 80, "the old number's withdrawal is found: {}", browser.wallet().balance_cents(Family::Paid));
    let s = browser.session("chat").await.unwrap();
    assert_eq!(echo(&stack.server, &s).await, 200);
    assert!(browser.state().contains("previous_seeds"), "the old seed is kept");
}

/// When the wallet and the account are both empty, the money sitting in this device's quiet
/// conversations comes back to fund the one in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quiet_conversations_give_their_money_to_the_one_in_use() {
    use unlinkable_inference::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 20).await;
    let seed = unlinkable_inference::seed::account_keys("8834 2290 5571 0016").unwrap().seed;
    let mut m = Manager::connect(&stack.server, seed, None).await.unwrap();
    m.api_key = Some(key.clone());
    m.start().await.unwrap();
    assert_eq!(m.wallet().balance_cents(Family::Paid), 20);
    let short = |secret: String| {
        let server = stack.server.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{server}/v1/chat/completions"))
                .bearer_auth(secret)
                .json(&json!({"model": "echo", "messages": [{"role": "user", "content": "hi"}]}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    for chat in ["a", "b"] {
        let s = m.session(chat).await.unwrap();
        assert_eq!(short(s).await, 200);
    }
    assert_eq!(balance_cents(&stack.server, &key).await, 0);
    m.policy.quiet_secs = 0;
    let s = m.session("c").await.expect("the quiet conversations' change funds it");
    assert_eq!(short(s).await, 200);
}
