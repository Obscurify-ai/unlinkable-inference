//! End to end: reference server and the proxy, over real sockets. Buy (test money) → withdraw → open → stream → close → change,
//! then read the server's whole database and try to link.

use futures::StreamExt;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chaumian_sessions::{Family, Wallet};
use chaumian_sessions::server::signer::{KeyStore, PassKey};
use chaumian_sessions_cli::serve::{Proxy, Settings};
use chaumian_sessions_cli::{connect, Options};

const VALUES: [i64; 10] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

struct Stack {
    server: String,
    backend: Arc<chaumian_sessions_reference_server::MemoryBackend>,
}

async fn listen() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    (l, format!("http://{addr}"))
}

async fn start_stack() -> Stack {
    // A fixed test pass key: generating one (safe primes) takes seconds.
    let pass = PassKey::from_pem(include_str!("../../reference-server/testdata/test_pass_key.pem")).unwrap();
    let dust = KeyStore::new(&chaumian_sessions::denominations::DUST_MILLICENTS, None).unwrap();
    let keys = KeyStore::new(&VALUES, None)
        .unwrap()
        .with_pass_key(pass)
        .with_dust(dust);
    let ref_server = chaumian_sessions_reference_server::build(keys, Duration::from_secs(3600));
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
        .join(format!("chaumian-sessions-e2e-{}", rand_id()))
        .join("wallet.json")
}

fn rand_id() -> String {
    chaumian_sessions::sha256_hex(format!("{:?}{:?}", Instant::now(), std::thread::current().id()))[..12].to_string()
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
    tokio::spawn(async move { chaumian_sessions_cli::serve::run(l, p, std::future::pending()).await.unwrap() });
    (proxy, url)
}

async fn status(proxy_url: &str) -> Value {
    reqwest::get(format!("{proxy_url}/_chaumian/status"))
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
    let account_hash = chaumian_sessions::sha256_hex(&api_key);
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
        let v = chaumian_sessions::Voucher::parse(code).unwrap();
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
    let period = chaumian_sessions::pass::current_period();
    {
        let mut wallet = Wallet::open(opts.wallet_path()).unwrap();
        let client = connect(&opts, &mut wallet).await.unwrap();
        client.withdraw(&mut wallet, &pro, 500).await.unwrap();
        // Asking for more than the month allows gets what is left.
        let got = client.get_passes(&mut wallet, &pro, 3).await.unwrap();
        assert_eq!(got, 3);
        let got = client.get_passes(&mut wallet, &pro, 100).await.unwrap();
        assert_eq!(got as i64, chaumian_sessions_reference_server::PASSES_PER_MONTH - 3);
        assert_eq!(client.get_passes(&mut wallet, &pro, 1).await.unwrap(), 0);
        assert_eq!(wallet.passes(&period).len() as i64, chaumian_sessions_reference_server::PASSES_PER_MONTH);
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
    assert_eq!(st["wallet"]["passes"], chaumian_sessions_reference_server::PASSES_PER_MONTH - 2);
    proxy.close_all().await;

    // A pass works once.
    let db = stack.backend.dump();
    assert_eq!(db["spent_passes"].as_array().unwrap().len(), 2);
    let tiers: Vec<&Value> = db["sessions"].as_array().unwrap().iter().map(|s| &s["tier"]).collect();
    assert_eq!(tiers.iter().filter(|t| **t == "pro").count(), 2);
    // The account row records how many passes it got, nothing about which
    // sessions used them; the session row records the tier, nothing else.
    let account_hash = chaumian_sessions::sha256_hex(&pro);
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

/// Claude Code without a base URL change: `chaumian-sessions mcp` runs as one of the
/// agent's MCP servers, `chaumian-sessions key` is its apiKeyHelper, and the agent
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
    let bin = env!("CARGO_BIN_EXE_chaumian-sessions");
    let mut mcp = tokio::process::Command::new(bin)
        .args(["mcp", "--listen", &listen, "--api-key", &key])
        .env("CHAUMIAN_SERVER", &stack.server)
        .env("CHAUMIAN_WALLET", &wallet)
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
    assert_eq!(init["result"]["serverInfo"]["name"], "chaumian-sessions");
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
    assert!(secret.starts_with(chaumian_sessions::SESSION_SECRET_PREFIX), "{secret}");

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
        chaumian_sessions::net::usd_to_cents_floor(st["balance_usd"].as_str().unwrap())
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
    use chaumian_sessions::net::{Client, Session, Transport};
    let stack = start_stack().await;
    let key = new_account(&stack.server, 2_000).await;
    let keys = chaumian_sessions::seed::account_keys("4821 0937 5512 8846").unwrap();
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
    let passes_had = wallet.passes(&chaumian_sessions::pass::current_period()).len();
    assert_eq!(passes_had, 1, "two of three passes went into sessions");
    drop(wallet);

    // A new device: nothing but the account number (and the key it gives).
    let b = client();
    let mut fresh = Wallet::in_memory();
    b.restore(&mut fresh, Some(&key)).await.unwrap();
    assert_eq!(fresh.balance_millicents(Family::Paid), had, "every millicent is back");
    assert_eq!(fresh.passes(&chaumian_sessions::pass::current_period()).len(), passes_had);
    assert!(b.status(&Session { secret: s2.secret.clone(), family: Family::Paid }).await.unwrap().closed);
    // Restoring again finds nothing new.
    b.restore(&mut fresh, Some(&key)).await.unwrap();
    assert_eq!(fresh.balance_millicents(Family::Paid), had);

    // The withdrawal is fully spent, so the server forgets it at once; the
    // sessions are forgotten once their change is spent too.
    b.flush_done(&mut fresh, Some(&key)).await.unwrap();
    let db = stack.backend.dump();
    assert!(db["issued"].as_array().unwrap().iter().all(|i| i["kind"] == "passes"), "{}", db["issued"]);
    assert_eq!(db["sessions"].as_array().unwrap().len(), 2);
    let s3 = b.open(&mut fresh, Family::Paid, had / 1000 + 1).await.unwrap();
    b.close(&mut fresh, &s3).await.unwrap();
    b.flush_done(&mut fresh, Some(&key)).await.unwrap();
    let db = stack.backend.dump();
    let hashes: Vec<&str> = db["sessions"].as_array().unwrap().iter().map(|s| s["secret_hash"].as_str().unwrap()).collect();
    assert_eq!(hashes, vec![chaumian_sessions::sha256_hex(&s3.secret)], "only the session whose change is still held");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_app_using_the_manager_gives_each_conversation_its_own_session_and_loses_nothing() {
    use chaumian_sessions::manager::Manager;
    let stack = start_stack().await;
    let key = new_account(&stack.server, 2_000).await;
    let seed = chaumian_sessions::seed::account_keys("7730 1945 2286 0413").unwrap().seed;
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

    // Quiet conversations are closed for their change.
    m.policy.idle_secs = 0;
    m.tick().await;
    let db = stack.backend.dump();
    assert!(db["sessions"].as_array().unwrap().iter().all(|s| !s["closed_at"].is_null()), "{}", db["sessions"]);

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
    use chaumian_sessions::manager::Manager;
    let seed = chaumian_sessions::seed::account_keys("1188 6021 4459 3307").unwrap().seed;
    let mut phone = Manager::connect(server, seed.clone(), None).await.unwrap();
    let mut laptop = Manager::connect(server, seed, None).await.unwrap();
    let mut secrets = std::collections::HashSet::new();
    for m in [&mut phone, &mut laptop] {
        m.api_key = Some(key.to_string());
        m.policy.funding_cents = 10;
        m.policy.refill_cents = 500; // a fixed withdrawal size
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
///   CHAUMIAN_SERVER=http://127.0.0.1:8230 CHAUMIAN_KEY=sk-obs1_… cargo test -p chaumian-sessions-cli --test e2e -- --ignored
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn against_a_real_server_two_devices_never_share_a_session() {
    let server = std::env::var("CHAUMIAN_SERVER").expect("CHAUMIAN_SERVER");
    let key = std::env::var("CHAUMIAN_KEY").expect("CHAUMIAN_KEY");
    two_devices_never_share_a_session(&server, &key).await;
}
