use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::io::Read;
use std::time::Duration;
use unlinkable_inference::keyset::Pins;
use unlinkable_inference::net::{Observed, Request, Transport};
use unlinkable_inference::{Family, Voucher, Wallet};
use unlinkable_inference_cli::serve::{self, Mode, Settings};
use unlinkable_inference_cli::{connect, dollars, lock_wallet, Options};

/// Use AI models without the server being able to tell who sent each chat.
///
/// Requests are paid from a wallet of blind-signed vouchers on this device,
/// one session per conversation, with a session secret instead of your API
/// key. The server still reads each prompt, and sees your IP address unless
/// you hide it yourself (Tor, a VPN).
///
/// Quick start (the key is your usual Obscurify key; it only ever moves
/// money into the wallet and is never sent with a chat):
///   unlinkable-inference serve                              # localhost:8899
///   ANTHROPIC_BASE_URL=http://127.0.0.1:8899 ANTHROPIC_AUTH_TOKEN=sk-obs1_… claude
///   OPENAI_BASE_URL=http://127.0.0.1:8899/v1 OPENAI_API_KEY=sk-obs1_… …
#[derive(Parser)]
#[command(name = "unlinkable-inference", version, verbatim_doc_comment)]
struct Cli {
    /// Server origin
    #[arg(long, global = true, env = "UNLINKABLE_SERVER", default_value = "https://obscurify.ai")]
    server: String,
    /// Wallet file (default: ~/.local/share/unlinkable-inference/<server>/wallet.json)
    #[arg(long, global = true, env = "UNLINKABLE_WALLET")]
    wallet: Option<std::path::PathBuf>,
    /// Also accept this keyset fingerprint (repeatable)
    #[arg(long = "pin", global = true, env = "UNLINKABLE_PINS", value_delimiter = ',')]
    pins: Vec<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "UNLINKABLE_LISTEN", default_value = "127.0.0.1:8899")]
    listen: String,
    /// What each new session starts with, in dollars
    #[arg(long, default_value = "0.50")]
    session_funding: String,
    /// conversation: a session per conversation; key: per API key the
    /// client sends; run: one session until idle
    #[arg(long, default_value = "conversation")]
    per: Mode,
    /// Close a session after this many seconds without a request
    #[arg(long, default_value_t = 300)]
    idle_close: u64,
    /// Print what leaves this device for every request
    #[arg(long)]
    show_traffic: bool,
    /// The account code (or an older account's 16-digit number). With it the wallet is seeded: everything in it can
    /// be rebuilt from the number on any device, so nothing is lost with the
    /// wallet file. Only a key derived from it is sent, never the number.
    #[arg(long, env = "OBSCURIFY_ACCOUNT_NUMBER", hide_env_values = true)]
    account_number: Option<String>,
    /// The account's API key: keeps the wallet and this month's passes
    /// topped up in the background. Never sent with a chat. Without it
    /// the proxy uses the first sk-obs1_ key a client sends.
    #[arg(long, env = "OBSCURIFY_API_KEY")]
    api_key: Option<String>,
    /// Top up when the wallet falls below this many dollars. The account is asked at random
    /// times, never when a request needs it (that would tie the request to the account), so keep
    /// enough for the largest reply you expect; a request the wallet can't pay waits (503 with
    /// Retry-After) until the next top-up.
    #[arg(long, default_value = "2")]
    keep: String,
    /// Top up by this many dollars (1, 5, 20, 50 or 100)
    #[arg(long, default_value_t = 5)]
    refill: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Run the local proxy: OpenAI and Anthropic APIs on localhost
    Serve(ServeArgs),
    /// The proxy as an MCP server with no tools: add it to an agent's MCP
    /// servers and the proxy runs while the agent does. If another proxy
    /// already runs, it stays idle. Pair it with `unlinkable-inference key` as Claude
    /// Code's apiKeyHelper, or point the agent's base URL at the proxy.
    Mcp(ServeArgs),
    /// Print a session secret to use in place of an API key (for Claude
    /// Code's apiKeyHelper; needs `unlinkable-inference mcp` or `serve` running)
    Key {
        #[arg(long, env = "UNLINKABLE_LISTEN", default_value = "127.0.0.1:8899")]
        listen: String,
    },
    /// Print the login key for an account code or number read from stdin: what
    /// `POST /login`, `/generate_token` and `/create_account` take as
    /// `account_key`, so the server never sees the code.
    LoginKey,
    /// Show the wallet
    Wallet,
    /// Move a fixed amount ($1, $5, $20, $50, $100) of account balance into
    /// the wallet. Do it ahead of time, not right before you need it: the
    /// server sees when the account withdraws.
    Withdraw {
        /// Dollars
        amount: u32,
        #[arg(long, env = "OBSCURIFY_API_KEY")]
        api_key: String,
    },
    /// Get this month's passes: tokens a session shows when the server asks,
    /// to prove the account was given something (certain models, an allowance)
    /// without saying which account it is. The server names them with labels;
    /// this gets some of each label the account can have. `serve` does it by
    /// itself; get them ahead of time, not when a session needs one.
    Passes {
        /// How many of each label (at most what is left this month)
        #[arg(long, default_value_t = 30)]
        count: i64,
        #[arg(long, env = "OBSCURIFY_API_KEY")]
        api_key: String,
    },
    /// Add voucher codes (obv1.…) to the wallet; `-` reads them from stdin
    Import { codes: Vec<String> },
    /// Print every voucher, for a backup
    Export,
    /// Trade all vouchers for a fresh, standard set with the same total
    Exchange,
    /// Close sessions and finish operations a previous run left open
    Recover,
    /// Show the server's keyset and whether it is pinned
    Keys {
        /// Pin the keyset the server serves now, replacing the old pin
        #[arg(long)]
        trust: bool,
    },
    /// Check the server's keys against your pins and the published pins, and
    /// show what the server receives
    Verify {
        /// Published pins to compare with
        #[arg(long)]
        published: Option<String>,
    },
}

fn parse_dollars(text: &str) -> Result<i64> {
    let cents = unlinkable_inference::net::usd_to_cents_floor(text);
    if cents <= 0 {
        bail!("{text} is not an amount");
    }
    Ok(cents)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "unlinkable_inference=info,unlinkable_inference_cli=info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let opts = Options {
        server: cli.server.trim_end_matches('/').to_string(),
        wallet: cli.wallet,
        pins: cli.pins,
    };

    match cli.command {
        Command::Serve(args) => {
            let (proxy, listener, _lock) = start(&opts, args).await?;
            serve::run(listener, proxy, async {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("unlinkable-inference: closing sessions…");
            })
            .await?;
        }
        Command::Mcp(args) => mcp(&opts, args).await?,
        Command::LoginKey => {
            let mut number = String::new();
            std::io::stdin().read_to_string(&mut number)?;
            println!("{}", unlinkable_inference::seed::account_keys(&number)?.login_key);
        }
        Command::Key { listen } => {
            // The agent may ask before the MCP server has started the proxy.
            let url = format!("http://{listen}/_unlinkable/key");
            let mut last = String::new();
            for _ in 0..60 {
                match reqwest::get(&url).await {
                    Ok(r) if r.status().is_success() => {
                        println!("{}", r.text().await?);
                        return Ok(());
                    }
                    Ok(r) => last = r.text().await.unwrap_or_default(),
                    Err(e) => last = e.to_string(),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            bail!("no session from the proxy at {listen}: {last}");
        }
        Command::Wallet => {
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let period = unlinkable_inference::pass::current_period();
            let passes = pass_counts(&mut wallet, &period);
            println!("wallet   {}", wallet.path().display());
            println!("paid     {}", dollars(wallet.balance_cents(Family::Paid)));
            println!("promo    {}", dollars(wallet.balance_cents(Family::Promo)));
            println!("vouchers {}", wallet.vouchers().len());
            println!("passes   {passes}");
            println!("sessions {} left open", wallet.sessions().len());
            let since = |days: u64| -> i64 {
                let cutoff = unlinkable_inference::unix_now().saturating_sub(days * 86_400);
                wallet.spending().iter().filter(|e| e.at >= cutoff).map(|e| e.millicents).sum()
            };
            let usd = |m: i64| format!("${:.4}", m as f64 / 100_000.0);
            println!("spent    {} last 24 h, {} last 30 days (closed sessions, kept on this device)", usd(since(1)), usd(since(30)));
            if !wallet.pending().is_empty() {
                println!("pending  {} (run `unlinkable-inference recover`)", wallet.pending().len());
            }
            println!("pinned   {}", wallet.pinned().unwrap_or("(nothing yet)"));
        }
        Command::Withdraw { amount, api_key } => {
            let _lock = lock_wallet(&opts)?;
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let client = connect(&opts, &mut wallet).await?;
            let cents = client.withdraw(&mut wallet, &api_key, amount as i64 * 100).await?;
            println!(
                "Added {} to the wallet. It now holds {}.",
                dollars(cents),
                dollars(wallet.balance_cents(Family::Paid))
            );
        }
        Command::Passes { count, api_key } => {
            let _lock = lock_wallet(&opts)?;
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let client = connect(&opts, &mut wallet).await?;
            let allowance = client.pass_allowance(&api_key).await?;
            let mut got = 0;
            for l in &allowance.labels {
                got += client.get_passes(&mut wallet, &api_key, &l.label, &allowance.period, count.min(l.remaining)).await?;
            }
            wallet.save()?;
            println!(
                "Got {got} pass{}. The wallet holds {}.",
                if got == 1 { "" } else { "es" },
                pass_counts(&mut wallet, &allowance.period)
            );
        }
        Command::Import { codes } => {
            let _lock = lock_wallet(&opts)?;
            let mut codes = codes;
            if codes.iter().any(|c| c == "-") {
                let mut text = String::new();
                std::io::stdin().read_to_string(&mut text)?;
                codes = text.split_whitespace().map(str::to_string).collect();
            }
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let client = connect(&opts, &mut wallet).await?;
            let mut added = 0;
            for code in &codes {
                let Some(voucher) = Voucher::parse(code) else {
                    bail!("not a voucher: {code}");
                };
                let Some(family) = unlinkable_inference::blank::verify(&client.keyset, &voucher) else {
                    bail!("{} did not sign {code}", opts.host());
                };
                added += voucher.denomination_cents;
                wallet.add(family, [voucher]);
            }
            wallet.save()?;
            println!("Added {}.", dollars(added));
        }
        Command::Export => {
            let wallet = Wallet::open(opts.wallet_path())?;
            for code in wallet.export() {
                println!("{code}");
            }
        }
        Command::Exchange => {
            let _lock = lock_wallet(&opts)?;
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let client = connect(&opts, &mut wallet).await?;
            for family in [Family::Paid, Family::Promo] {
                let cents = client.exchange(&mut wallet, family).await?;
                if cents > 0 {
                    println!("Exchanged {} of {} vouchers.", dollars(cents), family.as_str());
                }
            }
        }
        Command::Recover => {
            let _lock = lock_wallet(&opts)?;
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let client = connect(&opts, &mut wallet).await?;
            let cents = client.recover(&mut wallet).await?;
            println!("Recovered {}.", dollars(cents));
        }
        Command::Keys { trust } => {
            let _lock = lock_wallet(&opts)?;
            let mut wallet = Wallet::open(opts.wallet_path())?;
            let keyset = opts.transport().fetch_keyset().await?;
            keyset.check()?;
            let fp = keyset.fingerprint();
            println!("server serves  {fp}");
            println!("pinned         {}", wallet.pinned().unwrap_or("(nothing)"));
            let builtin = Pins::builtin(&opts.host());
            println!(
                "built-in pins  {}",
                if builtin.fingerprints.is_empty() {
                    "(none for this server)".to_string()
                } else {
                    builtin.fingerprints.iter().cloned().collect::<Vec<_>>().join(", ")
                }
            );
            if trust {
                wallet.pin(Some(fp.clone()));
                wallet.save()?;
                println!("Pinned {fp}.");
            }
        }
        Command::Verify { published } => {
            verify(&opts, published).await?;
        }
    }
    Ok(())
}

async fn start(
    opts: &Options,
    args: ServeArgs,
) -> Result<(std::sync::Arc<serve::Proxy>, tokio::net::TcpListener, unlinkable_inference_cli::WalletLock)> {
    let ServeArgs {
        listen,
        session_funding,
        per,
        idle_close,
        show_traffic,
        account_number,
        mut api_key,
        keep,
        refill,
    } = args;
    let lock = lock_wallet(opts)?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let mut wallet = Wallet::open(opts.wallet_path())?;
    let mut client = connect(opts, &mut wallet).await?;
    let keys = account_number
        .as_deref()
        .map(unlinkable_inference::seed::account_keys)
        .transpose()?;
    if let Some(keys) = &keys {
        if api_key.is_none() {
            api_key = Some(unlinkable_inference_cli::api_key_for(opts, &keys.login_key).await?);
        }
        client.seed = Some(keys.seed.clone());
    }
    match client.recover(&mut wallet).await {
        Ok(0) => {}
        Ok(c) => eprintln!("unlinkable-inference: recovered {} from an earlier run", dollars(c)),
        Err(e) => eprintln!("unlinkable-inference: could not finish an earlier run's work yet: {e:#}"),
    }
    if keys.is_some() {
        match client.restore(&mut wallet, api_key.as_deref()).await {
            Ok(0) => {}
            Ok(c) => eprintln!("unlinkable-inference: restored {} from the account code", dollars(c)),
            Err(e) => eprintln!("unlinkable-inference: could not restore the wallet yet: {e:#}"),
        }
    }
    let settings = Settings {
        funding_cents: parse_dollars(&session_funding)?,
        mode: per,
        idle_close: Duration::from_secs(idle_close),
        show_traffic,
        account_key: api_key,
        keep_cents: parse_dollars(&keep)?,
        refill_cents: refill as i64 * 100,
        keep_passes: 10,
        account_key_prefix: "sk-obs1_".into(),
        ..Settings::default()
    };
    eprintln!(
        "unlinkable-inference: wallet {} ({}); proxy on http://{listen} (page: http://{listen}/_unlinkable)",
        dollars(wallet.balance_cents(Family::Paid) + wallet.balance_cents(Family::Promo)),
        wallet.path().display()
    );
    Ok((serve::Proxy::new(client, wallet, settings, opts.clone()), listener, lock))
}

/// A minimal MCP server (stdio, JSON-RPC per line) with no tools: it exists so
/// the agent starts and stops the proxy. Ends when the agent closes stdin.
async fn mcp(opts: &Options, args: ServeArgs) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
    let rpc = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        let mut out = tokio::io::stdout();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let Some(id) = msg.get("id").cloned() else {
                continue; // a notification
            };
            let reply = match msg["method"].as_str().unwrap_or("") {
                "initialize" => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "unlinkable-inference", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Runs the unlinkable-inference proxy while the agent runs. It has no tools."
                }}),
                "tools/list" => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
                "ping" => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                _ => serde_json::json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "method not found"}}),
            };
            let mut bytes = reply.to_string().into_bytes();
            bytes.push(b'\n');
            if out.write_all(&bytes).await.is_err() || out.flush().await.is_err() {
                break;
            }
        }
        let _ = eof_tx.send(());
    });
    match start(opts, args).await {
        Ok((proxy, listener, _lock)) => {
            serve::run(listener, proxy, async {
                tokio::select! {
                    _ = eof_rx => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            })
            .await?;
        }
        Err(e) => {
            // Another agent's MCP server (or `unlinkable-inference serve`) has it.
            eprintln!("unlinkable-inference: not starting a proxy here: {e:#}");
            let _ = rpc.await;
        }
    }
    Ok(())
}

async fn verify(opts: &Options, published: Option<String>) -> Result<()> {
    let mut ok = true;
    let keyset = Transport::new(&opts.server).fetch_keyset().await?;
    keyset.check()?;
    let fp = keyset.fingerprint();
    println!("Keys the server serves you:      {fp}");
    let wallet = Wallet::open(opts.wallet_path())?;
    let mut pins = Pins::builtin(&opts.host());
    pins.fingerprints.extend(opts.pins.iter().cloned());
    if let Some(p) = wallet.pinned() {
        pins.fingerprints.insert(p.to_string());
    }
    if pins.fingerprints.is_empty() {
        println!("Pinned:                          nothing yet (pinned on first use)");
    } else if pins.accepts(&keyset) {
        println!("Pinned:                          yes");
    } else {
        ok = false;
        println!("Pinned:                          NO: these keys are not the ones you pinned");
    }
    let published = published.or_else(|| {
        (opts.host() == "obscurify.ai").then(|| {
            "https://raw.githubusercontent.com/Obscurify-ai/unlinkable-inference/main/lib/keys/obscurify.ai.pins"
                .to_string()
        })
    });
    if let Some(url) = published {
        match reqwest::get(&url).await {
            Ok(r) if r.status().is_success() => {
                let text = r.text().await.unwrap_or_default();
                if text.lines().any(|l| l.trim() == fp) {
                    println!("In the published pins:           yes ({url})");
                } else {
                    ok = false;
                    println!("In the published pins:           NO ({url})");
                }
            }
            _ => println!("In the published pins:           could not fetch {url}"),
        }
    }

    println!();
    println!("What the server receives for one request:");
    let seen: std::sync::Arc<std::sync::Mutex<Vec<Observed>>> = Default::default();
    let log = seen.clone();
    let transport = opts
        .transport()
        .observe(std::sync::Arc::new(move |o: &Observed| log.lock().unwrap().push(o.clone())));
    let resp = transport.send(Request::get("/v1/models")).await?;
    let status = resp.status;
    let _ = resp.bytes().await;
    for o in seen.lock().unwrap().iter() {
        println!("  {}", o.server_sees);
    }
    println!("  answer: HTTP {status}");
    println!("  (plus your IP address, unless Tor or a VPN hides it)");
    if !ok {
        bail!("verification failed");
    }
    println!("\nAll checks passed.");
    Ok(())
}

/// "12 for 2026-11 (plus 10, metered 2)"
fn pass_counts(wallet: &mut Wallet, period: &str) -> String {
    let held = wallet.passes(period);
    let mut by_label = std::collections::BTreeMap::<&str, usize>::new();
    for p in &held {
        *by_label.entry(p.label.as_str()).or_default() += 1;
    }
    let labels: Vec<String> = by_label.iter().map(|(l, n)| format!("{l} {n}")).collect();
    match labels.is_empty() {
        true => format!("0 for {period}"),
        false => format!("{} for {period} ({})", held.len(), labels.join(", ")),
    }
}
