use clap::Parser;

/// A minimal Oblivious HTTP relay. Clients post sealed requests to
/// http://<listen>/<name>; they go to <origin>/ohttp for that name.
#[derive(Parser)]
#[command(name = "unlinkable-relay", version)]
struct Args {
    /// Address to listen on
    #[arg(long, env = "RELAY_LISTEN", default_value = "127.0.0.1:8240")]
    listen: String,
    /// Gateways this relay forwards to, as name=https://origin (repeatable)
    #[arg(long = "target", env = "RELAY_TARGETS", value_delimiter = ',', required = true)]
    targets: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .init();
    let args = Args::parse();
    let relay = unlinkable_relay::Relay::from_specs(&args.targets)?;
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    eprintln!("relay listening on {} for {}", args.listen, args.targets.join(", "));
    // Plain serve: no connect info is ever read, so client addresses never
    // reach a handler, let alone a log.
    axum::serve(listener, relay.router()).await?;
    Ok(())
}
