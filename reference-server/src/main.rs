use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use unlinkable_inference::server::signer::{KeyStore, PassKey};

/// Reference unlinkable-inference server with an echo model and play money.
/// `POST /test/accounts` makes an account; `GET /debug/db` dumps everything.
#[derive(Parser)]
#[command(name = "unlinkable-inference-reference-server", version)]
struct Args {
    #[arg(long, env = "LISTEN", default_value = "127.0.0.1:8250")]
    listen: SocketAddr,
    /// Keep voucher keys here (otherwise they last for the process)
    #[arg(long, env = "KEYS_DIR")]
    keys_dir: Option<PathBuf>,
    /// Sessions stop working after this many idle seconds
    #[arg(long, env = "IDLE_TIMEOUT_SECONDS", default_value_t = 6 * 3600)]
    idle_timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let pass = match &args.keys_dir {
        Some(dir) => PassKey::load_or_create(&dir.join("pass_master.pem"))?,
        None => PassKey::from_pem(&PassKey::generate()?)?,
    };
    let dust = KeyStore::new(
        &unlinkable_inference::denominations::DUST_MILLICENTS,
        args.keys_dir.as_ref().map(|d| d.join("dust")).as_deref(),
    )?;
    let keys = KeyStore::all(args.keys_dir.as_deref())?
        .with_pass_key(pass)
        .with_dust(dust);
    let server = unlinkable_inference_reference_server::build(
        keys,
        Duration::from_secs(args.idle_timeout_seconds),
    );
    eprintln!(
        "reference server on http://{} (keyset {})",
        args.listen,
        server.gateway.keyset.fingerprint()
    );
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(
        listener,
        server
            .router
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
