use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use flipple_multiplayer_relay::auth::TicketVerifier;
use flipple_multiplayer_relay::relay::Relay;
use flipple_multiplayer_relay::tls;
use quinn::Endpoint;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(about = "Flipple Minecraft Bedrock QUIC relay")]
struct Args {
    #[arg(long, env = "MULTIPLAYER_RELAY_BIND", default_value = "0.0.0.0:443")]
    bind: SocketAddr,
    #[arg(long, env = "MULTIPLAYER_RELAY_CERT")]
    certificate: PathBuf,
    #[arg(long, env = "MULTIPLAYER_RELAY_KEY")]
    private_key: PathBuf,
    #[arg(long, env = "MULTIPLAYER_TICKET_KID")]
    ticket_key_id: String,
    #[arg(long, env = "MULTIPLAYER_TICKET_PUBLIC_KEY")]
    ticket_public_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let public_key = URL_SAFE_NO_PAD
        .decode(args.ticket_public_key)
        .context("MULTIPLAYER_TICKET_PUBLIC_KEY must be base64url without padding")?
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("MULTIPLAYER_TICKET_PUBLIC_KEY must contain exactly 32 bytes")
        })?;
    let verifier = TicketVerifier::new(args.ticket_key_id, public_key)?;
    let server_config = tls::server_config(
        tls::load_certificate(&args.certificate)?,
        tls::load_private_key(&args.private_key)?,
    )?;
    let endpoint = Endpoint::server(server_config, args.bind).context("bind QUIC relay")?;
    Relay::new(verifier).serve(endpoint).await
}
