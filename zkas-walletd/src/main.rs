//! Thin CLI over the `zkas-walletd` library — flag parsing and bind policy only;
//! the daemon itself (REST API, sync loops, shielded engine) lives in `lib.rs` so
//! the desktop wallet can embed it in-process.

use clap::Parser;
use std::net::SocketAddr;
use zkas_walletd::{Config, default_wallet_dir, serve};

#[derive(Parser, Debug)]
#[command(name = "zkas-walletd", about = "ZKas shielded wallet daemon (self-hosted or hosted)")]
struct Cli {
    /// ZKas node gRPC endpoint (host:port). In hosted mode, a public node.
    #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
    rpc_server: String,
    /// Address:port to serve the wallet REST API on. Loopback by default.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8501")]
    listen: String,
    /// Directory holding one wallet file per token. Default: ~/.ZKas/wallets.
    #[arg(long)]
    wallet_dir: Option<String>,
    /// Network: mainnet | testnet | devnet | simnet.
    #[arg(long, default_value = "mainnet")]
    network: String,
    /// Permit binding a non-loopback address directly (prefer a TLS proxy instead).
    #[arg(long, default_value_t = false)]
    allow_remote: bool,
    /// Browser origin allowed to call the wallet API via CORS (repeatable, e.g.
    /// `--allow-origin https://wallet.ZKas.info`). With none given, cross-origin
    /// browser requests are refused (same-origin only) — this closes the drive-by
    /// wallet-read/drain vector where any page a user visits could reach the daemon.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// Permit the tokenless "default" wallet when no `X-Wallet-Token` header is sent.
    /// Off by default: every request must carry a token, so another local process
    /// can't read the default wallet. Enable only for a trusted single-user localhost.
    #[arg(long, default_value_t = false)]
    allow_default_token: bool,
    /// Secret used to encrypt wallet seed files at rest (XChaCha20-Poly1305, Argon2
    /// key). May also be set via the `ZKAS_WALLET_SECRET` env var (the legacy
    /// `FIRECASH_WALLET_SECRET` is still honored). If unset, seeds are stored in
    /// plaintext (0600 on unix) and a warning is logged at startup.
    #[arg(long)]
    wallet_secret: Option<String>,
    /// Offline admin: print each wallet's note/base/STRANDED-note report and exit.
    /// Run with the daemon stopped.
    #[arg(long, default_value_t = false)]
    diagnose: bool,
    /// Offline admin: repair a stranded wallet by grafting the leaf stream from an
    /// older snapshot of the same wallet (format: `TOKEN:/path/to/older.scan`).
    /// Run with the daemon stopped.
    #[arg(long)]
    graft: Option<String>,
}

// Oversubscribe worker threads (2x cores). The background sync loop does CPU-bound
// work (trial decryption, witness advance) on the runtime; with only `ncpu` workers a
// mass initial scan of many wallets pins every worker and HTTP handlers — which only
// read in-memory state — starve for seconds (observed live: public /api/status timing
// out at 15s during a 170-wallet rescan). With more workers than cores, a newly
// runnable HTTP handler is always schedulable within a time slice, so status stays
// responsive while scans grind in the background.
#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let cli = Cli::parse();

    // Offline admin modes: operate on the wallet files directly and exit.
    let admin_secret = cli
        .wallet_secret
        .clone()
        .or_else(|| std::env::var("ZKAS_WALLET_SECRET").ok())
        .or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok());
    if cli.diagnose || cli.graft.is_some() {
        let dir = cli.wallet_dir.clone().unwrap_or_else(default_wallet_dir);
        if let Some(spec) = &cli.graft {
            let Some((token, older)) = spec.split_once(':') else {
                eprintln!("--graft wants TOKEN:/path/to/older.scan");
                std::process::exit(2);
            };
            match zkas_walletd::graft_wallet(&dir, token, older, admin_secret.as_deref()) {
                Ok(report) => println!("{token}: {report}"),
                Err(e) => {
                    eprintln!("{token}: graft refused: {e}");
                    std::process::exit(1);
                }
            }
        }
        if cli.diagnose {
            print!("{}", zkas_walletd::diagnose_wallets(&dir, admin_secret.as_deref()));
        }
        return;
    }

    let listen: SocketAddr = cli.listen.parse().unwrap_or_else(|e| {
        log::error!("bad --listen {:?}: {e}", cli.listen);
        std::process::exit(1);
    });
    if !listen.ip().is_loopback() && !cli.allow_remote {
        log::error!("refusing to bind non-loopback {} without --allow-remote (put a TLS proxy in front instead)", listen);
        std::process::exit(1);
    }

    let cfg = Config {
        rpc_server: cli.rpc_server,
        listen,
        wallet_dir: cli.wallet_dir.unwrap_or_else(default_wallet_dir),
        network: cli.network,
        allow_origin: cli.allow_origin,
        allow_default_token: cli.allow_default_token,
        // Seed-file encryption secret: CLI flag, ZKAS_WALLET_SECRET, or the legacy
        // FIRECASH_WALLET_SECRET env (still honored so pre-rebrand service files work).
        wallet_secret: cli
            .wallet_secret
            .or_else(|| std::env::var("ZKAS_WALLET_SECRET").ok())
            .or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok()),
    };

    // The sender is held (never fired) so the daemon runs until the process dies.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    if let Err(e) = serve(cfg, shutdown_rx).await {
        log::error!("{e}");
        std::process::exit(1);
    }
}
