//! `kasprivate-miner` — a standalone CPU miner for the kasprivate network
//! (blocker #4). It talks the standard `get_block_template` / `submit_block` RPC to
//! a `kaspad` node, searches the nonce space with the shared FishHashPlus PoW
//! ([`kaspa_pow::State`], the very code the node verifies with), and submits solved
//! blocks. The mining reward is paid to a `kasprivate:` shielded address, so a
//! bootstrapped chain is private-by-default from its first mined block.
//!
//! This is intentionally a CPU miner: on a fresh, low-difficulty genesis chain a
//! CPU is enough to produce the first blocks and get the network moving. A GPU
//! kernel is a later optimization; the search logic and the node acceptance
//! contract are identical either way (see [`solver`]).

mod solver;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use kaspa_addresses::Address;
use kaspa_consensus_core::header::Header;
use kaspa_grpc_client::GrpcClient;
use kaspa_hashes::FishHashContext;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

/// CLI arguments.
#[derive(Parser, Debug)]
#[command(name = "kasprivate-miner", about = "Standalone CPU miner for the kasprivate network (FishHashPlus PoW)")]
struct Args {
    /// kaspad gRPC endpoint (host:port).
    #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
    rpc_server: String,

    /// The `kasprivate:` shielded address the block reward is paid to.
    #[arg(short = 'a', long)]
    mining_address: String,

    /// Worker threads (0 = one per logical CPU).
    #[arg(short = 't', long, default_value_t = 0)]
    threads: usize,

    /// Build the full ~4.6GB FishHash dataset for the fast memory-hard path.
    /// Without it, the shared light cache is used (slower per hash, no big alloc).
    #[arg(long, default_value_t = false)]
    full_dataset: bool,

    /// Seconds to mine one template before refetching a fresh one (so the miner
    /// follows new tips instead of wasting work on a stale parent set).
    #[arg(long, default_value_t = 5)]
    refresh_secs: u64,
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let args = Args::parse();

    let mining_address = match Address::try_from(args.mining_address.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            log::error!("invalid --mining-address {:?}: {e}", args.mining_address);
            std::process::exit(1);
        }
    };
    let threads = if args.threads == 0 { num_cpus::get() } else { args.threads };

    // The full dataset (if requested) is built once, up front; the light path lazily
    // builds only the ~75MB verification cache on first hash.
    let full_ctx: Option<Arc<FishHashContext>> = if args.full_dataset {
        log::info!("building full FishHash dataset (~4.6GB, one-time)...");
        Some(Arc::new(FishHashContext::new(true, None)))
    } else {
        log::info!("using the light FishHash cache (pass --full-dataset for the fast path)");
        None
    };

    let client = connect(&args.rpc_server).await;
    log::info!("mining to {} with {threads} threads, refreshing template every {}s", mining_address, args.refresh_secs);

    let mut warned_unsynced = false;
    loop {
        // Fetch a fresh template for the current tips.
        let template = match client.get_block_template(mining_address.clone(), Vec::new()).await {
            Ok(t) => t,
            Err(e) => {
                log::warn!("get_block_template failed: {e}; retrying in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if !template.is_synced && !warned_unsynced {
            log::warn!("node reports NOT synced — solved blocks may be orphaned until it catches up");
            warned_unsynced = true;
        }

        let mut raw_block = template.block;
        let header: Header = match raw_block.header.clone().try_into() {
            Ok(h) => h,
            Err(e) => {
                log::warn!("template header could not be converted: {e}; refetching");
                continue;
            }
        };

        // Mine this template for up to `refresh_secs`, then abandon it for a fresh one.
        let stop = Arc::new(AtomicBool::new(false));
        let deadline = {
            let stop = stop.clone();
            let secs = args.refresh_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                stop.store(true, Ordering::Relaxed);
            })
        };

        let nonce = {
            let header = header.clone();
            let full_ctx = full_ctx.clone();
            let stop = stop.clone();
            tokio::task::spawn_blocking(move || solver::mine_header(&header, full_ctx, threads, &stop))
                .await
                .expect("mining worker panicked")
        };
        deadline.abort();

        let Some(nonce) = nonce else {
            // Template expired without a solution; loop to fetch a fresh one.
            continue;
        };

        // The node recomputes and validates the block hash itself, so setting the
        // winning nonce on the raw header is all that's needed before submitting.
        raw_block.header.nonce = nonce;
        let block_hash = header_hash_with_nonce(&header, nonce);
        match client.submit_block(raw_block, false).await {
            Ok(resp) if resp.report.is_success() => log::info!("BLOCK ACCEPTED  nonce={nonce}  hash={block_hash}"),
            Ok(resp) => log::warn!("block rejected: {:?}  (nonce={nonce})", resp.report),
            Err(e) => log::warn!("submit_block failed: {e}  (nonce={nonce})"),
        }
    }
}

/// Recompute the block hash for logging (the node is the source of truth; this is
/// only so the log line matches what the node will report).
fn header_hash_with_nonce(header: &Header, nonce: u64) -> kaspa_hashes::Hash {
    let mut h = header.clone();
    h.nonce = nonce;
    h.finalize();
    h.hash
}

/// Connect a gRPC client to `address` (Direct notification mode; the miner does not
/// subscribe to notifications, it polls templates).
async fn connect(address: &str) -> GrpcClient {
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{address}"),
        None,
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    .unwrap_or_else(|e| {
        log::error!("failed to connect to {address}: {e}");
        std::process::exit(1);
    })
}
