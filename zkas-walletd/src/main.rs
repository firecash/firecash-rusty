//! `ZKas-walletd` — a shielded wallet daemon for the ZKas network.
//!
//! It is the engine behind the ZKas web wallet. It drives the *same* shielded
//! primitives the CLI `shielded-pay` uses (`kaspa-shielded-core`): key generation,
//! chain scan with the wallet's viewing key, real Orchard (Halo 2) shielded spends,
//! and message sign/verify. Proofs are generated natively here (no in-browser Halo 2
//! needed) and submitted to a ZKas node over gRPC.
//!
//! ## Two deployment modes
//!
//! - **Self-hosted (non-custodial):** the user runs this on their own machine; the
//!   seed never leaves it. Point the web UI's daemon URL at `http://127.0.0.1:8501`.
//! - **Hosted (convenience hot-wallet):** one instance serves many browsers behind a
//!   reverse proxy, connected to a public ZKas node so users need no node of
//!   their own. Each browser owns a random **wallet token** (an `X-Wallet-Token`
//!   header); the daemon keeps one wallet per token. In this mode the seed is stored
//!   server-side — weaker than keys-in-browser; the endgame is a client-side WASM
//!   wallet (WebZjs-style). Do not expose this daemon directly; put a TLS proxy in
//!   front and keep the bind on loopback.
//!
//! ## Sync model
//!
//! Each wallet keeps a live [`WalletDb`] in memory and advances it **incrementally**:
//! an initial one-time replay from genesis (needed to build the note-commitment tree
//! correctly), then cheap catch-up of only new blocks. The background loop processes
//! wallets in bounded chunks so status stays responsive while a big initial scan runs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    routing::{get, post},
};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use clap::Parser;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcHash, RpcShieldedChainBlock, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::{ShieldedBundle, expected_wire_len};
use kaspa_shielded_core::coinbase::CoinbaseNoteDesc;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::FrontierState;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::{PreparedPayment, build_wallet_payment, finalize_payment, prepare_payment, proving_key};
use kaspa_shielded_core::walletdb::{Preview, WalletDb};
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tokio::sync::Mutex;

/// 1 FC = 10^8 sompi.
const SOMPI_PER_ZKAS: u64 = 100_000_000;
/// Shielded output script length (raw Orchard address carried in a reward script).
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Anchor maturity depth (blocks) — must match consensus `shielded_anchor_depth`
/// (600 * BPS = 600 at 1 BPS, ~10 min). A note is spendable once this deep.
const DEFAULT_ANCHOR_DEPTH: u64 = 600;
/// Max `GetShieldedBlocks` pages a wallet advances per sync chunk. Kept small so
/// the per-wallet lock is released frequently (status stays responsive); speed
/// comes from looping back immediately instead of pausing between chunks.
// Small so each `sync_chunk` — which holds the wallet's mutex the whole time — is short
// (one page ≈ 200 blocks ≈ tens of ms). The status handler locks the same mutex; a large
// chunk held the lock for seconds and hung status behind the sync loop. The loop drops
// the lock and re-acquires per chunk, so status interleaves.
// 4 pages/chunk: the shared decode (see `DecodedPage`) makes per-wallet ingest
// cheaper, so a wallet can absorb more blocks per pass — fewer passes to clear a
// mass rescan — while the lock is still dropped between chunks for status calls.
// NB: kept small on purpose. Enlarging the page/chunk (tried 1000/2) lengthens the
// synchronous decode burst under the wallet lock and starves the axum HTTP handlers
// during a scan — it took wallet.zkas.info's /health/status to timeouts on 2026-07-15.
const PAGES_PER_CHUNK: usize = 4;
/// Chain blocks requested per `GetShieldedBlocks` page (node max 2000). Raised
/// 200→1000 for fewer round-trips and bigger ingest bursts between the node's
/// pruning-lock stalls — safe now that (a) the RPC target is the local node
/// (~ms/page), (b) the eager witness advance is gone from the sync path, and
/// (c) status reads lock-free snapshots, so a longer burst under the wallet
/// lock no longer blocks status calls.
const SHIELDED_PAGE: u64 = 1000;
/// Blue-score margin the sync holds back from the sink before ingesting a chain
/// block. The wallet's tree is append-only (no rollback), so it must not ingest a
/// block that a routine near-tip reorg could still replace. Blue score advances
/// roughly with the DAG block rate, so on a wide DAG a small margin is only
/// seconds of depth — 20 was observed thrashing live (dozens of reorg evictions
/// per hour). 200 ≈ 2–3 minutes of settling; balances simply lag the tip by
/// that much. A reorg deeper than this margin triggers a rescan.
const SYNC_TIP_MARGIN: u64 = 200;
/// How many consecutive sync passes must see the cursor off the selected chain
/// before the wallet is evicted and rescanned. The virtual chain flips
/// transiently near the tip; a single `reorged` response is usually stale within
/// a pass or two, and a rescan costs the whole scan history.
const REORG_STRIKES: u32 = 3;
/// Node error substrings that are *positive* evidence the wallet's cursor block is
/// no longer retrievable, so its checkpoint must be retired and the wallet rescanned
/// from the current pruning-point frontier:
/// - `cannot find full block` — the node never knew the hash (`ConsensusError::BlockNotFound`).
/// - `cannot find header` — the block was **pruned away** (its header is gone;
///   `ConsensusError::HeaderNotFound`). A wallet that falls behind the pruning point —
///   e.g. the daemon was starved for a while and the chain pruned past its cursor —
///   lands here. Before this it stalled **forever**, stuck at whatever % it froze at,
///   because only the first string was matched.
/// - `required chain data is missing` — pruned/corrupt chain store (`SyncManagerError`).
///
/// Discarding a checkpoint is destructive (forces a rescan), so it must be driven by
/// one of these *positive* signals — never by the mere fact that an RPC returned `Err`.
/// A timeout or an overloaded node also returns `Err`, and treating that as "cursor
/// unknown" is what nuked eleven wallets in one 20ms burst on 2026-07-12 and a live
/// user's wallet seconds after a send on 2026-07-13 (the send's Halo 2 proof is exactly
/// the CPU spike that makes the probe RPC time out).
const CURSOR_GONE_MARKERS: [&str; 4] = [
    "cannot find full block",
    "cannot find header",
    "required chain data is missing",
    // The node refuses to base a chain walk on this cursor: it is below the retention
    // period root, or on a stale branch whose chain no longer reaches it. The block may
    // still *exist* (a `get_block` probe succeeds!), but the walk can never proceed from
    // it — deterministic, not transient. Observed live 2026-07-16: a wallet frozen at 74%
    // for hours, its page fetch failing with this while `get_block` kept succeeding.
    "does not have retention root",
];

/// True if a node error string is positive evidence the cursor block is gone (see
/// [`CURSOR_GONE_MARKERS`]).
fn cursor_gone(err: &str) -> bool {
    CURSOR_GONE_MARKERS.iter().any(|m| err.contains(m))
}
/// Extra blue-score slack under the consensus anchor-maturity depth when picking
/// the anchor a spend roots at, so it stays matured while the tx awaits merging.
const ANCHOR_SLACK: u64 = 30;

// ---------------------------------------------------------------------------
// Standard-mass budget: how many notes one shielded tx may spend.
//
// The mempool rejects any tx whose per-dimension mass exceeds 100 000, and
// transient mass = serialized bytes × 4 — so a standard shielded tx must fit in
// ~25 000 bytes. Each spent note adds one 884-byte action PLUS 2 272 proof
// bytes, which caps spends per tx at SIX. A send that needs more notes must be
// split into several transactions; previously walletd would happily build a
// 14-spend bundle (a 106-minute proof!) only to have the node reject it at
// 188 460 transient mass.
// ---------------------------------------------------------------------------

/// Mempool `MAXIMUM_STANDARD_TRANSACTION_MASS` (per dimension).
const STANDARD_TX_MASS_CAP: u64 = 100_000;
/// Consensus `TRANSIENT_BYTE_TO_MASS_FACTOR` (transient mass per serialized byte).
const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;
/// Bytes of transaction envelope outside the bundle payload (~94 observed live;
/// padded for safety).
const TX_ENVELOPE_MARGIN: usize = 256;

/// Largest number of spent notes whose bundle still fits the standard transient
/// mass cap. A payment bundle carries `max(spends, 2)` actions (recipient +
/// change outputs are padded in). Evaluates to 6 with today's constants.
fn max_spends_per_tx() -> usize {
    let budget = (STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR) as usize - TX_ENVELOPE_MARGIN;
    let mut n = 1usize;
    while expected_wire_len((n + 1).max(2)) <= budget {
        n += 1;
    }
    n
}

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
}

/// Map the `--network` string to the consensus [`NetworkType`] the compile-time
/// params are keyed by.
fn state_prefix_network(network: &str) -> kaspa_consensus_core::network::NetworkType {
    use kaspa_consensus_core::network::NetworkType;
    match network.to_ascii_lowercase().as_str() {
        "testnet" => NetworkType::Testnet,
        "devnet" => NetworkType::Devnet,
        "simnet" => NetworkType::Simnet,
        _ => NetworkType::Mainnet,
    }
}

fn prefix_from(network: &str) -> Prefix {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Prefix::Mainnet,
        "testnet" => Prefix::Testnet,
        "devnet" => Prefix::Devnet,
        "simnet" => Prefix::Simnet,
        _ => Prefix::Mainnet,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A wallet token identifies one browser's wallet. Sanitise it hard: it becomes a
/// filename, so allow only url-safe token chars and a sane length.
fn sanitize_token(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > 128 {
        return None;
    }
    if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') { Some(t.to_string()) } else { None }
}

/// Pull the wallet token from the request. A token is required by default (401 when
/// absent), so an unauthenticated caller can't reach any wallet. When
/// `allow_default` is set the daemon falls back to the "default" wallet for the
/// trusted single-user localhost case.
fn token_from(headers: &HeaderMap, allow_default: bool) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    match headers.get("x-wallet-token").and_then(|v| v.to_str().ok()) {
        Some(raw) => sanitize_token(raw).ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid X-Wallet-Token")),
        None if allow_default => Ok("default".to_string()),
        None => Err(err(StatusCode::UNAUTHORIZED, "missing X-Wallet-Token")),
    }
}

// ---------------------------------------------------------------------------
// Persistence: one 0600 JSON file per wallet token.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    network: String,
    seed_hex: String,
    encrypted: bool,
    /// Wallet "birthday": the block height the display scan starts from. 0 = scan
    /// from genesis (a wallet that may hold historical funds). A freshly created
    /// wallet is born at the current tip, so it needs no historical scan.
    #[serde(default)]
    birthday: u64,
    /// Non-custodial wallets store their 96-byte FULL VIEWING KEY here and leave
    /// `seed_hex` empty: the daemon can scan and build proofs, but holds no spend
    /// authority. Absent in v1 files, which are all seed wallets.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fvk_hex: String,
}

/// What key material the daemon holds for a wallet.
///
/// `Fvk` is the non-custodial (mobile) case: the device generated the seed, kept it,
/// and registered only its viewing key. Every spend path is refused for such a wallet
/// — signatures must come from the device (`/prepare` + `/submit`).
#[derive(Clone, Copy)]
enum WalletKey {
    Seed([u8; 32]),
    Fvk([u8; 96]),
}

impl WalletKey {
    fn is_watch_only(&self) -> bool {
        matches!(self, WalletKey::Fvk(_))
    }

    /// The seed, or a 403 telling the caller where spend authority actually lives.
    fn seed(&self) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
        match self {
            WalletKey::Seed(s) => Ok(*s),
            WalletKey::Fvk(_) => Err(err(
                StatusCode::FORBIDDEN,
                "this wallet is watch-only: the daemon holds no seed and cannot spend or sign for it. \
                 Use /api/wallet/prepare + /api/wallet/submit and sign on the device that holds the seed.",
            )),
        }
    }

    fn empty_db(&self) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_seed(*s),
            WalletKey::Fvk(f) => WalletDb::from_fvk(f),
        }
    }

    fn db_from_checkpoint(&self, bytes: &[u8]) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_checkpoint(*s, bytes),
            WalletKey::Fvk(f) => WalletDb::from_checkpoint_fvk(f, bytes),
        }
    }

    /// As [`Self::db_from_checkpoint`], but with the tip tree the node reported for the
    /// checkpoint's own cursor block — so an old (v3) checkpoint restores without
    /// replaying its leaf stream. Falls back to the replay if the frontier doesn't match.
    fn db_from_checkpoint_with_tip(&self, bytes: &[u8], tip: &kaspa_shielded_core::tree::FrontierState) -> Option<WalletDb> {
        match self {
            WalletKey::Seed(s) => WalletDb::from_checkpoint_with_tip(*s, bytes, tip),
            WalletKey::Fvk(f) => WalletDb::from_checkpoint_fvk_with_tip(f, bytes, tip),
        }
    }

    /// A wallet view fast-synced onto a pruning-point frontier.
    fn db_from_frontier(&self, fs: &kaspa_shielded_core::tree::FrontierState) -> Option<WalletDb> {
        let mut db = self.empty_db()?;
        db.apply_frontier(fs)?;
        Some(db)
    }
}

fn wallet_path(dir: &str, token: &str) -> String {
    format!("{dir}/{token}.json")
}

/// Encrypt a 32-byte seed under `secret` → `salt(16) || nonce(24) || ciphertext`.
/// Key = Argon2 over `(secret, salt)`; the key is never written to the file.
fn encrypt_seed(seed: &[u8; 32], secret: &str) -> Result<Vec<u8>, String> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut key = [0u8; 32];
    argon2::Argon2::default().hash_password_into(secret.as_bytes(), &salt, &mut key).map_err(|e| format!("argon2: {e}"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), seed.as_slice()).map_err(|e| format!("encrypt: {e}"))?;
    let mut blob = Vec::with_capacity(16 + 24 + ct.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Inverse of [`encrypt_seed`]: recover the 32-byte seed from `blob` using `secret`.
fn decrypt_seed(blob: &[u8], secret: &str) -> Result<[u8; 32], String> {
    if blob.len() < 16 + 24 + 16 {
        return Err("ciphertext too short".into());
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce, ct) = rest.split_at(24);
    let mut key = [0u8; 32];
    argon2::Argon2::default().hash_password_into(secret.as_bytes(), salt, &mut key).map_err(|e| format!("argon2: {e}"))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| "decrypt failed (wrong --wallet-secret?)".to_string())?;
    <[u8; 32]>::try_from(pt.as_slice()).map_err(|_| "decrypted seed is not 32 bytes".to_string())
}

/// Load a wallet's (key, birthday) from disk, decrypting the seed with `secret`
/// when the file is encrypted. A file carrying an `fvk_hex` is a watch-only
/// (non-custodial) wallet: there is no seed on this machine to decrypt.
fn load_wallet_meta(dir: &str, token: &str, secret: Option<&str>) -> Option<(WalletKey, u64)> {
    let bytes = std::fs::read(wallet_path(dir, token)).ok()?;
    let wf: WalletFile = serde_json::from_slice(&bytes).ok()?;
    if !wf.fvk_hex.is_empty() {
        let fvk = unhex(&wf.fvk_hex).and_then(|b| <[u8; 96]>::try_from(b.as_slice()).ok())?;
        return Some((WalletKey::Fvk(fvk), wf.birthday));
    }
    let seed = if wf.encrypted {
        let blob = unhex(&wf.seed_hex)?;
        let secret = secret.or_else(|| {
            log::error!("wallet '{token}' is encrypted but no --wallet-secret / ZKAS_WALLET_SECRET is set");
            None
        })?;
        decrypt_seed(&blob, secret).map_err(|e| log::error!("cannot decrypt wallet '{token}': {e}")).ok()?
    } else {
        unhex(&wf.seed_hex).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?
    };
    Some((WalletKey::Seed(seed), wf.birthday))
}

fn wallet_exists(dir: &str, token: &str) -> bool {
    std::path::Path::new(&wallet_path(dir, token)).exists()
}

fn save_seed(dir: &str, token: &str, network: &str, seed: &[u8; 32], birthday: u64, secret: Option<&str>) -> std::io::Result<()> {
    let (seed_hex, encrypted) = match secret {
        Some(s) => {
            let blob = encrypt_seed(seed, s).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            (hex(&blob), true)
        }
        None => (hex(seed), false),
    };
    let wf = WalletFile { version: 1, network: network.to_string(), seed_hex, encrypted, birthday, fvk_hex: String::new() };
    write_wallet_file(dir, token, &wf)
}

/// Persist a **watch-only** wallet: only the full viewing key is written — there is
/// no seed to protect, so `--wallet-secret` encryption is moot. A compromise of this
/// file leaks the ability to *see* the wallet, never to spend it.
fn save_fvk(dir: &str, token: &str, network: &str, fvk: &[u8; 96], birthday: u64) -> std::io::Result<()> {
    let wf = WalletFile {
        version: 2,
        network: network.to_string(),
        seed_hex: String::new(),
        encrypted: false,
        birthday,
        fvk_hex: hex(fvk),
    };
    write_wallet_file(dir, token, &wf)
}

fn write_wallet_file(dir: &str, token: &str, wf: &WalletFile) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = wallet_path(dir, token);
    std::fs::write(&path, serde_json::to_vec_pretty(wf).expect("serializes"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan checkpoint: persist the scanned commitment stream + owned notes + cursor
// so a restart resumes instead of rescanning the chain from the wallet birthday.
// ---------------------------------------------------------------------------

/// Sidecar file holding a token's scan checkpoint (next to its `.json` seed file).
fn scan_path(dir: &str, token: &str) -> String {
    format!("{dir}/{token}.scan")
}

const SCAN_MAGIC: &[u8; 4] = b"FCWS";
/// v3: WalletDb v3 (spent-nullifier drop rule) — v2 trees may hold
/// double-applied bundles (phantom notes + shifted positions), so they rescan.
/// v2: chain-ordered sync (cursor = last ingested *chain* block), guarded by the
/// network genesis hash, with the matured-anchor ring + sink blue score appended.
/// Bumping from v1 deliberately invalidates every v1 checkpoint: those were built
/// from DAG-ordered `get_blocks` ingestion, which double-counts non-chain
/// coinbases and mis-orders leaves on a wide DAG (the live balance-mismatch bug).
const SCAN_VERSION: u8 = 3;
/// magic(4) + version(1) + genesis(32) + low(32) + scanned(8).
const SCAN_HEADER_LEN: usize = 77;
/// Rewrite the checkpoint after this many newly-scanned blocks (and once a wallet
/// first reaches the tip). Bounds work lost on a crash without writing the growing
/// blob on every tiny sync pass; a restart re-scans at most this many cheap blocks.
// Persist scan progress this often. Kept modest so a daemon restart during a long
// initial scan doesn't throw away all progress and re-trigger a full rescan of the
// whole wallet cohort (a "thundering herd" that pins every core). At ~32B/leaf the
// checkpoint blob stays small, so frequent writes are cheap.
const CHECKPOINT_EVERY: usize = 1000;

/// Max leaves the background loop advances a wallet's spend-witnesses per step before
/// yielding, so a large catch-up never runs as one core-pinning burst.
#[allow(dead_code)]
const WITNESS_ADVANCE_CAP: u64 = 4000;

/// Total per-pass budget for eager witness catch-up, in (leaf × witness) hash units.
/// `advance_witnesses_capped(cap)` costs `cap × (owned-note count)` Sinsemilla hashes —
/// so a fixed leaf cap makes a many-note wallet's step blow up: a pool/miner wallet with
/// thousands of notes was observed taking **7–15 s per step**, which pins the sync loop
/// and freezes every other wallet's scan. Deriving the per-pass leaf cap as
/// `BUDGET / note_count` (floored at [`WITNESS_MIN_STEP`]) bounds the step to roughly this
/// many hashes regardless of wallet size, keeping the loop responsive. Witnesses that
/// don't finish catching up here are rebuilt on demand at spend time anyway.
#[allow(dead_code)]
const WITNESS_ADVANCE_BUDGET: u64 = 400_000;
/// Floor on the per-pass leaf cap, so even a huge wallet still makes some progress.
#[allow(dead_code)]
const WITNESS_MIN_STEP: u64 = 32;

/// A wallet is synced by the background loop only while it has been touched by a
/// request within this window; after that it is parked until the next request. Keeps a
/// public daemon's CPU proportional to *active* wallets, not total tokens ever seen.
const ACTIVE_SYNC_WINDOW: std::time::Duration = std::time::Duration::from_secs(90);

/// How many active wallets the sync loop advances **concurrently**. The per-wallet
/// scan is CPU-bound (Sinsemilla appends + trial decryption) with no await inside, so
/// a single sequential loop pins exactly one core while the other cores sit idle — a
/// wallet then advances at (one core's rate ÷ number of active wallets), which crawls
/// once several wallets are active (observed: a wallet "stuck at 74%" on the live
/// daemon while one tokio worker ran at 99% and the rest were idle). Running a bounded
/// number in parallel uses the idle cores, multiplying throughput ~N×. Bounded (not
/// unbounded) so it never consumes every core — HTTP handlers, the node, and the
/// mempool loop must still get scheduled. Kept at cores-2 (min 2) to leave headroom.
// Shielded scanning performs substantial synchronous curve work while holding a
// wallet lock. More than one scan at a time can occupy every Tokio worker and make
// /health and /api/status time out. Keep it serial until the CPU portion is moved
// behind spawn_blocking; availability is more important than catch-up throughput.
const SYNC_CONCURRENCY: usize = 3;

/// Real sleep between wallets in the sync loop, to guarantee CPU headroom for the HTTP
/// handlers even while scans run. Caps sync throughput; keeps the daemon responsive.
/// Hard ceiling on any single node RPC made from the shared sync loop. The loop drives
/// every wallet sequentially, so an un-timed-out await there is a whole-daemon stall, not
/// a one-wallet stall (see `sync_chunk`). Generous enough that a merely busy node is never
/// mistaken for a dead one.
const SYNC_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// How often the sync loop re-checks the chain + mempool once every active wallet is
/// caught up. This is the floor on how fast an incoming payment can appear, so it is a
/// UX number, not a throughput one.
const IDLE_SYNC_POLL: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the dedicated mempool loop looks for unmined payments. This is the floor on
/// "the receiver's screen changed" — keep it fast; the work behind it is trivial.
const MEMPOOL_POLL: std::time::Duration = std::time::Duration::from_millis(700);
// 150→50 ms: with the bounded-parallel loop another scan task overlaps this sleep, so
// its only job is guaranteeing the HTTP runtime a scheduling gap — 50 ms is plenty.
const SYNC_WALLET_THROTTLE_MS: u64 = 50;
/// Sleep after each ingested page inside a wallet's chunk, same reason (a single page
/// is ~200 blocks of pure-CPU trial decryption with no natural await).
const SYNC_PAGE_THROTTLE_MS: u64 = 5;

/// Persist a wallet's scan checkpoint atomically (write-tmp + rename). `genesis`
/// is the network genesis hash (a chain relaunch invalidates the checkpoint);
/// `low` is the last ingested chain block, from which sync resumes. The
/// matured-anchor ring and sink blue score ride along so a restarted wallet can
/// select a matured spend anchor without a replay.
fn save_checkpoint(
    dir: &str,
    token: &str,
    genesis: &RpcHash,
    low: &RpcHash,
    scanned: u64,
    db: &WalletDb,
    boundaries: &VecDeque<(u64, u64)>,
    sink_blue: u64,
) -> std::io::Result<()> {
    let db_blob = db.to_checkpoint();
    let mut buf = Vec::with_capacity(SCAN_HEADER_LEN + 8 + db_blob.len() + 4 + boundaries.len() * 16 + 8);
    buf.extend_from_slice(SCAN_MAGIC);
    buf.push(SCAN_VERSION);
    buf.extend_from_slice(&genesis.as_bytes());
    buf.extend_from_slice(&low.as_bytes());
    buf.extend_from_slice(&scanned.to_le_bytes());
    buf.extend_from_slice(&(db_blob.len() as u64).to_le_bytes());
    buf.extend_from_slice(&db_blob);
    buf.extend_from_slice(&(boundaries.len() as u32).to_le_bytes());
    for (blue, leaves) in boundaries {
        buf.extend_from_slice(&blue.to_le_bytes());
        buf.extend_from_slice(&leaves.to_le_bytes());
    }
    buf.extend_from_slice(&sink_blue.to_le_bytes());
    let path = scan_path(dir, token);
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &buf)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)
}

/// The cursor block a wallet's checkpoint resumes from, read from the header alone.
/// Needed before the body is parsed, because the node must be asked for the tree state
/// *at that block* so the restore can skip the leaf replay.
fn checkpoint_cursor(dir: &str, token: &str, current_genesis: &RpcHash) -> Option<RpcHash> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || buf[4] != SCAN_VERSION {
        return None;
    }
    if RpcHash::from_bytes(buf[5..37].try_into().ok()?) != *current_genesis {
        return None;
    }
    Some(RpcHash::from_bytes(buf[37..69].try_into().ok()?))
}

/// Load a wallet's scan checkpoint if present and still valid for
/// `current_genesis` (the network genesis hash). Returns the reconstructed
/// `(db, low_cursor, scanned, boundaries, sink_blue)`, or `None` on any absence /
/// corruption / version or genesis mismatch — the caller then rescans, so a stale
/// checkpoint can never yield a wrong tree.
#[allow(clippy::type_complexity)]
fn load_checkpoint(
    dir: &str,
    token: &str,
    key: WalletKey,
    current_genesis: &RpcHash,
    tip: Option<&kaspa_shielded_core::tree::FrontierState>,
) -> Option<(WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64)> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || buf[4] != SCAN_VERSION {
        return None;
    }
    let saved_genesis = RpcHash::from_bytes(buf[5..37].try_into().ok()?);
    if saved_genesis != *current_genesis {
        return None; // chain relaunched → rescan
    }
    let low = RpcHash::from_bytes(buf[37..69].try_into().ok()?);
    let scanned = u64::from_le_bytes(buf[69..77].try_into().ok()?) as usize;
    let mut pos = SCAN_HEADER_LEN;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        let end = pos.checked_add(n)?;
        let s = buf.get(*pos..end)?;
        *pos = end;
        Some(s)
    };
    let db_len = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?) as usize;
    let blob = take(&mut pos, db_len)?;
    let db = match tip {
        Some(fs) => key.db_from_checkpoint_with_tip(blob, fs)?,
        None => key.db_from_checkpoint(blob)?,
    };
    let ring_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    let mut boundaries = VecDeque::with_capacity(ring_len.min(MATURED_RING));
    for _ in 0..ring_len {
        let blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        let leaves = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        boundaries.push_back((blue, leaves));
    }
    let sink_blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    if pos != buf.len() {
        return None;
    }
    Some((db, low, scanned, boundaries, sink_blue))
}

// ---------------------------------------------------------------------------
// Shared sync page cache
//
// During a mass rescan every wallet walks the same chain-block stream from the
// same start (the pruning point), so without sharing, N wallets cost N full
// chain fetches (~170 x 169K blocks observed live). Caching each
// `GetShieldedBlocks` page by its start cursor for a few seconds means one
// fetch serves the whole cohort — fetch cost becomes O(chain), leaving only
// per-wallet trial decryption. The short TTL keeps near-tip pages fresh (the
// same cursor returns more blocks as the chain grows).
// ---------------------------------------------------------------------------

/// One chain block, fetched once and **decoded once** for the whole wallet cohort.
/// The two costs that are identical for every wallet — parsing each accepted
/// bundle, and computing each coinbase note's Sinsemilla leaf commitment — are paid
/// here, so a wallet's per-block work drops to the parts that actually depend on its
/// key (a coinbase recipient byte-compare, and trial-decryption of the rare real
/// payment bundles). `coinbase` holds only the notes that commit successfully, in
/// coinbase order — exactly what `WalletDb::ingest_block_precomputed` expects.
struct DecodedBlock {
    hash: RpcHash,
    blue_score: u64,
    daa_score: u64,
    coinbase: Vec<(kaspa_shielded_core::coinbase::CoinbaseNoteDesc, u64, kaspa_shielded_core::ExtractedNoteCommitment)>,
    bundles: Vec<ShieldedBundle>,
}

/// A decoded `GetShieldedBlocks` page: the response envelope plus the per-block
/// decode shared across wallets.
struct DecodedPage {
    reorged: bool,
    sink_blue_score: u64,
    blocks: Vec<DecodedBlock>,
}

/// Shared page decoding gets a bounded pool so it cannot consume every host core
/// and starve HTTP or kaspad while several wallets ingest concurrently.
static PAGE_DECODE_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .thread_name(|i| format!("wallet-page-decode-{i}"))
        .build()
        .expect("build wallet page decode pool")
});

fn decode_block(b: &kaspa_rpc_core::RpcShieldedChainBlock) -> DecodedBlock {
    let mut coinbase = Vec::new();
    for (i, out) in b.coinbase_outputs.iter().enumerate() {
        if out.script_public_key.len() >= ORCHARD_SCRIPT_LEN {
            let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
            recipient.copy_from_slice(&out.script_public_key[..ORCHARD_SCRIPT_LEN]);
            let mut note_seed = Vec::with_capacity(36);
            note_seed.extend_from_slice(&b.coinbase_txid.as_bytes());
            note_seed.extend_from_slice(&(i as u32).to_le_bytes());
            let desc = derive_coinbase_note_desc(recipient, &note_seed);
            // Only keep a note that commits — exactly `WalletDb::ingest_block`'s skip
            // rule, so the shared leaf stream matches the recompute path leaf-for-leaf.
            if let Ok(cmx) = kaspa_shielded_core::coinbase::coinbase_note_commitment(&desc, out.value) {
                coinbase.push((desc, out.value, cmx));
            }
        }
    }
    let bundles: Vec<ShieldedBundle> = b.accepted_bundles.iter().filter_map(|p| ShieldedBundle::from_bytes(p).ok()).collect();
    DecodedBlock { hash: b.hash, blue_score: b.blue_score, daa_score: b.daa_score, coinbase, bundles }
}

struct PageCache {
    map: HashMap<RpcHash, (std::time::Instant, Arc<DecodedPage>)>,
    order: VecDeque<RpcHash>,
}

const PAGE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);
const PAGE_CACHE_CAP: usize = 64;

impl PageCache {
    fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new() }
    }
}

/// Fetch one `GetShieldedBlocks` page through the shared cache, decoding it once.
/// During a mass rescan every active wallet walks the same stream, so the single
/// fetch+decode here serves the whole cohort for `PAGE_CACHE_TTL`.
async fn fetch_shielded_page(
    client: &GrpcClient,
    cache: &Mutex<PageCache>,
    low: RpcHash,
) -> Result<Arc<DecodedPage>, kaspa_rpc_core::RpcError> {
    {
        let c = cache.lock().await;
        if let Some((at, resp)) = c.map.get(&low) {
            if at.elapsed() < PAGE_CACHE_TTL {
                return Ok(resp.clone());
            }
        }
    }
    let raw = client.get_shielded_blocks(low, SHIELDED_PAGE).await?;
    // Decode the page ACROSS CORES. The per-block coinbase Sinsemilla commitment is the
    // dominant scan cost (~1 ms/block — it, not decryption, set the measured ~900 blk/s
    // single-thread ceiling), and each block decodes independently. `block_in_place`
    // moves this task off the async worker pool so the rayon fan-out doesn't stall other
    // tokio tasks; the decode is done once here and shared by every wallet via the cache.
    let blocks = tokio::task::block_in_place(|| {
        PAGE_DECODE_POOL.install(|| {
            use rayon::prelude::*;
            raw.blocks.par_iter().map(decode_block).collect::<Vec<_>>()
        })
    });
    let decoded = Arc::new(DecodedPage { reorged: raw.reorged, sink_blue_score: raw.sink_blue_score, blocks });
    let mut c = cache.lock().await;
    c.map.insert(low, (std::time::Instant::now(), decoded.clone()));
    c.order.push_back(low);
    if c.order.len() > PAGE_CACHE_CAP {
        if let Some(old) = c.order.pop_front() {
            c.map.remove(&old);
        }
    }
    Ok(decoded)
}

// ---------------------------------------------------------------------------
// In-memory wallet + incremental sync
// ---------------------------------------------------------------------------

struct WalletEntry {
    /// Spend authority (seed) — or, for a non-custodial wallet, viewing key only.
    key: WalletKey,
    db: WalletDb,
    /// The network genesis hash — guards the persisted checkpoint against a chain
    /// relaunch (and is also the shielded sighash network domain).
    genesis: RpcHash,
    /// Sync cursor: the last ingested **chain** block; `GetShieldedBlocks`
    /// resumes strictly after it.
    low: RpcHash,
    caught_up: bool,
    /// DAA score of the last ingested chain block (progress display).
    scanned: usize,
    chain_len: u64,
    updated_unix: u64,
    error: Option<String>,
    /// `scanned` at the last persisted checkpoint — the sync loop rewrites the
    /// checkpoint once enough new blocks accrue past this.
    saved_scanned: usize,
    /// `(blue_score, absolute leaf count)` after each ingested chain block,
    /// oldest→newest, capped at [`MATURED_RING`]. `send` picks the newest entry
    /// at least `anchor_depth + slack` blue units below the sink to root a spend
    /// at a matured, canonical chain-block anchor without a rescan. Persisted in
    /// the v2 checkpoint, so it survives restarts.
    boundaries: VecDeque<(u64, u64)>,
    /// The sink's blue score from the latest sync response — the reference the
    /// matured cutoff is measured against.
    sink_blue: u64,
    /// Consecutive sync passes that saw the cursor off the selected chain
    /// (deeper reorg than [`SYNC_TIP_MARGIN`]). Transient virtual flips clear on
    /// retry; at [`REORG_STRIKES`] the sync loop discards the checkpoint and
    /// reloads this wallet from scratch (the append-only tree cannot roll back).
    reorged_strikes: u32,
    /// Balance effect of the blocks between the settled cutoff and the tip — value
    /// arriving and owned value being spent, seen by trial-decryption without touching
    /// the append-only tree. This is what makes a payment visible ~1 second after it is
    /// mined instead of ~3 minutes later when SYNC_TIP_MARGIN clears.
    preview: Preview,
    /// Balance effect of shielded txs sitting in the node's **mempool** — not mined yet,
    /// not in any block. Trial-decrypting these is what makes an incoming payment visible
    /// within a second of being broadcast instead of only after it is mined AND the sync
    /// loop next runs. Costs nothing on-chain: it never touches the tree, and if the tx is
    /// dropped the figure simply disappears (the same contract as any 0-conf balance).
    mempool: Preview,
    /// Nullifiers of the bundles already counted in `preview` (the unsettled blocks).
    /// A tx that has just been mined can still linger in the mempool for a moment, and
    /// counting it from both places would briefly double the pending amount — so mempool
    /// bundles whose nullifiers appear here are skipped.
    unsettled_nulls: HashSet<kaspa_shielded_core::nullifier::NullifierBytes>,
}

/// How many chain-block→leaf boundaries [`WalletEntry`] keeps. Anchor maturity is
/// measured in *blue score*, which advances at least one per chain block, so
/// `depth + slack` entries always reach the cutoff, with room to spare.
const MATURED_RING: usize = (DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK) as usize + 64;

/// How close (in DAA/blue score) the wallet's latest ingested block must be to the
/// node tip to report `synced: true`. On a live ~1-block/s chain the strict
/// `caught_up` flag rarely latches, so we treat "within this many blocks of the tip"
/// as synced (~32 s at 1 BPS).
const SYNC_MARGIN: u64 = 32;

impl WalletEntry {
    /// Rebuild an entry from a wallet view + cursor (a fresh frontier start or a
    /// persisted checkpoint): the background sync resumes strictly after `low`.
    /// `saved_scanned == scanned` so the next checkpoint write waits for
    /// genuinely new blocks.
    fn from_parts(
        key: WalletKey,
        db: WalletDb,
        genesis: RpcHash,
        low: RpcHash,
        scanned: usize,
        boundaries: VecDeque<(u64, u64)>,
        sink_blue: u64,
    ) -> Self {
        Self {
            key,
            db,
            genesis,
            low,
            caught_up: false,
            scanned,
            chain_len: 0,
            updated_unix: 0,
            error: None,
            saved_scanned: scanned,
            boundaries,
            sink_blue,
            reorged_strikes: 0,
            preview: Preview::default(),
            mempool: Preview::default(),
            unsettled_nulls: HashSet::new(),
        }
    }

    /// Trial-decrypt the shielded bundles currently in the node's mempool and record what
    /// they would do to this wallet. Purely a display figure: no tree mutation, no leaf,
    /// no position — so it carries none of the reorg hazard that keeps `sync_chunk` from
    /// ingesting unsettled blocks. This is what makes an incoming payment appear about a
    /// second after the sender hits Confirm, rather than only after it has been mined.
    fn scan_mempool(&mut self, bundles: &[ShieldedBundle]) {
        // Skip anything already counted from the unsettled blocks: a just-mined tx can
        // still linger in the mempool, and counting it twice would double the pending sum.
        let fresh: Vec<&ShieldedBundle> =
            bundles.iter().filter(|b| !b.actions.iter().any(|a| self.unsettled_nulls.contains(&a.nullifier))).collect();
        self.mempool = if fresh.is_empty() { Preview::default() } else { self.db.preview_block(&[], &fresh) };
    }

    /// Advance this wallet by up to `PAGES_PER_CHUNK` pages of new **chain**
    /// blocks, ingesting exactly the shielded effects consensus applied per block
    /// (own coinbase mint + accepted post-retain bundles, consensus order), and
    /// only once a block is `SYNC_TIP_MARGIN` blue units below the sink (the
    /// append-only tree must not ingest anything a routine reorg could replace).
    async fn sync_chunk(&mut self, client: &GrpcClient, cache: &Mutex<PageCache>) {
        for _ in 0..PAGES_PER_CHUNK {
            // HARD TIMEOUT. There is ONE sync loop for every wallet, and it advances them
            // sequentially — so an await here that never returns does not stall one wallet,
            // it stalls ALL of them, forever. That was a live outage: a hung page fetch
            // froze the loop, so no wallet's cursor advanced, `sink_blue` went stale, the
            // maturity cutoff never moved, and every wallet's whole balance showed as
            // "maturing" and unspendable — indistinguishable from a broken wallet, and only
            // a daemon restart cleared it. A timed-out page is treated exactly like any
            // other transient node failure: keep the checkpoint, record it, move on.
            let fetched = tokio::time::timeout(SYNC_RPC_TIMEOUT, fetch_shielded_page(client, cache, self.low)).await;
            let resp = match fetched {
                Ok(Ok(r)) => r,
                Err(_elapsed) => {
                    log::warn!("wallet sync page timed out after {SYNC_RPC_TIMEOUT:?} (checkpoint kept); will retry next pass");
                    self.error = Some("node is slow to answer; retrying".into());
                    return;
                }
                Ok(Err(e)) => {
                    // Distinguish "cursor unusable" (pruned / stale-branch / relaunched —
                    // needs a rescan) from a transient node failure.
                    //
                    // FIRST, read the page error itself: if the node *answered* with one of
                    // the definitive cursor-gone verdicts (see [`CURSOR_GONE_MARKERS`]),
                    // that IS the evidence — no probe needed. Probing `get_block` here was
                    // the trap that froze wallets for hours: a cursor below the retention
                    // root still *exists* (probe succeeds → "transient") while every page
                    // fetch is deterministically refused. The node answering at all also
                    // proves it is alive.
                    //
                    // Otherwise (timeout, transport, node busy), the error says nothing
                    // about the cursor: probe it, and only a definitive verdict on a live
                    // node counts. Either way, take a single strike and require
                    // REORG_STRIKES *consecutive* passes to agree — a merely-slow node must
                    // never be able to delete a wallet's scan history (2026-07-12 outage).
                    // Probes are timed out too — they run on the same shared loop.
                    let gone = if cursor_gone(&e.to_string()) {
                        true
                    } else {
                        let probe_gone = match tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block(self.low, false)).await {
                            Ok(Err(probe)) => cursor_gone(&probe.to_string()),
                            Ok(Ok(_)) => false,
                            Err(_) => false, // timed out: says nothing about the cursor
                        };
                        let node_alive =
                            matches!(tokio::time::timeout(SYNC_RPC_TIMEOUT, client.get_block_dag_info()).await, Ok(Ok(_)));
                        probe_gone && node_alive
                    };
                    if gone {
                        self.reorged_strikes += 1;
                        self.error = Some("wallet cursor no longer usable on the node; rescanning".into());
                        log::info!("wallet cursor unusable (strike {}/{REORG_STRIKES}): {e}", self.reorged_strikes);
                    } else {
                        log::debug!("wallet sync page failed (transient, checkpoint kept): {e}");
                        self.error = Some(format!("get_shielded_blocks failed: {e}"));
                    }
                    return;
                }
            };
            if resp.reorged {
                // Usually a transient virtual flip near the tip: retry a few
                // passes before paying for a full rescan.
                self.reorged_strikes += 1;
                self.error = Some("chain reorged below the wallet cursor; retrying".into());
                return;
            }
            self.reorged_strikes = 0;
            self.sink_blue = resp.sink_blue_score;
            let settled = resp.sink_blue_score.saturating_sub(SYNC_TIP_MARGIN);
            // This section is synchronous trial-decryption/tree work. Mark it as
            // blocking so Tokio starts replacement workers for HTTP and RPC tasks
            // while up to three wallets continue ingesting in parallel.
            let (advanced, at_margin) = tokio::task::block_in_place(|| {
                let mut advanced = false;
                let mut at_margin = false;
                for (i, b) in resp.blocks.iter().enumerate() {
                    if b.blue_score > settled {
                        // Everything from here to the tip is inside the reorg margin and must
                        // not be appended to the tree. Preview it instead, so a payment shows
                        // up as pending the moment it is mined rather than ~3 minutes later
                        // when the margin clears. Recomputed from scratch each pass (not
                        // accumulated), so it self-corrects if a block drops out.
                        let mut preview = Preview::default();
                        let mut nulls = HashSet::new();
                        for u in &resp.blocks[i..] {
                            let bundle_refs: Vec<&ShieldedBundle> = u.bundles.iter().collect();
                            let cb: Vec<(CoinbaseNoteDesc, u64)> = u.coinbase.iter().map(|(d, v, _)| (d.clone(), *v)).collect();
                            preview.add(self.db.preview_block(&cb, &bundle_refs));
                            // Remember what these blocks spend, so the same tx still sitting in
                            // the mempool is not counted a second time (see `mempool`).
                            for b in &bundle_refs {
                                for a in &b.actions {
                                    nulls.insert(a.nullifier);
                                }
                            }
                        }
                        self.preview = preview;
                        self.unsettled_nulls = nulls;
                        at_margin = true;
                        break;
                    }
                    // Ingest with the coinbase commitments the shared cache already
                    // computed for this block — the Sinsemilla work is not repeated per
                    // wallet.
                    let bundle_refs: Vec<&ShieldedBundle> = b.bundles.iter().collect();
                    self.db.ingest_block_precomputed(&b.coinbase, &bundle_refs);
                    self.low = b.hash;
                    self.scanned = b.daa_score as usize;
                    self.boundaries.push_back((b.blue_score, self.db.size()));
                    if self.boundaries.len() > MATURED_RING {
                        self.boundaries.pop_front();
                    }
                    advanced = true;
                }
                if !at_margin {
                    // No unsettled blocks in this page — nothing is pending from the margin.
                    self.preview = Preview::default();
                    self.unsettled_nulls.clear();
                }
                (advanced, at_margin)
            });
            if !advanced || at_margin {
                self.caught_up = true;
                break;
            }
            // Just yield between pages — do NOT sleep here: this runs while the wallet's
            // mutex is held, and sleeping would block any status call for this wallet for
            // the sleep's duration. The CPU throttle is the between-wallet sleep in
            // `sync_loop`, which runs with the lock released.
            tokio::task::yield_now().await;
        }
        // Advance the spend witnesses toward the matured anchor a bounded step at a time,
        // yielding between steps. Only near the tip (`caught_up`): during a long initial
        // scan the user cannot spend anyway, and advancing witnesses across the whole
        // 170K-leaf history in one pass is an O(N*k) burst that pins a core and starves
        // the HTTP handler — the live "wallet won't connect" outage. Near the tip the
        // catch-up is small and, once done, stays incremental.
        // NB: no eager witness pre-advancing here. It was the last heavy *synchronous*
        // step in the sync path — one `advance_witnesses_capped` call hashes
        // cap × (note count) Sinsemilla commitments with no await inside, which on a
        // heavy wallet blocks the tokio worker for tens of seconds and stalls every
        // HTTP request and every other wallet's scan (the "stuck at N%" outage). It was
        // only ever a spend-latency optimization: a spend that needs a note's witness
        // rebuilds it on demand from the persisted leaf stream (`witness_path_at`, which
        // already falls back to a fresh rebuild when no live witness is held). Dropping
        // the pre-advance keeps sync_chunk O(scan) and non-blocking; the one-time
        // rebuild cost moves to spend time, where it's paid only for the notes a spend
        // actually selects.
        self.error = None;
        self.updated_unix = now_unix();
    }

    /// The newest chain-block boundary at least `anchor_depth + slack` blue units below
    /// the sink: the matured, canonical anchor a spend roots at.
    fn matured_leaves(&self) -> Option<u64> {
        let cutoff_blue = self.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        self.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, leaves)| leaves)
    }

    fn advance_spend_witnesses(&mut self) {
        if let Some(matured) = self.matured_leaves() {
            self.db.advance_witnesses(matured);
        }
    }
}

/// Ingest one chain block's shielded effects — the node already assembled them
/// (`GetShieldedBlocks`) exactly as the consensus §2.4 transition applied them:
/// the block's own coinbase notes first, then each accepted (post-retain)
/// shielded bundle's actions in consensus order.
fn ingest_shielded_chain_block(db: &mut WalletDb, blk: &RpcShieldedChainBlock) {
    let mut coinbase_notes = Vec::new();
    for (i, out) in blk.coinbase_outputs.iter().enumerate() {
        if out.script_public_key.len() >= ORCHARD_SCRIPT_LEN {
            let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
            recipient.copy_from_slice(&out.script_public_key[..ORCHARD_SCRIPT_LEN]);
            let mut note_seed = Vec::with_capacity(36);
            note_seed.extend_from_slice(&blk.coinbase_txid.as_bytes());
            note_seed.extend_from_slice(&(i as u32).to_le_bytes());
            coinbase_notes.push((derive_coinbase_note_desc(recipient, &note_seed), out.value));
        }
    }
    let bundles: Vec<ShieldedBundle> = blk.accepted_bundles.iter().filter_map(|p| ShieldedBundle::from_bytes(p).ok()).collect();
    let bundle_refs: Vec<&ShieldedBundle> = bundles.iter().collect();
    db.ingest_block(&coinbase_notes, &bundle_refs);
}

/// One-off replay of the settled **matured** chain prefix into a fresh wallet
/// view (send fallback + non-custodial `/prepare`): anchors the tree at the
/// pruning-point frontier (all recoverable history, correct absolute positions),
/// then ingests chain blocks up to `sink_blue − (anchor_depth + slack)` — so
/// every recovered note is matured and `witness_path` roots at a matured,
/// canonical chain-block anchor. `db` must be freshly constructed (seed or FVK).
async fn replay_matured(client: &GrpcClient, mut db: WalletDb) -> Result<WalletDb, String> {
    let dag = client.get_block_dag_info().await.map_err(|e| format!("get_block_dag_info failed: {e}"))?;
    let start = dag.pruning_point_hash;
    let ts = client.get_shielded_tree_state(Some(start)).await.map_err(|e| format!("get_shielded_tree_state({start}) failed: {e}"))?;
    if ts.block_hash != start {
        return Err("node does not support explicit tree-state checkpoints (update the node)".into());
    }
    let fs = FrontierState {
        size: ts.size,
        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
        ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
    };
    db.apply_frontier(&fs).ok_or("inconsistent pruning-point frontier")?;

    let mut low = start;
    loop {
        let resp = client.get_shielded_blocks(low, SHIELDED_PAGE).await.map_err(|e| format!("get_shielded_blocks failed: {e}"))?;
        if resp.reorged {
            return Err("chain reorged during the matured replay; retry".into());
        }
        let cutoff = resp.sink_blue_score.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        let mut advanced = false;
        for b in &resp.blocks {
            if b.blue_score > cutoff {
                return Ok(db);
            }
            ingest_shielded_chain_block(&mut db, b);
            low = b.hash;
            advanced = true;
        }
        if !advanced {
            return Ok(db);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

type Wallet = Arc<Mutex<WalletEntry>>;

struct AppState {
    /// gRPC connection for the REQUEST path — wallet loads, the tip ticker, prepare /
    /// submit. Kept separate from `sync_client` so the background sync loop's continuous
    /// block-fetch traffic can't make a user's wallet load (which needs a couple of node
    /// RPCs) queue for seconds. Sharing one connection for both was the root cause of the
    /// "wallet won't connect": loads timed out behind the sync loop, so wallets never
    /// cached and every poll re-ran a slow, timing-out load.
    client: GrpcClient,
    /// Dedicated gRPC connection for the background sync loop's block fetches.
    sync_client: GrpcClient,
    wallet_dir: String,
    prefix: Prefix,
    network: String,
    wallets: Mutex<HashMap<String, Wallet>>,
    /// When true, a missing `X-Wallet-Token` maps to the "default" wallet (trusted
    /// single-user localhost). Off by default → a token is required on every request.
    allow_default_token: bool,
    /// Secret for encrypting seed files at rest. `None` → seeds stored in plaintext.
    wallet_secret: Option<String>,
    /// The network genesis hash: the shielded sighash **network domain** (what
    /// consensus signs against — `params.genesis.hash`, NOT the moving pruning
    /// point) and the guard persisted checkpoints are keyed by.
    genesis: RpcHash,
    /// Shared `GetShieldedBlocks` page cache for the sync loop (see [`PageCache`]).
    page_cache: Mutex<PageCache>,
    /// Last time each wallet token was touched by a request. The sync loop only keeps
    /// a wallet synced while it is being actively viewed; idle wallets (the bulk of a
    /// public daemon's tokens are one-time visitors) stop consuming CPU. Without this,
    /// 272 loaded wallets all full-scanning at once pinned every core and starved even
    /// `/health` — a live outage. A returning user's first poll re-touches and resumes
    /// it from its checkpoint.
    last_touch: Mutex<HashMap<String, std::time::Instant>>,
    /// Caps how many wallets load (rebuild their Merkle tree from the checkpoint /
    /// pruning point — tens of thousands of Sinsemilla hashes, synchronous on the async
    /// worker) at once. Without it, a daemon restart makes every reconnecting browser
    /// trigger a load simultaneously; hundreds of concurrent tree rebuilds pin every
    /// runtime worker and starve even `/health` (a live outage). With a small cap, most
    /// workers stay free for HTTP and loads queue briefly instead of melting the box.
    load_gate: tokio::sync::Semaphore,
    /// Payment preparation is deliberately serialized. Witness reconstruction and
    /// Halo2 proving are CPU-heavy synchronous work; browser retries used to start
    /// overlapping copies after the first request timed out, exhausting every runtime
    /// worker and taking the whole wallet API offline. A caller that races an existing
    /// preparation gets a fast 429 and can retry after the original finishes.
    prepare_gate: tokio::sync::Semaphore,
    /// Last known virtual DAA score, refreshed by the sync loop and successful status
    /// calls, so status can answer instantly when the node RPC is momentarily contended.
    node_tip: Mutex<(u64, std::time::Instant)>,
    /// In-flight **non-custodial** payments: a `/api/wallet/prepare` builds the proof
    /// from a viewing key and parks the awaiting-signature bundle here, keyed by a
    /// random session id; `/api/wallet/submit` pops it, applies the device's spend-auth
    /// signatures, and broadcasts. Held in memory only — a restart drops pending
    /// sessions (the device just re-prepares). The seed is never involved.
    prepared: Mutex<HashMap<String, PreparedSession>>,
    /// Last-known-good status per loaded wallet, read by `status` when the wallet mutex
    /// is momentarily held by the sync loop (see [`StatusSnap`]). Refreshed by the sync
    /// loop each pass and by any `status` call that acquires the wallet lock.
    snapshots: Mutex<HashMap<String, StatusSnap>>,
}

/// Build a status snapshot from a locked wallet entry. Shared by the sync loop and the
/// `status` handler so the spendable/maturing split is computed identically to what
/// `/prepare` will actually draw on (same anchor-depth cutoff).
fn snap_from_entry(address: String, e: &WalletEntry, daa_score: u64) -> StatusSnap {
    let tip = e.chain_len.max(daa_score);
    let total = e.db.balance();
    let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
    let matured_leaves = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc);
    let spendable: u128 = match matured_leaves {
        Some(matured) => e.db.notes().iter().filter(|n| n.position < matured).map(|n| n.value() as u128).sum(),
        None => 0,
    };
    // "I have a balance but cannot spend any of it" is the single worst state this
    // wallet can be in, and from the outside it is indistinguishable from a hang.
    // When it happens, say exactly why: the anchor cutoff, whether the boundary ring
    // even reaches back that far, and where the notes sit relative to it.
    // NB: debug, not info — `snap_from_entry` runs on every status call AND every mempool
    // tick (sub-second, per wallet), so an info! here floods the log. Turn it on with
    // RUST_LOG=zkas_walletd=debug when actually investigating a stuck balance.
    if total > 0 && spendable == 0 {
        log::debug!(
            "spendable=0 with balance {total}: sink_blue={} cutoff_blue={cutoff_blue} boundaries={} (oldest_blue={:?} newest_blue={:?}) matured_leaves={:?} note_positions={:?}",
            e.sink_blue,
            e.boundaries.len(),
            e.boundaries.front().map(|b| b.0),
            e.boundaries.back().map(|b| b.0),
            matured_leaves,
            e.db.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
        );
    }
    StatusSnap {
        address,
        watch_only: e.key.is_watch_only(),
        // `tip > 0` guard: when the pass's dag-info call times out, `chain_len` is 0 and
        // `scanned + margin >= 0` is trivially true — the UI then flashed "synced" on a
        // wallet that was mid-scan (observed live 2026-07-16). No tip info ⇒ not synced.
        synced: tip > 0 && (e.caught_up || (e.scanned as u64) + SYNC_MARGIN >= tip),
        scanned: e.scanned,
        chain_len: tip,
        balance_sompi: total,
        spendable_sompi: spendable,
        maturing_sompi: total.saturating_sub(spendable),
        // 0-conf = what the unsettled blocks do + what the mempool would do once mined.
        // The two are de-duplicated by nullifier in `scan_mempool`, so a tx crossing from
        // mempool into a block is counted exactly once throughout.
        pending_in: e.preview.incoming + e.mempool.incoming,
        pending_out: e.preview.outgoing + e.mempool.outgoing,
        note_count: e.db.notes().len(),
        updated_unix: e.updated_unix,
        error: e.error.clone(),
    }
}

/// Project a cached snapshot onto a `StatusResp` (the wire shape the SPA reads).
fn fill_status_from_snap(resp: &mut StatusResp, s: &StatusSnap) {
    resp.has_wallet = true;
    resp.address = Some(s.address.clone());
    resp.watch_only = s.watch_only;
    resp.synced = s.synced;
    resp.scanned_blocks = s.scanned;
    resp.chain_len = s.chain_len;
    resp.balance_sompi = s.balance_sompi.to_string();
    resp.balance_fc = fmt_fc(s.balance_sompi);
    resp.spendable_sompi = s.spendable_sompi.to_string();
    resp.spendable_fc = fmt_fc(s.spendable_sompi);
    resp.maturing_sompi = s.maturing_sompi.to_string();
    resp.maturing_fc = fmt_fc(s.maturing_sompi);
    resp.pending_in_sompi = s.pending_in.to_string();
    resp.pending_in_fc = fmt_fc(s.pending_in);
    resp.pending_out_sompi = s.pending_out.to_string();
    resp.pending_out_fc = fmt_fc(s.pending_out);
    resp.note_count = s.note_count;
    resp.updated_unix = s.updated_unix;
    resp.error = s.error.clone();
}

/// Last-known-good status for a loaded wallet, kept OUTSIDE the wallet mutex so the
/// `status` handler can answer from it the moment the sync loop is holding the wallet
/// lock (which, during a scan, is most of the time). Without this, a `try_lock` miss
/// on the request path returned an all-zero default — balance and scan progress
/// flickered to 0 on every poll that raced a scan pass, which read as "the wallet
/// stopped updating". The sync loop refreshes this after each pass; `status` also
/// refreshes it whenever it does get the lock.
#[derive(Clone, Default)]
struct StatusSnap {
    address: String,
    watch_only: bool,
    synced: bool,
    scanned: usize,
    chain_len: u64,
    balance_sompi: u128,
    spendable_sompi: u128,
    maturing_sompi: u128,
    pending_in: u128,
    pending_out: u128,
    note_count: usize,
    updated_unix: u64,
    error: Option<String>,
}

/// A non-custodial payment proven and awaiting on-device spend-auth signatures.
struct PreparedSession {
    payment: PreparedPayment,
    amount: u64,
    fee: u64,
    created: std::time::Instant,
}

/// How long a prepared (unsigned) non-custodial payment lives before it is swept.
const PREPARED_TTL: std::time::Duration = std::time::Duration::from_secs(300);

impl AppState {
    /// The wallet's receive address, taken from its view (works for seed and
    /// watch-only wallets alike — both know the address).
    fn address_of(&self, db: &WalletDb) -> String {
        String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &db.my_address_bytes()))
    }

    fn address_for_seed(&self, seed: &[u8; 32]) -> Option<String> {
        let raw = address_bytes_from_seed(*seed)?;
        Some(String::from(&Address::new(self.prefix, Version::ShieldedOrchard, &raw)))
    }

    /// Build a **fast-sync** wallet entry from the node's pruning-point frontier
    /// (`GetShieldedTreeState`): the wallet's note-commitment tree starts at that
    /// finalized checkpoint and it scans only later blocks. Since the node prunes
    /// pre-checkpoint blocks anyway, this is both the *correct* start (right absolute
    /// leaf positions once pruning is active) and the *fast* one — sync is O(blocks
    /// since the pruning point), not O(chain). Returns `None` if the node lacks the
    /// RPC or a frontier yet, so the caller falls back to a full pruning-point scan.
    ///
    /// **Completeness gate:** a fast-synced wallet is blind to notes minted before
    /// the checkpoint, so this path is only sound for a wallet *born at or after*
    /// it. `birthday` is the wallet's birth DAA score; when it precedes the
    /// checkpoint (and in particular `birthday == 0`, "may hold funds from any
    /// height"), this returns `None` and the caller must full-scan. Skipping this
    /// gate was a live bug: imported wallets silently showed less than their real
    /// balance ("fully synced but missing coins") because their older notes were
    /// behind the fast-sync base.
    async fn fast_sync_entry(&self, key: WalletKey, guard: RpcHash, birthday: u64) -> Option<WalletEntry> {
        // Bound the checkpoint RPC: on a healthy chain it returns immediately, but the
        // node's finality-point walk can be pathologically slow on a degenerate DAG
        // (e.g. difficulty collapsed to the floor). Time it out and fall back to a full
        // scan rather than hanging the wallet.
        let cp = match tokio::time::timeout(std::time::Duration::from_secs(5), self.client.get_shielded_tree_state(None)).await {
            Ok(Ok(cp)) => cp,
            _ => return None,
        };
        if birthday < cp.daa_score {
            log::info!("wallet birthday {birthday} precedes fast-sync checkpoint (daa {}); full scan required", cp.daa_score);
            return None;
        }
        // Default start = the finality checkpoint. But when the wallet's birthday is
        // meaningfully later than the checkpoint, don't replay the whole finality window
        // (tens of thousands of blocks of sequential Sinsemilla tree-building — the "super
        // slow even though I set a birthday" report). The node retains a per-block tree
        // frontier for every selected-chain block, so walk the chain to the birthday block
        // (metadata only, no tree work) and start the tree from *that* block's frontier.
        // Sound because a birthday asserts the wallet holds no notes before it. Any failure
        // (RPC hiccup, tip reached early) falls back to the checkpoint start.
        let (start_hash, start_daa, start_size, start_leaf, start_ommers) = match self.birthday_start(cp.block_hash, birthday).await {
            Some(s) => s,
            None => (cp.block_hash, cp.daa_score, cp.size, cp.leaf, cp.ommers),
        };
        if start_daa > cp.daa_score {
            log::info!(
                "fast-sync from birthday block daa {start_daa} (checkpoint daa {}) — skipped {} blocks of replay",
                cp.daa_score,
                start_daa - cp.daa_score
            );
        }
        let fs = FrontierState {
            size: start_size,
            leaf: (start_size > 0).then(|| start_leaf.as_bytes()),
            ommers: start_ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = key.db_from_frontier(&fs)?;
        // low = the start chain block; sync resumes strictly after it.
        // Progress is proxied by its DAA score so status reads "near tip".
        Some(WalletEntry::from_parts(key, db, guard, start_hash, start_daa as usize, VecDeque::new(), 0))
    }

    /// Walk the selected chain forward from the finality checkpoint `from` until the
    /// first block whose DAA score reaches `birthday`, and return that block's retained
    /// shielded tree frontier `(hash, daa, size, leaf, ommers)`. Metadata-only: it reads
    /// only each block's hash + daa from `GetShieldedBlocks` (no tree work), so skipping
    /// a large finality window is cheap. Returns `None` on any RPC error, a reorg during
    /// the walk, or if the tip is reached before `birthday` — the caller then starts from
    /// the checkpoint as before.
    async fn birthday_start(&self, from: RpcHash, birthday: u64) -> Option<(RpcHash, u64, u64, RpcHash, Vec<RpcHash>)> {
        const WALK_PAGE: u64 = 2000; // RPC MAX_LIMIT — few round-trips across the window
        let mut cursor = from;
        // The last selected-chain block seen with daa < birthday. The tree starts from
        // ITS frontier so that scanning resumes at (and trial-decrypts) the birthday block
        // itself — a note received *in* the birthday block must not be skipped.
        let mut base_below: Option<RpcHash> = None;
        // Bound the walk (a 2000-block page × this cap covers many millions of blocks).
        for _ in 0..4000 {
            let page = self.client.get_shielded_blocks(cursor, WALK_PAGE).await.ok()?;
            if page.reorged {
                return None;
            }
            let Some(last) = page.blocks.last() else { return None };
            if last.daa_score >= birthday {
                // Birthday reached within this page. Advance `base_below` to the last block
                // still strictly below it, then start the tree from that block's frontier.
                for b in &page.blocks {
                    if b.daa_score >= birthday {
                        break;
                    }
                    base_below = Some(b.hash);
                }
                // No block below birthday anywhere (birthday <= first block past the
                // checkpoint) → nothing to skip; let the caller start from the checkpoint.
                let base = base_below?;
                let ts = self.client.get_shielded_tree_state(Some(base)).await.ok()?;
                return Some((ts.block_hash, ts.daa_score, ts.size, ts.leaf, ts.ommers));
            }
            base_below = Some(last.hash);
            cursor = last.hash;
            // Short page → we walked all the way to the tip without reaching the birthday,
            // which is exactly what a wallet born *now* looks like (its birthday is the
            // current tip). Start it at the tip: it cannot hold a note older than itself.
            // Falling back to the checkpoint here was a bug with a very visible symptom —
            // a freshly created wallet opened at "syncing 87%" and ground through ~44K
            // blocks of history it could not possibly appear in.
            if (page.blocks.len() as u64) < WALK_PAGE {
                let base = base_below?;
                let ts = self.client.get_shielded_tree_state(Some(base)).await.ok()?;
                return Some((ts.block_hash, ts.daa_score, ts.size, ts.leaf, ts.ommers));
            }
        }
        None
    }

    /// Full-history wallet entry: the tree is anchored at the **pruning-point
    /// frontier** (all recoverable history, correct absolute leaf positions even
    /// after pruning advances past genesis) and every later chain block is
    /// scanned. Used when the wallet may hold funds older than the fast-sync
    /// checkpoint (birthday 0 / early birthday).
    async fn full_scan_entry(&self, key: WalletKey, guard: RpcHash) -> Option<WalletEntry> {
        let start = self.client.get_block_dag_info().await.ok()?.pruning_point_hash;
        let ts = self.client.get_shielded_tree_state(Some(start)).await.ok()?;
        if ts.block_hash != start {
            log::error!("node ignored the explicit tree-state checkpoint (update the node)");
            return None;
        }
        let fs = FrontierState {
            size: ts.size,
            leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
            ommers: ts.ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = key.db_from_frontier(&fs)?;
        Some(WalletEntry::from_parts(key, db, guard, start, ts.daa_score as usize, VecDeque::new(), 0))
    }

    /// Mark a token active so the sync loop keeps it current (idle wallets are parked).
    async fn touch(&self, token: &str) {
        self.last_touch.lock().await.insert(token.to_string(), std::time::Instant::now());
    }

    /// The wallet if it is already loaded in memory — never loads. For the request path,
    /// which must not block on a load.
    async fn cached_wallet(&self, token: &str) -> Option<Wallet> {
        self.wallets.lock().await.get(token).cloned()
    }

    /// Ensure a known-but-unloaded wallet gets loaded, in the background, exactly once.
    /// The request path calls this and returns "loading…" immediately; when the load
    /// finishes the wallet is in the map and the next poll answers from it.
    fn spawn_load(self: &Arc<Self>, token: &str) {
        let state = self.clone();
        let token = token.to_string();
        tokio::spawn(async move {
            // `get_wallet` dedupes via the load gate + cache re-check, so racing spawns
            // for the same token collapse to one real load.
            let _ = state.get_wallet(&token).await;
        });
    }

    /// Fetch a loaded wallet for a token, loading it from disk on first use.
    async fn get_wallet(self: &Arc<Self>, token: &str) -> Option<Wallet> {
        // Mark the wallet active so the sync loop keeps it current; idle wallets are
        // parked (see `sync_loop`).
        self.last_touch.lock().await.insert(token.to_string(), std::time::Instant::now());
        {
            let map = self.wallets.lock().await;
            if let Some(w) = map.get(token) {
                return Some(w.clone());
            }
        }
        // Cache miss → an expensive load. Gate concurrent loads so a reconnect storm
        // can't pin every worker with tree rebuilds. Re-check the cache after acquiring
        // the permit: while we waited, another task may have loaded this same wallet.
        let _permit = self.load_gate.acquire().await.ok()?;
        {
            let map = self.wallets.lock().await;
            if let Some(w) = map.get(token) {
                return Some(w.clone());
            }
        }
        let (key, birthday) = load_wallet_meta(&self.wallet_dir, token, self.wallet_secret.as_deref())?;
        let genesis = self.genesis;
        // Resume from a persisted checkpoint when one is present and version/genesis
        // valid; otherwise fast-sync (birthday-gated: a fast-synced wallet is blind
        // to notes older than its base) or the pruning-point full scan.
        // Ask the node for the tree at this checkpoint's cursor. It is the same tree the
        // wallet would rebuild from its own leaf stream, so having it turns a ~60s
        // Sinsemilla replay into a frontier copy. Best-effort: if the node can't answer
        // (pruned cursor, RPC hiccup), we simply restore the old way.
        let tip = match checkpoint_cursor(&self.wallet_dir, token, &genesis) {
            Some(cursor) => match self.client.get_shielded_tree_state(Some(cursor)).await {
                Ok(ts) => Some(kaspa_shielded_core::tree::FrontierState {
                    size: ts.size,
                    leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
                    ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
                }),
                Err(e) => {
                    log::debug!("no tree state for checkpoint cursor ({e}); restoring from the leaf stream");
                    None
                }
            },
            None => None,
        };
        let entry = match load_checkpoint(&self.wallet_dir, token, key, &genesis, tip.as_ref()) {
            Some((db, low, scanned, boundaries, sink_blue)) => {
                WalletEntry::from_parts(key, db, genesis, low, scanned, boundaries, sink_blue)
            }
            None => match self.fast_sync_entry(key, genesis, birthday).await {
                Some(e) => e,
                None => self.full_scan_entry(key, genesis).await?,
            },
        };
        // Decode the leaf stream to curve points NOW, on a blocking thread, while we still
        // own the entry exclusively. `warm_leaves` was written for exactly this and then
        // never called, so the cost landed on the first *spend* instead — a big chunk of the
        // ~29s a send took. Doing it here costs the user nothing: the wallet is already
        // usable (balance, notes, receive) and this finishes long before anyone hits Send.
        let entry = tokio::task::spawn_blocking(move || {
            let t = std::time::Instant::now();
            entry.db.warm_leaves();
            log::info!("wallet leaf-stream decoded in {:.1?} (kept off the spend path)", t.elapsed());
            entry
        })
        .await
        .ok()?;
        let w = Arc::new(Mutex::new(entry));
        self.wallets.lock().await.insert(token.to_string(), w.clone());
        // NB: do NOT eagerly decode the leaf stream here. It is tempting — only a spend
        // needs curve points, so "warm them in the background" sounds free. It is not:
        // decoding is ~60s of curve arithmetic per wallet, and firing it for every wallet
        // that loads (a restart touches all of them) buries every tokio worker on a
        // 4-core box and starves the HTTP handler — the daemon stops answering entirely
        // (observed live: a 331-deep accept backlog, every wallet reading "node offline").
        // The decode stays lazy: it happens inside the spend path, which already runs on
        // a blocking thread, and is paid once by the one wallet that actually spends.
        Some(w)
    }
}

// ---------------------------------------------------------------------------
// Background sync: advance every loaded wallet a bounded chunk each pass.
// ---------------------------------------------------------------------------

/// Watch the node's **mempool** and tell every active wallet what is heading its way,
/// *before* any of it is mined. This is the whole "instant payment" path.
///
/// It is deliberately its OWN loop, not a step inside `sync_loop`. The sync loop walks
/// wallets one at a time and does real block work (page fetches, tree ingest, a throttle
/// between each), so a wallet's turn can come many seconds after the pass began — putting
/// the mempool check in there made an incoming payment take ~28s to show for no reason
/// other than queueing. Here the only per-wallet cost is trial decryption of a handful of
/// mempool bundles: microseconds, no RPC, no tree. So a payment appears within about a
/// second of the sender hitting Confirm, no matter how many wallets are mid-scan.
async fn mempool_loop(state: Arc<AppState>) {
    let mut last_seen = 0usize;
    loop {
        let active: HashSet<String> = {
            let now = std::time::Instant::now();
            state
                .last_touch
                .lock()
                .await
                .iter()
                .filter(|(_, t)| now.duration_since(**t) < ACTIVE_SYNC_WINDOW)
                .map(|(k, _)| k.clone())
                .collect()
        };
        if !active.is_empty() {
            // One decode of the mempool, shared by every wallet.
            let bundles: Vec<ShieldedBundle> =
                match tokio::time::timeout(SYNC_RPC_TIMEOUT, state.client.get_mempool_entries(false, false)).await {
                    Ok(Ok(entries)) => entries
                        .iter()
                        .filter(|e| e.transaction.version == TX_VERSION_SHIELDED)
                        .filter_map(|e| ShieldedBundle::from_bytes(&e.transaction.payload).ok())
                        .collect(),
                    _ => Vec::new(), // node hiccup: no preview this tick, never a stall
                };
            // Log only on change — this loop runs sub-second. Without this line there is no
            // way to tell "the mempool preview is working and the tx simply isn't there yet"
            // apart from "the mempool preview is silently broken", which is exactly the hole
            // that let an incoming payment take minutes to show.
            if bundles.len() != last_seen {
                log::info!("mempool: {} shielded bundle(s) pending", bundles.len());
                last_seen = bundles.len();
            }
            let wallets: Vec<(String, Wallet)> = {
                state.wallets.lock().await.iter().filter(|(k, _)| active.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect()
            };
            for (token, w) in wallets {
                // try_lock, never lock: if the sync loop is mid-chunk on this wallet, skip it
                // and catch it next tick. Blocking here would re-couple us to the very queue
                // this loop exists to escape.
                let Ok(mut e) = w.try_lock() else { continue };
                e.scan_mempool(&bundles);
                let snap = snap_from_entry(state.address_of(&e.db), &e, e.chain_len);
                drop(e);
                state.snapshots.lock().await.insert(token, snap);
            }
        }
        tokio::time::sleep(MEMPOOL_POLL).await;
    }
}

/// What advancing one wallet a chunk told the loop it must do afterwards.
enum SyncOutcome {
    /// Cursor is gone (pruned/unknown) for `REORG_STRIKES` passes: its checkpoint was
    /// retired to `.bak`; the loop must evict it so the next request reloads it clean.
    Retired(String),
    /// Still catching up (or taking reorg strikes): the loop should spin its fast path.
    Behind,
    /// Caught up to the tip.
    Idle,
}

/// Advance a single wallet by one chunk and do its post-chunk bookkeeping (witness
/// catch-up, reorg-strike handling, checkpoint, status snapshot). Factored out of
/// [`sync_loop`] so several wallets can run **concurrently** (see [`SYNC_CONCURRENCY`]);
/// the logic is identical to the old sequential body.
async fn sync_one_wallet(state: Arc<AppState>, token: String, w: Wallet, chain_len: u64) -> SyncOutcome {
    let mut e = w.lock().await;
    e.chain_len = chain_len;
    // Advance one chunk from `low` (also the cheap tip catch-up once already synced).
    let was_caught_up = e.caught_up;
    e.caught_up = false;
    e.sync_chunk(&state.sync_client, &state.page_cache).await;
    // NB: NO eager witness advance here. Its cost is `leaves × note_count × TREE_DEPTH(32)`
    // Sinsemilla hashes, so for a many-note wallet even a small leaf cap cost 13–15 s per
    // pass — it ran on the sync path and froze every wallet's scan (observed live
    // 2026-07-16). It is only ever a spend-latency optimization: a spend rebuilds the
    // witness it needs on demand from the persisted leaf stream (`witness_path_at`, which
    // already falls back to a fresh rebuild). Dropping it keeps this function O(scan) and
    // non-blocking; the one-time rebuild cost moves to spend time, paid only for the notes
    // a spend actually selects. (`WITNESS_ADVANCE_*` consts retained for a future
    // work-budgeted re-enable.)
    if e.reorged_strikes >= REORG_STRIKES {
        // Cursor off the selected chain (or pruned away) for enough passes: retire the
        // checkpoint to .bak and let the caller evict + reload it from a fresh anchor.
        let scan = scan_path(&state.wallet_dir, &token);
        log::warn!(
            "wallet '{token}': cursor off the selected chain for {} consecutive passes ({}) \
             — retiring checkpoint to .bak and rescanning",
            e.reorged_strikes,
            e.error.as_deref().unwrap_or("no error recorded")
        );
        let _ = std::fs::rename(&scan, format!("{scan}.bak"));
        return SyncOutcome::Retired(token);
    }
    if e.reorged_strikes > 0 {
        // Striking but not yet retired: don't checkpoint a suspect cursor. Come back next pass.
        return SyncOutcome::Behind;
    }
    let behind = !e.caught_up;
    // Persist a checkpoint once enough new blocks accrue, or the first time this wallet
    // reaches the tip, so a restart resumes here instead of rescanning from birthday.
    let advanced = e.scanned.saturating_sub(e.saved_scanned);
    let just_caught_up = e.caught_up && !was_caught_up;
    if e.error.is_none() && (advanced >= CHECKPOINT_EVERY || (just_caught_up && advanced > 0)) {
        if let Err(err) =
            save_checkpoint(&state.wallet_dir, &token, &e.genesis, &e.low, e.scanned as u64, &e.db, &e.boundaries, e.sink_blue)
        {
            eprintln!("checkpoint write failed for {token}: {err}");
        } else {
            e.saved_scanned = e.scanned;
        }
    }
    // Refresh the out-of-band status snapshot while we still hold the lock.
    let snap = snap_from_entry(state.address_of(&e.db), &e, chain_len);
    drop(e);
    state.snapshots.lock().await.insert(token.clone(), snap);
    // A real sleep (not just yield_now) after each wallet, so HTTP handlers get a cycle
    // even while scans run. With bounded concurrency each in-flight scan still yields here.
    tokio::time::sleep(std::time::Duration::from_millis(SYNC_WALLET_THROTTLE_MS)).await;
    if behind { SyncOutcome::Behind } else { SyncOutcome::Idle }
}

async fn sync_loop(state: Arc<AppState>) {
    loop {
        let wallets: Vec<(String, Wallet)> = { state.wallets.lock().await.iter().map(|(k, v)| (k.clone(), v.clone())).collect() };
        let mut any_behind = false;
        let mut reorged_tokens: Vec<String> = Vec::new();
        // Only sync wallets touched within this window. The rest are parked (kept in
        // memory at their last checkpoint) until a request re-touches them — so a
        // public daemon with hundreds of one-time-visitor tokens doesn't try to
        // full-scan all of them at once and pin every core.
        let active: HashSet<String> = {
            let now = std::time::Instant::now();
            state
                .last_touch
                .lock()
                .await
                .iter()
                .filter(|(_, t)| now.duration_since(**t) < ACTIVE_SYNC_WINDOW)
                .map(|(k, _)| k.clone())
                .collect()
        };
        if !wallets.is_empty() {
            // Timed out for the same reason as the page fetch: this runs once per pass on
            // the shared loop, so a hang here freezes every wallet.
            let chain_len = match tokio::time::timeout(SYNC_RPC_TIMEOUT, state.sync_client.get_block_dag_info()).await {
                Ok(Ok(d)) => d.virtual_daa_score,
                _ => 0,
            };
            if chain_len > 0 {
                *state.node_tip.lock().await = (chain_len, std::time::Instant::now());
            }
            // Advance the active wallets with BOUNDED CONCURRENCY across the idle cores.
            // A single sequential loop pinned exactly one core (the per-wallet scan and
            // witness step are CPU-bound), so one wallet's heavy step — e.g. a 7–15 s
            // witness advance on a many-note wallet — froze every other wallet's scan.
            // Running up to `SYNC_CONCURRENCY` at once uses the otherwise-idle cores while
            // still leaving headroom for the HTTP handlers, the node RPC, and the mempool
            // loop. Per-wallet correctness is unchanged (each holds only its own lock).
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(SYNC_CONCURRENCY));
            let mut set = tokio::task::JoinSet::new();
            for (token, w) in wallets {
                if !active.contains(&token) {
                    continue; // parked: nobody is looking at this wallet right now
                }
                let permit = sem.clone().acquire_owned().await.expect("sync semaphore closed");
                let st = state.clone();
                set.spawn(async move {
                    let _permit = permit; // held for the wallet's whole chunk, bounding concurrency
                    sync_one_wallet(st, token, w, chain_len).await
                });
            }
            while let Some(res) = set.join_next().await {
                match res {
                    Ok(SyncOutcome::Retired(t)) => reorged_tokens.push(t),
                    Ok(SyncOutcome::Behind) => any_behind = true,
                    Ok(SyncOutcome::Idle) => {}
                    Err(join_err) => log::warn!("wallet sync task failed: {join_err}"),
                }
            }
        }
        if !reorged_tokens.is_empty() {
            let mut map = state.wallets.lock().await;
            let mut snaps = state.snapshots.lock().await;
            for t in reorged_tokens {
                map.remove(&t);
                snaps.remove(&t);
            }
        }
        // While catching up a big initial scan, loop back immediately (only a
        // tiny yield so status calls can grab the lock); idle slowly once synced.
        if any_behind {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        } else {
            // A caught-up wallet used to idle here for 12 SECONDS, which is most of the
            // delay before a payment appears: the tx is mined in ~1s, but nothing looks at
            // it until this sleep ends. It is a cheap pass when nothing has changed (one
            // dag-info call, one mempool call, a short page), so poll at ~1s instead —
            // payments are supposed to feel instant.
            tokio::time::sleep(IDLE_SYNC_POLL).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(serde_json::json!({ "error": msg.into() })))
}

fn fmt_fc(sompi: u128) -> String {
    let whole = sompi / SOMPI_PER_ZKAS as u128;
    let frac = sompi % SOMPI_PER_ZKAS as u128;
    format!("{whole}.{frac:08}")
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "zkas-walletd" }))
}

#[derive(Serialize)]
struct NoteInfo {
    position: u64,
    value: u64,
}

#[derive(Serialize)]
struct StatusResp {
    has_wallet: bool,
    address: Option<String>,
    network: String,
    node_connected: bool,
    daa_score: u64,
    synced: bool,
    scanned_blocks: usize,
    chain_len: u64,
    balance_sompi: String,
    balance_fc: String,
    /// Spendable-now balance: the subset of `balance_*` held in notes matured past
    /// the shielded anchor depth (~10 min). A send can only draw on this; the rest
    /// is `maturing_*`. Exposed so the wallet shows "spendable vs maturing" instead
    /// of offering the full balance and then failing a send with "have 0".
    spendable_sompi: String,
    spendable_fc: String,
    /// balance − spendable: value in notes too new to spend yet (still maturing).
    maturing_sompi: String,
    maturing_fc: String,
    /// 0-conf: value seen arriving/leaving in blocks too near the tip to ingest. Lets a
    /// payment show up ~1s after it is mined instead of ~3min later. Older daemons omit
    /// these; a missing value means "none pending".
    pending_in_sompi: String,
    pending_in_fc: String,
    pending_out_sompi: String,
    pending_out_fc: String,
    note_count: usize,
    updated_unix: u64,
    error: Option<String>,
    /// True when the daemon holds only this wallet's viewing key: it can show the
    /// balance but cannot spend. Sends must go through /prepare + /submit with the
    /// signature produced on the device that holds the seed.
    watch_only: bool,
}

async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<StatusResp> {
    let token = token_from(&headers, state.allow_default_token).ok();
    // Do NOT call the node here. The gRPC client is shared with the background sync loop,
    // whose block fetches make a fresh get_block_dag_info queue for seconds — which made
    // every status call take ~4s. The sync loop already refreshes `node_tip` every pass,
    // and a dedicated ticker keeps it current even with no wallets loaded, so status reads
    // the cached tip instantly. `node_connected` follows whether the tip is fresh.
    let (node_connected, daa_score) = {
        let (tip, at) = *state.node_tip.lock().await;
        (at.elapsed() < std::time::Duration::from_secs(30), tip)
    };

    let mut resp = StatusResp {
        has_wallet: false,
        address: None,
        network: state.network.clone(),
        node_connected,
        daa_score,
        synced: false,
        scanned_blocks: 0,
        chain_len: daa_score,
        balance_sompi: "0".into(),
        balance_fc: "0.00000000".into(),
        spendable_sompi: "0".into(),
        spendable_fc: "0.00000000".into(),
        maturing_sompi: "0".into(),
        maturing_fc: "0.00000000".into(),
        pending_in_sompi: "0".into(),
        pending_in_fc: "0.00000000".into(),
        pending_out_sompi: "0".into(),
        pending_out_fc: "0.00000000".into(),
        note_count: 0,
        updated_unix: 0,
        error: None,
        watch_only: false,
    };

    if let Some(token) = token {
        // NEVER load on the request path. A wallet load makes node RPCs and rebuilds a
        // Merkle tree — seconds of work. Doing it here (even with a timeout) livelocked
        // the daemon: the timeout cancelled the half-done load, so the wallet never
        // cached, so every poll re-ran and re-cancelled it. Instead: if the wallet is
        // already loaded, answer from it (fast); otherwise kick off a background load
        // and report "syncing" until it lands. Subsequent polls are instant.
        state.touch(&token).await;
        if let Some(w) = state.cached_wallet(&token).await {
            if let Ok(e) = w.try_lock() {
                // Got the lock → compute a fresh snapshot, cache it out-of-band for the
                // polls that will race the next scan pass, and answer from it.
                let snap = snap_from_entry(state.address_of(&e.db), &e, daa_score);
                drop(e);
                state.snapshots.lock().await.insert(token.clone(), snap.clone());
                fill_status_from_snap(&mut resp, &snap);
            } else if let Some(snap) = state.snapshots.lock().await.get(&token).cloned() {
                // Lock held by the sync loop this instant — answer from the last-known-good
                // snapshot (real balance + progress) instead of a zero default. This is the
                // fix for the balance/scan-progress flickering to 0 mid-scan.
                fill_status_from_snap(&mut resp, &snap);
                if resp.error.is_none() {
                    resp.error = Some("updating…".into());
                }
            } else {
                // Loaded but not yet snapshotted (very first pass) — report presence only.
                resp.has_wallet = true;
                resp.error = Some("updating…".into());
            }
        } else if wallet_exists(&state.wallet_dir, &token) {
            // Known wallet, not yet in memory — load it in the background.
            state.spawn_load(&token);
            resp.has_wallet = true;
            resp.error = Some("loading…".into());
        }
    }
    Json(resp)
}

#[derive(Serialize)]
struct CreateResp {
    address: String,
    seed_hex: String,
    network: String,
    warning: String,
}

async fn wallet_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CreateResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    if wallet_exists(&state.wallet_dir, &token) {
        return Err(err(StatusCode::CONFLICT, "a wallet already exists for this token; import replaces it"));
    }
    use rand::RngCore;
    let mut seed = [0u8; 32];
    let address = loop {
        rand::rngs::OsRng.fill_bytes(&mut seed);
        if let Some(addr) = state.address_for_seed(&seed) {
            break addr;
        }
    };
    // A brand-new wallet holds no historical funds: birth it at the current tip so
    // it is instantly ready to receive — no full-history scan needed.
    let tip = state.client.get_block_dag_info().await.map(|d| d.virtual_daa_score).unwrap_or(0);
    load_new_wallet(&state, &token, seed, tip).await?;
    Ok(Json(CreateResp {
        address,
        seed_hex: hex(&seed),
        network: state.network.clone(),
        warning: "Write this seed down and keep it offline. Anyone with it controls these funds. Shown once.".into(),
    }))
}

#[derive(Deserialize)]
struct ImportReq {
    seed_hex: String,
    /// Optional wallet birthday (block height). Start the display scan here instead
    /// of genesis to sync fast; omit / 0 to scan the whole chain for old funds.
    #[serde(default)]
    birthday: u64,
}

async fn wallet_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ImportReq>,
) -> Result<Json<CreateResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let bytes = unhex(&req.seed_hex).ok_or_else(|| err(StatusCode::BAD_REQUEST, "seed_hex is not valid hex"))?;
    if bytes.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, "seed must be exactly 32 bytes (64 hex chars)"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let address =
        state.address_for_seed(&seed).ok_or_else(|| err(StatusCode::BAD_REQUEST, "seed is not a valid Orchard spending key"))?;
    load_new_wallet(&state, &token, seed, req.birthday).await?;
    Ok(Json(CreateResp {
        address,
        seed_hex: req.seed_hex,
        network: state.network.clone(),
        warning: "Wallet imported. Keep your seed offline.".into(),
    }))
}

/// Persist a new seed for a token and (re)load it into memory, replacing any prior.
/// `birthday` is the block height the display scan starts from (0 = from genesis).
async fn load_new_wallet(
    state: &Arc<AppState>,
    token: &str,
    seed: [u8; 32],
    birthday: u64,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    save_seed(&state.wallet_dir, token, &state.network, &seed, birthday, state.wallet_secret.as_deref())
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Drop any prior scan checkpoint: a (re)imported seed must rescan from its own
    // birthday, not resume a different wallet's stream.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, token));
    // Fast-sync from the node's frontier when the wallet is born after the
    // checkpoint (complete by construction); otherwise the pruning-point full scan.
    let entry = match state.fast_sync_entry(WalletKey::Seed(seed), state.genesis, birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(WalletKey::Seed(seed), state.genesis)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.to_string(), Arc::new(Mutex::new(entry)));
    Ok(())
}

#[derive(Serialize)]
struct AddressResp {
    address: String,
}

async fn wallet_address(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AddressResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let address = state.address_of(&e.db);
    Ok(Json(AddressResp { address }))
}

#[derive(Serialize)]
struct RevealResp {
    address: String,
    seed_hex: String,
    network: String,
}

/// Return the wallet's recovery seed. On the hosted daemon the server already
/// holds the seed (hot-wallet model), so this discloses nothing new to the host;
/// it lets the owning browser (identified by its wallet token) back up or export
/// the phrase at any time — not just once at creation.
async fn wallet_reveal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RevealResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let address = state.address_of(&e.db);
    let seed = e.key.seed()?;
    Ok(Json(RevealResp { address, seed_hex: hex(&seed), network: state.network.clone() }))
}

#[derive(Deserialize)]
struct WatchReq {
    /// 96-byte full viewing key (hex), derived on the device from a seed the daemon
    /// never sees.
    fvk_hex: String,
    /// Birth DAA score. A wallet generated on-device right now is born at the tip and
    /// needs no historical scan; 0 means "may hold funds from any height" → full scan.
    #[serde(default)]
    birthday: u64,
}

/// Register a **watch-only** wallet for this token: the daemon syncs it, shows its
/// balance and builds spend *proofs* for it, but never holds spend authority. This is
/// the non-custodial (mobile) registration path — the device keeps the seed, sends only
/// the viewing key, and signs every spend itself via `/prepare` + `/submit`.
///
/// A daemon compromise then leaks *visibility* into these wallets, never their coins.
async fn wallet_watch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WatchReq>,
) -> Result<Json<AddressResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let fvk = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;
    let key = WalletKey::Fvk(fvk);
    let db = key.empty_db().ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?;
    let address = state.address_of(&db);

    save_fvk(&state.wallet_dir, &token, &state.network, &fvk, req.birthday)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // A re-registered key must rescan from its own birthday, not resume another
    // wallet's checkpoint stream.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
    let entry = match state.fast_sync_entry(key, state.genesis, req.birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(key, state.genesis)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.clone(), Arc::new(Mutex::new(entry)));
    log::info!("registered watch-only wallet for token {token} (birthday {})", req.birthday);
    Ok(Json(AddressResp { address }))
}

#[derive(Serialize)]
struct BalanceResp {
    balance_sompi: String,
    balance_fc: String,
    synced: bool,
    scanned_blocks: usize,
    chain_len: u64,
    notes: Vec<NoteInfo>,
    updated_unix: u64,
    error: Option<String>,
}

async fn wallet_balance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<BalanceResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let notes = e.db.notes().iter().map(|n| NoteInfo { position: n.position, value: n.value() }).collect();
    Ok(Json(BalanceResp {
        balance_sompi: e.db.balance().to_string(),
        balance_fc: fmt_fc(e.db.balance()),
        synced: e.caught_up || (e.scanned as u64) + SYNC_MARGIN >= e.chain_len,
        scanned_blocks: e.scanned,
        chain_len: e.chain_len,
        notes,
        updated_unix: e.updated_unix,
        error: e.error.clone(),
    }))
}

#[derive(Deserialize)]
struct SendReq {
    to: String,
    amount_sompi: Option<u64>,
    amount_fc: Option<f64>,
    fee: Option<u64>,
}

#[derive(Serialize)]
struct SendResp {
    /// First transaction id (kept for callers that expect a single txid).
    txid: String,
    amount_sompi: u64,
    /// Total fees paid across all transactions.
    fee_sompi: u64,
    /// Every transaction id: a large send is split across several
    /// standard-size transactions (at most [`max_spends_per_tx`] spends each).
    txids: Vec<String>,
    tx_count: usize,
}

/// Greedy chunk planning over **value-descending** candidate notes: each
/// transaction spends at most `max_per` notes and pays `min(remaining,
/// chunk_sum − fee)` to the recipient, until `amount` is covered. Returns the
/// per-chunk `(note_count, pay)` plan, or `None` if the notes run out
/// (insufficient funds once per-tx fees are accounted).
fn plan_chunks(values: &[u64], amount: u64, fee: u64, max_per: usize) -> Option<Vec<(usize, u64)>> {
    let mut chunks = Vec::new();
    let mut remaining = amount;
    let mut i = 0usize;
    while remaining > 0 {
        let mut sum = 0u64;
        let mut n = 0usize;
        while n < max_per && i < values.len() && sum < remaining.saturating_add(fee) {
            sum = sum.saturating_add(values[i]);
            i += 1;
            n += 1;
        }
        if sum <= fee {
            return None;
        }
        let pay = remaining.min(sum - fee);
        chunks.push((n, pay));
        remaining -= pay;
    }
    Some(chunks)
}

async fn wallet_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let seed = { w.lock().await.key.seed()? };

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    let fee = req.fee.unwrap_or(3_000_000);

    let client = &state.client;
    // The shielded sighash network domain: the GENESIS hash — what consensus
    // verifies signatures against (`params.genesis.hash`). The moving pruning
    // point only coincides with it on a young, unpruned chain.
    let net: [u8; 32] = state.genesis.as_bytes();

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;

    if amount == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "amount must be positive"));
    }
    let max_per_tx = max_spends_per_tx();
    let insufficient = |have: u64| {
        err(
            StatusCode::CONFLICT,
            format!(
                "insufficient matured funds: have {have}, need {need}+ (amount {amount} + a {fee} fee per tx; funds must be ~10 min old to spend)"
            ),
        )
    };

    // Gather ALL matured candidates and plan the transactions. A standard tx fits
    // at most `max_per_tx` spends (transient-mass cap), so a large send is split
    // into several transactions, each paying part of the amount. Everything —
    // candidates, plan, witnesses — is materialized before any proving starts, so
    // an over-cap or underfunded request fails in milliseconds, not after a
    // multi-minute (or, live, 106-minute) proof.
    //
    // Fast path: reuse the wallet state the sync loop already maintains, rooting
    // each spend at the newest chain-block boundary at least `anchor_depth +
    // slack` blue units below the sink — a matured, canonical chain-block root
    // consensus accepts (`is_shielded_anchor_final`; maturity is measured in blue
    // score). The entry lock is held only for selection + witness building.
    let mut planned: Option<(Vec<(Vec<_>, u64, Vec<u64>)>, u64, bool)> = None;
    {
        let mut e = w.lock().await;
        // Top up the live witnesses to the current matured anchor (a no-op unless a
        // block landed since the last sync tick), so witnessing below is a lookup.
        e.advance_spend_witnesses();
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
            let mut candidates: Vec<_> = e.db.notes().iter().filter(|n| n.position < matured).collect();
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
            let have: u64 = values.iter().sum();
            match plan_chunks(&values, amount, fee, max_per_tx) {
                Some(plan) => {
                    let mut chunks = Vec::with_capacity(plan.len());
                    let mut idx = 0usize;
                    for (n_notes, pay) in plan {
                        let mut inputs = Vec::with_capacity(n_notes);
                        let mut positions = Vec::with_capacity(n_notes);
                        for note in &candidates[idx..idx + n_notes] {
                            let path =
                                e.db.witness_path_at(note.position, matured)
                                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                            inputs.push((note.note.clone(), path));
                            positions.push(note.position);
                        }
                        idx += n_notes;
                        chunks.push((inputs, pay, positions));
                    }
                    planned = Some((chunks, have, e.caught_up));
                }
                None => planned = Some((Vec::new(), have, e.caught_up)),
            }
        }
    }

    let chunks = match planned {
        // A complete plan at the wallet's own anchor — the fast, no-rescan path.
        Some((chunks, _, _)) if !chunks.is_empty() => chunks,
        // Planning failed but the wallet is caught up to the tip, so a full replay
        // would see the exact same matured notes: authoritative insufficient.
        Some((_, have, true)) => return Err(insufficient(have)),
        // Ring not filled yet (cold start) or wallet behind the tip: one-off matured
        // replay — correct, just slow, and transient until the sync loop catches up.
        _ => {
            log::warn!("send: fast path unavailable/insufficient; falling back to a matured chain replay (slow, one-off)");
            let fresh = WalletDb::from_seed(seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad seed"))?;
            let db = replay_matured(client, fresh).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let mut candidates = db.notes().to_vec();
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
            let have: u64 = values.iter().sum();
            let plan = plan_chunks(&values, amount, fee, max_per_tx).ok_or_else(|| insufficient(have))?;
            let mut chunks = Vec::with_capacity(plan.len());
            let mut idx = 0usize;
            for (n_notes, pay) in plan {
                let mut inputs = Vec::with_capacity(n_notes);
                let mut positions = Vec::with_capacity(n_notes);
                for note in &candidates[idx..idx + n_notes] {
                    let path = db
                        .witness_path(note.position)
                        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                    inputs.push((note.note.clone(), path));
                    positions.push(note.position);
                }
                idx += n_notes;
                chunks.push((inputs, pay, positions));
            }
            chunks
        }
    };

    // Prove + submit each chunk sequentially. Proving runs on a blocking thread so
    // the daemon (status/balance endpoints, other wallets) stays responsive; each
    // accepted chunk's notes are marked spent immediately so a concurrent or
    // follow-up send cannot re-select them before the scan loop observes the tx.
    let ctx = payment_tx_context();
    let tx_count = chunks.len();
    let mut txids: Vec<String> = Vec::with_capacity(tx_count);
    let mut sent = 0u64;
    for (ci, (inputs, pay, positions)) in chunks.into_iter().enumerate() {
        log::info!("send: building Orchard proof for tx {}/{tx_count} ({} spends, {pay} sompi + {fee} fee)...", ci + 1, inputs.len());
        let ctx2 = ctx.clone();
        let started = std::time::Instant::now();
        let payload = tokio::task::spawn_blocking(move || build_wallet_payment(seed, inputs, recipient, pay, fee, &net, &ctx2))
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build payment: {e:?}")))?;
        log::info!("send: tx {}/{tx_count} proven in {:.0?}", ci + 1, started.elapsed());

        let tx: Transaction = payment_tx(payload);
        match client.submit_transaction(RpcTransaction::from(&tx), false).await {
            Ok(accepted) => {
                txids.push(accepted.to_string());
                sent += pay;
                let mut e = w.lock().await;
                for p in positions {
                    e.db.mark_spent(p);
                }
            }
            Err(e) if txids.is_empty() => return Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the payment: {e}"))),
            Err(e) => {
                // Partial success: report what actually went through.
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("payment partially sent: {}/{tx_count} txs accepted, then the node rejected: {e}", txids.len()),
                        "txids": txids,
                        "sent_sompi": sent,
                    })),
                ));
            }
        }
    }

    let total_fee = fee * tx_count as u64;
    Ok(Json(SendResp { txid: txids[0].clone(), amount_sompi: amount, fee_sompi: total_fee, txids, tx_count }))
}

#[derive(Deserialize, Default)]
struct ConsolidateReq {
    fee: Option<u64>,
}

#[derive(Serialize)]
struct ConsolidateResp {
    txid: String,
    /// How many notes were merged into one.
    consolidated: usize,
    /// Value of the resulting note (inputs minus fee).
    value_sompi: u64,
    /// Unspent notes the wallet still tracks after this merge.
    notes_remaining: usize,
}

/// Merge the wallet's **smallest matured notes** into a single note paid back to
/// its own address. Mining wallets accumulate one ~60 FC coinbase note per block;
/// since a standard transaction spends at most [`max_spends_per_tx`] notes
/// (transient-mass cap), a fragmented wallet needs many chunked transactions per
/// large send. Calling this periodically (each call folds up to 6 notes → 1, the
/// result spendable after ~10 min maturity) keeps big payouts down to a single tx.
async fn wallet_consolidate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<ConsolidateReq>>,
) -> Result<Json<ConsolidateResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let seed = { w.lock().await.key.seed()? };
    let fee = body.and_then(|Json(b)| b.fee).unwrap_or(3_000_000);
    let own_recipient =
        address_bytes_from_seed(seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "seed is not a valid spending key"))?;

    let net: [u8; 32] = state.genesis.as_bytes();

    // Select up to a tx-full of the smallest matured notes under the entry lock.
    let (inputs, positions, sum) = {
        let e = w.lock().await;
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) else {
            return Err(err(StatusCode::CONFLICT, "wallet is still syncing the maturity window; try again shortly"));
        };
        let mut candidates: Vec<_> = e.db.notes().iter().filter(|n| n.position < matured).collect();
        candidates.sort_by_key(|n| n.value());
        candidates.truncate(max_spends_per_tx());
        let sum: u64 = candidates.iter().map(|n| n.value()).sum();
        if candidates.len() < 2 {
            return Err(err(StatusCode::CONFLICT, "nothing to consolidate: fewer than 2 matured notes"));
        }
        if sum <= fee {
            return Err(err(StatusCode::CONFLICT, format!("smallest notes sum to {sum}, not more than the {fee} fee")));
        }
        let mut inputs = Vec::with_capacity(candidates.len());
        let mut positions = Vec::with_capacity(candidates.len());
        for n in &candidates {
            let path =
                e.db.witness_path_at(n.position, matured)
                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
            inputs.push((n.note.clone(), path));
            positions.push(n.position);
        }
        (inputs, positions, sum)
    };

    let consolidated = inputs.len();
    let value = sum - fee;
    let ctx = payment_tx_context();
    log::info!("consolidate: merging {consolidated} notes ({sum} sompi) into one...");
    let payload = tokio::task::spawn_blocking(move || build_wallet_payment(seed, inputs, own_recipient, value, fee, &net, &ctx))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build consolidation: {e:?}")))?;

    let tx: Transaction = payment_tx(payload);
    match state.client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            let mut e = w.lock().await;
            for p in positions {
                e.db.mark_spent(p);
            }
            let notes_remaining = e.db.notes().len();
            Ok(Json(ConsolidateResp { txid: accepted.to_string(), consolidated, value_sompi: value, notes_remaining }))
        }
        Err(e) => Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the consolidation: {e}"))),
    }
}

// ===========================================================================
// Non-custodial payment: prepare (viewing key only) + submit (device sigs).
//
// This is the mobile / hardened path. The device holds the seed and never sends
// it: it posts only its 96-byte FULL VIEWING KEY to `/prepare`. The daemon scans
// watch-only, builds the Halo 2 proof, signs the throwaway padding dummies, and
// returns the payment sighash plus one spend randomizer (`alpha`) per real spend.
// The device signs each with `ask.randomize(alpha)` (e.g. via ZKas-signer) and
// posts the signatures to `/submit`, which applies them and broadcasts. A server
// compromise can see balances but CANNOT move funds — it never holds spend authority.
// The crypto split is proven in shielded-core (`non_custodial_payment_api_roundtrip`).
// ===========================================================================

#[derive(Deserialize)]
struct PrepareReq {
    /// 96-byte full viewing key (hex). Grants viewing capability, not spend.
    fvk_hex: String,
    /// Recipient `zkas:` shielded address.
    to: String,
    amount_sompi: Option<u64>,
    amount_fc: Option<f64>,
    fee: Option<u64>,
}

#[derive(Serialize)]
struct SpendAuthReq {
    /// Action index in the bundle this randomizer authorizes.
    index: usize,
    /// 32-byte spend randomizer (hex); the device signs `ask.randomize(alpha)`.
    alpha: String,
}

#[derive(Serialize)]
struct PrepareResp {
    /// Opaque id to submit the signatures against.
    session: String,
    /// 32-byte payment sighash (hex) the device signs.
    sighash: String,
    /// Public fee / value balance of the payment.
    value_balance: i64,
    amount_sompi: u64,
    fee_sompi: u64,
    /// One randomizer per real spend the device must sign.
    spend_auth: Vec<SpendAuthReq>,
    /// The unsigned bundle (hex). The device MUST recompute the sighash from this
    /// itself rather than trust `sighash` above, and MUST verify the bundle against
    /// `disclosure` before signing — otherwise it is blind-signing whatever this
    /// daemon says, and a compromised daemon could have it authorize a payment to
    /// the attacker (`kaspa_shielded_core::wallet::build::check_prepared_payment`).
    bundle_hex: String,
    /// Per-action plaintext of the payment, so the device can check what it signs.
    disclosure: Vec<ActionDisclosureJson>,
}

/// [`kaspa_shielded_core::wallet::build::ActionDisclosure`] over the wire.
#[derive(Serialize)]
struct ActionDisclosureJson {
    spend_value: u64,
    out_value: u64,
    out_recipient: String,
    out_rseed: String,
    rcv: String,
}

async fn wallet_prepare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PrepareReq>,
) -> Result<Json<PrepareResp>, (StatusCode, Json<serde_json::Value>)> {
    use rand::RngCore;

    let _prepare_permit = state.prepare_gate.try_acquire().map_err(|_| {
        err(StatusCode::TOO_MANY_REQUESTS, "a shielded payment is already being prepared; wait for it to finish before retrying")
    })?;

    // Watch-only: authenticated by possession of the FVK, not a token/seed.
    let fvk_bytes = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    let fee = req.fee.unwrap_or(3_000_000);

    let client = &state.client;
    let net: [u8; 32] = state.genesis.as_bytes();

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;

    let max_per_tx = max_spends_per_tx();

    // Fast path: if the caller also presents the wallet token this key is registered
    // under (the app always does), the sync loop is already holding a live, matured
    // view of exactly this wallet — reuse it and spend straight from it. Without this
    // every send re-walked the chain watch-only first (measured: 3m24s on a 174K-block
    // chain), which on a phone reads as a hung app; the proof itself is ~7s.
    let mut inputs = Vec::new();
    let mut selected = 0u64;
    let mut have_total: Option<u64> = None;
    if let Ok(token) = token_from(&headers, state.allow_default_token) {
        if let Some(w) = state.get_wallet(&token).await {
            let mut e = w.lock().await;
            if e.db.fvk().to_bytes() == fvk_bytes {
                let t_w = std::time::Instant::now();
                e.advance_spend_witnesses();
                log::info!("prepare: witness advance took {:.1?}", t_w.elapsed());
                let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
                if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
                    let mut candidates: Vec<_> = e.db.notes().iter().filter(|n| n.position < matured).collect();
                    candidates.sort_by(|a, b| b.value().cmp(&a.value()));
                    have_total = Some(candidates.iter().map(|n| n.value()).sum());
                    for n in &candidates {
                        if selected >= need || inputs.len() == max_per_tx {
                            break;
                        }
                        let t_p = std::time::Instant::now();
                        let path =
                            e.db.witness_path_at(n.position, matured)
                                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                        log::info!("prepare: witness_path_at(note@{}) took {:.1?}", n.position, t_p.elapsed());
                        inputs.push((n.note.clone(), path));
                        selected += n.value();
                    }
                }
            }
        }
    }

    // Slow path (no token, unsynced wallet, or a key we don't track): recover the note
    // set from the FVK alone over the settled matured chain prefix, so every witness
    // still roots at a matured canonical anchor.
    if have_total.is_none() {
        let db =
            WalletDb::from_fvk(&fvk_bytes).ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?;
        log::info!("non-custodial prepare: watch-only matured chain replay...");
        let db = replay_matured(client, db).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let mut candidates = db.notes().to_vec();
        candidates.sort_by(|a, b| b.value().cmp(&a.value()));
        have_total = Some(candidates.iter().map(|n| n.value()).sum());
        for n in &candidates {
            if selected >= need || inputs.len() == max_per_tx {
                break;
            }
            let path = db
                .witness_path(n.position)
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
            inputs.push((n.note.clone(), path));
            selected += n.value();
        }
    }
    if selected < need {
        let have: u64 = have_total.unwrap_or(0);
        return Err(if have >= need {
            err(
                StatusCode::CONFLICT,
                format!(
                    "amount needs more than {max_per_tx} input notes (standard tx size cap): max sendable in one tx is {} sompi; send in smaller chunks",
                    selected.saturating_sub(fee)
                ),
            )
        } else {
            err(
                StatusCode::CONFLICT,
                format!("insufficient matured funds: have {have}, need amount+fee={need} (funds must be ~10 min old to spend)"),
            )
        });
    }

    let ctx = payment_tx_context();
    log::info!("non-custodial prepare: building Orchard payment proof (Halo 2) for {} spends...", inputs.len());
    let fvk = WalletDb::from_fvk(&fvk_bytes)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?
        .fvk()
        .clone();
    let t_proof = std::time::Instant::now();
    let payment = tokio::task::spawn_blocking(move || prepare_payment(&fvk, inputs, recipient, amount, fee, &net, &ctx))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to prepare payment: {e:?}")))?;
    log::info!("prepare: Halo2 proof took {:.1?}", t_proof.elapsed());

    let spend_auth: Vec<SpendAuthReq> =
        payment.spend_auth_requests.iter().map(|(i, alpha)| SpendAuthReq { index: *i, alpha: hex(alpha) }).collect();
    let sighash_hex = hex(&payment.sighash);
    let value_balance = payment.value_balance;

    // Hand the device everything it needs to check this payment for itself: the
    // unsigned bundle and the plaintext of every action. Anything we lie about here
    // fails the device's commitment checks, so it can refuse to sign.
    let bundle_hex = hex(&payment.effects.to_bytes());
    let disclosure: Vec<ActionDisclosureJson> = payment
        .disclosure
        .iter()
        .map(|d| ActionDisclosureJson {
            spend_value: d.spend_value,
            out_value: d.out_value,
            out_recipient: hex(&d.out_recipient),
            out_rseed: hex(&d.out_rseed),
            rcv: hex(&d.rcv),
        })
        .collect();

    // Park the awaiting-signature payment under a random, unguessable session id.
    let mut sid = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut sid);
    let session = hex(&sid);
    {
        let now = std::time::Instant::now();
        let mut map = state.prepared.lock().await;
        map.retain(|_, s| now.duration_since(s.created) < PREPARED_TTL); // bound memory
        map.insert(session.clone(), PreparedSession { payment, amount, fee, created: now });
    }

    Ok(Json(PrepareResp {
        session,
        sighash: sighash_hex,
        value_balance,
        amount_sompi: amount,
        fee_sompi: fee,
        spend_auth,
        bundle_hex,
        disclosure,
    }))
}

#[derive(Deserialize)]
struct SubmitSig {
    /// Action index this signature authorizes (echoed from `spend_auth`).
    index: usize,
    /// 64-byte RedPallas spend-auth signature (hex).
    sig: String,
}

#[derive(Deserialize)]
struct SubmitReq {
    /// The `session` returned by `/prepare`.
    session: String,
    /// The device's spend-auth signatures, one per `spend_auth` request.
    sigs: Vec<SubmitSig>,
}

async fn wallet_submit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    // Pop the session (single-use); also sweep any expired ones.
    let session = {
        let now = std::time::Instant::now();
        let mut map = state.prepared.lock().await;
        map.retain(|_, s| now.duration_since(s.created) < PREPARED_TTL);
        map.remove(&req.session)
    };
    let PreparedSession { payment, amount, fee, .. } =
        session.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such prepared session (expired or already submitted)"))?;

    let mut device_sigs: Vec<(usize, [u8; SIG_LEN])> = Vec::with_capacity(req.sigs.len());
    for s in &req.sigs {
        let sig = unhex(&s.sig)
            .and_then(|b| <[u8; SIG_LEN]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "each sig must be 64 bytes of hex"))?;
        device_sigs.push((s.index, sig));
    }

    let bundle = finalize_payment(payment, device_sigs)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("could not finalize payment (bad/missing signatures?): {e:?}")))?;
    let tx: Transaction = payment_tx(bundle.to_bytes());
    match state.client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            let txid = accepted.to_string();
            Ok(Json(SendResp { txid: txid.clone(), amount_sompi: amount, fee_sompi: fee, txids: vec![txid], tx_count: 1 }))
        }
        Err(e) => Err(err(StatusCode::BAD_GATEWAY, format!("node rejected the payment: {e}"))),
    }
}

#[derive(Deserialize)]
struct SignReq {
    message: String,
}

#[derive(Serialize)]
struct SignResp {
    address: String,
    message: String,
    signature: String,
    note: String,
}

async fn wallet_sign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SignReq>,
) -> Result<Json<SignResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let seed = { w.lock().await.key.seed()? };
    let tag = state.prefix.to_string();
    let signed = sign_message(seed, tag.as_bytes(), req.message.as_bytes(), rand::rngs::OsRng)
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "seed is not a valid spending key"))?;
    let address = String::from(&Address::new(state.prefix, Version::ShieldedOrchard, &signed.address));
    let mut blob = Vec::with_capacity(FVK_LEN + SIG_LEN);
    blob.extend_from_slice(&signed.fvk);
    blob.extend_from_slice(&signed.sig);
    Ok(Json(SignResp {
        address,
        message: req.message,
        signature: hex(&blob),
        note:
            "This signature discloses the wallet's viewing key (proves ownership + enables note detection, but NOT spend authority)."
                .into(),
    }))
}

#[derive(Deserialize)]
struct VerifyReq {
    address: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct VerifyResp {
    valid: bool,
    reason: Option<String>,
}

async fn verify(Json(req): Json<VerifyReq>) -> Result<Json<VerifyResp>, (StatusCode, Json<serde_json::Value>)> {
    let addr = Address::try_from(req.address.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid address: {e}")))?;
    let tag = addr.prefix.to_string();
    let raw =
        orchard_recipient_bytes(&addr).ok_or_else(|| err(StatusCode::BAD_REQUEST, "address is not a shielded Orchard address"))?;
    let blob = unhex(&req.signature).ok_or_else(|| err(StatusCode::BAD_REQUEST, "signature is not valid hex"))?;
    if blob.len() != FVK_LEN + SIG_LEN {
        return Err(err(StatusCode::BAD_REQUEST, format!("signature must be {} bytes (fvk||sig)", FVK_LEN + SIG_LEN)));
    }
    let fvk: [u8; FVK_LEN] = blob[..FVK_LEN].try_into().expect("checked");
    let s: [u8; SIG_LEN] = blob[FVK_LEN..].try_into().expect("checked");
    match verify_message(&raw, tag.as_bytes(), req.message.as_bytes(), &fvk, &s) {
        Ok(()) => Ok(Json(VerifyResp { valid: true, reason: None })),
        Err(e) => Ok(Json(VerifyResp { valid: false, reason: Some(format!("{e:?}")) })),
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

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

    let listen: SocketAddr = cli.listen.parse().unwrap_or_else(|e| {
        log::error!("bad --listen {:?}: {e}", cli.listen);
        std::process::exit(1);
    });
    if !listen.ip().is_loopback() && !cli.allow_remote {
        log::error!("refusing to bind non-loopback {} without --allow-remote (put a TLS proxy in front instead)", listen);
        std::process::exit(1);
    }

    let wallet_dir = cli.wallet_dir.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/.firecash/wallets")
    });
    let _ = std::fs::create_dir_all(&wallet_dir);

    // Two node connections: one for the request path, one for the background sync loop,
    // so heavy sync traffic can't stall user wallet loads. Retry until the node is up.
    async fn connect_node(rpc_server: &str, label: &str) -> GrpcClient {
        loop {
            match GrpcClient::connect_with_args(
                NotificationMode::Direct,
                format!("grpc://{rpc_server}"),
                None,
                true,
                None,
                false,
                Some(500_000),
                Default::default(),
            )
            .await
            {
                Ok(c) => break c,
                Err(e) => {
                    log::warn!("node {rpc_server} ({label}) not reachable yet ({e}); retrying in 3s...");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
    }
    let client = connect_node(&cli.rpc_server, "request").await;
    let sync_client = connect_node(&cli.rpc_server, "sync").await;
    log::info!("connected to node at {} (2 connections: request + sync)", cli.rpc_server);

    // Seed-file encryption secret: CLI flag, ZKAS_WALLET_SECRET, or the legacy
    // FIRECASH_WALLET_SECRET env (still honored so pre-rebrand service files work).
    let wallet_secret = cli
        .wallet_secret
        .or_else(|| std::env::var("ZKAS_WALLET_SECRET").ok())
        .or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok());
    if wallet_secret.is_none() {
        log::warn!("no --wallet-secret / ZKAS_WALLET_SECRET set: seed files are stored in PLAINTEXT (0600 on unix)");
    }
    if cli.allow_default_token {
        log::warn!(
            "--allow-default-token: tokenless requests map to the 'default' wallet; use only on a trusted single-user localhost"
        );
    }

    // The network genesis hash — the shielded sighash domain consensus verifies
    // against, and the checkpoint guard. Taken from the compile-time network
    // params (identical to what consensus signs against); resolving it over RPC
    // (`get_blocks(None)`) fails on any pruned node, whose genesis chain data is
    // gone.
    let genesis = RpcHash::from_bytes(
        kaspa_consensus_core::config::params::Params::from(state_prefix_network(&cli.network)).genesis.hash.as_bytes(),
    );
    log::info!("network genesis (shielded sighash domain): {genesis}");

    let state = Arc::new(AppState {
        client,
        sync_client,
        wallet_dir,
        prefix: prefix_from(&cli.network),
        network: cli.network,
        wallets: Mutex::new(HashMap::new()),
        allow_default_token: cli.allow_default_token,
        wallet_secret,
        genesis,
        page_cache: Mutex::new(PageCache::new()),
        last_touch: Mutex::new(HashMap::new()),
        load_gate: tokio::sync::Semaphore::new(2),
        prepare_gate: tokio::sync::Semaphore::new(1),
        node_tip: Mutex::new((0, std::time::Instant::now())),
        prepared: Mutex::new(HashMap::new()),
        snapshots: Mutex::new(HashMap::new()),
    });

    tokio::spawn(sync_loop(state.clone()));
    // Unmined payments — the instant-payment path. Separate from sync_loop on purpose
    // (see mempool_loop): it must never queue behind block scanning.
    tokio::spawn(mempool_loop(state.clone()));

    // Keep the cached node tip fresh independently of loaded wallets, so `status` can
    // report node connectivity + chain height without ever calling the node on the
    // request path (which was contended by the sync loop and made status take ~4s).
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(d) = state.client.get_block_dag_info().await {
                    *state.node_tip.lock().await = (d.virtual_daa_score, std::time::Instant::now());
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    // Build the (deterministic, process-wide) Orchard proving key now, off the
    // async runtime, so the first send doesn't eat the multi-minute keygen.
    std::thread::spawn(|| {
        let started = std::time::Instant::now();
        let _ = proving_key();
        log::info!("Orchard proving key ready in {:.0?} (max {} spends per standard tx)", started.elapsed(), max_spends_per_tx());
    });

    // Lock CORS to an explicit browser-origin allowlist. With no --allow-origin given
    // the list is empty, so cross-origin browser reads are refused (same-origin only):
    // a random page a user visits can no longer read /reveal or call /send. We also
    // drop allow_private_network(true) so a public site can't reach the loopback daemon.
    let origins: Vec<HeaderValue> = cli
        .allow_origin
        .iter()
        .filter_map(|o| match o.parse::<HeaderValue>() {
            Ok(hv) => Some(hv),
            Err(_) => {
                log::error!("ignoring invalid --allow-origin {o:?}");
                None
            }
        })
        .collect();
    log::info!("CORS allowed origins: {:?}", cli.allow_origin);
    let cors = tower_http::cors::CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-wallet-token")])
        .allow_origin(origins);

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/status", get(status))
        .route("/api/wallet/create", post(wallet_create))
        .route("/api/wallet/import", post(wallet_import))
        .route("/api/wallet/watch", post(wallet_watch))
        .route("/api/wallet/address", get(wallet_address))
        .route("/api/wallet/reveal", get(wallet_reveal))
        .route("/api/wallet/balance", get(wallet_balance))
        .route("/api/wallet/send", post(wallet_send))
        .route("/api/wallet/consolidate", post(wallet_consolidate))
        .route("/api/wallet/prepare", post(wallet_prepare))
        .route("/api/wallet/submit", post(wallet_submit))
        .route("/api/wallet/sign", post(wallet_sign))
        .route("/api/verify", post(verify))
        .layer(cors)
        .with_state(state);

    log::info!("zkas-walletd listening on http://{listen}");
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| {
        log::error!("failed to bind {listen}: {e}");
        std::process::exit(1);
    });
    axum::serve(listener, app).await.unwrap_or_else(|e| {
        log::error!("server error: {e}");
        std::process::exit(1);
    });
}
