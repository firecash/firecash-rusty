//! `firecash-walletd` — a shielded wallet daemon for the FireCash network.
//!
//! It is the engine behind the FireCash web wallet. It drives the *same* shielded
//! primitives the CLI `shielded-pay` uses (`kaspa-shielded-core`): key generation,
//! chain scan with the wallet's viewing key, real Orchard (Halo 2) shielded spends,
//! and message sign/verify. Proofs are generated natively here (no in-browser Halo 2
//! needed) and submitted to a FireCash node over gRPC.
//!
//! ## Two deployment modes
//!
//! - **Self-hosted (non-custodial):** the user runs this on their own machine; the
//!   seed never leaves it. Point the web UI's daemon URL at `http://127.0.0.1:8501`.
//! - **Hosted (convenience hot-wallet):** one instance serves many browsers behind a
//!   reverse proxy, connected to a public FireCash node so users need no node of
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

use std::collections::{HashMap, VecDeque};
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
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::FrontierState;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::{PreparedPayment, build_wallet_payment, finalize_payment, prepare_payment, proving_key};
use kaspa_shielded_core::walletdb::WalletDb;
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// 1 FC = 10^8 sompi.
const SOMPI_PER_FC: u64 = 100_000_000;
/// Shielded output script length (raw Orchard address carried in a reward script).
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Anchor maturity depth (blocks) — must match consensus `shielded_anchor_depth`
/// (600 * BPS = 600 at 1 BPS, ~10 min). A note is spendable once this deep.
const DEFAULT_ANCHOR_DEPTH: u64 = 600;
/// Max `GetShieldedBlocks` pages a wallet advances per sync chunk. Kept small so
/// the per-wallet lock is released frequently (status stays responsive); speed
/// comes from looping back immediately instead of pausing between chunks.
const PAGES_PER_CHUNK: usize = 16;
/// Chain blocks requested per `GetShieldedBlocks` page.
const SHIELDED_PAGE: u64 = 200;
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
#[command(name = "firecash-walletd", about = "FireCash shielded wallet daemon (self-hosted or hosted)")]
struct Cli {
    /// FireCash node gRPC endpoint (host:port). In hosted mode, a public node.
    #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
    rpc_server: String,
    /// Address:port to serve the wallet REST API on. Loopback by default.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8501")]
    listen: String,
    /// Directory holding one wallet file per token. Default: ~/.firecash/wallets.
    #[arg(long)]
    wallet_dir: Option<String>,
    /// Network: mainnet | testnet | devnet | simnet.
    #[arg(long, default_value = "mainnet")]
    network: String,
    /// Permit binding a non-loopback address directly (prefer a TLS proxy instead).
    #[arg(long, default_value_t = false)]
    allow_remote: bool,
    /// Browser origin allowed to call the wallet API via CORS (repeatable, e.g.
    /// `--allow-origin https://wallet.firecash.info`). With none given, cross-origin
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
    /// key). May also be set via the `FIRECASH_WALLET_SECRET` env var. If unset, seeds
    /// are stored in plaintext (0600 on unix) and a warning is logged at startup.
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
            log::error!("wallet '{token}' is encrypted but no --wallet-secret / FIRECASH_WALLET_SECRET is set");
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
const CHECKPOINT_EVERY: usize = 5000;

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
    let db = key.db_from_checkpoint(take(&mut pos, db_len)?)?;
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

struct PageCache {
    map: HashMap<RpcHash, (std::time::Instant, Arc<kaspa_rpc_core::GetShieldedBlocksResponse>)>,
    order: VecDeque<RpcHash>,
}

const PAGE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);
const PAGE_CACHE_CAP: usize = 64;

impl PageCache {
    fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new() }
    }
}

/// Fetch one `GetShieldedBlocks` page through the shared cache.
async fn fetch_shielded_page(
    client: &GrpcClient,
    cache: &Mutex<PageCache>,
    low: RpcHash,
) -> Result<Arc<kaspa_rpc_core::GetShieldedBlocksResponse>, kaspa_rpc_core::RpcError> {
    {
        let c = cache.lock().await;
        if let Some((at, resp)) = c.map.get(&low) {
            if at.elapsed() < PAGE_CACHE_TTL {
                return Ok(resp.clone());
            }
        }
    }
    let resp = Arc::new(client.get_shielded_blocks(low, SHIELDED_PAGE).await?);
    let mut c = cache.lock().await;
    c.map.insert(low, (std::time::Instant::now(), resp.clone()));
    c.order.push_back(low);
    if c.order.len() > PAGE_CACHE_CAP {
        if let Some(old) = c.order.pop_front() {
            c.map.remove(&old);
        }
    }
    Ok(resp)
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
        }
    }

    /// Advance this wallet by up to `PAGES_PER_CHUNK` pages of new **chain**
    /// blocks, ingesting exactly the shielded effects consensus applied per block
    /// (own coinbase mint + accepted post-retain bundles, consensus order), and
    /// only once a block is `SYNC_TIP_MARGIN` blue units below the sink (the
    /// append-only tree must not ingest anything a routine reorg could replace).
    async fn sync_chunk(&mut self, client: &GrpcClient, cache: &Mutex<PageCache>) {
        for _ in 0..PAGES_PER_CHUNK {
            let resp = match fetch_shielded_page(client, cache, self.low).await {
                Ok(r) => r,
                Err(e) => {
                    // Distinguish "cursor no longer known" (pruned / relaunched —
                    // needs a rescan) from a transient node failure.
                    if client.get_block(self.low, false).await.is_err() && client.get_block_dag_info().await.is_ok() {
                        self.reorged_strikes = REORG_STRIKES;
                        self.error = Some("wallet cursor no longer known to the node; rescanning".into());
                    } else {
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
            let mut advanced = false;
            let mut at_margin = false;
            for b in &resp.blocks {
                if b.blue_score > settled {
                    at_margin = true;
                    break;
                }
                ingest_shielded_chain_block(&mut self.db, b);
                self.low = b.hash;
                self.scanned = b.daa_score as usize;
                self.boundaries.push_back((b.blue_score, self.db.size()));
                if self.boundaries.len() > MATURED_RING {
                    self.boundaries.pop_front();
                }
                advanced = true;
            }
            if !advanced || at_margin {
                self.caught_up = true;
                break;
            }
        }
        // Keep every spendable note's Merkle witness advanced to the anchor a spend will
        // actually root at, here in the background — so pressing Send costs a lookup, not
        // a full Sinsemilla replay of the chain (measured: 21s per note, and a send needs
        // one per input note).
        self.advance_spend_witnesses();
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
    /// One shared gRPC connection to the node, reused by every request and the sync
    /// loop. Opening a fresh connection per request (as before) exhausted the node's
    /// connection budget under polling and surfaced as spurious "node offline".
    client: GrpcClient,
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
    /// In-flight **non-custodial** payments: a `/api/wallet/prepare` builds the proof
    /// from a viewing key and parks the awaiting-signature bundle here, keyed by a
    /// random session id; `/api/wallet/submit` pops it, applies the device's spend-auth
    /// signatures, and broadcasts. Held in memory only — a restart drops pending
    /// sessions (the device just re-prepares). The seed is never involved.
    prepared: Mutex<HashMap<String, PreparedSession>>,
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
        let fs = FrontierState {
            size: cp.size,
            leaf: (cp.size > 0).then(|| cp.leaf.as_bytes()),
            ommers: cp.ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = key.db_from_frontier(&fs)?;
        // low = the checkpoint chain block; sync resumes strictly after it.
        // Progress is proxied by its DAA score so status reads "near tip".
        Some(WalletEntry::from_parts(key, db, guard, cp.block_hash, cp.daa_score as usize, VecDeque::new(), 0))
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

    /// Fetch a loaded wallet for a token, loading it from disk on first use.
    async fn get_wallet(&self, token: &str) -> Option<Wallet> {
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
        let entry = match load_checkpoint(&self.wallet_dir, token, key, &genesis) {
            Some((db, low, scanned, boundaries, sink_blue)) => {
                WalletEntry::from_parts(key, db, genesis, low, scanned, boundaries, sink_blue)
            }
            None => match self.fast_sync_entry(key, genesis, birthday).await {
                Some(e) => e,
                None => self.full_scan_entry(key, genesis).await?,
            },
        };
        let w = Arc::new(Mutex::new(entry));
        self.wallets.lock().await.insert(token.to_string(), w.clone());
        Some(w)
    }
}

// ---------------------------------------------------------------------------
// Background sync: advance every loaded wallet a bounded chunk each pass.
// ---------------------------------------------------------------------------

async fn sync_loop(state: Arc<AppState>) {
    loop {
        let wallets: Vec<(String, Wallet)> = { state.wallets.lock().await.iter().map(|(k, v)| (k.clone(), v.clone())).collect() };
        let mut any_behind = false;
        let mut reorged_tokens: Vec<String> = Vec::new();
        if !wallets.is_empty() {
            let chain_len = state.client.get_block_dag_info().await.map(|d| d.virtual_daa_score).unwrap_or(0);
            for (token, w) in wallets {
                let mut e = w.lock().await;
                e.chain_len = chain_len;
                // Advance one chunk from `low` (also serves as the cheap tip catch-up
                // once already synced).
                let was_caught_up = e.caught_up;
                e.caught_up = false;
                e.sync_chunk(&state.client, &state.page_cache).await;
                if e.reorged_strikes >= REORG_STRIKES {
                    // The append-only tree cannot roll back a deep reorg: discard
                    // the checkpoint and evict the wallet; the next request reloads
                    // it cleanly (fast-sync or full scan).
                    log::warn!("wallet '{token}': deep reorg below cursor — discarding checkpoint and rescanning");
                    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
                    reorged_tokens.push(token.clone());
                    continue;
                }
                if e.reorged_strikes > 0 {
                    any_behind = true;
                    continue;
                }
                if !e.caught_up {
                    any_behind = true;
                }
                // Persist a checkpoint once enough new blocks accrue, or the first time
                // this wallet reaches the tip, so a restart resumes here instead of
                // rescanning from birthday.
                let advanced = e.scanned.saturating_sub(e.saved_scanned);
                let just_caught_up = e.caught_up && !was_caught_up;
                if e.error.is_none() && (advanced >= CHECKPOINT_EVERY || (just_caught_up && advanced > 0)) {
                    if let Err(err) = save_checkpoint(
                        &state.wallet_dir,
                        &token,
                        &e.genesis,
                        &e.low,
                        e.scanned as u64,
                        &e.db,
                        &e.boundaries,
                        e.sink_blue,
                    ) {
                        eprintln!("checkpoint write failed for {token}: {err}");
                    } else {
                        e.saved_scanned = e.scanned;
                    }
                }
            }
        }
        if !reorged_tokens.is_empty() {
            let mut map = state.wallets.lock().await;
            for t in reorged_tokens {
                map.remove(&t);
            }
        }
        // While catching up a big initial scan, loop back immediately (only a
        // tiny yield so status calls can grab the lock); idle slowly once synced.
        if any_behind {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(12)).await;
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
    let whole = sompi / SOMPI_PER_FC as u128;
    let frac = sompi % SOMPI_PER_FC as u128;
    format!("{whole}.{frac:08}")
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "firecash-walletd" }))
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
    let (node_connected, daa_score) = match state.client.get_block_dag_info().await {
        Ok(d) => (true, d.virtual_daa_score),
        Err(_) => (false, 0),
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
        note_count: 0,
        updated_unix: 0,
        error: None,
        watch_only: false,
    };

    if let Some(token) = token {
        if let Some(w) = state.get_wallet(&token).await {
            let e = w.lock().await;
            resp.has_wallet = true;
            resp.address = Some(state.address_of(&e.db));
            resp.watch_only = e.key.is_watch_only();
            let tip = e.chain_len.max(daa_score);
            resp.synced = e.caught_up || (e.scanned as u64) + SYNC_MARGIN >= tip;
            resp.scanned_blocks = e.scanned;
            resp.chain_len = tip;
            resp.balance_sompi = e.db.balance().to_string();
            resp.balance_fc = fmt_fc(e.db.balance());
            resp.note_count = e.db.notes().len();
            resp.updated_unix = e.updated_unix;
            resp.error = e.error.clone();
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
        (None, Some(fc)) => (fc * SOMPI_PER_FC as f64).round() as u64,
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
// The device signs each with `ask.randomize(alpha)` (e.g. via firecash-signer) and
// posts the signatures to `/submit`, which applies them and broadcasts. A server
// compromise can see balances but CANNOT move funds — it never holds spend authority.
// The crypto split is proven in shielded-core (`non_custodial_payment_api_roundtrip`).
// ===========================================================================

#[derive(Deserialize)]
struct PrepareReq {
    /// 96-byte full viewing key (hex). Grants viewing capability, not spend.
    fvk_hex: String,
    /// Recipient `firecash:` shielded address.
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
}

async fn wallet_prepare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PrepareReq>,
) -> Result<Json<PrepareResp>, (StatusCode, Json<serde_json::Value>)> {
    use rand::RngCore;

    // Watch-only: authenticated by possession of the FVK, not a token/seed.
    let fvk_bytes = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_FC as f64).round() as u64,
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
                e.advance_spend_witnesses();
                let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
                if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
                    let mut candidates: Vec<_> = e.db.notes().iter().filter(|n| n.position < matured).collect();
                    candidates.sort_by(|a, b| b.value().cmp(&a.value()));
                    have_total = Some(candidates.iter().map(|n| n.value()).sum());
                    for n in &candidates {
                        if selected >= need || inputs.len() == max_per_tx {
                            break;
                        }
                        let path =
                            e.db.witness_path_at(n.position, matured)
                                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
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
    let payment = tokio::task::spawn_blocking(move || prepare_payment(&fvk, inputs, recipient, amount, fee, &net, &ctx))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to prepare payment: {e:?}")))?;

    let spend_auth: Vec<SpendAuthReq> =
        payment.spend_auth_requests.iter().map(|(i, alpha)| SpendAuthReq { index: *i, alpha: hex(alpha) }).collect();
    let sighash_hex = hex(&payment.sighash);
    let value_balance = payment.value_balance;

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

    Ok(Json(PrepareResp { session, sighash: sighash_hex, value_balance, amount_sompi: amount, fee_sompi: fee, spend_auth }))
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

#[tokio::main]
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

    // Open the single shared node connection up front; retry until the node is up.
    let client = loop {
        match GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{}", cli.rpc_server),
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
                log::warn!("node {} not reachable yet ({e}); retrying in 3s...", cli.rpc_server);
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    };
    log::info!("connected to node at {}", cli.rpc_server);

    // Seed-file encryption secret: CLI flag or FIRECASH_WALLET_SECRET env.
    let wallet_secret = cli.wallet_secret.or_else(|| std::env::var("FIRECASH_WALLET_SECRET").ok());
    if wallet_secret.is_none() {
        log::warn!("no --wallet-secret / FIRECASH_WALLET_SECRET set: seed files are stored in PLAINTEXT (0600 on unix)");
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
        wallet_dir,
        prefix: prefix_from(&cli.network),
        network: cli.network,
        wallets: Mutex::new(HashMap::new()),
        allow_default_token: cli.allow_default_token,
        wallet_secret,
        genesis,
        page_cache: Mutex::new(PageCache::new()),
        prepared: Mutex::new(HashMap::new()),
    });

    tokio::spawn(sync_loop(state.clone()));

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

    log::info!("firecash-walletd listening on http://{listen}");
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| {
        log::error!("failed to bind {listen}: {e}");
        std::process::exit(1);
    });
    axum::serve(listener, app).await.unwrap_or_else(|e| {
        log::error!("server error: {e}");
        std::process::exit(1);
    });
}
