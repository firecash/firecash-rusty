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
use kaspa_rpc_core::{RpcHash, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::FrontierState;
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::build_wallet_payment;
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
/// Max `get_blocks` pages a wallet advances per sync chunk. Kept small so the
/// per-wallet lock is released frequently (status stays responsive); speed comes
/// from looping back immediately instead of the old 1s pause between chunks.
const PAGES_PER_CHUNK: usize = 32;

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

/// Load a wallet's (seed, birthday) from disk, decrypting the seed with `secret`
/// when the file is encrypted.
fn load_wallet_meta(dir: &str, token: &str, secret: Option<&str>) -> Option<([u8; 32], u64)> {
    let bytes = std::fs::read(wallet_path(dir, token)).ok()?;
    let wf: WalletFile = serde_json::from_slice(&bytes).ok()?;
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
    Some((seed, wf.birthday))
}

fn wallet_exists(dir: &str, token: &str) -> bool {
    std::path::Path::new(&wallet_path(dir, token)).exists()
}

fn save_seed(dir: &str, token: &str, network: &str, seed: &[u8; 32], birthday: u64, secret: Option<&str>) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let (seed_hex, encrypted) = match secret {
        Some(s) => {
            let blob = encrypt_seed(seed, s).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            (hex(&blob), true)
        }
        None => (hex(seed), false),
    };
    let wf = WalletFile { version: 1, network: network.to_string(), seed_hex, encrypted, birthday };
    let path = wallet_path(dir, token);
    std::fs::write(&path, serde_json::to_vec_pretty(&wf).expect("serializes"))?;
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
const SCAN_VERSION: u8 = 1;
/// magic(4) + version(1) + genesis(32) + low(32) + scanned(8).
const SCAN_HEADER_LEN: usize = 77;
/// Rewrite the checkpoint after this many newly-scanned blocks (and once a wallet
/// first reaches the tip). Bounds work lost on a crash without writing the growing
/// blob on every tiny sync pass; a restart re-scans at most this many cheap blocks.
const CHECKPOINT_EVERY: usize = 5000;

/// Persist a wallet's scan checkpoint atomically (write-tmp + rename). `genesis` is
/// the pruning-point hash the scan is anchored to; a moved pruning point invalidates
/// the checkpoint on load (the note-commitment tree would no longer line up), forcing
/// a clean rescan.
fn save_checkpoint(dir: &str, token: &str, genesis: &RpcHash, low: &RpcHash, scanned: u64, db: &WalletDb) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(SCAN_HEADER_LEN + db.leaf_count() * 32);
    buf.extend_from_slice(SCAN_MAGIC);
    buf.push(SCAN_VERSION);
    buf.extend_from_slice(&genesis.as_bytes());
    buf.extend_from_slice(&low.as_bytes());
    buf.extend_from_slice(&scanned.to_le_bytes());
    buf.extend_from_slice(&db.to_checkpoint());
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

/// Load a wallet's scan checkpoint if present and still valid for `current_genesis`.
/// Returns the reconstructed `(db, low_cursor, scanned)`, or `None` on any
/// absence / corruption / version or pruning-point mismatch — the caller then falls
/// back to a birthday scan, so a stale checkpoint can never yield a wrong tree.
fn load_checkpoint(dir: &str, token: &str, seed: [u8; 32], current_genesis: &RpcHash) -> Option<(WalletDb, RpcHash, usize)> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || buf[4] != SCAN_VERSION {
        return None;
    }
    let saved_genesis = RpcHash::from_bytes(buf[5..37].try_into().ok()?);
    if saved_genesis != *current_genesis {
        return None; // chain pruned/relaunched past our anchor → rescan
    }
    let low = RpcHash::from_bytes(buf[37..69].try_into().ok()?);
    let scanned = u64::from_le_bytes(buf[69..77].try_into().ok()?) as usize;
    let db = WalletDb::from_checkpoint(seed, &buf[SCAN_HEADER_LEN..])?;
    Some((db, low, scanned))
}

// ---------------------------------------------------------------------------
// In-memory wallet + incremental sync
// ---------------------------------------------------------------------------

struct WalletEntry {
    seed: [u8; 32],
    db: WalletDb,
    genesis: RpcHash,
    /// Paging cursor: next `get_blocks` resumes from here.
    low: RpcHash,
    caught_up: bool,
    scanned: usize,
    chain_len: u64,
    updated_unix: u64,
    error: Option<String>,
    /// `scanned` at the last persisted checkpoint — the sync loop rewrites the
    /// checkpoint once enough new blocks accrue past this.
    saved_scanned: usize,
    /// Recent per-block **absolute** leaf counts (`db.size()` after each ingested
    /// block), oldest→newest, capped at [`MATURED_RING`]. `send` reads the entry
    /// `anchor_depth + 2` blocks back to root a spend at a matured anchor without a
    /// full-chain rescan. In-memory only (not part of the persisted checkpoint), so
    /// it is empty right after a load and refills as the sync loop advances; `send`
    /// falls back to a one-off matured replay until it covers the maturity depth.
    block_leaf_counts: VecDeque<u64>,
}

/// How many recent block→leaf boundaries [`WalletEntry`] keeps: enough to look back
/// `DEFAULT_ANCHOR_DEPTH + 2` blocks (the matured-anchor cutoff) with a small margin.
const MATURED_RING: usize = DEFAULT_ANCHOR_DEPTH as usize + 16;

impl WalletEntry {
    /// `start_low` is the block hash the display scan resumes from (genesis for a
    /// full scan, or the birthday-height block for a fast start). `base_scanned` is
    /// how many blocks that start skips, so progress reporting stays meaningful.
    fn new(seed: [u8; 32], genesis: RpcHash, start_low: RpcHash, base_scanned: usize) -> Option<Self> {
        Some(Self {
            seed,
            db: WalletDb::from_seed(seed)?,
            genesis,
            low: start_low,
            caught_up: false,
            scanned: base_scanned,
            chain_len: 0,
            updated_unix: 0,
            error: None,
            saved_scanned: base_scanned,
            block_leaf_counts: VecDeque::new(),
        })
    }

    /// Rebuild an entry from a persisted checkpoint: the commitment stream, owned
    /// notes, cursor and progress are restored, so the background sync resumes from
    /// `low` with no rescan. `saved_scanned == scanned` so the next checkpoint write
    /// waits for genuinely new blocks.
    fn from_checkpoint(seed: [u8; 32], db: WalletDb, genesis: RpcHash, low: RpcHash, scanned: usize) -> Self {
        Self {
            seed,
            db,
            genesis,
            low,
            caught_up: false,
            scanned,
            chain_len: 0,
            updated_unix: 0,
            error: None,
            saved_scanned: scanned,
            block_leaf_counts: VecDeque::new(),
        }
    }

    /// Advance this wallet by up to `PAGES_PER_CHUNK` pages of new blocks.
    async fn sync_chunk(&mut self, client: &GrpcClient) {
        for _ in 0..PAGES_PER_CHUNK {
            let resp = match client.get_blocks(Some(self.low), true, true).await {
                Ok(r) => r,
                Err(e) => {
                    self.error = Some(format!("get_blocks failed: {e}"));
                    return;
                }
            };
            let mut advanced = false;
            for (hash, block) in resp.block_hashes.iter().zip(resp.blocks.iter()) {
                if *hash == self.low || *hash == self.genesis {
                    continue;
                }
                ingest_rpc_block(&mut self.db, block);
                self.scanned += 1;
                advanced = true;
                // Record the block→leaf boundary so `send` can root a spend at a
                // matured anchor (a real block's tree root) without a rescan.
                self.block_leaf_counts.push_back(self.db.size());
                if self.block_leaf_counts.len() > MATURED_RING {
                    self.block_leaf_counts.pop_front();
                }
            }
            match resp.block_hashes.last().copied() {
                Some(h) if h != self.low && advanced => self.low = h,
                _ => {
                    self.caught_up = true;
                    break;
                }
            }
        }
        self.error = None;
        self.updated_unix = now_unix();
    }
}

fn ingest_rpc_block(db: &mut WalletDb, block: &kaspa_rpc_core::RpcBlock) {
    let mut coinbase_notes = Vec::new();
    if let Some(cb) = block.transactions.first() {
        if let Some(vd) = cb.verbose_data.as_ref() {
            let txid = vd.transaction_id;
            for (i, out) in cb.outputs.iter().enumerate() {
                let script = out.script_public_key.script();
                if script.len() >= ORCHARD_SCRIPT_LEN {
                    let mut recipient = [0u8; ORCHARD_SCRIPT_LEN];
                    recipient.copy_from_slice(&script[..ORCHARD_SCRIPT_LEN]);
                    let mut note_seed = Vec::with_capacity(36);
                    note_seed.extend_from_slice(&txid.as_bytes());
                    note_seed.extend_from_slice(&(i as u32).to_le_bytes());
                    coinbase_notes.push((derive_coinbase_note_desc(recipient, &note_seed), out.value));
                }
            }
        }
    }
    let mut bundles = Vec::new();
    for tx in block.transactions.iter().skip(1) {
        if tx.version == TX_VERSION_SHIELDED {
            if let Ok(b) = ShieldedBundle::from_bytes(&tx.payload) {
                bundles.push(b);
            }
        }
    }
    let bundle_refs: Vec<&ShieldedBundle> = bundles.iter().collect();
    db.ingest_block(&coinbase_notes, &bundle_refs);
}

/// One-off full replay up to `ingest_limit` blocks (used by send to root a spend to
/// a matured anchor, independent of the live tip db).
async fn scan_to_limit(client: &GrpcClient, seed: [u8; 32], ingest_limit: usize) -> Result<WalletDb, String> {
    let dag = client.get_block_dag_info().await.map_err(|e| format!("get_block_dag_info failed: {e}"))?;
    let genesis = dag.pruning_point_hash;
    let mut db = WalletDb::from_seed(seed).ok_or("seed is not a valid Orchard spending key")?;
    let mut low = genesis;
    let mut count = 0usize;
    loop {
        if count >= ingest_limit {
            break;
        }
        let resp = client.get_blocks(Some(low), true, true).await.map_err(|e| format!("get_blocks failed: {e}"))?;
        let mut advanced = false;
        for (hash, block) in resp.block_hashes.iter().zip(resp.blocks.iter()) {
            if *hash == low || *hash == genesis {
                continue;
            }
            if count >= ingest_limit {
                break;
            }
            ingest_rpc_block(&mut db, block);
            count += 1;
            advanced = true;
        }
        match resp.block_hashes.last().copied() {
            Some(h) if h != low && advanced => low = h,
            _ => break,
        }
    }
    Ok(db)
}

/// Resolve a wallet birthday (block height) to the block hash the scan should start
/// from, plus how many blocks that skips. `birthday == 0` means scan from genesis.
/// Falls back to genesis if the chain can't be walked.
async fn resolve_start(client: &GrpcClient, genesis: RpcHash, birthday: u64) -> (RpcHash, usize) {
    if birthday == 0 {
        return (genesis, 0);
    }
    match client.get_virtual_chain_from_block(genesis, false, None).await {
        Ok(chain) => {
            let hashes = chain.added_chain_block_hashes;
            if hashes.is_empty() {
                return (genesis, 0);
            }
            let idx = (birthday as usize).min(hashes.len()).saturating_sub(1);
            (hashes[idx], idx + 1)
        }
        Err(_) => (genesis, 0),
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
}

impl AppState {
    fn address_for(&self, seed: &[u8; 32]) -> Option<String> {
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
    async fn fast_sync_entry(&self, seed: [u8; 32], guard: RpcHash) -> Option<WalletEntry> {
        // Bound the checkpoint RPC: on a healthy chain it returns immediately, but the
        // node's finality-point walk can be pathologically slow on a degenerate DAG
        // (e.g. difficulty collapsed to the floor). Time it out and fall back to a full
        // scan rather than hanging the wallet.
        let cp = match tokio::time::timeout(std::time::Duration::from_secs(5), self.client.get_shielded_tree_state()).await {
            Ok(Ok(cp)) => cp,
            _ => return None,
        };
        let fs = FrontierState {
            size: cp.size,
            leaf: (cp.size > 0).then(|| cp.leaf.as_bytes()),
            ommers: cp.ommers.iter().map(|h| h.as_bytes()).collect(),
        };
        let db = WalletDb::from_frontier(seed, &fs)?;
        // genesis = `guard` (the pruning point) keeps the persisted checkpoint stable
        // across restarts (the finality-point base moves every block, so guarding on it
        // would drop notes on resume). low = the finality-point checkpoint block we
        // actually scan from; sync_chunk skips it. Progress is proxied by its DAA score
        // so status reads "near tip", not "scanning from 0".
        Some(WalletEntry::from_checkpoint(seed, db, guard, cp.block_hash, cp.daa_score as usize))
    }

    /// Fetch a loaded wallet for a token, loading it from disk on first use.
    async fn get_wallet(&self, token: &str) -> Option<Wallet> {
        {
            let map = self.wallets.lock().await;
            if let Some(w) = map.get(token) {
                return Some(w.clone());
            }
        }
        let (seed, birthday) = load_wallet_meta(&self.wallet_dir, token, self.wallet_secret.as_deref())?;
        let genesis = self.client.get_block_dag_info().await.ok()?.pruning_point_hash;
        // Resume from a persisted checkpoint when one is present and still anchored to
        // the current pruning point; otherwise do the (birthday-bounded) chain scan.
        let entry = match load_checkpoint(&self.wallet_dir, token, seed, &genesis) {
            Some((db, low, scanned)) => WalletEntry::from_checkpoint(seed, db, genesis, low, scanned),
            // No persisted checkpoint: fast-sync from the node's pruning-point frontier,
            // falling back to a full pruning-point-onward scan only if that RPC fails.
            None => match self.fast_sync_entry(seed, genesis).await {
                Some(e) => e,
                None => {
                    let (low, base) = resolve_start(&self.client, genesis, birthday).await;
                    WalletEntry::new(seed, genesis, low, base)?
                }
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
        if !wallets.is_empty() {
            let chain_len = state.client.get_block_dag_info().await.map(|d| d.virtual_daa_score).unwrap_or(0);
            for (token, w) in wallets {
                let mut e = w.lock().await;
                e.chain_len = chain_len;
                // Advance one chunk from `low` (also serves as the cheap tip catch-up
                // once already synced).
                let was_caught_up = e.caught_up;
                e.caught_up = false;
                e.sync_chunk(&state.client).await;
                if !e.caught_up {
                    any_behind = true;
                }
                // Persist a checkpoint once enough new blocks accrue, or the first time
                // this wallet reaches the tip, so a restart resumes here instead of
                // rescanning from birthday.
                let advanced = e.scanned.saturating_sub(e.saved_scanned);
                let just_caught_up = e.caught_up && !was_caught_up;
                if e.error.is_none() && (advanced >= CHECKPOINT_EVERY || (just_caught_up && advanced > 0)) {
                    if let Err(err) = save_checkpoint(&state.wallet_dir, &token, &e.genesis, &e.low, e.scanned as u64, &e.db) {
                        eprintln!("checkpoint write failed for {token}: {err}");
                    } else {
                        e.saved_scanned = e.scanned;
                    }
                }
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
    };

    if let Some(token) = token {
        if let Some(w) = state.get_wallet(&token).await {
            let e = w.lock().await;
            resp.has_wallet = true;
            resp.address = state.address_for(&e.seed);
            resp.synced = e.caught_up;
            resp.scanned_blocks = e.scanned;
            resp.chain_len = e.chain_len.max(daa_score);
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
        if let Some(addr) = state.address_for(&seed) {
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
    let address = state.address_for(&seed).ok_or_else(|| err(StatusCode::BAD_REQUEST, "seed is not a valid Orchard spending key"))?;
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
    let genesis = state
        .client
        .get_block_dag_info()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("get_block_dag_info failed: {e}")))?
        .pruning_point_hash;
    // Fast-sync from the node's pruning-point frontier (correct + O(blocks since
    // pruning)); fall back to a full pruning-point scan only if that RPC is absent.
    let entry = match state.fast_sync_entry(seed, genesis).await {
        Some(e) => e,
        None => {
            let (low, base) = resolve_start(&state.client, genesis, birthday).await;
            WalletEntry::new(seed, genesis, low, base).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad seed"))?
        }
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
    let address = state.address_for(&e.seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad seed"))?;
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
    let address = state.address_for(&e.seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad seed"))?;
    Ok(Json(RevealResp { address, seed_hex: hex(&e.seed), network: state.network.clone() }))
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
        synced: e.caught_up,
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
    txid: String,
    amount_sompi: u64,
    fee_sompi: u64,
}

async fn wallet_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let seed = { w.lock().await.seed };

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_FC as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    let fee = req.fee.unwrap_or(3_000_000);
    let anchor_depth = DEFAULT_ANCHOR_DEPTH;

    let client = &state.client;
    let dag =
        client.get_block_dag_info().await.map_err(|e| err(StatusCode::BAD_GATEWAY, format!("get_block_dag_info failed: {e}")))?;
    let net: [u8; 32] = dag.pruning_point_hash.as_bytes();

    let chain_len = dag.virtual_daa_score as usize;
    let need_len = anchor_depth as usize + 2;
    if chain_len <= need_len {
        return Err(err(
            StatusCode::CONFLICT,
            format!("chain too short ({chain_len} blocks): no note has matured past depth {anchor_depth} yet"),
        ));
    }
    let ingest_limit = chain_len - need_len;

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;
    // The matured cutoff: `anchor_depth + 2` blocks back from the tip (mirrors the
    // block count `scan_to_limit` would replay to).
    let need_back = need_len;

    let insufficient = |have: u64| {
        err(
            StatusCode::CONFLICT,
            format!("insufficient matured funds: have {have}, need amount+fee={need} (funds must be ~10 min old to spend)"),
        )
    };

    // Fast path: reuse the wallet state the sync loop already maintains, instead of
    // replaying the whole chain into a throwaway db. Root the spend at the leaf count
    // recorded `need_back` blocks back from the wallet's latest scanned block — always a
    // matured, canonical block root (a wallet that is behind the tip simply roots at an
    // even deeper anchor, still valid), which consensus accepts as a finalized anchor
    // (`is_shielded_anchor_final`). Selection + witness build run under the entry lock
    // (CPU-only, no await); the lock is dropped before the slow proof build below. We do
    // NOT gate on `caught_up` — on a fast chain that flag is rarely set, and the ring
    // anchor is valid regardless; `caught_up` is only used to decide whether an
    // insufficient result is authoritative (see the match below).
    let mut fast: Option<(Vec<_>, u64, bool)> = None;
    {
        let e = w.lock().await;
        if e.block_leaf_counts.len() > need_back {
            let matured = e.block_leaf_counts[e.block_leaf_counts.len() - 1 - need_back];
            let caught_up = e.caught_up;
            let mut candidates: Vec<_> = e.db.notes().iter().filter(|n| n.position < matured).collect();
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let mut ins = Vec::new();
            let mut selected = 0u64;
            for n in candidates {
                if selected >= need {
                    break;
                }
                let path =
                    e.db.witness_path_at(n.position, matured)
                        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                ins.push((n.note.clone(), path));
                selected += n.value();
            }
            fast = Some((ins, selected, caught_up));
        }
    }

    let inputs = match fast {
        // Enough matured funds at the wallet's own anchor — the fast, no-rescan path.
        Some((ins, selected, _)) if selected >= need => ins,
        // Not enough, but the wallet is caught up to the tip, so a full replay would see
        // the exact same matured notes: report insufficient without the slow scan.
        Some((_, selected, true)) => return Err(insufficient(selected)),
        // Either the ring has not reached the maturity depth yet (cold start, right after
        // a checkpoint load), or the wallet is still behind the tip and may be missing
        // recently-matured notes. Fall back to the one-off matured replay — correct, just
        // slow, and only transient until the sync loop catches up and fills the ring.
        _ => {
            log::warn!(
                "send: fast path unavailable/insufficient (ring or sync not caught up); falling back to full matured scan (slow, one-off)"
            );
            let db = scan_to_limit(client, seed, ingest_limit).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let mut candidates = db.notes().to_vec();
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let mut ins = Vec::new();
            let mut selected = 0u64;
            for n in &candidates {
                if selected >= need {
                    break;
                }
                let path = db
                    .witness_path(n.position)
                    .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                ins.push((n.note.clone(), path));
                selected += n.value();
            }
            if selected < need {
                return Err(insufficient(selected));
            }
            ins
        }
    };

    let ctx = payment_tx_context();
    log::info!("building Orchard payment proof (Halo 2) for {amount} sompi + {fee} fee...");
    let payload = build_wallet_payment(seed, inputs, recipient, amount, fee, &net, &ctx)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build payment: {e:?}")))?;

    let tx: Transaction = payment_tx(payload);
    match client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => Ok(Json(SendResp { txid: accepted.to_string(), amount_sompi: amount, fee_sompi: fee })),
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
    let seed = { w.lock().await.seed };
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

    let state = Arc::new(AppState {
        client,
        wallet_dir,
        prefix: prefix_from(&cli.network),
        network: cli.network,
        wallets: Mutex::new(HashMap::new()),
        allow_default_token: cli.allow_default_token,
        wallet_secret,
    });

    tokio::spawn(sync_loop(state.clone()));

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
        .route("/api/wallet/address", get(wallet_address))
        .route("/api/wallet/reveal", get(wallet_reveal))
        .route("/api/wallet/balance", get(wallet_balance))
        .route("/api/wallet/send", post(wallet_send))
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
