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
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    routing::{get, post},
};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcHash, RpcShieldedChainBlock, RpcTransaction, api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::coinbase::CoinbaseNoteDesc;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{FVK_LEN, SIG_LEN, sign_message, verify_message};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::tree::{FrontierState, GlobalTree, NoteCommitmentTree};
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::wallet::build::{PreparedPayment, build_wallet_payment, finalize_payment, prepare_payment, proving_key};
use kaspa_shielded_core::walletdb::{BlockMeta, HistoryKind, OwnedNote, Preview, WalletDb};
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tokio::sync::Mutex;
use zkas_sdk::{
    ClaimedIntent as SdkClaimedIntent, Network as SdkNetwork, PreparedPayment as SdkPreparedPayment, PreparedPaymentEnvelope,
    SpendAuthRequest as SdkSpendAuthRequest,
};
use zkas_wallet_engine::{
    DEFAULT_FEE_SOMPI, chunk_fee, max_spends_per_tx, plan_payment, select_spend_count as engine_select_spend_count,
};

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

/// Compatibility seam while payment preparation moves into the engine. Inputs
/// have already been validated by the HTTP boundary; an arithmetic failure is
/// represented as no selectable notes and becomes the existing conflict error.
fn select_spend_count(values: &[u64], amount: u64, base_fee: u64, max_per: usize) -> (usize, u64) {
    engine_select_spend_count(values, amount, base_fee, max_per).unwrap_or((0, chunk_fee(base_fee, 1)))
}

/// Runtime configuration for the wallet daemon — the library entry point's input.
/// The CLI binary builds this from flags; the desktop app builds it directly.
///
/// Policy note: the CLI refuses non-loopback binds without `--allow-remote`; that
/// check lives in the binary, so an embedding caller owns its own bind policy.
pub struct Config {
    /// ZKas node gRPC endpoint (host:port).
    pub rpc_server: String,
    /// Address:port to serve the wallet REST API on.
    pub listen: SocketAddr,
    /// Directory holding one wallet file per token.
    pub wallet_dir: String,
    /// Network: mainnet | testnet | devnet | simnet.
    pub network: String,
    /// Browser origins allowed via CORS; empty = same-origin only.
    pub allow_origin: Vec<String>,
    /// Permit the tokenless "default" wallet (trusted single-user localhost only).
    pub allow_default_token: bool,
    /// Secret encrypting wallet seed files at rest; None = plaintext (0600) + warning.
    pub wallet_secret: Option<String>,
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
    /// Transaction history, **opt-in**: when on, ingest records readable history
    /// rows in the scan checkpoint AND each send's details are encrypted to the
    /// wallet's own OVK (Zcash-standard), so history recovers recipient/amount/
    /// memo even after a seed restore. Trade-offs the user accepts by enabling:
    /// anyone holding this wallet's file/token reads the record, and someone the
    /// user hands the FULL VIEWING KEY to (message-sign verification!) also sees
    /// outgoing recipients. Default off — nothing readable is stored until the
    /// user activates it.
    #[serde(default)]
    recoverable_history: bool,
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

    /// The 96-byte Orchard full viewing key this wallet watches with — the identity
    /// two registrations of the same wallet share, whatever form (seed or FVK) the
    /// key material arrived in. Everything in a scan checkpoint is derivable from
    /// this key plus the public chain, which is what makes checkpoint adoption
    /// (see [`adopt_twin_checkpoint`]) sound.
    fn fvk_bytes(&self) -> Option<[u8; 96]> {
        self.empty_db().map(|db| db.fvk().to_bytes())
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
fn load_wallet_meta(dir: &str, token: &str, secret: Option<&str>) -> Option<(WalletKey, u64, bool)> {
    let bytes = std::fs::read(wallet_path(dir, token)).ok()?;
    let wf: WalletFile = serde_json::from_slice(&bytes).ok()?;
    if !wf.fvk_hex.is_empty() {
        let fvk = unhex(&wf.fvk_hex).and_then(|b| <[u8; 96]>::try_from(b.as_slice()).ok())?;
        return Some((WalletKey::Fvk(fvk), wf.birthday, wf.recoverable_history));
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
    Some((WalletKey::Seed(seed), wf.birthday, wf.recoverable_history))
}

/// How a wallet file on disk is protected — what an embedding shell (the desktop
/// app) must know before it can decide between "ask for a new passphrase",
/// "ask to unlock", and "offer to encrypt what is already here".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultState {
    /// No wallet yet: the next step is creating one under a fresh passphrase.
    Missing,
    /// A wallet exists with its seed in CLEARTEXT (a daemon run without a
    /// secret, or a wallet from before passphrases). Anyone who reads the file
    /// holds the funds — it should be encrypted in place.
    Plaintext,
    /// Seed encrypted at rest; a passphrase is required to load it.
    Encrypted,
    /// Watch-only: no seed on this machine, so there is nothing to encrypt.
    WatchOnly,
}

/// Inspect a wallet file's protection ([`VaultState`]) without decrypting it.
pub fn vault_state(dir: &str, token: &str) -> VaultState {
    let Ok(bytes) = std::fs::read(wallet_path(dir, token)) else { return VaultState::Missing };
    let Ok(wf) = serde_json::from_slice::<WalletFile>(&bytes) else { return VaultState::Missing };
    if !wf.fvk_hex.is_empty() {
        VaultState::WatchOnly
    } else if wf.encrypted {
        VaultState::Encrypted
    } else {
        VaultState::Plaintext
    }
}

/// Check a passphrase against an encrypted wallet **without** starting a daemon
/// or loading the wallet — the unlock screen's verification step. `true` for a
/// wallet that needs no passphrase (plaintext or watch-only), so a caller can
/// treat "unlocked" uniformly.
pub fn verify_wallet_secret(dir: &str, token: &str, secret: &str) -> bool {
    match vault_state(dir, token) {
        VaultState::Missing => false,
        VaultState::Plaintext | VaultState::WatchOnly => true,
        VaultState::Encrypted => load_wallet_meta(dir, token, Some(secret)).is_some(),
    }
}

/// Encrypt an existing cleartext wallet in place under `secret`, so a wallet
/// created before passphrases (or by a secretless daemon) gains protection
/// without the user re-importing a seed. Writes via the same 0600 path as
/// creation. No-op for an already-encrypted or watch-only wallet.
///
/// The rewrite is atomic in the sense that matters: the new file is only
/// written after the seed has been successfully re-encrypted, so a failure
/// leaves the original readable wallet intact rather than a corpse the user
/// cannot open.
pub fn encrypt_wallet_in_place(dir: &str, token: &str, secret: &str) -> Result<(), String> {
    match vault_state(dir, token) {
        VaultState::Missing => return Err("no wallet to encrypt".into()),
        VaultState::Encrypted | VaultState::WatchOnly => return Ok(()),
        VaultState::Plaintext => {}
    }
    let bytes = std::fs::read(wallet_path(dir, token)).map_err(|e| format!("read wallet: {e}"))?;
    let mut wf: WalletFile = serde_json::from_slice(&bytes).map_err(|e| format!("parse wallet: {e}"))?;
    let seed = unhex(&wf.seed_hex)
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| "wallet seed is not 32 bytes".to_string())?;
    let blob = encrypt_seed(&seed, secret)?;
    wf.seed_hex = hex(&blob);
    wf.encrypted = true;
    write_wallet_file(dir, token, &wf).map_err(|e| format!("write wallet: {e}"))
}

/// A portable, self-contained wallet backup: the seed encrypted under a
/// passphrase of the user's choosing, plus the little bit of metadata a restore
/// needs. Safe to keep on a USB stick, in cloud storage, or in a password
/// manager — without the passphrase it is 32 bytes of noise.
///
/// Deliberately NOT a copy of the on-disk wallet file: the backup carries its
/// own salt/nonce and its own passphrase, so exporting cannot leak anything
/// about the device passphrase, and a user can hand a backup to a restore on
/// another machine without reusing the daily unlock secret.
#[derive(Serialize, Deserialize)]
pub struct WalletBackup {
    /// Fixed marker so a restore can reject an unrelated JSON file with a clear
    /// message instead of a decryption error.
    pub magic: String,
    pub version: u32,
    pub network: String,
    /// Wallet birthday, so a restore syncs from there instead of genesis.
    pub birthday: u64,
    /// `salt(16) || nonce(24) || ciphertext` — see [`encrypt_seed`].
    pub encrypted_seed_hex: String,
    pub created_unix: u64,
}

const BACKUP_MAGIC: &str = "zkas-wallet-backup";
const BACKUP_VERSION: u32 = 1;

/// Produce an encrypted backup of `token`'s seed under `backup_secret`.
///
/// `wallet_secret` is the device passphrase, needed only to read the seed that
/// is being backed up (`None` for a legacy cleartext wallet). Watch-only
/// wallets have no seed and are refused — backing one up would produce a file
/// that cannot restore spending ability, which is worse than no backup because
/// the user would believe they were covered.
pub fn export_backup(dir: &str, token: &str, wallet_secret: Option<&str>, backup_secret: &str) -> Result<String, String> {
    if backup_secret.chars().count() < 8 {
        return Err("backup passphrase must be at least 8 characters".into());
    }
    let bytes = std::fs::read(wallet_path(dir, token)).map_err(|_| "no wallet on this device".to_string())?;
    let wf: WalletFile = serde_json::from_slice(&bytes).map_err(|e| format!("parse wallet: {e}"))?;
    if !wf.fvk_hex.is_empty() {
        return Err("this is a watch-only wallet — it holds no seed to back up".into());
    }
    let (key, birthday, _) = load_wallet_meta(dir, token, wallet_secret).ok_or("cannot read the wallet seed (wrong passphrase?)")?;
    let seed = match key {
        WalletKey::Seed(s) => s,
        WalletKey::Fvk(_) => return Err("this is a watch-only wallet — it holds no seed to back up".into()),
    };
    let blob = encrypt_seed(&seed, backup_secret)?;
    let backup = WalletBackup {
        magic: BACKUP_MAGIC.into(),
        version: BACKUP_VERSION,
        network: wf.network,
        birthday,
        encrypted_seed_hex: hex(&blob),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    serde_json::to_string_pretty(&backup).map_err(|e| format!("serialize backup: {e}"))
}

/// Restore a wallet from an [`export_backup`] file: decrypt with
/// `backup_secret`, then write it as `token`'s wallet encrypted under
/// `wallet_secret` (the device passphrase from here on).
///
/// Refuses to clobber an existing wallet — restoring over a live wallet whose
/// seed the user has not backed up would destroy funds. Any stale scan
/// checkpoint is dropped so the restored wallet rescans from its birthday
/// rather than resuming a different wallet's stream.
pub fn import_backup(dir: &str, token: &str, json: &str, backup_secret: &str, wallet_secret: &str) -> Result<(), String> {
    if wallet_secret.chars().count() < 8 {
        return Err("passphrase must be at least 8 characters".into());
    }
    let backup: WalletBackup = serde_json::from_str(json).map_err(|_| "not a ZKas wallet backup file".to_string())?;
    if backup.magic != BACKUP_MAGIC {
        return Err("not a ZKas wallet backup file".into());
    }
    if backup.version > BACKUP_VERSION {
        return Err(format!("this backup was written by a newer wallet (format v{}) — update the app", backup.version));
    }
    if wallet_exists(dir, token) {
        return Err("a wallet already exists on this device; remove it before restoring".into());
    }
    let blob = unhex(&backup.encrypted_seed_hex).ok_or("backup is corrupt (bad seed field)")?;
    let seed = decrypt_seed(&blob, backup_secret).map_err(|_| "wrong backup passphrase".to_string())?;
    save_seed(dir, token, &backup.network, &seed, backup.birthday, Some(wallet_secret))
        .map_err(|e| format!("write wallet: {e}"))?;
    let _ = std::fs::remove_file(scan_path(dir, token));
    Ok(())
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
    let wf = WalletFile {
        version: 1,
        network: network.to_string(),
        seed_hex,
        encrypted,
        birthday,
        fvk_hex: String::new(),
        // History is opt-in: nothing readable is recorded until the user
        // explicitly enables it (accepting that anyone holding the wallet
        // file / server token could read the record).
        recoverable_history: false,
    };
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
        // Opt-in, same as the seed path above.
        recoverable_history: false,
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
const SCAN_VERSION: u8 = 4;
/// v3 checkpoints (no `blind_below` trailer) still load — the field defaults to 0.
const SCAN_VERSION_PREV: u8 = 3;
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
const WITNESS_ADVANCE_BUDGET: u64 = 400_000;
/// Floor on the per-pass leaf cap, so even a huge wallet still makes some progress.
const WITNESS_MIN_STEP: u64 = 32;

/// Leaves the background compaction rolls the fast-sync base forward per step. Each step
/// costs O(step) Sinsemilla work (it rebuilds the frontier at the new base), so it is
/// bounded like the witness step; a full-scan wallet's base climbs to its own notes over a
/// couple of minutes of throttled passes, after which every spend replays only the few
/// thousand leaves above the notes instead of the whole chain. See
/// [`WalletDb::advance_base_capped`].
const BASE_ADVANCE_STEP: u64 = 8192;

/// Leaves per step for the ONE-TIME cold warm (base roll + witness build) of a freshly
/// loaded / full-scan wallet. Larger than the steady step so the ~30–90 s one-time build
/// converges in a handful of passes instead of crawling for minutes while the user keeps
/// hitting a COLD send. Each step is one `block_in_place`, so it holds the wallet lock for
/// ~a few seconds at a time (status calls for that one wallet wait briefly); it runs at
/// most once per wallet load, then `witnesses_warm` latches and only the cheap incremental
/// step runs.
const COLD_WARM_STEP: u64 = 16384;

/// Per-step WORK budget (≈ leaves × witnesses) for the cold warm. Dividing the leaf step
/// by the note count keeps a 32-note wallet's step as cheap as a 1-note wallet's, so no
/// single wallet monopolises a warm slot and starves the interactive few-note wallets.
const COLD_WARM_BUDGET: u64 = 32768;

/// Wall-clock the cold warm may spend per sync tick, running back-to-back steps.
///
/// One step is ~5.7 s of work, but the sync loop only reached this branch about once
/// every 47 s — a ~12 % duty cycle, so a wallet needing ~4.4 min of CPU took the better
/// part of an hour, and every restart lost ground. The total work is unchanged; this
/// just stops it being spread so thin that it never finishes. The wallet lock is held
/// for a step at a time, so that wallet's own status calls wait briefly during its
/// one-time warm — worth it to have sends stop costing 20 s per note.
/// Kept short deliberately. The warm holds the wallet lock and a sync slot for its whole
/// tick, so a long tick starves every other wallet's ordinary sync — a 1-note wallet was
/// observed stuck at "syncing 97%" while the note-heavy backlog warmed. Short ticks cost
/// slightly more overhead but interleave, so warming stays a background task instead of
/// monopolising the box.
const COLD_WARM_TICK: std::time::Duration = std::time::Duration::from_secs(4);

/// Above this many notes a wallet keeps only a *bounded* witness set rather than one per
/// note — witnessing them all costs leaves × notes and would hog the shared loop for
/// minutes. These are pool/treasury/miner wallets.
///
/// This used to disable witnessing for such a wallet **entirely**, on the reasoning that
/// they rarely spend and the few notes a send selects could rebuild on demand. That was
/// wrong in a way that only shows up at scale: the rebuild is a base→matured Sinsemilla
/// replay whose length is the gap between the wallet's oldest unspent note and the matured
/// tip, and `advance_base_capped` cannot roll the base past that oldest note — so the gap
/// grows with the chain, forever. On the live miner wallet it reached ~117 K leaves ≈ 20 s
/// *per selected note*, making a 6-note send take two minutes and getting worse daily.
/// Bounding the witness *set* keeps the cost `leaves × budget` (a constant) instead of
/// `leaves × notes`, so these wallets stay warm like any other.
const EAGER_WARM_MAX_NOTES: u64 = 32;

/// Witness slots kept for a note-heavy wallet. Enough to cover a full standard
/// transaction's spends (`max_spends_per_tx()` = 6) with slack, so the value-descending
/// selection a send makes lands on warm notes — but a small constant, so the one-time
/// catch-up is bounded regardless of how many thousands of notes the wallet holds.
const SPENDABLE_WITNESS_BUDGET: usize = 12;

/// Longest witness climb a note-heavy (never-eager-warmed) wallet may do inline at
/// send time. Each climbed leaf costs one Sinsemilla append per live witness (up to
/// 256, ~15 ms/leaf worst case), so 512 leaves ≈ ≤8 s — and at 1 BPS it comfortably
/// covers the gap since the wallet's last spend. Anything longer is skipped: the few
/// selected notes rebuild on demand instead, which is witness-count-free.
const SPEND_CLIMB_INLINE_MAX: u64 = 512;

/// Minimum wall-clock gap between two background witness pre-advance steps for the SAME
/// wallet. The sync loop spins as fast as every 10 ms while any wallet is behind, so
/// without this a caught-up wallet would fire a `WITNESS_ADVANCE_BUDGET` step ~100×/s and
/// pin every core. One step per second caps the steady witness work to ~`BUDGET` hashes/s
/// per wallet: a cold miner wallet (≈491 K leaves) warms in ~2–3 min at low CPU, then the
/// step drops to ~1 leaf/block and idles. See [`WalletEntry::last_witness_advance`].
const WITNESS_ADVANCE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1000);

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

/// How many wallets may be in their one-time COLD WARM at once.
///
/// Warming is the only sync work that runs flat out for whole seconds at a time
/// (`COLD_WARM_TICK`), so without a cap of its own every [`SYNC_CONCURRENCY`] slot can be
/// occupied by one, pinning a core each. On the live 4-core host that left one core for
/// the HTTP handlers, the node RPC and Halo 2 proving combined — so one user's first send
/// visibly slowed everyone else's sync. Ordinary incremental sync is unaffected by this
/// cap; only the heavy catch-up queues behind it.
const WARM_CONCURRENCY: usize = 1;

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
    blind_below: u64,
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
    buf.extend_from_slice(&blind_below.to_le_bytes());
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
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || !matches!(buf[4], SCAN_VERSION | SCAN_VERSION_PREV) {
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
) -> Option<(WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64, u64)> {
    let buf = std::fs::read(scan_path(dir, token)).ok()?;
    let (saved_genesis, rest) = parse_scan_bytes(&buf, key, tip)?;
    if saved_genesis != *current_genesis {
        return None; // chain relaunched → rescan
    }
    Some(rest)
}

/// Parse one scan-file blob into `(genesis, (db, low, scanned, boundaries,
/// sink_blue, blind_below))`. Factored out of [`load_checkpoint`] so the offline
/// admin tooling (`--diagnose`, `--graft`) can read snapshots at arbitrary paths
/// with exactly the daemon's own parser.
#[allow(clippy::type_complexity)]
fn parse_scan_bytes(
    buf: &[u8],
    key: WalletKey,
    tip: Option<&kaspa_shielded_core::tree::FrontierState>,
) -> Option<(RpcHash, (WalletDb, RpcHash, usize, VecDeque<(u64, u64)>, u64, u64))> {
    if buf.len() < SCAN_HEADER_LEN || &buf[0..4] != SCAN_MAGIC || !matches!(buf[4], SCAN_VERSION | SCAN_VERSION_PREV) {
        return None;
    }
    let saved_genesis = RpcHash::from_bytes(buf[5..37].try_into().ok()?);
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
    // A syntactically valid checkpoint is not necessarily a canonical one. Older
    // walletd versions could ingest ordinary-accepted shielded bundles whose state
    // transition was actually dropped, leaving a plausible but divergent tree.
    // Bind every restored checkpoint to the node's frontier at its exact cursor.
    if let Some(fs) = tip {
        let expected = GlobalTree::from_state(fs).ok()?.anchor().to_bytes();
        if db.size() != fs.size || db.anchor() != expected {
            log::warn!(
                "rejecting divergent wallet checkpoint at cursor {low}: wallet size/root {}/{}, node size/root {}/{}",
                db.size(),
                hex(&db.anchor()),
                fs.size,
                hex(&expected),
            );
            return None;
        }
    }
    let ring_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    let mut boundaries = VecDeque::with_capacity(ring_len.min(MATURED_RING));
    for _ in 0..ring_len {
        let blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        let leaves = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
        boundaries.push_back((blue, leaves));
    }
    let sink_blue = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    // v4 trailer: the frontier size this view was anchored on while the wallet may
    // hold OLDER notes it cannot see (0 = complete view). v3 files predate it.
    let blind_below = if buf[4] == SCAN_VERSION { u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?) } else { 0 };
    if pos != buf.len() {
        return None;
    }
    Some((saved_genesis, (db, low, scanned, boundaries, sink_blue, blind_below)))
}

// ---------------------------------------------------------------------------
// Twin-checkpoint adoption: "enter the seed on a second device → synced at once".
//
// A scan checkpoint is a pure function of (full viewing key, public chain): the
// notes, positions, witnesses and cursor in it are exactly what ANY scan with
// that key would produce. So when a seed/FVK is registered under a fresh token
// and some other token on this daemon has already scanned the same key, cloning
// that token's checkpoint hands the new registration a fully synced wallet —
// and hands it nothing the presented key couldn't derive by scanning, so the
// fast path is security-neutral. Spend authority is not involved at all.
// ---------------------------------------------------------------------------

/// The `blind_below` trailer of a checkpoint file, read without the wallet key
/// (the full body needs one; the trailer is plain). `0` = the view is complete.
fn checkpoint_blind_below(path: &str) -> Option<u64> {
    let buf = std::fs::read(path).ok()?;
    if buf.len() < SCAN_HEADER_LEN + 8 || &buf[0..4] != SCAN_MAGIC {
        return None;
    }
    match buf[4] {
        SCAN_VERSION => Some(u64::from_le_bytes(buf[buf.len() - 8..].try_into().ok()?)),
        SCAN_VERSION_PREV => Some(0), // v3 predates fast-sync blindness — always a full view
        _ => None,
    }
}

/// Find another token in `dir` holding the SAME full viewing key with a resumable
/// checkpoint for `genesis`, and clone that checkpoint for `token`. Returns the
/// donor token and the birthday to persist (the earlier of the donor's and the
/// requested one, so a later cold rescan can never skip notes either wallet knew
/// about). `candidates` comes from the in-RAM viewing-key index; every donor is
/// re-verified against its wallet file here, so a stale index entry (a token that
/// re-imported a different seed since) is harmless.
fn adopt_twin_checkpoint(
    dir: &str,
    token: &str,
    fvk: &[u8; 96],
    birthday: u64,
    genesis: &RpcHash,
    secret: Option<&str>,
    candidates: &[String],
) -> Option<(String, u64)> {
    let mut best: Option<(String, u64, std::time::SystemTime)> = None;
    for donor in candidates {
        if donor == token {
            continue;
        }
        if checkpoint_cursor(dir, donor, genesis).is_none() {
            continue;
        }
        let Some((key, donor_birthday, _)) = load_wallet_meta(dir, donor, secret) else { continue };
        if key.fvk_bytes() != Some(*fvk) {
            continue;
        }
        // Only adopt a view at least as complete as this registration asked for: a
        // donor fast-synced from a LATER birthday is blind to older notes
        // (`blind_below` > 0) that a birthday-0 / earlier-birthday restore explicitly
        // wants recovered — scanning honestly beats inheriting someone else's blind
        // spot and silently under-reporting the balance.
        let blind = checkpoint_blind_below(&scan_path(dir, donor)).unwrap_or(u64::MAX);
        if blind != 0 && (birthday == 0 || birthday < donor_birthday) {
            continue;
        }
        // Freshest donor wins: least catch-up left for the clone.
        let mtime = std::fs::metadata(scan_path(dir, donor))
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(_, _, m)| mtime > *m) {
            best = Some((donor.clone(), donor_birthday, mtime));
        }
    }
    let (donor, donor_birthday, _) = best?;
    // save_checkpoint writes are atomic (tmp + rename), so a plain copy always sees
    // a consistent file. At worst it lags the donor's RAM state by CHECKPOINT_EVERY
    // blocks; the clone re-scans that tail in seconds.
    std::fs::copy(scan_path(dir, &donor), scan_path(dir, token)).ok()?;
    Some((donor, donor_birthday.min(birthday)))
}

/// One pass over every wallet file in `dir` → viewing key → tokens map. Argon2 per
/// encrypted seed file, so this belongs on a blocking thread (startup does ~50 ms ×
/// wallet count there once; registrations keep the map current after that).
fn build_fvk_index(dir: &str, secret: Option<&str>) -> HashMap<[u8; 96], HashSet<String>> {
    let mut map: HashMap<[u8; 96], HashSet<String>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return map };
    for name in entries.flatten().filter_map(|e| e.file_name().into_string().ok()) {
        let Some(token) = name.strip_suffix(".json") else { continue };
        let Some((key, ..)) = load_wallet_meta(dir, token, secret) else { continue };
        if let Some(f) = key.fvk_bytes() {
            map.entry(f).or_default().insert(token.to_string());
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Offline admin tooling (`--diagnose` / `--graft`). Run with the daemon STOPPED:
// both operate on the same scan files the sync loop rewrites.

/// Report every wallet in `dir`: note count, compaction base, and — the reason
/// this exists — **stranded** notes (below the base with no witness; the
/// note@564934 incident). One line per wallet.
pub fn diagnose_wallets(dir: &str, secret: Option<&str>) -> String {
    let mut out = String::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return format!("cannot read wallet dir {dir}\n");
    };
    let mut tokens: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".scan").map(str::to_owned))
        .collect();
    tokens.sort();
    for token in tokens {
        let Some((key, ..)) = load_wallet_meta(dir, &token, secret) else {
            out.push_str(&format!("{token}: wallet file missing/undecryptable (need --wallet-secret?)\n"));
            continue;
        };
        let Ok(buf) = std::fs::read(scan_path(dir, &token)) else {
            out.push_str(&format!("{token}: scan file unreadable\n"));
            continue;
        };
        let Some((_, (db, _, scanned, ..))) = parse_scan_bytes(&buf, key, None) else {
            out.push_str(&format!("{token}: scan checkpoint does not parse\n"));
            continue;
        };
        let stranded = db.stranded_notes();
        let stranded_value: u64 = stranded.iter().map(|n| n.value()).sum();
        out.push_str(&format!(
            "{token}: notes={} balance={} scanned={} base={} size={} stranded={} stranded_value={}{}\n",
            db.notes().len(),
            fmt_fc(db.balance()),
            scanned,
            db.base_size(),
            db.size(),
            stranded.len(),
            fmt_fc(stranded_value as u128),
            if stranded.is_empty() {
                String::new()
            } else {
                format!(" positions={:?}", stranded.iter().map(|n| n.position).collect::<Vec<_>>())
            },
        ));
    }
    out
}

/// Repair a stranded wallet (see [`WalletDb::graft_history`]) by re-inserting the
/// leaf prefix from `older_scan` — an older snapshot of the SAME wallet (its
/// `.scan.bak`, a `wallets-PRESERVE` copy, …). Verifies the streams agree before
/// touching anything, then rewrites the wallet's scan checkpoint in place.
pub fn graft_wallet(dir: &str, token: &str, older_scan: &str, secret: Option<&str>) -> Result<String, String> {
    let (key, ..) = load_wallet_meta(dir, token, secret).ok_or("wallet file missing/undecryptable (need --wallet-secret?)")?;
    let buf = std::fs::read(scan_path(dir, token)).map_err(|e| format!("read current scan: {e}"))?;
    let (genesis, (mut db, low, scanned, boundaries, sink_blue, blind_below)) =
        parse_scan_bytes(&buf, key, None).ok_or("current scan checkpoint does not parse")?;
    let old_buf = std::fs::read(older_scan).map_err(|e| format!("read older snapshot: {e}"))?;
    let (old_genesis, (old_db, ..)) = parse_scan_bytes(&old_buf, key, None).ok_or("older snapshot does not parse")?;
    if old_genesis != genesis {
        return Err("older snapshot is from a different chain (genesis mismatch)".into());
    }
    let before = db.stranded_notes().len();
    let restored = db.graft_history(&old_db).map_err(|e| e.to_string())?;
    let after = db.stranded_notes().len();
    save_checkpoint(dir, token, &genesis, &low, scanned as u64, &db, &boundaries, sink_blue, blind_below)
        .map_err(|e| format!("write repaired checkpoint: {e}"))?;
    Ok(format!(
        "grafted {restored} leaves back (base now {}); stranded notes {before} -> {after}",
        db.base_size()
    ))
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
    /// Txid per decoded bundle (parallel to `bundles`), from the v2 RPC fields.
    /// Empty when the node predates them — history simply isn't recorded then.
    txids: Vec<[u8; 32]>,
    coinbase_txid: [u8; 32],
    /// Header timestamp ms (0 from a pre-v2 node).
    timestamp: u64,
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
    // Keep the txid pairing aligned through the decode filter: a payload that fails
    // to parse drops its txid with it.
    let mut bundles = Vec::with_capacity(b.accepted_bundles.len());
    let mut txids = Vec::with_capacity(b.accepted_bundles.len());
    for (i, p) in b.accepted_bundles.iter().enumerate() {
        if let Ok(bun) = ShieldedBundle::from_bytes(p) {
            bundles.push(bun);
            txids.push(b.accepted_txids.get(i).map(|h| h.as_bytes()).unwrap_or([0u8; 32]));
        }
    }
    DecodedBlock {
        hash: b.hash,
        blue_score: b.blue_score,
        daa_score: b.daa_score,
        coinbase,
        bundles,
        txids,
        coinbase_txid: b.coinbase_txid.as_bytes(),
        timestamp: b.timestamp,
    }
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
    /// From the wallet file: build sends with the wallet's own OVK so history can
    /// recover recipient/amount/memo (see `WalletFile::recoverable_history`).
    recoverable_history: bool,
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
    /// When the background witness pre-advance last ran for this wallet. The sync loop
    /// spins as fast as every 10 ms while any wallet is behind, so without this throttle
    /// a caught-up note-heavy wallet fires a full `WITNESS_ADVANCE_BUDGET` step ~100×/s
    /// and pins every core (observed live: walletd at 214 % CPU that never relents). We
    /// take at most one witness step per [`WITNESS_ADVANCE_INTERVAL`], which caps the
    /// steady witness work to ~`BUDGET` hashes/s per wallet — a cold miner wallet warms
    /// over a couple of minutes at low CPU, then idles (matured grows ~1 leaf/block).
    last_witness_advance: Option<std::time::Instant>,
    /// Set once this wallet's witnesses have first been warmed all the way to the matured
    /// anchor (base compacted to its notes + every note witnessed). Until then the
    /// caught-up tail does the one-time heavy build in large steps so it converges in a
    /// few passes instead of crawling; after it, only the cheap ~1-leaf/block incremental
    /// advance runs.
    witnesses_warm: bool,
    /// Request an immediate checkpoint write on the next `sync_one_wallet` pass, regardless
    /// of the block-count threshold — set the moment the witnesses first warm, so the
    /// expensive-to-rebuild witness state is persisted at once (a restart seconds later
    /// must not throw it away and re-do the ~30–90 s warm).
    force_checkpoint: bool,
    /// Tree size of the frontier this view was anchored on when the wallet may hold
    /// notes MINTED BELOW it — notes this view can never discover, because the node
    /// has pruned their blocks (0 = complete view). Set on a full-scan rebuild of a
    /// wallet whose birthday predates the pruning point, persisted in the v4
    /// checkpoint, and surfaced as `missing_history` in status — the 2026-07-19
    /// incident was a wallet silently "losing" 23K ZKAS to exactly this after a
    /// rescan, with nothing anywhere admitting the view was partial.
    blind_below: u64,
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

/// How long (chain DAA ≈ seconds at 1 BPS) a submitted spend may stay unobserved
/// on-chain before the wallet concludes the transaction was lost and returns its
/// notes to the spendable set. Long enough to ride out mempool latency, ingest
/// maturity lag (~3 min) and a node restart with room to spare; short enough that
/// a user whose send evaporated gets their balance back within the hour instead
/// of never.
const PENDING_SPEND_EXPIRY_DAA: u64 = 3_600;

impl WalletEntry {
    /// Rebuild an entry from a wallet view + cursor (a fresh frontier start or a
    /// persisted checkpoint): the background sync resumes strictly after `low`.
    /// `saved_scanned == scanned` so the next checkpoint write waits for
    /// genuinely new blocks.
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        key: WalletKey,
        recoverable_history: bool,
        db: WalletDb,
        genesis: RpcHash,
        low: RpcHash,
        scanned: usize,
        boundaries: VecDeque<(u64, u64)>,
        sink_blue: u64,
    ) -> Self {
        let mut db = db;
        // History is opt-in per wallet: the same flag that makes sends
        // OVK-recoverable also authorizes recording rows at all. Applying it here
        // (the one place every entry is built) also purges rows persisted while
        // the flag was on if the user has since turned it off.
        db.set_history_enabled(recoverable_history);
        Self {
            key,
            recoverable_history,
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
            last_witness_advance: None,
            witnesses_warm: false,
            force_checkpoint: false,
            blind_below: 0,
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
    async fn sync_chunk(&mut self, client: &GrpcClient, cache: &Mutex<PageCache>, warm_gate: &tokio::sync::Semaphore) {
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
                    // History dating needs the v2 RPC fields; a pre-v2 node serves
                    // timestamp 0 and no txids — sync still works, history is skipped.
                    let meta = (b.timestamp > 0 && b.txids.len() == b.bundles.len()).then(|| BlockMeta {
                        coinbase_txid: b.coinbase_txid,
                        txids: b.txids.clone(),
                        timestamp_ms: b.timestamp,
                        daa_score: b.daa_score,
                    });
                    self.db.ingest_block_precomputed_with_meta(&b.coinbase, &bundle_refs, meta.as_ref());
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
        // Keep this wallet's spend-witnesses tracking the matured anchor so pressing Send is
        // a witness *lookup* (~ms), never a Sinsemilla replay of the chain (measured cold:
        // 30–36 s, 90 % of a send). Two regimes, only near the tip (`caught_up`):
        //
        //   COLD (`!witnesses_warm`): the one-time heavy build for a full-scan / freshly
        //   loaded wallet — roll the base up to the wallet's notes (dropping the leaves
        //   below, `advance_base_capped`), then witness every note up to the matured anchor
        //   (`advance_witnesses_capped`). Done in LARGE steps so it converges in a handful
        //   of passes instead of crawling for minutes (the earlier throttled version let the
        //   user keep sending mid-warm — every send stayed COLD). Each big step is a single
        //   `block_in_place`, so it can't spin the loop; and it latches `witnesses_warm`
        //   when done, so this heavy path runs at most once per wallet load. The instant it
        //   warms it asks for a checkpoint (`force_checkpoint`) so the expensive witness
        //   state is persisted (v5) and a restart never has to redo it.
        //
        //   WARM: cheap throttled maintenance — the base only needs a nudge if a note
        //   arrived below it (rare), and witnesses advance ~1 leaf/block as the anchor moves.
        //
        // The base compaction no longer wipes warm witnesses (they are self-contained and
        // valid above the base — see `advance_base_capped`), so the two no longer fight.
        // Any note not yet reached still rebuilds on demand in `witness_path_at`, so
        // correctness never depends on this pre-advance.
        if self.caught_up {
            if let Some(matured) = self.matured_leaves() {
                // How many witnesses this wallet maintains. Every step below costs
                // `leaves × budget`, so pinning the budget to a constant for a note-heavy
                // wallet is what keeps its catch-up bounded — see EAGER_WARM_MAX_NOTES.
                let note_count = self.db.notes().len() as u64;
                let budget = if note_count > EAGER_WARM_MAX_NOTES {
                    SPENDABLE_WITNESS_BUDGET
                } else {
                    note_count.max(1) as usize
                };
                self.db.set_witness_budget(budget);
                // Take a warm permit, or leave the heavy catch-up to another tick. This is
                // `try_acquire`, not `acquire`: a wallet that can't warm right now should
                // fall through and keep doing its cheap incremental sync rather than block
                // a sync slot waiting. Ordinary sync never touches this gate.
                let warm_permit = if self.witnesses_warm { None } else { warm_gate.try_acquire().ok() };
                if !self.witnesses_warm && warm_permit.is_some() {
                    // Roll the base up to our notes first (cheap: cost is leaves, not
                    // leaves×budget), then warm the witnesses to the matured anchor.
                    // Bound each step by WORK (≈ leaves×budget ≤ COLD_WARM_BUDGET) so every
                    // wallet's step costs the same regardless of its size.
                    let wstep = (COLD_WARM_BUDGET / budget as u64).clamp(WITNESS_MIN_STEP, COLD_WARM_STEP);
                    // Run every phase of the warm back-to-back inside one tick, instead of
                    // one step per sync pass.
                    //
                    // Spreading it out was the real cost. The three phases are sequential —
                    // roll the base, sweep the witnesses to `matured`, then adopt the notes
                    // the sweep passed — and adoption is the ONLY phase that makes a spend
                    // fast. On the live miner wallet the sweep had ~46 K leaves to climb
                    // while opening zero witnesses (every eligible note sits below it), which
                    // is ~8 s of actual work; at one 2 730-leaf step per pass that became a
                    // 30-minute prologue, and adoption never ran at all. Meanwhile every
                    // send paid 6 × 22 s of rebuilds. Same total work, run to completion.
                    let deadline = std::time::Instant::now() + COLD_WARM_TICK;
                    let t_tick = std::time::Instant::now();
                    let mut adopted = 0usize;
                    loop {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                        // Phase 1: roll the base up to our notes (cost is leaves, not
                        // leaves×budget), which shortens every later replay.
                        if tokio::task::block_in_place(|| self.db.advance_base_capped(matured, COLD_WARM_STEP)) {
                            continue;
                        }
                        // Phase 2: sweep the witness set forward to the matured anchor.
                        if tokio::task::block_in_place(|| self.db.advance_witnesses_capped(matured, wstep)) {
                            continue;
                        }
                        // Phase 3: the sweep only opens a witness for a note it PASSES, so
                        // notes below it — a note-heavy wallet's entire holding — get none
                        // and would replay on every spend forever. Adopt them: one O(chain)
                        // replay each, paid here rather than on the send path, kept for good.
                        let Some(pos) = self.db.next_note_needing_witness() else {
                            self.witnesses_warm = true;
                            break;
                        };
                        let t = std::time::Instant::now();
                        let ok = tokio::task::block_in_place(|| self.db.install_witness(pos, matured));
                        adopted += 1;
                        log::info!(
                            "adopted witness for note@{pos} in {:.1?} (ok={ok}, {}/{} slots warm) — this note no longer replays at spend time",
                            t.elapsed(),
                            self.db.live_witness_count(),
                            budget,
                        );
                        if !ok {
                            break;
                        }
                    }
                    // Persist only when this tick achieved something worth a checkpoint.
                    //
                    // A checkpoint serialises the whole leaf stream — 15–29 MB on these
                    // wallets — so forcing one every tick (as this did) meant tens of MB of
                    // write amplification per wallet per few seconds, on top of the warm's
                    // own CPU. Adoption is expensive to redo (a full replay each) so it is
                    // always persisted; raw sweep progress is cheap by comparison and rides
                    // the ordinary `CHECKPOINT_EVERY` cadence instead.
                    if adopted > 0 || self.witnesses_warm {
                        self.force_checkpoint = true;
                    }
                    if self.witnesses_warm {
                        log::info!(
                            "witnesses warmed for wallet (notes={}, witness_budget={}, warm={}, adopted {} this tick, base_size={}, witnessed_upto={} == matured {})",
                            note_count,
                            budget,
                            self.db.live_witness_count(),
                            adopted,
                            self.db.base_size(),
                            self.db.witnessed_upto(),
                            matured,
                        );
                    } else {
                        log::info!(
                            "warming wallet: {:.1?} this tick (notes={}, warm={}/{}, adopted {}, witnessed_upto={} of matured {}, {} leaves to go)",
                            t_tick.elapsed(),
                            note_count,
                            self.db.live_witness_count(),
                            budget,
                            adopted,
                            self.db.witnessed_upto(),
                            matured,
                            matured.saturating_sub(self.db.witnessed_upto()),
                        );
                    }
                } else {
                    let due = self.last_witness_advance.map(|t| t.elapsed() >= WITNESS_ADVANCE_INTERVAL).unwrap_or(true);
                    if due {
                        // Bound the step by WORK, not leaves. `WITNESS_ADVANCE_CAP` is a
                        // LEAF cap sized when only ≤32-note wallets reached this path; with
                        // a 12-witness budget it costs 4 000 × 12 ≈ 48 000 Sinsemilla
                        // appends ≈ 8 s — once per second, per wallet, holding the wallet
                        // lock. Every note-heavy wallet that loses the race for a warm
                        // permit lands here, so that alone saturated the box and starved
                        // ordinary sync (a 1-note wallet stuck at "syncing 97%").
                        let steady_cap = (COLD_WARM_BUDGET / budget as u64).clamp(WITNESS_MIN_STEP, WITNESS_ADVANCE_CAP);
                        tokio::task::block_in_place(|| {
                            self.db.advance_base_capped(matured, BASE_ADVANCE_STEP);
                            // Only a WARM wallet belongs on the incremental step: it is a
                            // few appends per new leaf (one leaf per block at 1 BPS). A
                            // wallet still waiting for a warm permit must NOT do its
                            // catch-up here — that is the warm's job, under the gate that
                            // bounds how many run at once.
                            if self.witnesses_warm && self.db.advance_witnesses_capped(matured, steady_cap) {
                                self.witnesses_warm = false;
                            }
                        });
                        self.last_witness_advance = Some(std::time::Instant::now());
                    }
                }
            }
        }
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

    /// Send-time witness top-up, **bounded**. For a warm wallet this is the cheap
    /// "climb the few leaves since the last sync tick". But for a note-heavy wallet
    /// the eager warm is skipped, so its first spend would climb the whole chain
    /// here — and each climbed leaf costs one append per live witness (up to 256),
    /// ~15 ms/leaf. Uncapped that was a 40+ minute compute (the 2026-07-17 outage:
    /// it ran on the async runtime holding the tokio I/O driver, freezing every
    /// HTTP request). So a note-heavy wallet only climbs a short gap inline; a
    /// long climb is skipped entirely — the ≤ max-spends notes a send selects
    /// rebuild on demand in `witness_path_at`, bounded and witness-count-free.
    fn advance_spend_witnesses_bounded(&mut self) {
        let note_count = self.db.notes().len() as u64;
        if note_count <= EAGER_WARM_MAX_NOTES {
            self.advance_spend_witnesses();
            return;
        }
        if let Some(matured) = self.matured_leaves() {
            let climb = matured.saturating_sub(self.db.witnessed_upto());
            if climb <= SPEND_CLIMB_INLINE_MAX {
                self.db.advance_witnesses(matured);
            } else {
                log::info!(
                    "send: skipping inline witness climb of {climb} leaves on note-heavy wallet (notes={note_count}); selected notes rebuild on demand"
                );
            }
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
    /// Payment preparation is deliberately serialized: witness reconstruction and Halo2
    /// proving are CPU-heavy synchronous work, and overlapping copies exhaust every
    /// runtime worker and take the whole wallet API offline.
    ///
    /// This bounds *total* proving CPU, so it is shared by every tenant — which means a
    /// caller must QUEUE on it, not fail on it. It used to be `try_acquire`, so on the
    /// hosted daemon one user's send made every other user's send fail outright with
    /// "a shielded payment is already being prepared", and a chunked payment (several
    /// sequential prepares) held that window open for minutes. Racing retries of the
    /// *same* wallet — the browser-retry storm this was really written for — are caught
    /// by `preparing` below, which is the check that should be a fast rejection.
    prepare_gate: tokio::sync::Semaphore,
    /// Wallets (by FVK) with a preparation already in flight. A second concurrent
    /// prepare for the SAME wallet is a duplicate — a retry, a double-clicked button —
    /// and is rejected immediately rather than queued: it would select the same notes.
    preparing: std::sync::Mutex<HashSet<String>>,
    /// Permits for the one-time cold warm; see [`WARM_CONCURRENCY`].
    warm_gate: tokio::sync::Semaphore,
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
    /// Full viewing key → tokens registered with it, for twin-checkpoint adoption
    /// (see [`adopt_twin_checkpoint`]). Built in the background at startup, kept
    /// current by registrations; entries are re-verified against the wallet files
    /// before use, so staleness only ever costs the fast path, never correctness.
    fvk_index: Mutex<HashMap<[u8; 96], HashSet<String>>>,
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
        // Synced, but still doing the ONE-TIME witness warm-up (building/persisting the
        // spend paths) — sends work but the first one is slow until this finishes. Lets the
        // UI show "Preparing wallet for fast sends…" instead of a confusing "syncing 100%".
        // Note-heavy wallets skip the eager warm, so they are never reported as warming.
        warming: e.caught_up && !e.witnesses_warm && (e.db.notes().len() as u64) <= EAGER_WARM_MAX_NOTES,
        missing_history: e.blind_below > 0,
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
    resp.warming = s.warming;
    resp.missing_history = s.missing_history;
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
    warming: bool,
    missing_history: bool,
}

/// A non-custodial payment proven and awaiting on-device spend-auth signatures.
struct PreparedSession {
    payment: PreparedPayment,
    amount: u64,
    fee: u64,
    created: std::time::Instant,
    /// Wallet this payment was prepared against, when the caller presented a token.
    /// `/submit` needs it to park the spent notes — without it the notes stay in the
    /// unspent set until the block carrying them clears the reorg holdback (~3 min),
    /// and a second send in that window re-selects the same note value-descending,
    /// producing a transaction consensus DROPS as a double-spend. The UI reports that
    /// send as successful, the payer's balance falls, and the payee never receives it.
    /// (The custodial `/send` path has always done this; the non-custodial one, which
    /// is what every shipped wallet actually uses, did not.)
    token: Option<String>,
    /// Absolute leaf positions of the notes this payment spends, to park on acceptance.
    positions: Vec<u64>,
}

/// How long a prepared (unsigned) non-custodial payment lives before it is swept.
const PREPARED_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// How long a prepare waits for the shared proving slot before giving up. Generous:
/// a cold witness rebuild plus proof can run tens of seconds, and waiting behind one
/// is a far better outcome for the user than being told to retry — which is what
/// produced the retry storms in the first place.
const PREPARE_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// Releases this wallet's in-flight prepare marker on every exit path, including the
/// `?` early returns and a panic in the proving task.
struct PreparingGuard {
    state: Arc<AppState>,
    key: String,
}

impl Drop for PreparingGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.state.preparing.lock() {
            set.remove(&self.key);
        }
    }
}

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
    async fn fast_sync_entry(&self, key: WalletKey, recoverable: bool, guard: RpcHash, birthday: u64) -> Option<WalletEntry> {
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
        Some(WalletEntry::from_parts(key, recoverable, db, guard, start_hash, start_daa as usize, VecDeque::new(), 0))
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
    async fn full_scan_entry(&self, key: WalletKey, recoverable: bool, guard: RpcHash, birthday: u64) -> Option<WalletEntry> {
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
        let mut e = WalletEntry::from_parts(key, recoverable, db, guard, start, ts.daa_score as usize, VecDeque::new(), 0);
        // The wallet claims history from before the pruning point (birthday below the
        // frontier's DAA, or 0 = "any height"), but the node cannot serve those blocks:
        // any note minted below this frontier is INVISIBLE to this view. Record it so
        // status can say so — a partial balance shown as the whole truth is how the
        // 2026-07-19 "23K ZKAS missing" report happened.
        if ts.size > 0 && birthday < ts.daa_score {
            e.blind_below = ts.size;
            log::warn!(
                "wallet rebuilt BLIND below tree position {} (birthday {birthday} predates pruning-point daa {}): \
                 notes minted before the pruning point cannot be recovered through this node",
                ts.size,
                ts.daa_score
            );
        }
        Some(e)
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
    /// Record that `token` is registered with `key`'s viewing key, so later
    /// registrations of the same wallet on other devices can adopt its checkpoint.
    async fn index_fvk(&self, token: &str, key: &WalletKey) {
        if let Some(f) = key.fvk_bytes() {
            self.fvk_index.lock().await.entry(f).or_default().insert(token.to_string());
        }
    }

    /// Try the twin-adoption fast path for a registration of `fvk` under `token`:
    /// clone the freshest same-key checkpoint another token already scanned. Runs
    /// the donor verification (argon2 decrypts included) off the async workers.
    async fn adopt_twin(&self, token: &str, fvk: &[u8; 96], birthday: u64) -> Option<(String, u64)> {
        // DISABLED 2026-07-20: cloning a donor token's checkpoint propagated stale /
        // phantom-note trees between same-seed devices, which is exactly the
        // divergent-anchor state `ensure_canonical_checkpoint` now rejects at send
        // time. A fresh registration must scan the canonical stream itself; re-enable
        // only behind a proof that the donor checkpoint equals the node frontier at
        // its cursor. Body kept for that future gated version.
        let _ = (token, fvk, birthday);
        return None;
        #[allow(unreachable_code)]
        let candidates: Vec<String> =
            self.fvk_index.lock().await.get(fvk).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        if candidates.is_empty() {
            return None;
        }
        // Flush RAM-resident candidates to disk first: the sync loop only rewrites a
        // live wallet's checkpoint every CHECKPOINT_EVERY blocks, so the file the
        // clone copies could otherwise lag the donor's actual state by ~17 minutes
        // of chain — the whole point here is that the second device starts where
        // the first one IS, not where it was at the last periodic save.
        {
            let map = self.wallets.lock().await;
            let resident: Vec<(String, Wallet)> =
                candidates.iter().filter_map(|t| map.get(t).map(|w| (t.clone(), w.clone()))).collect();
            drop(map);
            for (t, w) in resident {
                let mut e = w.lock().await;
                if e.error.is_none()
                    && save_checkpoint(
                        &self.wallet_dir,
                        &t,
                        &e.genesis,
                        &e.low,
                        e.scanned as u64,
                        &e.db,
                        &e.boundaries,
                        e.sink_blue,
                        e.blind_below,
                    )
                    .is_ok()
                {
                    e.saved_scanned = e.scanned;
                    e.force_checkpoint = false;
                }
            }
        }
        let (dir, genesis, secret) = (self.wallet_dir.clone(), self.genesis, self.wallet_secret.clone());
        let (token, fvk) = (token.to_string(), *fvk);
        tokio::task::spawn_blocking(move || {
            adopt_twin_checkpoint(&dir, &token, &fvk, birthday, &genesis, secret.as_deref(), &candidates)
        })
        .await
        .ok()?
    }

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
        let (key, birthday, recoverable_history) = load_wallet_meta(&self.wallet_dir, token, self.wallet_secret.as_deref())?;
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
                // Never load an unverified checkpoint. A transient node failure is
                // retried on the next request; treating it as permission to trust the
                // local file is how stale twin state previously propagated.
                Err(e) => {
                    log::warn!("cannot verify checkpoint cursor against selected chain ({e}); keeping checkpoint and retrying");
                    return None;
                }
            },
            None => None,
        };
        let restored = load_checkpoint(&self.wallet_dir, token, key, &genesis, tip.as_ref());
        // Preserve a rejected checkpoint for forensic recovery/grafting. Never let
        // the subsequent clean scan overwrite the only copy of older owned notes.
        if restored.is_none() && tip.is_some() && checkpoint_cursor(&self.wallet_dir, token, &genesis).is_some() {
            let scan = scan_path(&self.wallet_dir, token);
            let quarantine = format!("{scan}.divergent-{}", now_unix());
            if std::fs::copy(&scan, &quarantine).is_ok() {
                log::warn!("preserved rejected checkpoint as {quarantine}");
            }
        }
        let entry = match restored {
            Some((db, low, scanned, boundaries, sink_blue, blind_below)) => {
                let mut e =
                    WalletEntry::from_parts(key, recoverable_history, db, genesis, low, scanned, boundaries, sink_blue);
                e.blind_below = blind_below;
                e
            }
            None => match self.fast_sync_entry(key, recoverable_history, genesis, birthday).await {
                Some(e) => e,
                None => self.full_scan_entry(key, recoverable_history, genesis, birthday).await?,
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
    e.sync_chunk(&state.sync_client, &state.page_cache, &state.warm_gate).await;
    // NB: the eager witness pre-advance and base compaction live in `sync_chunk`'s
    // `caught_up` tail, THROTTLED to one bounded step per `WITNESS_ADVANCE_INTERVAL` per
    // wallet (an unthrottled advance on the 10 ms sync spin pinned every core, observed
    // live 2026-07-16). Together with the v5 checkpoint persisting the resulting witnesses,
    // a spend becomes a lookup instead of an O(chain) Sinsemilla replay; `witness_path_at`
    // still rebuilds on demand for any note whose witness isn't held (correctness never
    // depends on the pre-advance).
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
    // A submitted spend the chain has still not shown after an hour of chain time
    // is lost — a node that crashed with it in the mempool, an eviction, or a
    // consensus-dropped shielded spend. Hand the notes back (live report
    // 2026-07-18: "ZKAS disappeared without a trace" was exactly this). Only
    // judged when caught up, so "unobserved" means the chain really doesn't have
    // it, not that we haven't looked yet.
    if e.caught_up {
        let now_daa = e.scanned as u64;
        for (txid, value) in e.db.reclaim_expired(now_daa, PENDING_SPEND_EXPIRY_DAA) {
            e.force_checkpoint = true; // persist the returned note promptly
            log::warn!(
                "wallet '{token}': submitted spend {} ({value} sompi) never appeared on-chain within ~{PENDING_SPEND_EXPIRY_DAA}s of chain time — note returned to the spendable balance",
                RpcHash::from_bytes(txid)
            );
        }
    }
    let behind = !e.caught_up;
    // Persist a checkpoint once enough new blocks accrue, or the first time this wallet
    // reaches the tip, so a restart resumes here instead of rescanning from birthday.
    let advanced = e.scanned.saturating_sub(e.saved_scanned);
    let just_caught_up = e.caught_up && !was_caught_up;
    // `force_checkpoint` is set the instant the witnesses first warm, so the expensive
    // witness state (v5) is persisted immediately — a restart seconds later must not throw
    // it away and re-do the ~30–90 s warm.
    let force = e.force_checkpoint;
    if e.error.is_none() && (advanced >= CHECKPOINT_EVERY || (just_caught_up && advanced > 0) || force) {
        if let Err(err) =
            save_checkpoint(&state.wallet_dir, &token, &e.genesis, &e.low, e.scanned as u64, &e.db, &e.boundaries, e.sink_blue, e.blind_below)
        {
            eprintln!("checkpoint write failed for {token}: {err}");
        } else {
            e.saved_scanned = e.scanned;
            e.force_checkpoint = false;
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
    /// Synced, but still doing the one-time witness warm-up. The SPA shows a "preparing for
    /// fast sends" notice; sends still work (the first is just slower). Absent/false on
    /// older daemons and on note-heavy wallets (which skip the eager warm).
    #[serde(default)]
    warming: bool,
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
    /// True when this wallet's view was rebuilt from a pruning-point frontier while
    /// its birthday claims older history: notes minted before that point exist on
    /// chain but CANNOT be discovered through this node (their blocks are pruned).
    /// The balance shown is a lower bound, and the UI must say so. False on older
    /// daemons (field absent) and on wallets with a complete view.
    #[serde(default)]
    missing_history: bool,
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
        warming: false,
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
        missing_history: false,
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
    load_new_wallet(&state, &token, seed, tip, false).await?;
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
    load_new_wallet(&state, &token, seed, req.birthday, true).await?;
    Ok(Json(CreateResp {
        address,
        seed_hex: req.seed_hex,
        network: state.network.clone(),
        warning: "Wallet imported. Keep your seed offline.".into(),
    }))
}

/// Persist a new seed for a token and (re)load it into memory, replacing any prior.
/// `birthday` is the block height the display scan starts from (0 = from genesis).
/// `adopt_twin`: for an IMPORTED seed, allow cloning a same-key checkpoint another
/// token already scanned (a freshly created seed cannot have a twin).
async fn load_new_wallet(
    state: &Arc<AppState>,
    token: &str,
    seed: [u8; 32],
    birthday: u64,
    adopt_twin: bool,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let key = WalletKey::Seed(seed);
    save_seed(&state.wallet_dir, token, &state.network, &seed, birthday, state.wallet_secret.as_deref())
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Drop any prior scan checkpoint: a (re)imported seed must rescan from its own
    // birthday, not resume a different wallet's stream.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, token));
    // Same-wallet-on-another-device fast path (see wallet_watch): a re-imported seed
    // whose viewing key some other token already scanned resumes from that
    // checkpoint instead of rescanning history the daemon already walked.
    if adopt_twin {
        if let Some(fvk) = key.fvk_bytes() {
            if let Some((donor, keep_birthday)) = state.adopt_twin(token, &fvk, birthday).await {
                if keep_birthday != birthday {
                    save_seed(&state.wallet_dir, token, &state.network, &seed, keep_birthday, state.wallet_secret.as_deref())
                        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
                }
                state.wallets.lock().await.remove(token);
                if state.get_wallet(token).await.is_some() {
                    state.index_fvk(token, &key).await;
                    log::info!("imported wallet for token {token}: adopted checkpoint from twin token {donor} (birthday {keep_birthday})");
                    return Ok(());
                }
                // The clone failed to load — fall back to the honest scan from the
                // REQUESTED birthday (restore it if the adoption lowered it).
                let _ = std::fs::remove_file(scan_path(&state.wallet_dir, token));
                if keep_birthday != birthday {
                    save_seed(&state.wallet_dir, token, &state.network, &seed, birthday, state.wallet_secret.as_deref())
                        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
                }
            }
        }
    }
    // Fast-sync from the node's frontier when the wallet is born after the
    // checkpoint (complete by construction); otherwise the pruning-point full scan.
    // History starts OFF (opt-in) — must match what `save_seed` just wrote, or
    // the in-memory entry records rows the user never consented to.
    let entry = match state.fast_sync_entry(key, false, state.genesis, birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(key, false, state.genesis, birthday)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.to_string(), Arc::new(Mutex::new(entry)));
    state.index_fvk(token, &key).await;
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

    // If this EXACT key is already registered under this token and has a resumable
    // checkpoint, a reconnect must NOT discard it and fast-sync from the client-supplied
    // birthday. A browser reconnecting after a daemon restart re-registers with
    // birthday ≈ tip; trusting that would skip the blocks where the wallet actually
    // received funds and show a ZERO balance for coins it still holds (live incident
    // 2026-07-16: a restart→re-register set birthday to the tip and the wallet's real note
    // sat in the skipped window). Resume the existing checkpoint instead, and never let the
    // persisted birthday move forward (min with the old value) so a later cold load can't
    // skip those notes either. Only a genuinely new/changed key, or a missing checkpoint,
    // takes the rescan-from-birthday path below.
    let existing = load_wallet_meta(&state.wallet_dir, &token, state.wallet_secret.as_deref());
    let same_key = matches!(&existing, Some((WalletKey::Fvk(f), _, _)) if *f == fvk);
    let has_checkpoint = checkpoint_cursor(&state.wallet_dir, &token, &state.genesis).is_some();
    if same_key && has_checkpoint {
        let stored_birthday = existing.as_ref().map(|(_, b, _)| *b).unwrap_or(0);
        let keep_birthday = stored_birthday.min(req.birthday);
        save_fvk(&state.wallet_dir, &token, &state.network, &fvk, keep_birthday)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
        // Evict any stale in-RAM entry so the next load resumes from the preserved checkpoint.
        state.wallets.lock().await.remove(&token);
        state
            .get_wallet(&token)
            .await
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to resume wallet from checkpoint"))?;
        log::info!("re-registered watch-only wallet for token {token}: resumed from checkpoint (birthday kept {keep_birthday})");
        return Ok(Json(AddressResp { address }));
    }

    // A new or changed key must not resume a DIFFERENT key's checkpoint stream.
    let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
    // Same-wallet-on-another-device fast path: if any other token here has already
    // scanned this exact viewing key, clone its checkpoint — the second device is
    // synced immediately instead of rescanning history the daemon already walked.
    if let Some((donor, keep_birthday)) = state.adopt_twin(&token, &fvk, req.birthday).await {
        save_fvk(&state.wallet_dir, &token, &state.network, &fvk, keep_birthday)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
        state.wallets.lock().await.remove(&token);
        if state.get_wallet(&token).await.is_some() {
            state.index_fvk(&token, &key).await;
            log::info!(
                "registered watch-only wallet for token {token}: adopted checkpoint from twin token {donor} (birthday {keep_birthday})"
            );
            return Ok(Json(AddressResp { address }));
        }
        // The clone failed to load (corrupt donor file, node hiccup) — scan honestly.
        let _ = std::fs::remove_file(scan_path(&state.wallet_dir, &token));
    }
    save_fvk(&state.wallet_dir, &token, &state.network, &fvk, req.birthday)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // History starts OFF (opt-in), matching what `save_fvk` just wrote.
    let entry = match state.fast_sync_entry(key, false, state.genesis, req.birthday).await {
        Some(e) => e,
        None => state
            .full_scan_entry(key, false, state.genesis, req.birthday)
            .await
            .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "cannot anchor a full scan (node unreachable or too old)"))?,
    };
    state.wallets.lock().await.insert(token.clone(), Arc::new(Mutex::new(entry)));
    state.index_fvk(&token, &WalletKey::Fvk(fvk)).await;
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
    /// Optional memo (max 512 bytes UTF-8) carried inside the recipient's
    /// encrypted note — readable only by them (and, with recoverable history,
    /// by this wallet's own OVK).
    memo: Option<String>,
}

#[derive(Serialize)]
struct SendResp {
    /// First transaction id (kept for callers that expect a single txid).
    txid: String,
    amount_sompi: u64,
    /// Total fees paid across all transactions.
    fee_sompi: u64,
    /// Exact decimal forms for clients whose number type cannot represent u64.
    amount_sompi_exact: String,
    fee_sompi_exact: String,
    /// Every transaction id: a large send is split across several
    /// standard-size transactions (at most [`max_spends_per_tx`] spends each).
    txids: Vec<String>,
    tx_count: usize,
}

/// Greedy chunk planning over **value-descending** candidate notes: each
/// transaction spends at most `max_per` notes and pays `min(remaining,
/// chunk_sum − fee)` to the recipient, until `amount` is covered. The fee is
/// **byte-proportional per chunk** (`chunk_fee`): the node's minimum relay fee
/// grows with the number of spends, so a flat fee that clears a 1-spend tx is
/// rejected for a 5-spend one. Returns the per-chunk `(note_count, pay, fee)`
/// plan, or `None` if the notes run out (insufficient funds once per-tx fees
/// are accounted).
fn plan_chunks(values: &[u64], amount: u64, base_fee: u64, max_per: usize) -> Option<Vec<(usize, u64, u64)>> {
    let plan = plan_payment(values.to_vec(), amount, base_fee, max_per).ok()?;
    Some(plan.chunks.into_iter().map(|chunk| (chunk.note_range.len(), chunk.amount, chunk.fee)).collect())
}

/// The wallet's chain-derived transaction history, newest first.
///
/// Rows are recorded by the sync loop as blocks are ingested (received amounts via
/// IVK trial decryption, spends via our nullifiers, recipients/memos of our own
/// sends via the OVK when `recoverableHistory` is on) and persisted in the scan
/// checkpoint, so they survive restarts — and, for OVK sends, a seed restore.
#[derive(Deserialize, Default)]
struct HistoryQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn wallet_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    let e = w.lock().await;
    let history_page = query.limit.unwrap_or(500).clamp(1, 5_000);
    let offset = query.offset.unwrap_or(0);
    let rows: Vec<serde_json::Value> =
        e.db.history()
            .iter()
            .rev()
            .skip(offset)
            .take(history_page)
            .map(|h| {
                serde_json::json!({
                    "kind": match h.kind {
                        HistoryKind::Coinbase => "coinbase",
                        HistoryKind::Received => "received",
                        HistoryKind::Sent => "sent",
                    },
                    "txid": hex(&h.txid),
                    "daaScore": h.daa_score,
                    "timestamp": h.timestamp_ms,
                    "amountSompi": h.amount,
                    "amountSompiExact": h.amount.to_string(),
                    "amountZkas": h.amount as f64 / SOMPI_PER_ZKAS as f64,
                    "feeSompi": h.fee,
                    "feeSompiExact": h.fee.to_string(),
                    "recipient": h.recipient.map(|r| String::from(&Address::new(state.prefix, Version::ShieldedOrchard, &r))),
                    "memo": (!h.memo.is_empty()).then(|| String::from_utf8_lossy(&h.memo).into_owned()),
                })
            })
            .collect();
    // Spends submitted from this daemon but not yet observed on-chain — surfaced
    // so "where did my money go" is answerable while a send is in flight (the
    // notes come back automatically if the tx is lost; see `reclaim_expired`).
    let pending: Vec<serde_json::Value> =
        e.db.pending_spends()
            .iter()
            .map(|p| {
                serde_json::json!({
                    "txid": hex(&p.txid),
                    "amountSompi": p.note.value(),
                    "amountZkas": p.note.value() as f64 / SOMPI_PER_ZKAS as f64,
                    "submittedDaa": p.submitted_daa,
                })
            })
            .collect();
    Ok(Json(serde_json::json!({
        "recoverableHistory": e.recoverable_history,
        "total": e.db.history().len(),
        "offset": offset,
        "limit": history_page,
        "rows": rows,
        "pendingOutgoing": pending,
    })))
}

#[derive(Deserialize)]
struct SettingsReq {
    /// Toggle OVK-recoverable send history for this wallet (see `WalletFile`).
    recoverable_history: Option<bool>,
}

async fn wallet_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let bytes = std::fs::read(wallet_path(&state.wallet_dir, &token)).map_err(|_| err(StatusCode::NOT_FOUND, "no such wallet"))?;
    let mut wf: WalletFile =
        serde_json::from_slice(&bytes).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt wallet file"))?;
    if let Some(v) = req.recoverable_history {
        wf.recoverable_history = v;
    }
    write_wallet_file(&state.wallet_dir, &token, &wf)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write wallet file: {e}")))?;
    // Keep a loaded entry in step so the next send honours the change immediately.
    // The same flag gates history-row recording: turning it OFF also purges the
    // rows already recorded (withdrawing consent removes the readable record).
    if let Some(w) = state.cached_wallet(&token).await {
        let mut e = w.lock().await;
        e.recoverable_history = wf.recoverable_history;
        e.db.set_history_enabled(wf.recoverable_history);
        e.force_checkpoint = true; // persist the purge/enable promptly
    }
    Ok(Json(serde_json::json!({ "recoverableHistory": wf.recoverable_history })))
}

/// Retire this wallet's scan checkpoint and reload it from its birthday — a full
/// re-derivation of the wallet from the chain itself. Two jobs: BACKFILL history
/// rows after the user enables history (rows are only recorded while blocks are
/// scanned), and RECOVER anything the incremental view ever lost (e.g. notes
/// deleted by the pre-v7 submit-and-forget spend bug — the "my ZKAS vanished"
/// report). Bounded work: birthday fast-sync + a scan of blocks since birthday.
#[derive(Deserialize, Default)]
struct RescanReq {
    /// Accept losing notes the node can no longer serve. Without it, a rescan that
    /// would forget anything is refused with the exact damage it would do.
    #[serde(default)]
    force: bool,
}

async fn wallet_rescan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RescanReq>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    if !wallet_exists(&state.wallet_dir, &token) {
        return Err(err(StatusCode::NOT_FOUND, "no such wallet"));
    }
    // NOTE: this deployment's nodes run with --archival, so a rescan re-reads the
    // full shielded history from genesis and loses nothing — the old "rescan
    // refused: N notes pruned" guard was a false positive that only ever blocked
    // legitimate recovery rescans (and, worse, defended STALE notes a fresh scan
    // proves are already spent). Rescan now always proceeds; `force` is accepted
    // for API compatibility but no longer gates anything. If this is ever pointed
    // at a genuinely pruned node, a birthday-0 wallet's rescan can drop notes below
    // the pruning point — run it against an archival node (which is the norm here).
    let _ = &body;
    // Poison any in-flight sync pass first: checkpoint writes are gated on
    // `error.is_none()`, so this stops a concurrent pass from re-persisting the
    // old cursor after we retire it below.
    if let Some(w) = state.cached_wallet(&token).await {
        w.lock().await.error = Some("rescanning from birthday".into());
    }
    state.wallets.lock().await.remove(&token);
    let scan = scan_path(&state.wallet_dir, &token);
    let _ = std::fs::rename(&scan, format!("{scan}.bak"));
    log::info!("wallet '{token}': rescan requested — checkpoint retired, will reload from birthday");
    // Return NOW. Reloading a wallet means a fast-sync anchor fetch and a scan
    // from birthday; doing that inline would hold the request open for minutes and
    // starve the HTTP path (the 2026-07-12 "wallet won't connect" outage). The
    // next status/balance poll — or the background sync loop — reloads it lazily.
    Ok(Json(serde_json::json!({ "rescanning": true })))
}

/// Pack an optional UTF-8 memo into the fixed 512-byte Orchard memo field.
fn memo_bytes(m: Option<&str>) -> Result<[u8; 512], (StatusCode, Json<serde_json::Value>)> {
    let mut out = [0u8; 512];
    if let Some(m) = m {
        let b = m.as_bytes();
        if b.len() > 512 {
            return Err(err(StatusCode::BAD_REQUEST, "memo too long (max 512 bytes)"));
        }
        out[..b.len()].copy_from_slice(b);
    }
    Ok(out)
}

/// Matured spend candidates for a wallet, EXCLUDING stranded notes — notes whose
/// leaves were compacted away with no surviving witness (the note@564934
/// incident: pending-spend → base compaction → reclaim left a note below the
/// base). A stranded note can never produce a witness path from local state, so
/// including it fails the entire payment with "matured note has no witness path"
/// even though every other note is spendable. Selection skips them; their value
/// is returned so error messages can be honest about funds that exist on-chain
/// but need a state graft (`--graft`) to spend. Unsorted — callers order.
fn matured_candidates(db: &WalletDb, matured: u64) -> (Vec<&OwnedNote>, u64) {
    let stranded = db.stranded_notes();
    let stranded_value: u64 = stranded.iter().map(|n| n.value()).sum();
    if stranded_value > 0 {
        log::warn!(
            "spend selection: skipping {} stranded note(s) worth {} sompi (below base {}, no witness) — recoverable only by grafting older wallet state",
            stranded.len(),
            stranded_value,
            db.base_size(),
        );
    }
    let skip: HashSet<u64> = stranded.iter().map(|n| n.position).collect();
    let candidates = db.notes().iter().filter(|n| n.position < matured && !skip.contains(&n.position)).collect();
    (candidates, stranded_value)
}

/// One line of honesty appended to "insufficient funds" errors when part of the
/// wallet's balance is stranded (see [`matured_candidates`]).
fn stranded_hint(stranded_value: u64) -> String {
    if stranded_value == 0 {
        String::new()
    } else {
        format!(
            "; note: {} ZKAS of this wallet is temporarily unspendable (stranded by an old state bug — contact support to recover it)",
            fmt_fc(stranded_value as u128)
        )
    }
}

/// Prove that a loaded wallet's commitment tree is exactly the node's canonical
/// tree at the wallet cursor. Height/freshness alone cannot establish this: a
/// legacy checkpoint may be near-tip yet contain bundles consensus dropped.
async fn ensure_canonical_checkpoint(
    state: &Arc<AppState>,
    w: &Wallet,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let (cursor, wallet_size, wallet_anchor) = {
        let e = w.lock().await;
        (e.low, e.db.size(), e.db.anchor())
    };
    let ts = tokio::time::timeout(SYNC_RPC_TIMEOUT, state.client.get_shielded_tree_state(Some(cursor)))
        .await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "node timed out while validating the wallet checkpoint; retry"))?
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("cannot validate wallet checkpoint: {e}")))?;
    let fs = FrontierState {
        size: ts.size,
        leaf: (ts.size > 0).then(|| ts.leaf.as_bytes()),
        ommers: ts.ommers.iter().map(|o| o.as_bytes()).collect(),
    };
    let node_anchor = GlobalTree::from_state(&fs)
        .map_err(|_| err(StatusCode::BAD_GATEWAY, "node returned an invalid shielded frontier"))?
        .anchor()
        .to_bytes();
    if wallet_size != fs.size || wallet_anchor != node_anchor {
        let mut e = w.lock().await;
        e.reorged_strikes = REORG_STRIKES;
        e.error = Some("wallet checkpoint diverged from canonical shielded state; repairing from chain".into());
        log::error!(
            "wallet checkpoint divergence at {cursor}: wallet size/root {}/{}, node size/root {}/{}; marked for repair",
            wallet_size,
            hex(&wallet_anchor),
            fs.size,
            hex(&node_anchor),
        );
        return Err(err(
            StatusCode::CONFLICT,
            "wallet checkpoint was created by an older broken sync path and differs from canonical chain state; automatic repair started—wait for sync before sending",
        ));
    }
    Ok(())
}

async fn wallet_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SendReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, state.allow_default_token)?;
    let w = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no wallet loaded"))?;
    ensure_canonical_checkpoint(&state, &w).await?;
    let node_tip = state.node_tip.lock().await.0;
    let (seed, recoverable) = {
        let e = w.lock().await;
        // `scanned` intentionally trails the live tip by SYNC_TIP_MARGIN: blocks
        // newer than that are previewed but not committed to the append-only tree.
        // Treat that normal settlement lag (plus two poll margins) as current.
        // `sink_blue` is a blue score while `node_tip` is DAA score, so comparing
        // those counters directly is invalid and used to reject healthy wallets.
        if node_tip == 0
            || (e.scanned as u64).saturating_add(SYNC_TIP_MARGIN + 2 * SYNC_MARGIN) < node_tip
            || e.reorged_strikes > 0
        {
            return Err(err(
                StatusCode::CONFLICT,
                format!(
                    "wallet is still updating its canonical chain view (wallet DAA {}, node DAA {}); wait for sync before sending",
                    e.scanned, node_tip
                ),
            ));
        }
        (e.key.seed()?, e.recoverable_history)
    };
    let memo = memo_bytes(req.memo.as_deref())?;

    let amount = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    // Floor fee: plan_chunks raises each chunk's fee to the node's
    // byte-proportional minimum for however many notes that chunk spends.
    let fee = req.fee.unwrap_or(DEFAULT_FEE_SOMPI);

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
    let insufficient = |have: u64, stranded: u64| {
        err(
            StatusCode::CONFLICT,
            format!(
                "insufficient matured funds: have {have}, need {need}+ (amount {amount} + a {fee} fee per tx; funds must be ~10 min old to spend){}",
                stranded_hint(stranded)
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
    let mut planned: Option<(Vec<(Vec<_>, u64, Vec<u64>, u64)>, u64, bool, u64)> = None;
    {
        let mut e = w.lock().await;
        // Top up the live witnesses to the current matured anchor (a no-op unless a
        // block landed since the last sync tick), so witnessing below is a lookup.
        // block_in_place: this is CPU-bound Sinsemilla; run inline on the async
        // runtime it can capture the tokio I/O driver and freeze ALL of HTTP.
        tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded());
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
            let (mut candidates, stranded_value) = matured_candidates(&e.db, matured);
            candidates.sort_by(|a, b| b.value().cmp(&a.value()));
            let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
            let have: u64 = values.iter().sum();
            match plan_chunks(&values, amount, fee, max_per_tx) {
                Some(plan) => {
                    let mut chunks = Vec::with_capacity(plan.len());
                    let mut idx = 0usize;
                    for (n_notes, pay, cfee) in plan {
                        let mut inputs = Vec::with_capacity(n_notes);
                        let mut positions = Vec::with_capacity(n_notes);
                        for note in &candidates[idx..idx + n_notes] {
                            // block_in_place: a cold note's on-demand rebuild is an
                            // O(chain) Sinsemilla replay — must not pin a runtime worker.
                            let path = tokio::task::block_in_place(|| e.db.witness_path_at(note.position, matured))
                                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                            inputs.push((note.note.clone(), path));
                            positions.push(note.position);
                        }
                        idx += n_notes;
                        chunks.push((inputs, pay, positions, cfee));
                    }
                    planned = Some((chunks, have, e.caught_up, stranded_value));
                }
                None => planned = Some((Vec::new(), have, e.caught_up, stranded_value)),
            }
        }
    }

    let chunks = match planned {
        // A complete plan at the wallet's own anchor — the fast, no-rescan path.
        Some((chunks, _, _, _)) if !chunks.is_empty() => chunks,
        // Planning failed but the wallet is caught up to the tip, so a full replay
        // would see the exact same matured notes: authoritative insufficient.
        Some((_, have, true, stranded)) => return Err(insufficient(have, stranded)),
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
            let plan = plan_chunks(&values, amount, fee, max_per_tx).ok_or_else(|| insufficient(have, 0))?;
            let mut chunks = Vec::with_capacity(plan.len());
            let mut idx = 0usize;
            for (n_notes, pay, cfee) in plan {
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
                chunks.push((inputs, pay, positions, cfee));
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
    let mut total_fee = 0u64;
    for (ci, (inputs, pay, positions, cfee)) in chunks.into_iter().enumerate() {
        log::info!("send: building Orchard proof for tx {}/{tx_count} ({} spends, {pay} sompi + {cfee} fee)...", ci + 1, inputs.len());
        let ctx2 = ctx.clone();
        let started = std::time::Instant::now();
        // The memo rides on the first chunk only — one memo per logical payment.
        let chunk_memo = if ci == 0 { memo } else { [0u8; 512] };
        let payload = tokio::task::spawn_blocking(move || {
            build_wallet_payment(seed, inputs, recipient, pay, cfee, &net, &ctx2, recoverable, chunk_memo)
        })
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build payment: {e:?}")))?;
        log::info!("send: tx {}/{tx_count} proven in {:.0?}", ci + 1, started.elapsed());

        let tx: Transaction = payment_tx(payload);
        match client.submit_transaction(RpcTransaction::from(&tx), false).await {
            Ok(accepted) => {
                txids.push(accepted.to_string());
                sent += pay;
                total_fee += cfee;
                let mut e = w.lock().await;
                // The wallet's scan cursor is its chain clock — available whether or
                // not the node serves block metadata, unlike WalletDb's own.
                let now_daa = e.scanned as u64;
                for p in positions {
                    e.db.mark_spent(p, accepted.as_bytes(), now_daa);
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

    Ok(Json(SendResp {
        txid: txids[0].clone(),
        amount_sompi: amount,
        fee_sompi: total_fee,
        amount_sompi_exact: amount.to_string(),
        fee_sompi_exact: total_fee.to_string(),
        txids,
        tx_count,
    }))
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
    let (seed, recoverable) = {
        let e = w.lock().await;
        (e.key.seed()?, e.recoverable_history)
    };
    let base_fee = body.and_then(|Json(b)| b.fee).unwrap_or(DEFAULT_FEE_SOMPI);
    let own_recipient =
        address_bytes_from_seed(seed).ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "seed is not a valid spending key"))?;

    let net: [u8; 32] = state.genesis.as_bytes();

    // Select up to a tx-full of the smallest matured notes under the entry lock.
    let (inputs, positions, sum, fee) = {
        let e = w.lock().await;
        let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
        let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) else {
            return Err(err(StatusCode::CONFLICT, "wallet is still syncing the maturity window; try again shortly"));
        };
        let (mut candidates, _stranded) = matured_candidates(&e.db, matured);
        candidates.sort_by_key(|n| n.value());
        candidates.truncate(max_spends_per_tx());
        let sum: u64 = candidates.iter().map(|n| n.value()).sum();
        if candidates.len() < 2 {
            return Err(err(StatusCode::CONFLICT, "nothing to consolidate: fewer than 2 matured notes"));
        }
        // A full consolidation tx is the biggest standard tx there is — its fee
        // must clear the node's byte-proportional minimum for that size.
        let fee = chunk_fee(base_fee, candidates.len());
        if sum <= fee {
            return Err(err(StatusCode::CONFLICT, format!("smallest notes sum to {sum}, not more than the {fee} fee")));
        }
        let mut inputs = Vec::with_capacity(candidates.len());
        let mut positions = Vec::with_capacity(candidates.len());
        for n in &candidates {
            // block_in_place: an on-demand rebuild is an O(chain) Sinsemilla replay —
            // must not pin a runtime worker (it can hold the tokio I/O driver).
            let path = tokio::task::block_in_place(|| e.db.witness_path_at(n.position, matured))
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
            inputs.push((n.note.clone(), path));
            positions.push(n.position);
        }
        (inputs, positions, sum, fee)
    };

    let consolidated = inputs.len();
    let value = sum - fee;
    let ctx = payment_tx_context();
    log::info!("consolidate: merging {consolidated} notes ({sum} sompi) into one...");
    let payload = tokio::task::spawn_blocking(move || {
        build_wallet_payment(seed, inputs, own_recipient, value, fee, &net, &ctx, recoverable, [0u8; 512])
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("proof task failed: {e}")))?
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build consolidation: {e:?}")))?;

    let tx: Transaction = payment_tx(payload);
    match state.client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            let mut e = w.lock().await;
            let now_daa = e.scanned as u64;
            for p in positions {
                e.db.mark_spent(p, accepted.as_bytes(), now_daa);
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
#[serde(untagged)]
enum JsonU64 {
    Number(u64),
    Decimal(String),
}

impl JsonU64 {
    fn parse(self, field: &'static str) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
        match self {
            Self::Number(value) => Ok(value),
            Self::Decimal(value) => {
                value.parse().map_err(|_| err(StatusCode::BAD_REQUEST, format!("{field} must be an unsigned 64-bit decimal integer")))
            }
        }
    }
}

#[derive(Deserialize)]
struct PrepareReq {
    /// 96-byte full viewing key (hex). Grants viewing capability, not spend.
    fvk_hex: String,
    /// Recipient `zkas:` shielded address.
    to: String,
    amount_sompi: Option<JsonU64>,
    amount_fc: Option<f64>,
    fee: Option<JsonU64>,
    /// Optional memo (max 512 bytes UTF-8), as in `SendReq`.
    memo: Option<String>,
    /// Opt in to a partial payment when the amount needs more notes than one standard
    /// transaction can spend. The response's `remaining_sompi` is what is still owed;
    /// the caller repeats prepare/submit until it reaches 0.
    allow_partial: Option<bool>,
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
    amount_sompi_exact: String,
    fee_sompi_exact: String,
    /// Sompi of the originally requested amount this payment does NOT cover, because it
    /// needed more notes than one standard transaction can spend. 0 for a complete
    /// payment. Only ever non-zero when the caller passed `allow_partial`.
    remaining_sompi: u64,
    remaining_sompi_exact: String,
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
    /// Stable SDK envelope. Legacy fields above remain during the compatibility
    /// window; new clients should deserialize and verify this object.
    #[serde(rename = "preparedPayment")]
    prepared_payment: PreparedPaymentEnvelope,
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

    // A duplicate prepare for THIS wallet is a retry or a double-click — reject it fast,
    // since it would select the same notes as the run already in flight.
    let _preparing = {
        let mut set = state
            .preparing
            .lock()
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare tracker poisoned"))?;
        if !set.insert(req.fvk_hex.clone()) {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "a payment from this wallet is already being prepared; wait for it to finish before retrying",
            ));
        }
        PreparingGuard { state: state.clone(), key: req.fvk_hex.clone() }
    };

    // Then queue for the proving slot shared with every other wallet. Waiting here is
    // correct: another tenant's send is not this caller's error.
    let _prepare_permit = tokio::time::timeout(PREPARE_QUEUE_WAIT, state.prepare_gate.acquire())
        .await
        .map_err(|_| {
            err(StatusCode::SERVICE_UNAVAILABLE, "the daemon is still busy preparing other payments; please try again shortly")
        })?
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare gate closed"))?;

    // Watch-only: authenticated by possession of the FVK, not a token/seed.
    let fvk_bytes = unhex(&req.fvk_hex)
        .and_then(|b| <[u8; FVK_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex must be 96 bytes of hex"))?;

    let requested = match (req.amount_sompi, req.amount_fc) {
        (Some(s), _) => s.parse("amount_sompi")?,
        (None, Some(fc)) => (fc * SOMPI_PER_ZKAS as f64).round() as u64,
        (None, None) => return Err(err(StatusCode::BAD_REQUEST, "specify amount_sompi or amount_fc")),
    };
    // A standard transaction spends at most `max_spends_per_tx()` notes, so a wallet
    // whose balance is spread over many small notes (a miner's per-block coinbase, say)
    // cannot pay a large amount in one transaction. `allow_partial` lets the caller ask
    // for "as much of this as one transaction can carry", then repeat for the remainder
    // — which is what the custodial `/send` path has always done internally via
    // `plan_chunks`. It is OPT-IN precisely because already-shipped wallets do not loop:
    // silently sending them a partial payment while reporting success would be the same
    // class of bug as the missing `mark_spent`. Callers that don't ask still get the
    // explicit "send in smaller chunks" error.
    let allow_partial = req.allow_partial.unwrap_or(false);
    let mut amount = requested;
    // The caller's fee (or the flat default) is a FLOOR: the actual fee is raised
    // to the node's byte-proportional minimum once the input count is known
    // (`select_spend_count`), so multi-note payments are never relay-rejected.
    let base_fee = match req.fee {
        Some(fee) => fee.parse("fee")?,
        None => DEFAULT_FEE_SOMPI,
    };
    let mut fee = chunk_fee(base_fee, 1);

    let client = &state.client;
    let net: [u8; 32] = state.genesis.as_bytes();

    let to_addr =
        Address::try_from(req.to.as_str()).map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid recipient address: {e}")))?;
    let recipient = orchard_recipient_bytes(&to_addr)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "recipient is not a shielded Orchard address"))?;
    let mut need = amount.checked_add(fee).ok_or_else(|| err(StatusCode::BAD_REQUEST, "amount + fee overflows"))?;

    let max_per_tx = max_spends_per_tx();

    // Fast path: if the caller also presents the wallet token this key is registered
    // under (the app always does), the sync loop is already holding a live, matured
    // view of exactly this wallet — reuse it and spend straight from it. Without this
    // every send re-walked the chain watch-only first (measured: 3m24s on a 174K-block
    // chain), which on a phone reads as a hung app; the proof itself is ~7s.
    let mut inputs = Vec::new();
    let mut selected = 0u64;
    let mut have_total: Option<u64> = None;
    // Notes this payment will spend, so `/submit` can park them once the node accepts.
    // Only the tracked-wallet path below can fill these: the FVK-only slow path has no
    // wallet to record against.
    let mut spent_positions: Vec<u64> = Vec::new();
    let mut session_token: Option<String> = None;
    let current_node_tip = state.node_tip.lock().await.0;
    if let Ok(token) = token_from(&headers, state.allow_default_token) {
        if let Some(w) = state.get_wallet(&token).await {
            ensure_canonical_checkpoint(&state, &w).await?;
            let mut e = w.lock().await;
            if e.db.fvk().to_bytes() == fvk_bytes {
                let node_tip = current_node_tip;
                if node_tip == 0
                    || (e.scanned as u64).saturating_add(SYNC_TIP_MARGIN + 2 * SYNC_MARGIN) < node_tip
                    || e.reorged_strikes > 0
                {
                    return Err(err(
                        StatusCode::CONFLICT,
                        format!(
                            "wallet is still updating its canonical chain view (wallet DAA {}, node DAA {}); wait for sync before sending",
                            e.scanned, node_tip
                        ),
                    ));
                }
                let matured_leaves = e.matured_leaves().unwrap_or(0);
                let warm_before = e.db.witnessed_upto();
                let climb = matured_leaves.saturating_sub(warm_before);
                let t_w = std::time::Instant::now();
                // Bounded + block_in_place: the uncapped inline climb here is what froze
                // the whole daemon for ~50 min on 2026-07-17 (3,304-note wallet).
                tokio::task::block_in_place(|| e.advance_spend_witnesses_bounded());
                log::info!(
                    "prepare: witness advance took {:.1?} (notes={}, base_size={}, witnessed_upto {}→{} of matured {}, climbed {} leaves; {} at send time)",
                    t_w.elapsed(),
                    e.db.notes().len(),
                    e.db.base_size(),
                    warm_before,
                    e.db.witnessed_upto(),
                    matured_leaves,
                    climb,
                    if climb == 0 { "WARM — background pre-advance kept up" } else { "COLD — witnesses were behind" },
                );
                let cutoff_blue = e.sink_blue.saturating_sub(DEFAULT_ANCHOR_DEPTH + ANCHOR_SLACK);
                if let Some(matured) = e.boundaries.iter().rev().find(|(bs, _)| *bs <= cutoff_blue).map(|&(_, lc)| lc) {
                    let (mut candidates, _stranded) = matured_candidates(&e.db, matured);
                    candidates.sort_by(|a, b| b.value().cmp(&a.value()));
                    have_total = Some(candidates.iter().map(|n| n.value()).sum());
                    let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
                    let (take, dyn_fee) = select_spend_count(&values, amount, base_fee, max_per_tx);
                    fee = dyn_fee;
                    need = amount.saturating_add(fee);
                    for n in candidates.iter().take(take) {
                        let t_p = std::time::Instant::now();
                        // block_in_place: a cold note's rebuild is an O(chain) Sinsemilla
                        // replay — must not pin a runtime worker.
                        let path = tokio::task::block_in_place(|| e.db.witness_path_at(n.position, matured))
                            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
                        log::info!("prepare: witness_path_at(note@{}) took {:.1?}", n.position, t_p.elapsed());
                        inputs.push((n.note.clone(), path));
                        spent_positions.push(n.position);
                        selected += n.value();
                    }
                    session_token = Some(token.clone());
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
        let values: Vec<u64> = candidates.iter().map(|n| n.value()).collect();
        let (take, dyn_fee) = select_spend_count(&values, amount, base_fee, max_per_tx);
        fee = dyn_fee;
        need = amount.saturating_add(fee);
        for n in candidates.iter().take(take) {
            let path = db
                .witness_path(n.position)
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "matured note has no witness path"))?;
            inputs.push((n.note.clone(), path));
            selected += n.value();
        }
    }
    if selected < need {
        let have: u64 = have_total.unwrap_or(0);
        // The notes exist, they just don't fit one transaction. Pay what this
        // transaction can carry and report the rest, if the caller opted in.
        let capacity = selected.saturating_sub(fee);
        // Chunking is only safe on the tracked-wallet path. The FVK-only slow path has
        // no wallet to record the spend against, so `/submit` cannot park the notes —
        // the caller's next chunk would re-select the very same notes value-descending
        // and build a transaction consensus drops as a double-spend, silently. Without a
        // token we refuse to chunk and return the explicit error instead.
        if allow_partial && session_token.is_some() && have >= need && capacity > 0 {
            // Change is then exactly zero: the chunk pays out every selected note less
            // the fee. `need` is not reassigned — past this point only `amount`/`fee`
            // matter, `prepare_payment` derives the change from the inputs themselves.
            amount = capacity;
            log::info!(
                "prepare: partial chunk — paying {amount} of {requested} sompi with {} note(s); {} sompi remain",
                inputs.len(),
                requested - amount,
            );
        } else {
            return Err(if have >= need {
                err(
                    StatusCode::CONFLICT,
                    format!(
                        "amount needs more than {max_per_tx} input notes (standard tx size cap): max sendable in one tx is {capacity} sompi; send in smaller chunks",
                    ),
                )
            } else {
                err(
                    StatusCode::CONFLICT,
                    format!("insufficient matured funds: have {have}, need amount+fee={need} (funds must be ~10 min old to spend)"),
                )
            });
        }
    }

    let ctx = payment_tx_context();
    log::info!("non-custodial prepare: building Orchard payment proof (Halo 2) for {} spends...", inputs.len());
    let fvk = WalletDb::from_fvk(&fvk_bytes)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "fvk_hex is not a valid full viewing key"))?
        .fvk()
        .clone();
    // The per-wallet recoverable-history flag lives in the wallet file; prepare is
    // keyed by FVK, so resolve it via the (optional) token — default on.
    let recoverable = token_from(&headers, state.allow_default_token)
        .ok()
        .and_then(|t| load_wallet_meta(&state.wallet_dir, &t, state.wallet_secret.as_deref()))
        .map(|(_, _, r)| r)
        .unwrap_or(true);
    let memo = memo_bytes(req.memo.as_deref())?;
    let t_proof = std::time::Instant::now();
    let payment =
        tokio::task::spawn_blocking(move || prepare_payment(&fvk, inputs, recipient, amount, fee, &net, &ctx, recoverable, memo))
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

    let sdk_network = match state.network.as_str() {
        "testnet" => SdkNetwork::Testnet,
        "devnet" => SdkNetwork::Devnet,
        "simnet" => SdkNetwork::Simnet,
        _ => SdkNetwork::Mainnet,
    };
    let prepared_payment = PreparedPaymentEnvelope::from_typed(
        &SdkPreparedPayment {
            version: SdkPreparedPayment::VERSION,
            network_domain: net,
            tx_context: payment_tx_context(),
            bundle: payment.effects.clone(),
            disclosure: payment.disclosure.clone(),
            spend_auth: payment
                .spend_auth_requests
                .iter()
                .map(|(action_index, alpha)| SdkSpendAuthRequest { action_index: *action_index, alpha: *alpha })
                .collect(),
            // What this payment IS, embedded so a detached signer can display and
            // verify it from the envelope alone. The device cross-checks these
            // against the user's approval and the bundle — lying here only makes
            // the device refuse to sign.
            claimed: SdkClaimedIntent { recipient, amount, fee },
        },
        &sdk_network,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("failed to build prepared envelope: {e}")))?;

    // Park the awaiting-signature payment under a random, unguessable session id.
    let mut sid = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut sid);
    let session = hex(&sid);
    {
        let now = std::time::Instant::now();
        let mut map = state.prepared.lock().await;
        map.retain(|_, s| now.duration_since(s.created) < PREPARED_TTL); // bound memory
        map.insert(
            session.clone(),
            PreparedSession { payment, amount, fee, created: now, token: session_token, positions: spent_positions },
        );
    }

    Ok(Json(PrepareResp {
        session,
        sighash: sighash_hex,
        value_balance,
        amount_sompi: amount,
        fee_sompi: fee,
        remaining_sompi: requested - amount,
        remaining_sompi_exact: (requested - amount).to_string(),
        amount_sompi_exact: amount.to_string(),
        fee_sompi_exact: fee.to_string(),
        spend_auth,
        bundle_hex,
        disclosure,
        prepared_payment,
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
    let PreparedSession { payment, amount, fee, token, positions, .. } =
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
            // The node has the transaction: park the notes it spends so they leave the
            // unspent set NOW rather than ~3 minutes from now when the block carrying
            // them clears the reorg holdback. Parking (not deleting) is what makes this
            // safe — `reclaim_expired` returns the notes if the transaction never lands.
            // Skipping this is what let a second send inside that window re-select the
            // same notes and build a transaction consensus drops as a double-spend.
            if let Some(token) = token {
                if let Some(w) = state.get_wallet(&token).await {
                    let mut e = w.lock().await;
                    let now_daa = e.scanned as u64;
                    for p in &positions {
                        e.db.mark_spent(*p, accepted.as_bytes(), now_daa);
                    }
                    log::info!("submit: parked {} spent note(s) for tx {}", positions.len(), accepted);
                }
            }
            let txid = accepted.to_string();
            Ok(Json(SendResp {
                txid: txid.clone(),
                amount_sompi: amount,
                fee_sompi: fee,
                amount_sompi_exact: amount.to_string(),
                fee_sompi_exact: fee.to_string(),
                txids: vec![txid],
                tx_count: 1,
            }))
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

/// Default wallet directory (`~/.zkas/wallets` — the pre-rebrand path is kept
/// so existing wallet files keep working).
pub fn default_wallet_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.zkas/wallets")
}

/// Run the daemon until `shutdown` resolves (hold the sender forever to run
/// forever). Returns once the HTTP server has stopped and the background loops are
/// aborted, so an embedding process (the desktop app) can call `serve` again with a
/// new config — e.g. after the user switches nodes.
pub async fn serve(cfg: Config, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<(), String> {
    let listen = cfg.listen;
    let wallet_dir = cfg.wallet_dir;
    let _ = std::fs::create_dir_all(&wallet_dir);

    // Two node connections: one for the request path, one for the background sync loop,
    // so heavy sync traffic can't stall user wallet loads. Retry until the node is up —
    // but stay interruptible, so an embedder can cancel while the node is unreachable.
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
    let client = tokio::select! {
        c = connect_node(&cfg.rpc_server, "request") => c,
        _ = &mut shutdown => return Ok(()),
    };
    let sync_client = tokio::select! {
        c = connect_node(&cfg.rpc_server, "sync") => c,
        _ = &mut shutdown => return Ok(()),
    };
    log::info!("connected to node at {} (2 connections: request + sync)", cfg.rpc_server);

    let wallet_secret = cfg.wallet_secret;
    if wallet_secret.is_none() {
        log::warn!("no wallet secret set: seed files are stored in PLAINTEXT (0600 on unix)");
    }
    if cfg.allow_default_token {
        log::warn!("allow_default_token: tokenless requests map to the 'default' wallet; use only on a trusted single-user localhost");
    }

    // The network genesis hash — the shielded sighash domain consensus verifies
    // against, and the checkpoint guard. Taken from the compile-time network
    // params (identical to what consensus signs against); resolving it over RPC
    // (`get_blocks(None)`) fails on any pruned node, whose genesis chain data is
    // gone.
    let genesis = RpcHash::from_bytes(
        kaspa_consensus_core::config::params::Params::from(state_prefix_network(&cfg.network)).genesis.hash.as_bytes(),
    );
    log::info!("network genesis (shielded sighash domain): {genesis}");

    let state = Arc::new(AppState {
        client,
        sync_client,
        wallet_dir,
        prefix: prefix_from(&cfg.network),
        network: cfg.network,
        wallets: Mutex::new(HashMap::new()),
        allow_default_token: cfg.allow_default_token,
        wallet_secret,
        genesis,
        page_cache: Mutex::new(PageCache::new()),
        last_touch: Mutex::new(HashMap::new()),
        load_gate: tokio::sync::Semaphore::new(2),
        // Two concurrent preparations: proving is CPU-heavy, but a single global permit
        // meant one tenant's send serialised every other tenant's on a shared daemon.
        prepare_gate: tokio::sync::Semaphore::new(2),
        preparing: std::sync::Mutex::new(HashSet::new()),
        warm_gate: tokio::sync::Semaphore::new(WARM_CONCURRENCY),
        node_tip: Mutex::new((0, std::time::Instant::now())),
        prepared: Mutex::new(HashMap::new()),
        snapshots: Mutex::new(HashMap::new()),
        fvk_index: Mutex::new(HashMap::new()),
    });

    // Index every existing wallet's viewing key in the background (argon2 per
    // encrypted seed file — a blocking thread, not the startup path), then MERGE
    // into the live index so registrations that landed while it built survive.
    // Until it finishes, adoption just misses and a restore scans as before.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let (dir, secret) = (state.wallet_dir.clone(), state.wallet_secret.clone());
            let started = std::time::Instant::now();
            if let Ok(map) = tokio::task::spawn_blocking(move || build_fvk_index(&dir, secret.as_deref())).await {
                let mut idx = state.fvk_index.lock().await;
                let wallets = map.values().map(|s| s.len()).sum::<usize>();
                for (k, tokens) in map {
                    idx.entry(k).or_default().extend(tokens);
                }
                log::info!(
                    "viewing-key index ready: {} keys / {wallets} wallets in {:.1?} (twin-checkpoint adoption armed)",
                    idx.len(),
                    started.elapsed()
                );
            }
        });
    }

    let sync_task = tokio::spawn(sync_loop(state.clone()));
    // Unmined payments — the instant-payment path. Separate from sync_loop on purpose
    // (see mempool_loop): it must never queue behind block scanning.
    let mempool_task = tokio::spawn(mempool_loop(state.clone()));

    // Keep the cached node tip fresh independently of loaded wallets, so `status` can
    // report node connectivity + chain height without ever calling the node on the
    // request path (which was contended by the sync loop and made status take ~4s).
    let tip_task = {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(d) = state.client.get_block_dag_info().await {
                    *state.node_tip.lock().await = (d.virtual_daa_score, std::time::Instant::now());
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        })
    };

    // Build the (deterministic, process-wide) Orchard proving key now, off the
    // async runtime, so the first send doesn't eat the multi-minute keygen.
    std::thread::spawn(|| {
        let started = std::time::Instant::now();
        let _ = proving_key();
        log::info!("Orchard proving key ready in {:.0?} (max {} spends per standard tx)", started.elapsed(), max_spends_per_tx());
    });

    // Lock CORS to an explicit browser-origin allowlist. With no allowed origin given
    // the list is empty, so cross-origin browser reads are refused (same-origin only):
    // a random page a user visits can no longer read /reveal or call /send. We also
    // drop allow_private_network(true) so a public site can't reach the loopback daemon.
    let origins: Vec<HeaderValue> = cfg
        .allow_origin
        .iter()
        .filter_map(|o| match o.parse::<HeaderValue>() {
            Ok(hv) => Some(hv),
            Err(_) => {
                log::error!("ignoring invalid allow_origin {o:?}");
                None
            }
        })
        .collect();
    log::info!("CORS allowed origins: {:?}", cfg.allow_origin);
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
        .route("/api/wallet/history", get(wallet_history))
        .route("/api/wallet/settings", post(wallet_settings))
        .route("/api/wallet/rescan", post(wallet_rescan))
        .route("/api/wallet/send", post(wallet_send))
        .route("/api/wallet/consolidate", post(wallet_consolidate))
        .route("/api/wallet/prepare", post(wallet_prepare))
        .route("/api/wallet/submit", post(wallet_submit))
        .route("/api/wallet/sign", post(wallet_sign))
        .route("/api/verify", post(verify))
        .layer(cors)
        .with_state(state);

    log::info!("zkas-walletd listening on http://{listen}");
    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("failed to bind {listen}: {e}"))?;
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
        })
        .await
        .map_err(|e| format!("server error: {e}"));
    // The loops hold node connections and wallet state; kill them so a re-`serve`
    // starts clean instead of double-scanning the same wallet files.
    sync_task.abort();
    mempool_task.abort();
    tip_task.abort();
    result
}

#[cfg(test)]
mod sdk_api_tests {
    use super::*;

    #[test]
    fn prepare_accepts_exact_decimal_u64_values() {
        let request: PrepareReq = serde_json::from_value(serde_json::json!({
            "fvk_hex": "00",
            "to": "zkas:test",
            "amount_sompi": "18446744073709551615",
            "fee": "3000000"
        }))
        .unwrap();
        assert_eq!(request.amount_sompi.unwrap().parse("amount_sompi").unwrap(), u64::MAX);
        assert_eq!(request.fee.unwrap().parse("fee").unwrap(), 3_000_000);
    }

    #[test]
    fn prepare_keeps_legacy_numeric_values_compatible() {
        let request: PrepareReq = serde_json::from_value(serde_json::json!({
            "fvk_hex": "00",
            "to": "zkas:test",
            "amount_sompi": 100,
            "fee": 3
        }))
        .unwrap();
        assert_eq!(request.amount_sompi.unwrap().parse("amount_sompi").unwrap(), 100);
        assert_eq!(request.fee.unwrap().parse("fee").unwrap(), 3);
    }

    /// A backup must restore the SAME wallet on another device, and must refuse
    /// a wrong passphrase, a foreign file, and clobbering a live wallet. A
    /// backup that cannot restore is worse than no backup — the user believes
    /// they are covered.
    #[test]
    fn backup_roundtrips_and_refuses_bad_input() {
        let tmp = std::env::temp_dir().join(format!("zkas-backup-test-{}", std::process::id()));
        let dir = tmp.to_string_lossy().to_string();
        std::fs::create_dir_all(&dir).unwrap();
        let seed = [0x5au8; 32];

        // A device wallet encrypted under the device passphrase.
        save_seed(&dir, "src", "mainnet", &seed, 4242, Some("device-passphrase")).unwrap();
        assert_eq!(vault_state(&dir, "src"), VaultState::Encrypted);

        let json = export_backup(&dir, "src", Some("device-passphrase"), "backup-passphrase").unwrap();
        // The backup must not be readable without its own passphrase.
        assert!(!json.contains(&hex(&seed)), "backup must not carry the seed in the clear");

        // Restoring on a "new device" (a different wallet dir) recovers the seed.
        let dir2 = format!("{dir}-restore");
        std::fs::create_dir_all(&dir2).unwrap();
        import_backup(&dir2, "dst", &json, "backup-passphrase", "new-device-pass").unwrap();
        let (key, birthday, _) = load_wallet_meta(&dir2, "dst", Some("new-device-pass")).unwrap();
        assert_eq!(birthday, 4242, "birthday survives so the restore does not rescan from genesis");
        match key {
            WalletKey::Seed(s) => assert_eq!(s, seed, "restored seed is identical"),
            WalletKey::Fvk(_) => panic!("expected a seed wallet"),
        }
        assert_eq!(vault_state(&dir2, "dst"), VaultState::Encrypted, "restored wallet is encrypted at rest");

        // Wrong backup passphrase, foreign file, and clobbering are all refused.
        let dir3 = format!("{dir}-neg");
        std::fs::create_dir_all(&dir3).unwrap();
        assert!(import_backup(&dir3, "x", &json, "not-the-passphrase", "new-device-pass").is_err());
        assert!(import_backup(&dir3, "x", "{\"hello\":1}", "backup-passphrase", "new-device-pass").is_err());
        assert!(
            import_backup(&dir2, "dst", &json, "backup-passphrase", "new-device-pass").is_err(),
            "must not overwrite an existing wallet"
        );

        // Wrong DEVICE passphrase cannot export.
        assert!(export_backup(&dir, "src", Some("wrong"), "backup-passphrase").is_err());

        // A legacy cleartext wallet encrypts in place, then still exports.
        save_seed(&dir, "legacy", "mainnet", &seed, 0, None).unwrap();
        assert_eq!(vault_state(&dir, "legacy"), VaultState::Plaintext);
        encrypt_wallet_in_place(&dir, "legacy", "device-passphrase").unwrap();
        assert_eq!(vault_state(&dir, "legacy"), VaultState::Encrypted);
        assert!(verify_wallet_secret(&dir, "legacy", "device-passphrase"));
        assert!(!verify_wallet_secret(&dir, "legacy", "nope"));
        assert!(export_backup(&dir, "legacy", Some("device-passphrase"), "backup-passphrase").is_ok());

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&dir2).ok();
        std::fs::remove_dir_all(&dir3).ok();
    }

    /// "Enter the seed on a second device → synced at once": a registration whose
    /// viewing key another token already scanned must clone that checkpoint, and
    /// the clone must parse under EITHER key form (the desktop imported the seed;
    /// the phone registers only the FVK — same wallet, same checkpoint).
    #[test]
    fn twin_checkpoint_adoption_clones_and_verifies() {
        let tmp = std::env::temp_dir().join(format!("zkas-adopt-test-{}", std::process::id()));
        let dir = tmp.to_string_lossy().to_string();
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let genesis = RpcHash::from_bytes([7u8; 32]);
        let seed = [0x5au8; 32];
        let db = WalletDb::from_seed(seed).expect("valid seed");
        let fvk = db.fvk().to_bytes();

        // Donor: a seed wallet with a persisted, complete-view checkpoint.
        save_seed(&dir, "donor", "mainnet", &seed, 4242, None).unwrap();
        let boundaries: VecDeque<(u64, u64)> = VecDeque::from([(100, 0)]);
        save_checkpoint(&dir, "donor", &genesis, &RpcHash::from_bytes([9u8; 32]), 777, &db, &boundaries, 100, 0).unwrap();

        // The index build finds the donor by viewing key.
        let index = build_fvk_index(&dir, None);
        assert_eq!(index.get(&fvk).map(|s| s.contains("donor")), Some(true), "index must find the donor by FVK");
        let candidates: Vec<String> = index.get(&fvk).unwrap().iter().cloned().collect();

        // A fresh FVK registration adopts the donor's checkpoint, keeping the
        // EARLIER birthday so a later cold rescan can't skip either wallet's notes.
        let (donor, birthday) =
            adopt_twin_checkpoint(&dir, "phone", &fvk, 9999, &genesis, None, &candidates).expect("must adopt");
        assert_eq!(donor, "donor");
        assert_eq!(birthday, 4242, "keeps the earlier of donor/requested birthdays");
        let restored = load_checkpoint(&dir, "phone", WalletKey::Fvk(fvk), &genesis, None)
            .expect("clone parses under the FVK key form");
        assert_eq!(restored.2, 777, "scanned-block cursor survives the clone");

        // A DIFFERENT key must never adopt, however many donors exist.
        let other = WalletDb::from_seed([0x33u8; 32]).unwrap().fvk().to_bytes();
        assert!(
            adopt_twin_checkpoint(&dir, "other", &other, 0, &genesis, None, &candidates).is_none(),
            "foreign viewing key must not clone someone else's checkpoint"
        );

        // A donor that is BLIND below its fast-sync base must not serve a
        // birthday-0 restore (which asked for the complete history)...
        save_checkpoint(&dir, "donor", &genesis, &RpcHash::from_bytes([9u8; 32]), 777, &db, &boundaries, 100, 555).unwrap();
        std::fs::remove_file(scan_path(&dir, "phone")).unwrap();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 0, &genesis, None, &candidates).is_none(),
            "a blind donor must not answer a full-history restore"
        );
        // ...but may serve a restore that asked for the same-or-later birthday.
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 5000, &genesis, None, &candidates).is_some(),
            "a blind donor is fine for a restore born at/after the donor"
        );

        // A wrong-genesis (relaunched-chain) checkpoint must never be adopted.
        std::fs::remove_file(scan_path(&dir, "phone")).unwrap();
        assert!(
            adopt_twin_checkpoint(&dir, "phone", &fvk, 9999, &RpcHash::from_bytes([8u8; 32]), None, &candidates).is_none(),
            "checkpoint for another chain must not be adopted"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The SDK republishes this daemon's timing constants and genesis so that
    /// external wallets hold back / anchor exactly like the production engine.
    /// They are separate definitions in separate crates — this is the tripwire
    /// that keeps them the same numbers.
    #[test]
    fn sdk_network_config_matches_walletd_and_consensus() {
        let cfg = zkas_sdk::NetworkConfig::mainnet();
        assert_eq!(cfg.settlement_blue_score, SYNC_TIP_MARGIN, "SDK settlement margin drifted from walletd");
        assert_eq!(cfg.anchor_depth, DEFAULT_ANCHOR_DEPTH, "SDK anchor depth drifted from walletd");
        assert_eq!(
            cfg.genesis,
            kaspa_consensus_core::config::params::MAINNET_PARAMS.genesis.hash.as_bytes(),
            "SDK genesis drifted from consensus"
        );
    }
}
