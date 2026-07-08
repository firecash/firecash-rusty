//! `shielded-pay` — a live shielded-payment client for the firecash network
//! (PLAN §2.10, blocker #2). It closes the last gap between the shielded wallet
//! primitives and a running node: it reconstructs a mined coinbase note, builds a
//! **real** Orchard spend of it (Halo 2 proof + spend-auth signature) paying a
//! recipient, wraps it in the canonical version-2 shielded transaction, and
//! submits it over gRPC — the same `submit_transaction` path any wallet uses.
//!
//! ## Spend maturity (~10 minutes, all networks)
//!
//! A shielded spend must prove its input note into a **matured** anchor (PLAN
//! §2.5): consensus rejects a spend whose anchor is not yet deep enough
//! (`ShieldedManagerError::UnfinalizedAnchor`). Maturity is governed by the
//! `shielded_anchor_depth` consensus parameter — the anchor as of the chain block
//! `600 * BPS` blue-score units below the sink (~10 minutes at 10 BPS). This is
//! deliberately **decoupled from chain finality** (`finality_depth`, ~12 h): a
//! freshly-mined coinbase note is spendable within ~10 minutes on mainnet, devnet
//! and every other network, while finality/pruning security is unchanged. The
//! trade-off is that spend safety rests on a ~10-minute confirmation window rather
//! than full finality — a reorg deeper than that (economically implausible under
//! GHOSTDAG at 10 BPS) could invalidate a matured anchor. This mirrors the
//! confirmation-depth model every chain uses, just applied to the shielded pool.
//!
//! ## Why the coinbase note, single-leaf
//!
//! The first coinbase note ever minted sits at tree position 0, so its
//! authentication path is the trivial single-leaf path and its anchor is exactly
//! the minting block's anchor. This is the wallet operation with the smallest
//! witness-tracking surface, so it is the one we drive live first (mirrors
//! `consensus::…::real_shielded_spend_through_mined_block`). The client itself is
//! network-agnostic; once the note is ~10 minutes deep, the spend is accepted.

use clap::{Parser, Subcommand};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::{Transaction, TX_VERSION_SHIELDED};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode, RpcHash, RpcTransaction};
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::coinbase::derive_coinbase_note_desc;
use kaspa_shielded_core::message::{sign_message, verify_message, FVK_LEN, SIG_LEN};
use kaspa_shielded_core::orchard_recipient_bytes;
use kaspa_shielded_core::wallet::build::{build_singleleaf_coinbase_spend, build_wallet_payment};
use kaspa_shielded_core::wallet::address_bytes_from_seed;
use kaspa_shielded_core::walletdb::WalletDb;
use kaspa_shielded_wallet::{payment_tx, payment_tx_context};

/// The shielded output script length for a `Version::ShieldedOrchard` address:
/// the 43 raw Orchard address bytes carried in a coinbase reward's script.
const ORCHARD_SCRIPT_LEN: usize = 43;

/// Default shielded-spend anchor maturity (blue-score depth) — must match the
/// consensus `shielded_anchor_depth` (`600 * BPS`, i.e. 6000 at 10 BPS, ~10 min).
/// A note is spendable once its minting block is this deep below the sink.
const DEFAULT_ANCHOR_DEPTH: u64 = 6000;

#[derive(Parser, Debug)]
#[command(name = "shielded-pay", about = "Build and submit a real shielded payment over RPC (firecash)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print the bech32 shielded (Orchard) address for a wallet seed on a network —
    /// e.g. to hand to the miner as `--mining-address`.
    Address {
        /// Seed byte: the 32-byte wallet seed is `[byte; 32]` (matches the test wallets).
        #[arg(long)]
        seed_byte: u8,
        /// Network prefix: mainnet | testnet | devnet | simnet.
        #[arg(long, default_value = "devnet")]
        network: String,
    },
    /// Print the node's current virtual DAA score (a proxy for chain height /
    /// blue score on a young single-chain devnet). Used to gate a spend on the
    /// note having matured past `shielded_anchor_depth` (~10 min at 10 BPS).
    Info {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
        rpc_server: String,
    },
    /// List the transaction ids currently in the node's mempool (transaction pool).
    /// Used to confirm a submitted shielded payment is subsequently mined (leaves
    /// the mempool).
    Mempool {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
        rpc_server: String,
    },
    /// Scan the whole accepted chain, discover every note owned by the wallet seed,
    /// and report the spendable balance and each note's position/value. This is the
    /// real wallet's receive side: it mirrors the consensus note stream and keeps a
    /// witness per owned note (via `WalletDb`), so it works for arbitrary notes, not
    /// just the first coinbase.
    Balance {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
        rpc_server: String,
        /// Wallet seed byte (32-byte seed is `[byte; 32]`).
        #[arg(long)]
        seed_byte: u8,
    },
    /// Real wallet payment: scan the chain, pick a **matured** owned note, and pay
    /// `--amount` to `--to`, returning the change to the sender and leaving `--fee`
    /// for the miner. Spends against the finalized anchor `--anchor-depth` blocks
    /// deep, so the note must be at least that old.
    Send {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
        rpc_server: String,
        /// Wallet seed byte of the sender (the note owner).
        #[arg(long)]
        owner_seed_byte: u8,
        /// Recipient bech32 shielded address.
        #[arg(long)]
        to: String,
        /// Amount to pay the recipient (base units).
        #[arg(long)]
        amount: u64,
        /// Public fee left as the bundle's value balance, collected by the miner.
        #[arg(long, default_value_t = 3_000_000)]
        fee: u64,
        /// Anchor maturity depth in blocks (must match consensus shielded_anchor_depth).
        #[arg(long, default_value_t = DEFAULT_ANCHOR_DEPTH)]
        anchor_depth: u64,
    },
    /// Sign a message with a wallet seed, proving control of the wallet's shielded
    /// address WITHOUT spending. Offline (no node needed). The signature discloses
    /// the wallet's full viewing key (needed to bind the signature to the address on
    /// a shielded chain, where the address itself carries no verification key) — this
    /// grants note-detection capability but never spend authority.
    Sign {
        /// Wallet seed byte (32-byte seed is `[byte; 32]`).
        #[arg(long)]
        seed_byte: u8,
        /// Network prefix: mainnet | testnet | devnet | simnet (scopes the signature).
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// The message to sign.
        #[arg(long)]
        message: String,
    },
    /// Verify a message signature against a shielded address (offline). Confirms the
    /// signer controls `--address` and signed exactly `--message`.
    Verify {
        /// The bech32 shielded address the signature claims to own.
        #[arg(long)]
        address: String,
        /// The message that was signed.
        #[arg(long)]
        message: String,
        /// The signature hex from `sign` (full-viewing-key ‖ signature).
        #[arg(long)]
        sig: String,
    },
    /// Spend the first coinbase note (tree position 0) minted to `--owner-seed-byte`
    /// and pay it to `--to`, submitting the shielded transaction over gRPC.
    Pay {
        /// kaspad gRPC endpoint (host:port).
        #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
        rpc_server: String,
        /// Seed byte of the wallet that mined the coinbase note (the note owner).
        #[arg(long)]
        owner_seed_byte: u8,
        /// Recipient bech32 shielded address (use the `address` subcommand to derive one).
        #[arg(long)]
        to: String,
        /// Public fee left as the bundle's value balance, collected by the miner.
        #[arg(long, default_value_t = 2_000)]
        fee: u64,
    },
}

fn prefix_from(network: &str) -> Prefix {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Prefix::Mainnet,
        "testnet" => Prefix::Testnet,
        "devnet" => Prefix::Devnet,
        "simnet" => Prefix::Simnet,
        other => {
            log::error!("unknown network {other:?} (expected mainnet|testnet|devnet|simnet)");
            std::process::exit(1);
        }
    }
}

/// Derive the bech32 shielded address string for a seed on a network. Uses
/// `String::from(&addr)` (not `Display`, which appends a `(ShieldedOrchard)` tag).
fn address_string(seed_byte: u8, prefix: Prefix) -> String {
    let raw = address_bytes_from_seed([seed_byte; 32]).unwrap_or_else(|| {
        log::error!("seed byte {seed_byte} is not a valid Orchard spending key");
        std::process::exit(1);
    });
    String::from(&Address::new(prefix, Version::ShieldedOrchard, &raw))
}

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

/// A minted coinbase note located on-chain: the note at global tree position 0.
struct Position0Note {
    coinbase_txid: RpcHash,
    out_index: u32,
    value: u64,
    block: RpcHash,
}

/// Walk the selected chain from genesis and return the first coinbase note ever
/// minted (global tree position 0). The genesis-merging block mints no note, so we
/// scan chain blocks in order and take the first coinbase carrying a shielded
/// (43-byte) output — matching the order consensus appends notes to the tree.
async fn find_position0_note(client: &GrpcClient, genesis: RpcHash) -> Position0Note {
    let chain = client
        .get_virtual_chain_from_block(genesis, false, None)
        .await
        .unwrap_or_else(|e| fatal(format!("get_virtual_chain_from_block failed: {e}")));

    for hash in chain.added_chain_block_hashes {
        if hash == genesis {
            continue;
        }
        let block = client.get_block(hash, true).await.unwrap_or_else(|e| fatal(format!("get_block failed: {e}")));
        let Some(coinbase) = block.transactions.first() else { continue };
        for (out_index, output) in coinbase.outputs.iter().enumerate() {
            if output.script_public_key.script().len() == ORCHARD_SCRIPT_LEN {
                let coinbase_txid = coinbase
                    .verbose_data
                    .as_ref()
                    .unwrap_or_else(|| fatal("coinbase tx missing verbose_data (transaction id)".into()))
                    .transaction_id;
                return Position0Note { coinbase_txid, out_index: out_index as u32, value: output.value, block: hash };
            }
        }
    }
    fatal("no coinbase note minted yet — mine some blocks first".into())
}

fn fatal(msg: String) -> ! {
    log::error!("{msg}");
    std::process::exit(1);
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

/// Sign a message with a wallet seed, proving control of the wallet's shielded
/// address. Offline. Prints the address, the message, and the signature hex.
fn sign(seed_byte: u8, network: String, message: String) {
    let prefix = prefix_from(&network);
    let tag = prefix.to_string();
    let signed = sign_message([seed_byte; 32], tag.as_bytes(), message.as_bytes(), rand::rngs::OsRng)
        .unwrap_or_else(|| fatal(format!("seed byte {seed_byte} is not a valid Orchard spending key")));

    let addr = String::from(&Address::new(prefix, Version::ShieldedOrchard, &signed.address));
    // The signature blob is `fvk (96) || sig (64)`; the fvk binds it to the address.
    let mut blob = Vec::with_capacity(FVK_LEN + SIG_LEN);
    blob.extend_from_slice(&signed.fvk);
    blob.extend_from_slice(&signed.sig);

    println!("address:   {addr}");
    println!("message:   {message}");
    println!("signature: {}", hex(&blob));
    eprintln!(
        "note: this signature discloses the wallet's viewing key (fvk). It proves \
         ownership and lets others detect this wallet's notes, but reveals NO spend authority."
    );
}

/// Verify a message signature against a shielded address. Offline. Exits non-zero
/// if the signature does not prove control of the address over the message.
fn verify(address: String, message: String, sig: String) {
    let addr = Address::try_from(address.as_str()).unwrap_or_else(|e| fatal(format!("invalid --address {address:?}: {e}")));
    let tag = addr.prefix.to_string();
    let raw = orchard_recipient_bytes(&addr).unwrap_or_else(|| fatal("--address is not a shielded Orchard address".into()));

    let blob = unhex(&sig).unwrap_or_else(|| fatal("--sig is not valid hex".into()));
    if blob.len() != FVK_LEN + SIG_LEN {
        fatal(format!("--sig must be {} hex bytes (fvk||sig); got {}", FVK_LEN + SIG_LEN, blob.len()));
    }
    let fvk: [u8; FVK_LEN] = blob[..FVK_LEN].try_into().expect("checked length");
    let s: [u8; SIG_LEN] = blob[FVK_LEN..].try_into().expect("checked length");

    match verify_message(&raw, tag.as_bytes(), message.as_bytes(), &fvk, &s) {
        Ok(()) => println!("VALID: signature proves control of {address}"),
        Err(e) => {
            println!("INVALID: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Build a [`WalletDb`] by replaying the accepted chain's shielded effects in
/// consensus order (PLAN §2.9/§2.10). For every accepted chain block it feeds the
/// coinbase notes (each output's `(recipient, txid||index)` derivation, exactly as
/// consensus mints them) and then the block's accepted shielded bundles, so the
/// wallet's mirrored tree, note positions and witnesses match the node's.
///
/// `ingest_blocks` caps how many chain blocks (after genesis) to replay: `None`
/// walks to the tip (full balance view); `Some(k)` stops at block `k`, so the
/// wallet's anchor is the tree root as of block `k` — used to root a spend to a
/// **finalized** anchor. Returns the db and the total accepted chain length.
///
/// Note (single-chain assumption): this feeds each chain block's own body. On a
/// linear chain (blue_score == index) that is exactly consensus's accepted set and
/// order. Handling wide-DAG mergeset acceptance order is the remaining item in the
/// real-wallet task.
async fn scan_chain(client: &GrpcClient, seed: [u8; 32], ingest_blocks: Option<usize>) -> (WalletDb, usize) {
    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let genesis = dag.pruning_point_hash;

    let mut db = WalletDb::from_seed(seed).unwrap_or_else(|| fatal("seed is not a valid Orchard spending key".into()));
    let limit = ingest_blocks.unwrap_or(usize::MAX);

    // Page through the chain with the batch `get_blocks` RPC (each call returns many
    // blocks in topological order after `low`), rather than one round-trip per block.
    // On a linear chain that order is the accepted-note order consensus uses.
    let mut low = genesis;
    let mut count = 0usize;
    loop {
        if count >= limit {
            break;
        }
        let resp = client
            .get_blocks(Some(low), true, true)
            .await
            .unwrap_or_else(|e| fatal(format!("get_blocks from {low} failed: {e}")));
        let mut advanced = false;
        for (hash, block) in resp.block_hashes.iter().zip(resp.blocks.iter()) {
            // Skip the page anchor (`low`, re-sent as the first element) and genesis.
            if *hash == low || *hash == genesis {
                continue;
            }
            if count >= limit {
                break;
            }
            ingest_rpc_block(&mut db, block);
            count += 1;
            advanced = true;
        }
        let last = resp.block_hashes.last().copied();
        match last {
            Some(h) if h != low && advanced => low = h,
            _ => break, // no progress -> reached the tip
        }
    }
    (db, count)
}

/// Feed one RPC block's shielded effects into the wallet in consensus order:
/// coinbase notes (each output's `(recipient, txid||index)` derivation, exactly as
/// consensus mints them), then the block's accepted shielded (v2) transactions.
fn ingest_rpc_block(db: &mut WalletDb, block: &kaspa_rpc_core::RpcBlock) {
    let mut coinbase_notes = Vec::new();
    if let Some(cb) = block.transactions.first() {
        let txid = cb
            .verbose_data
            .as_ref()
            .unwrap_or_else(|| fatal("coinbase tx missing verbose_data (transaction id)".into()))
            .transaction_id;
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

    let mut bundles = Vec::new();
    for tx in block.transactions.iter().skip(1) {
        if tx.version == TX_VERSION_SHIELDED {
            match ShieldedBundle::from_bytes(&tx.payload) {
                Ok(b) => bundles.push(b),
                Err(e) => log::warn!("skipping undecodable shielded payload: {e:?}"),
            }
        }
    }
    let bundle_refs: Vec<&ShieldedBundle> = bundles.iter().collect();
    db.ingest_block(&coinbase_notes, &bundle_refs);
}

async fn balance(rpc_server: String, seed_byte: u8) {
    let client = connect(&rpc_server).await;
    log::info!("scanning accepted chain for notes owned by seed {seed_byte}...");
    let (db, total) = scan_chain(&client, [seed_byte; 32], None).await;
    log::info!("scanned {total} accepted chain blocks; anchor(tip) = {}", hex32(&db.anchor()));
    println!("balance: {} ({} note(s))", db.balance(), db.notes().len());
    for n in db.notes() {
        println!("  note position={} value={}", n.position, n.value());
    }
}

async fn send(rpc_server: String, owner_seed_byte: u8, to: String, amount: u64, fee: u64, anchor_depth: u64) {
    let client = connect(&rpc_server).await;

    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let genesis = dag.pruning_point_hash;
    let net: [u8; 32] = genesis.as_bytes();

    // Root the spend to a finalized anchor: ingest only up to the block at the
    // maturity depth (a small margin below it for safety). Every anchor at or below
    // that block has been published into the node's finalized ring. On a linear
    // chain the virtual DAA score equals the chain length (blue score).
    let chain_len = dag.virtual_daa_score as usize;
    let margin = 2usize;
    let need_len = anchor_depth as usize + margin;
    if chain_len <= need_len {
        fatal(format!("chain too short ({chain_len} blocks): no note has matured past anchor_depth {anchor_depth} yet"));
    }
    let ingest_limit = chain_len - need_len;
    log::info!("scanning to matured block {ingest_limit}/{chain_len} (anchor_depth {anchor_depth})...");
    let db = scan_chain(&client, [owner_seed_byte; 32], Some(ingest_limit)).await.0;

    let to_addr = Address::try_from(to.as_str()).unwrap_or_else(|e| fatal(format!("invalid --to address {to:?}: {e}")));
    let recipient = orchard_recipient_bytes(&to_addr).unwrap_or_else(|| fatal("--to is not a shielded Orchard address".into()));

    // Select matured notes to cover amount + fee: greedily take the largest notes
    // first, so the fewest inputs are needed (a smaller, cheaper proof).
    let need = amount.checked_add(fee).unwrap_or_else(|| fatal("amount + fee overflows".into()));
    let mut candidates: Vec<_> = db.notes().to_vec();
    candidates.sort_by(|a, b| b.value().cmp(&a.value())); // descending
    let mut inputs = Vec::new();
    let mut selected = 0u64;
    for n in &candidates {
        if selected >= need {
            break;
        }
        let path = db.witness_path(n.position).unwrap_or_else(|| fatal("matured note has no witness path".into()));
        inputs.push((n.note.clone(), path));
        selected += n.value();
        log::info!("  input: note position={} value={}", n.position, n.value());
    }
    if selected < need {
        fatal(format!(
            "insufficient matured funds: have {selected} across {} matured note(s), need amount+fee={need} (total balance {})",
            inputs.len(),
            db.balance()
        ));
    }
    log::info!(
        "spending {} matured note(s) totalling {} (change {}) against anchor {}",
        inputs.len(),
        selected,
        selected - need,
        hex32(&db.anchor())
    );

    let ctx = payment_tx_context();
    log::info!("building real Orchard payment proof (Halo 2) — this takes a few seconds...");
    let payload = build_wallet_payment([owner_seed_byte; 32], inputs, recipient, amount, fee, &net, &ctx)
        .unwrap_or_else(|e| fatal(format!("failed to build wallet payment: {e:?}")));

    let tx: Transaction = payment_tx(payload);
    let txid = tx.id();
    log::info!("assembled shielded payment tx {txid} (amount={amount}, fee={fee}); submitting over RPC...");
    match client.submit_transaction(RpcTransaction::from(&tx), false).await {
        Ok(accepted) => {
            log::info!("ACCEPTED: node admitted shielded payment {accepted} to the mempool");
            println!("{accepted}");
        }
        Err(e) => fatal(format!("submit_transaction rejected the shielded payment: {e}")),
    }
}

async fn pay(rpc_server: String, owner_seed_byte: u8, to: String, fee: u64) {
    let client = connect(&rpc_server).await;

    // The sighash's network separator is the chain's genesis hash; on a young chain
    // the pruning point is still genesis, so we read it straight from the node.
    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let genesis = dag.pruning_point_hash;
    let net: [u8; 32] = genesis.as_bytes();
    log::info!("network domain (genesis) = {genesis}, virtual daa = {}", dag.virtual_daa_score);

    // Locate the position-0 coinbase note on-chain.
    let note = find_position0_note(&client, genesis).await;
    log::info!(
        "position-0 coinbase note: block={} txid={} out={} value={}",
        note.block,
        note.coinbase_txid,
        note.out_index,
        note.value
    );

    // Recipient address -> raw 43-byte Orchard recipient.
    let to_addr = Address::try_from(to.as_str()).unwrap_or_else(|e| fatal(format!("invalid --to address {to:?}: {e}")));
    let recipient = orchard_recipient_bytes(&to_addr).unwrap_or_else(|| fatal("--to is not a shielded Orchard address".into()));

    let output_value = note.value.checked_sub(fee).unwrap_or_else(|| fatal(format!("fee {fee} exceeds note value {}", note.value)));

    // The bundle binds its signatures to the canonical shielded-tx sighash context;
    // it is payload-independent, so we compute it before building the (heavy) proof.
    let tx_ctx = payment_tx_context();

    log::info!("building real Orchard spend proof (Halo 2) — this takes a few seconds...");
    let payload = build_singleleaf_coinbase_spend(
        [owner_seed_byte; 32],
        note.coinbase_txid.as_bytes(),
        note.out_index,
        note.value,
        recipient,
        output_value,
        &net,
        &tx_ctx,
    )
    .unwrap_or_else(|e| fatal(format!("failed to build shielded spend: {e:?}")));

    // Wrap into the canonical version-2 shielded transaction and submit it.
    let tx: Transaction = payment_tx(payload);
    let txid = tx.id();
    log::info!("assembled shielded tx {txid} (value_out={output_value}, fee={fee}); submitting over RPC...");
    let rpc_tx = RpcTransaction::from(&tx);

    match client.submit_transaction(rpc_tx, false).await {
        Ok(accepted) => {
            log::info!("ACCEPTED: node admitted shielded payment {accepted} to the mempool");
            println!("{accepted}");
        }
        Err(e) => fatal(format!("submit_transaction rejected the shielded payment: {e}")),
    }
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    match Cli::parse().cmd {
        Cmd::Address { seed_byte, network } => {
            println!("{}", address_string(seed_byte, prefix_from(&network)));
        }
        Cmd::Info { rpc_server } => {
            let client = connect(&rpc_server).await;
            let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
            // Print just the score on stdout so a script can capture it directly.
            println!("{}", dag.virtual_daa_score);
        }
        Cmd::Mempool { rpc_server } => {
            let client = connect(&rpc_server).await;
            // (include_orphan_pool=false, filter_transaction_pool=false) => the
            // transaction pool only (see RpcCoreService::extract_tx_query).
            let entries = client
                .get_mempool_entries(false, false)
                .await
                .unwrap_or_else(|e| fatal(format!("get_mempool_entries failed: {e}")));
            for entry in entries {
                // `RpcTransaction::id()` recomputes the id from the tx itself.
                println!("{}", Transaction::try_from(entry.transaction).map(|t| t.id().to_string()).unwrap_or_default());
            }
        }
        Cmd::Balance { rpc_server, seed_byte } => {
            balance(rpc_server, seed_byte).await;
        }
        Cmd::Send { rpc_server, owner_seed_byte, to, amount, fee, anchor_depth } => {
            send(rpc_server, owner_seed_byte, to, amount, fee, anchor_depth).await;
        }
        Cmd::Sign { seed_byte, network, message } => {
            sign(seed_byte, network, message);
        }
        Cmd::Verify { address, message, sig } => {
            verify(address, message, sig);
        }
        Cmd::Pay { rpc_server, owner_seed_byte, to, fee } => {
            pay(rpc_server, owner_seed_byte, to, fee).await;
        }
    }
}
