//! `firecash-api` — the FireCash explorer backend.
//!
//! Translates a running FireCash node's gRPC interface into the small REST +
//! shielded-pool API the explorer frontend (a fork of kaspa-explorer-ng) consumes,
//! and follows the chain tip to maintain a live "recent blocks" feed and a running
//! shielded-pool aggregate (notes minted, nullifiers spent, value shielded).
//!
//! It intentionally does NOT stand up the full kaspa-rest-server + Postgres stack:
//! on a shielded-by-default chain most transparent address/UTXO data is empty, so
//! the meaningful surface is blocks/DAG/coinbase plus the FireCash-specific
//! `/info/shielded` endpoint — all servable straight from the node.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode, RpcBlock, RpcHash};
use kaspa_shielded_core::bundle::ShieldedBundle;
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

/// Orchard (shielded) recipient script length in a coinbase output.
const ORCHARD_SCRIPT_LEN: usize = 43;
/// Coinbase-payload offset where the 32-byte shielded state-root commitment sits
/// (after blue_score(8) + subsidy(8)); see consensus `processes/coinbase.rs`.
const COMMITMENT_OFFSET: usize = 16;
const SOMPI_PER_FC: u64 = 100_000_000;
/// Terminal FireCash supply, whole FC (~5.15B).
const MAX_SUPPLY_FC: u64 = 5_150_000_000;
/// Blocks per halving ≈ 3 months at 10 BPS (90d · 86400s · 10).
const HALVING_INTERVAL_BLOCKS: u64 = 77_760_000;
/// How many recent blocks to keep in the live feed ring.
const RECENT_CAP: usize = 200;

#[derive(Parser, Debug)]
#[command(name = "firecash-api", about = "FireCash explorer backend (gRPC → REST)")]
struct Cli {
    /// kaspad (FireCash) gRPC endpoint.
    #[arg(short = 's', long, default_value = "127.0.0.1:16110")]
    rpc_server: String,
    /// Address to serve the HTTP API on.
    #[arg(short = 'l', long, default_value = "127.0.0.1:8500")]
    listen: String,
}

/// One block as the frontend's live feed expects it.
#[derive(Clone, serde::Serialize)]
struct BlockSummary {
    block_hash: String,
    difficulty: f64,
    #[serde(rename = "blueScore")]
    blue_score: String,
    timestamp: String,
    #[serde(rename = "txCount")]
    tx_count: u64,
    txs: Vec<TxSummary>,
}

#[derive(Clone, serde::Serialize)]
struct TxSummary {
    #[serde(rename = "txId")]
    tx_id: String,
    /// `[amount, label]` pairs; on a shielded chain the label is "shielded".
    outputs: Vec<[String; 2]>,
}

/// Running shielded-pool aggregate, advanced as the follower ingests blocks.
#[derive(Default, Clone)]
struct ShieldedAgg {
    note_count: u64,
    nullifier_count: u64,
    turnstile_in_sompi: u128,
    emission_per_block_fc: f64,
    state_root: String,
    blue_score: u64,
}

struct AppState {
    client: GrpcClient,
    recent: RwLock<VecDeque<BlockSummary>>,
    shielded: RwLock<ShieldedAgg>,
    network_name: String,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn fatal(msg: String) -> ! {
    log::error!("{msg}");
    std::process::exit(1);
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
    .unwrap_or_else(|e| fatal(format!("failed to connect to {address}: {e}")))
}

/// Read the u64 subsidy (sompi) a coinbase paid, from bytes 8..16 of its payload.
fn coinbase_subsidy_sompi(block: &RpcBlock) -> Option<u64> {
    let cb = block.transactions.first()?;
    if cb.payload.len() < 16 {
        return None;
    }
    Some(u64::from_le_bytes(cb.payload[8..16].try_into().ok()?))
}

/// Read the 32-byte shielded state-root commitment from a coinbase payload.
fn coinbase_state_root(block: &RpcBlock) -> Option<String> {
    let cb = block.transactions.first()?;
    let end = COMMITMENT_OFFSET + 32;
    if cb.payload.len() < end {
        return None;
    }
    Some(cb.payload[COMMITMENT_OFFSET..end].iter().map(|b| format!("{b:02x}")).collect())
}

/// Turn an `RpcBlock` into the summary the live feed serves, and fold its shielded
/// effects into `agg`.
fn ingest(block: &RpcBlock, agg: &mut ShieldedAgg) -> BlockSummary {
    let vd = block.verbose_data.as_ref();
    let blue_score = vd.map(|v| v.blue_score).unwrap_or(block.header.blue_score);
    let difficulty = vd.map(|v| v.difficulty).unwrap_or(0.0);

    let mut txs = Vec::new();
    for (i, tx) in block.transactions.iter().enumerate() {
        let tx_id = tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default();
        let mut outputs = Vec::new();

        if i == 0 {
            // Coinbase: each Orchard-scripted output mints a shielded note.
            for out in &tx.outputs {
                let is_shielded = out.script_public_key.script().len() == ORCHARD_SCRIPT_LEN;
                if is_shielded {
                    agg.note_count += 1;
                    agg.turnstile_in_sompi += out.value as u128;
                }
                outputs.push([out.value.to_string(), if is_shielded { "shielded".into() } else { "transparent".into() }]);
            }
        } else if tx.version == TX_VERSION_SHIELDED {
            // Shielded transfer: each Orchard action is a spend (nullifier) + an
            // output note (cmx).
            if let Ok(bundle) = ShieldedBundle::from_bytes(&tx.payload) {
                let n = bundle.actions.len() as u64;
                agg.nullifier_count += n;
                agg.note_count += n;
                outputs.push([n.to_string(), "shielded".into()]);
            }
        } else {
            for out in &tx.outputs {
                outputs.push([out.value.to_string(), "transparent".into()]);
            }
        }
        txs.push(TxSummary { tx_id, outputs });
    }

    if let Some(sub) = coinbase_subsidy_sompi(block) {
        agg.emission_per_block_fc = sub as f64 / SOMPI_PER_FC as f64;
    }
    if let Some(root) = coinbase_state_root(block) {
        agg.state_root = root;
    }
    agg.blue_score = agg.blue_score.max(blue_score);

    BlockSummary {
        block_hash: block.header.hash.to_string(),
        difficulty,
        blue_score: blue_score.to_string(),
        timestamp: block.header.timestamp.to_string(),
        tx_count: block.transactions.len() as u64,
        txs,
    }
}

/// Follow the chain tip: pre-seed from near the sink, then poll for new blocks,
/// updating the recent-block ring and the shielded aggregate.
async fn follow(state: Arc<AppState>) {
    let sink = match state.client.get_block_dag_info().await {
        Ok(dag) => dag.sink,
        Err(e) => {
            log::warn!("get_block_dag_info failed at startup: {e}");
            return;
        }
    };

    // Pre-fill the recent feed by walking selected parents back from the sink.
    // These blocks don't mutate the aggregate (a throwaway scratch soaks the fold);
    // the aggregate is seeded from chain totals below and advanced only forward.
    let mut backfill: Vec<RpcBlock> = Vec::new();
    let mut cursor = sink;
    for _ in 0..RECENT_CAP {
        match state.client.get_block(cursor, true).await {
            Ok(b) => {
                let parent = b.verbose_data.as_ref().map(|v| v.selected_parent_hash);
                backfill.push(b);
                match parent {
                    Some(p) if p != RpcHash::default() => cursor = p,
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }
    backfill.reverse(); // oldest → newest

    // Seed cumulative counters from chain totals so history is right without
    // replaying every block: on a shielded chain every block mints one coinbase
    // note, so noteCount ≈ blueScore and value-shielded ≈ blueScore × subsidy.
    // (No shielded spends on mainnet yet ⇒ nullifierCount starts at 0 and is
    // advanced exactly by the forward follower.)
    {
        let mut agg = state.shielded.write().await;
        if let Some(sink_block) = backfill.last() {
            if let Some(sub) = coinbase_subsidy_sompi(sink_block) {
                agg.emission_per_block_fc = sub as f64 / SOMPI_PER_FC as f64;
                if let Ok(dag) = state.client.get_block_dag_info().await {
                    agg.blue_score = dag.virtual_daa_score;
                    agg.note_count = dag.virtual_daa_score;
                    agg.turnstile_in_sompi = dag.virtual_daa_score as u128 * sub as u128;
                }
            }
            if let Some(root) = coinbase_state_root(sink_block) {
                agg.state_root = root;
            }
        }
        let mut scratch = ShieldedAgg::default();
        let mut recent = state.recent.write().await;
        for b in &backfill {
            let summary = ingest(b, &mut scratch);
            recent.push_front(summary);
            if recent.len() > RECENT_CAP {
                recent.pop_back();
            }
        }
    }
    log::info!("seeded {} recent blocks; following tip...", backfill.len());

    // Poll forward from the last block we have.
    let mut low = sink;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let resp = match state.client.get_blocks(Some(low), true, true).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("get_blocks failed: {e}");
                continue;
            }
        };
        let mut advanced = false;
        for (hash, block) in resp.block_hashes.iter().zip(resp.blocks.iter()) {
            if *hash == low {
                continue; // page anchor re-sent as first element
            }
            let mut agg = state.shielded.write().await;
            let summary = ingest(block, &mut agg);
            drop(agg);
            let mut recent = state.recent.write().await;
            recent.push_front(summary);
            if recent.len() > RECENT_CAP {
                recent.pop_back();
            }
            advanced = true;
        }
        if let Some(last) = resp.block_hashes.last().copied() {
            if last != low && advanced {
                low = last;
            }
        }
    }
}

// ---- REST handlers ----

async fn info_blockdag(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match s.client.get_block_dag_info().await {
        Ok(d) => Json(json!({
            "networkName": s.network_name,
            "blockCount": d.block_count.to_string(),
            "headerCount": d.header_count.to_string(),
            "tipHashes": d.tip_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "difficulty": d.difficulty,
            "pastMedianTime": d.past_median_time.to_string(),
            "virtualParentHashes": d.virtual_parent_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "pruningPointHash": [d.pruning_point_hash.to_string()],
            "virtualDaaScore": d.virtual_daa_score.to_string(),
            "sink": d.sink.to_string(),
        }))
        .into_response(),
        Err(e) => err(e.to_string()),
    }
}

async fn info_coinsupply(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // On a shielded chain the node's UTXO-based coin supply is 0 (no transparent
    // outputs); the real circulating supply is the value that has entered the
    // shielded pool via coinbase (the turnstile-in total).
    let circulating = { s.shielded.read().await.turnstile_in_sompi };
    Json(json!({
        "circulatingSupply": circulating.to_string(),
        "maxSupply": (MAX_SUPPLY_FC as u128 * SOMPI_PER_FC as u128).to_string(),
    }))
    .into_response()
}

async fn info_blockreward(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let agg = s.shielded.read().await;
    Json(json!({ "blockreward": agg.emission_per_block_fc })).into_response()
}

async fn info_halving(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let (blue_score, subsidy) = {
        let agg = s.shielded.read().await;
        (agg.blue_score, agg.emission_per_block_fc)
    };
    let next_h = ((blue_score / HALVING_INTERVAL_BLOCKS) + 1) * HALVING_INTERVAL_BLOCKS;
    let blocks_left = next_h.saturating_sub(blue_score);
    let secs_left = blocks_left / 10; // 10 BPS
    let ts = now_secs() + secs_left;
    let days = secs_left / 86400;
    Json(json!({
        "nextHalvingTimestamp": ts,
        "nextHalvingDate": format!("in ~{days} days"),
        "nextHalvingAmount": subsidy / 2.0,
    }))
    .into_response()
}

async fn info_shielded(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let agg = s.shielded.read().await;
    Json(json!({
        "anchor": if agg.state_root.is_empty() { Value::Null } else { json!(agg.state_root) },
        "nullifierCount": agg.nullifier_count,
        "noteCount": agg.note_count,
        "turnstileIn": agg.turnstile_in_sompi.to_string(),
        "turnstileOut": "0",
        "emissionPerBlock": agg.emission_per_block_fc,
        "blueScore": agg.blue_score.to_string(),
    }))
    .into_response()
}

async fn info_feeestimate() -> impl IntoResponse {
    // FireCash shielded txs carry a flat public fee; expose a nominal estimate.
    Json(json!({
        "priorityBucket": { "feerate": 1.0, "estimateSeconds": 1.0 },
        "normalBuckets": [{ "feerate": 1.0, "estimateSeconds": 1.0 }],
        "lowBuckets": [{ "feerate": 1.0, "estimateSeconds": 2.0 }],
    }))
}

async fn info_marketdata() -> impl IntoResponse {
    // No market for a young chain.
    StatusCode::NO_CONTENT
}

async fn transactions_count(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Approximate: one coinbase per block; regular ≈ ingested shielded spends.
    let (blue_score, nullifiers) = {
        let agg = s.shielded.read().await;
        (agg.blue_score, agg.nullifier_count)
    };
    Json(json!({
        "timestamp": now_secs() * 1000,
        "dateTime": "",
        "coinbase": blue_score,
        "regular": nullifiers,
    }))
}

async fn blocks_recent(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let recent = s.recent.read().await;
    Json(recent.iter().cloned().collect::<Vec<_>>())
}

async fn block_by_id(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    let hash = match id.parse::<RpcHash>() {
        Ok(h) => h,
        Err(_) => return err("invalid block hash".into()),
    };
    match s.client.get_block(hash, true).await {
        Ok(b) => {
            let vd = b.verbose_data.as_ref();
            Json(json!({
                "block_hash": b.header.hash.to_string(),
                "header": {
                    "hash": b.header.hash.to_string(),
                    "version": b.header.version,
                    "timestamp": b.header.timestamp,
                    "daaScore": b.header.daa_score.to_string(),
                    "blueScore": b.header.blue_score.to_string(),
                    "blueWork": b.header.blue_work.to_string(),
                    "bits": b.header.bits,
                    "nonce": b.header.nonce.to_string(),
                    "pruningPoint": b.header.pruning_point.to_string(),
                    "hashMerkleRoot": b.header.hash_merkle_root.to_string(),
                    "acceptedIdMerkleRoot": b.header.accepted_id_merkle_root.to_string(),
                    "utxoCommitment": b.header.utxo_commitment.to_string(),
                    // Kaspa shape: parents are grouped per level as { parentHashes: [...] }.
                    "parents": b.header.parents_by_level.iter()
                        .map(|level| json!({ "parentHashes": level.iter().map(|h| h.to_string()).collect::<Vec<_>>() }))
                        .collect::<Vec<_>>(),
                },
                "verboseData": {
                    "difficulty": vd.map(|v| v.difficulty).unwrap_or(0.0),
                    "selectedParentHash": vd.map(|v| v.selected_parent_hash.to_string()).unwrap_or_default(),
                    "transactionIds": vd.map(|v| v.transaction_ids.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "isChainBlock": vd.map(|v| v.is_chain_block).unwrap_or(false),
                    "childrenHashes": vd.map(|v| v.children_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "mergeSetBluesHashes": vd.map(|v| v.merge_set_blues_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                    "mergeSetRedsHashes": vd.map(|v| v.merge_set_reds_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                },
                "transactions": b.transactions.iter().map(tx_json).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Err(e) => err(e.to_string()),
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(serde::Deserialize)]
struct TxSearchReq {
    #[serde(rename = "transactionIds", default)]
    transaction_ids: Vec<String>,
}

/// Batch acceptance lookup (`POST /transactions/search`): the block-details page asks
/// which of a block's txids are accepted. Everything in the recent ring is accepted
/// chain data, so answer from the ring with each tx's accepting blue score.
async fn transactions_search(State(s): State<Arc<AppState>>, Json(req): Json<TxSearchReq>) -> impl IntoResponse {
    let recent = s.recent.read().await;
    let mut found = Vec::new();
    for b in recent.iter() {
        for t in &b.txs {
            if req.transaction_ids.iter().any(|id| *id == t.tx_id) {
                found.push(json!({
                    "transaction_id": t.tx_id,
                    "is_accepted": true,
                    "accepting_block_hash": b.block_hash,
                    "accepting_block_blue_score": b.blue_score.parse::<u64>().unwrap_or(0),
                    "block_time": b.timestamp.parse::<u64>().unwrap_or(0),
                }));
            }
        }
    }
    Json(found)
}

/// The full transaction-detail shape the explorer's tx page consumes. We locate the
/// tx by scanning the recent-block ring for its id (the explorer only links txs it
/// has just shown), then fetch that block from the node for the full transaction.
async fn transaction_by_id(State(s): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    // Find which recent block carries this tx id.
    let block_hash = {
        let recent = s.recent.read().await;
        recent
            .iter()
            .find(|b| b.txs.iter().any(|t| t.tx_id == id))
            .map(|b| b.block_hash.clone())
    };
    let Some(block_hash) = block_hash else {
        return err(format!("transaction {id} not found in the recent window"));
    };
    let hash = match block_hash.parse::<RpcHash>() {
        Ok(h) => h,
        Err(_) => return err("bad block hash".into()),
    };
    let block = match s.client.get_block(hash, true).await {
        Ok(b) => b,
        Err(e) => return err(e.to_string()),
    };
    let Some((i, tx)) = block
        .transactions
        .iter()
        .enumerate()
        .find(|(_, t)| t.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default() == id)
    else {
        return err(format!("transaction {id} not in block"));
    };

    let is_coinbase = i == 0;
    let block_hash_s = block.header.hash.to_string();
    let block_time = block.header.timestamp;
    let blue_score = block.verbose_data.as_ref().map(|v| v.blue_score).unwrap_or(block.header.blue_score);

    // Transparent/shielded outputs → address rows. A 43-byte Orchard script is a
    // shielded note; render its firecash: address.
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(idx, o)| {
            let script = o.script_public_key.script();
            let shielded = script.len() == ORCHARD_SCRIPT_LEN;
            let address = if shielded {
                String::from(&kaspa_addresses::Address::new(
                    kaspa_addresses::Prefix::Mainnet,
                    kaspa_addresses::Version::ShieldedOrchard,
                    script,
                ))
            } else {
                String::new()
            };
            json!({
                "transaction_id": id,
                "index": idx,
                "amount": o.value,
                "script_public_key": hexs(script),
                "script_public_key_address": address,
                "script_public_key_type": if shielded { "shielded" } else { "pubkey" },
                "accepting_block_hash": block_hash_s,
            })
        })
        .collect();

    Json(json!({
        "subnetwork_id": tx.subnetwork_id.to_string(),
        "transaction_id": id,
        "hash": tx.verbose_data.as_ref().map(|v| v.hash.to_string()).unwrap_or_else(|| id.clone()),
        "mass": tx.verbose_data.as_ref().map(|v| v.compute_mass).unwrap_or(0).to_string(),
        "payload": hexs(&tx.payload),
        "block_hash": [block_hash_s.clone()],
        "block_time": block_time,
        "is_accepted": true,
        "accepting_block_hash": block_hash_s,
        "accepting_block_blue_score": blue_score,
        "accepting_block_time": block_time,
        // Coinbase and shielded spends expose no transparent inputs; null renders the
        // "Coinbase" / shielded source in the UI instead of a transparent address list.
        "inputs": Value::Null,
        "outputs": if is_coinbase || !outputs.is_empty() { json!(outputs) } else { Value::Null },
    }))
    .into_response()
}

/// Emit a transaction in the Kaspa-node JSON shape the explorer's block-details page
/// consumes (`verboseData.transactionId`, `inputs[].previousOutpoint`, and
/// `outputs[].verboseData.scriptPublicKeyAddress`). Shielded (43-byte) output scripts
/// render their firecash: address.
fn tx_json(tx: &kaspa_rpc_core::RpcTransaction) -> Value {
    let outputs = tx.outputs.iter().map(|o| {
        let script = o.script_public_key.script();
        let shielded = script.len() == ORCHARD_SCRIPT_LEN;
        let address = if shielded {
            String::from(&kaspa_addresses::Address::new(
                kaspa_addresses::Prefix::Mainnet,
                kaspa_addresses::Version::ShieldedOrchard,
                script,
            ))
        } else {
            String::new()
        };
        json!({
            "amount": o.value,
            "scriptPublicKey": { "version": o.script_public_key.version(), "scriptPublicKey": hexs(script) },
            "verboseData": {
                "scriptPublicKeyType": if shielded { "shielded" } else { "pubkey" },
                "scriptPublicKeyAddress": address,
            },
        })
    }).collect::<Vec<_>>();

    let inputs = tx.inputs.iter().map(|i| json!({
        "previousOutpoint": {
            "transactionId": i.previous_outpoint.transaction_id.to_string(),
            "index": i.previous_outpoint.index,
        },
        "signatureScript": hexs(&i.signature_script),
        "sequence": i.sequence,
        "sigOpCount": i.sig_op_count,
    })).collect::<Vec<_>>();

    json!({
        "version": tx.version,
        "shielded": tx.version == TX_VERSION_SHIELDED,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": tx.lock_time,
        "subnetworkId": tx.subnetwork_id.to_string(),
        "payload": hexs(&tx.payload),
        "verboseData": {
            "transactionId": tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default(),
            "hash": tx.verbose_data.as_ref().map(|v| v.hash.to_string()).unwrap_or_default(),
            "mass": tx.verbose_data.as_ref().map(|v| v.compute_mass).unwrap_or(0),
        },
    })
}

/// Shielded chains expose no meaningful transparent address data; answer these so
/// the frontend degrades gracefully instead of erroring.
async fn address_empty() -> impl IntoResponse {
    Json(json!({ "balance": 0 }))
}
async fn empty_array() -> impl IntoResponse {
    Json(json!([]))
}

fn err(msg: String) -> axum::response::Response {
    (StatusCode::BAD_GATEWAY, Json(json!({ "error": msg }))).into_response()
}

#[tokio::main]
async fn main() {
    kaspa_core::log::try_init_logger("info");
    let cli = Cli::parse();

    let client = connect(&cli.rpc_server).await;
    let dag = client.get_block_dag_info().await.unwrap_or_else(|e| fatal(format!("get_block_dag_info failed: {e}")));
    let network_name = dag.network.to_string();
    log::info!("connected to FireCash node on {} (network {network_name})", cli.rpc_server);

    let state = Arc::new(AppState {
        client,
        recent: RwLock::new(VecDeque::with_capacity(RECENT_CAP)),
        shielded: RwLock::new(ShieldedAgg::default()),
        network_name,
    });

    tokio::spawn(follow(state.clone()));

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new()
        .route("/info/blockdag", get(info_blockdag))
        .route("/info/coinsupply", get(info_coinsupply))
        .route("/info/blockreward", get(info_blockreward))
        .route("/info/halving", get(info_halving))
        .route("/info/shielded", get(info_shielded))
        .route("/info/fee-estimate", get(info_feeestimate))
        .route("/info/market-data", get(info_marketdata))
        .route("/transactions/count", get(transactions_count))
        .route("/transactions/count/", get(transactions_count))
        .route("/transactions/:id", get(transaction_by_id))
        .route("/transactions/search", axum::routing::post(transactions_search))
        .route("/addresses/:address/full-transactions-page", get(empty_array))
        .route("/blocks/recent", get(blocks_recent))
        .route("/blocks/:id", get(block_by_id))
        .route("/addresses/:address/balance", get(address_empty))
        .route("/addresses/:address/utxos", get(empty_array))
        .route("/addresses/:address/transactions-count", get(address_empty))
        .route("/addresses/names", get(empty_array))
        .route("/addresses/top", get(empty_array))
        .route("/addresses/distribution", get(empty_array))
        .route("/health", get(|| async { "ok" }))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .unwrap_or_else(|e| fatal(format!("failed to bind {}: {e}", cli.listen)));
    log::info!("FireCash explorer API listening on http://{}", cli.listen);
    axum::serve(listener, app).await.unwrap_or_else(|e| fatal(format!("server error: {e}")));
}
