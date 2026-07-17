use async_trait::async_trait;
use kaspa_shielded_core::coinbase::CoinbaseNoteDesc;
use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainIdentity {
    pub network: String,
    pub genesis: Hash,
    /// Whether the node reports ZKas merged-mining consensus active. This is
    /// identity/diagnostic information; the wallet still validates its genesis.
    pub merged_mining_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTip {
    pub selected_hash: Hash,
    pub blue_score: u64,
    pub daa_score: u64,
    pub pruning_point: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseNote {
    pub description: CoinbaseNoteDesc,
    pub value: u64,
}

/// Wallet-relevant effects of one selected-chain block, already ordered by the
/// node in GHOSTDAG accepted order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedChainBlock {
    pub hash: Hash,
    pub blue_score: u64,
    pub daa_score: u64,
    pub timestamp_ms: u64,
    pub coinbase_txid: Hash,
    pub coinbase: Vec<CoinbaseNote>,
    pub accepted_bundle_bytes: Vec<Vec<u8>>,
    pub accepted_txids: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBatch {
    pub blocks: Vec<ShieldedChainBlock>,
    /// Positive evidence that `after` is no longer on the selected chain.
    pub reorged: bool,
    pub sink_blue_score: u64,
    pub pruning_point: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum TransactionState {
    Unknown,
    Mempool,
    Confirmed { block: Hash, daa_score: u64 },
    Rejected { reason: String },
}

#[async_trait]
pub trait ChainSource: Send + Sync {
    async fn identity(&self) -> Result<ChainIdentity, String>;
    async fn tip(&self) -> Result<ChainTip, String>;
    async fn shielded_blocks(&self, after: Option<Hash>, limit: usize) -> Result<BlockBatch, String>;
    async fn submit_transaction(&self, transaction: Vec<u8>) -> Result<Hash, String>;
    async fn transaction_state(&self, transaction_id: Hash) -> Result<TransactionState, String>;
}
