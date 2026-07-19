//! # Reference sync skeleton — NOT the production wallet engine
//!
//! This module demonstrates the `ChainSource`/`WalletStore` contracts with a
//! minimal, deterministic sync loop. The production engine — the one with a
//! send path, witness maintenance/budgeting, anchor-boundary tracking,
//! mempool/preview 0-conf, reorg *recovery* (not just detection), birthday
//! fast-sync (`WalletDb::from_frontier`), and pruning-loss accounting
//! (`blind_below` / `missing_history`) — lives in `zkas-walletd` today and is
//! being extracted here incrementally, by moving that code, not rewriting it.
//!
//! **Do not build a user-facing wallet on this module as it stands.** In
//! particular it cannot spend, it starts scanning from the node's earliest
//! served block with no birthday bound, and a wallet restored through a
//! pruning node will silently miss notes minted below the pruning point — the
//! exact failure the production engine refuses to allow.

use kaspa_shielded_core::{
    bundle::ShieldedBundle,
    walletdb::{BlockMeta, HistoryEntry, WalletDb},
};

use crate::{
    chain::{ChainSource, Hash},
    network::NetworkConfig,
    store::{StoredWallet, WalletStore},
};

#[derive(Clone, Debug)]
pub struct WalletConfig {
    pub wallet_id: String,
    pub network: NetworkConfig,
    pub page_size: usize,
}

impl WalletConfig {
    pub fn mainnet(wallet_id: impl Into<String>) -> Self {
        Self { wallet_id: wallet_id.into(), network: NetworkConfig::mainnet(), page_size: 1_000 }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalletBalance {
    pub settled: u128,
    pub pending_incoming: u128,
    pub pending_outgoing: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEvent {
    Started { after: Option<Hash> },
    BlockCommitted { hash: Hash, blue_score: u64, daa_score: u64 },
    HeldBack { hash: Hash, blue_score: u64 },
    ReorgDetected { cursor: Hash },
    Finished { cursor: Option<Hash>, balance: u128 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub scanned: usize,
    pub held_back: usize,
    pub cursor: Option<Hash>,
    pub events: Vec<SyncEvent>,
}

#[derive(Debug)]
pub enum SdkError {
    InvalidSeedOrViewingKey,
    WrongNetwork,
    Source(String),
    Store(String),
    CorruptSnapshot,
    UnsupportedSnapshot(u16),
    ReorgRequiresRecovery { cursor: Hash, pruning_point: Hash },
    InvalidBundle { block: Hash, index: usize },
    TransactionMetadataMismatch { block: Hash },
}

impl core::fmt::Display for SdkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SdkError {}

/// Stateful shielded wallet independent of transport and durable storage.
pub struct Wallet {
    config: WalletConfig,
    db: WalletDb,
    cursor: Option<Hash>,
    blue_score: u64,
    daa_score: u64,
}

impl Wallet {
    pub fn from_seed(config: WalletConfig, seed: [u8; 32]) -> Result<Self, SdkError> {
        let db = WalletDb::from_seed(seed).ok_or(SdkError::InvalidSeedOrViewingKey)?;
        Ok(Self { config, db, cursor: None, blue_score: 0, daa_score: 0 })
    }

    pub fn from_viewing_key(config: WalletConfig, fvk: &[u8; 96]) -> Result<Self, SdkError> {
        let db = WalletDb::from_fvk(fvk).ok_or(SdkError::InvalidSeedOrViewingKey)?;
        Ok(Self { config, db, cursor: None, blue_score: 0, daa_score: 0 })
    }

    pub async fn restore_seed(config: WalletConfig, seed: [u8; 32], store: &dyn WalletStore) -> Result<Self, SdkError> {
        let Some(snapshot) = store.load(&config.wallet_id).await.map_err(SdkError::Store)? else {
            return Self::from_seed(config, seed);
        };
        if snapshot.schema_version != StoredWallet::SCHEMA_VERSION {
            return Err(SdkError::UnsupportedSnapshot(snapshot.schema_version));
        }
        let db = WalletDb::from_checkpoint(seed, &snapshot.wallet_checkpoint).ok_or(SdkError::CorruptSnapshot)?;
        Ok(Self { config, db, cursor: snapshot.cursor, blue_score: snapshot.blue_score, daa_score: snapshot.daa_score })
    }

    pub fn address_bytes(&self) -> [u8; 43] {
        self.db.my_address_bytes()
    }
    pub fn full_viewing_key(&self) -> [u8; 96] {
        self.db.fvk().to_bytes()
    }
    pub fn balance(&self) -> WalletBalance {
        WalletBalance { settled: self.db.balance(), ..WalletBalance::default() }
    }
    pub fn history(&self) -> &[HistoryEntry] {
        self.db.history()
    }
    pub fn cursor(&self) -> Option<Hash> {
        self.cursor
    }

    pub async fn sync_once(&mut self, source: &dyn ChainSource, store: &dyn WalletStore) -> Result<SyncReport, SdkError> {
        let identity = source.identity().await.map_err(SdkError::Source)?;
        if identity.genesis != self.config.network.genesis {
            return Err(SdkError::WrongNetwork);
        }
        let batch = source.shielded_blocks(self.cursor, self.config.page_size).await.map_err(SdkError::Source)?;
        if batch.reorged {
            let cursor = self.cursor.unwrap_or([0; 32]);
            return Err(SdkError::ReorgRequiresRecovery { cursor, pruning_point: batch.pruning_point });
        }
        let settled_blue = batch.sink_blue_score.saturating_sub(self.config.network.settlement_blue_score);
        let mut report =
            SyncReport { scanned: 0, held_back: 0, cursor: self.cursor, events: vec![SyncEvent::Started { after: self.cursor }] };

        for block in batch.blocks {
            if block.blue_score > settled_blue {
                report.held_back += 1;
                report.events.push(SyncEvent::HeldBack { hash: block.hash, blue_score: block.blue_score });
                continue;
            }
            if !block.accepted_txids.is_empty() && block.accepted_txids.len() != block.accepted_bundle_bytes.len() {
                return Err(SdkError::TransactionMetadataMismatch { block: block.hash });
            }
            let bundles = block
                .accepted_bundle_bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    ShieldedBundle::from_bytes(bytes).map_err(|_| SdkError::InvalidBundle { block: block.hash, index })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let refs: Vec<&ShieldedBundle> = bundles.iter().collect();
            let coinbase: Vec<_> = block.coinbase.into_iter().map(|note| (note.description, note.value)).collect();
            let meta = BlockMeta {
                coinbase_txid: block.coinbase_txid,
                txids: block.accepted_txids,
                timestamp_ms: block.timestamp_ms,
                daa_score: block.daa_score,
            };
            self.db.ingest_block_with_meta(&coinbase, &refs, Some(&meta));
            self.cursor = Some(block.hash);
            self.blue_score = block.blue_score;
            self.daa_score = block.daa_score;
            report.scanned += 1;
            report.cursor = self.cursor;
            report.events.push(SyncEvent::BlockCommitted {
                hash: block.hash,
                blue_score: block.blue_score,
                daa_score: block.daa_score,
            });
        }
        // Checkpoint once per batch, not once per block: `to_checkpoint`
        // serializes the whole wallet, so a per-block save makes initial sync
        // O(blocks²) in I/O — the same complexity class as the witness bug this
        // codebase already paid for once. A crash between batches only re-scans
        // the last batch from the durable cursor; it cannot corrupt state,
        // because the snapshot pairs the cursor and the tree atomically.
        if report.scanned > 0 {
            store
                .save(
                    &self.config.wallet_id,
                    &StoredWallet {
                        schema_version: StoredWallet::SCHEMA_VERSION,
                        cursor: self.cursor,
                        blue_score: self.blue_score,
                        daa_score: self.daa_score,
                        wallet_checkpoint: self.db.to_checkpoint(),
                    },
                )
                .await
                .map_err(SdkError::Store)?;
        }
        report.events.push(SyncEvent::Finished { cursor: self.cursor, balance: self.db.balance() });
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::{BlockBatch, ChainIdentity, ChainTip, MemoryStore, ShieldedChainBlock, TransactionState, chain::ChainSource};

    struct MockSource {
        identity: ChainIdentity,
        batch: Mutex<Option<BlockBatch>>,
    }

    #[async_trait]
    impl ChainSource for MockSource {
        async fn identity(&self) -> Result<ChainIdentity, String> {
            Ok(self.identity.clone())
        }
        async fn tip(&self) -> Result<ChainTip, String> {
            Err("unused".into())
        }
        async fn shielded_blocks(&self, _after: Option<Hash>, _limit: usize) -> Result<BlockBatch, String> {
            self.batch.lock().unwrap().take().ok_or_else(|| "batch consumed".into())
        }
        async fn submit_transaction(&self, _transaction: Vec<u8>) -> Result<Hash, String> {
            Err("unused".into())
        }
        async fn transaction_state(&self, _transaction_id: Hash) -> Result<TransactionState, String> {
            Ok(TransactionState::Unknown)
        }
    }

    fn source(batch: BlockBatch) -> MockSource {
        MockSource {
            identity: ChainIdentity { network: "mainnet".into(), genesis: NetworkConfig::MAINNET_GENESIS, merged_mining_active: true },
            batch: Mutex::new(Some(batch)),
        }
    }

    fn empty_block(hash: u8, blue_score: u64) -> ShieldedChainBlock {
        ShieldedChainBlock {
            hash: [hash; 32],
            blue_score,
            daa_score: blue_score,
            timestamp_ms: 1,
            coinbase_txid: [hash.wrapping_add(1); 32],
            coinbase: vec![],
            accepted_bundle_bytes: vec![],
            accepted_txids: vec![],
        }
    }

    #[tokio::test]
    async fn commits_only_settled_selected_chain_blocks() {
        let store = MemoryStore::default();
        let mut wallet = Wallet::from_seed(WalletConfig::mainnet("alice"), [7; 32]).unwrap();
        let batch = BlockBatch {
            blocks: vec![empty_block(1, 700), empty_block(2, 901)],
            reorged: false,
            sink_blue_score: 1_100,
            pruning_point: [3; 32],
        };
        let report = wallet.sync_once(&source(batch), &store).await.unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.held_back, 1);
        assert_eq!(wallet.cursor(), Some([1; 32]));
        assert!(store.load("alice").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn refuses_wrong_genesis_before_reading_blocks() {
        let store = MemoryStore::default();
        let mut wallet = Wallet::from_seed(WalletConfig::mainnet("alice"), [7; 32]).unwrap();
        let mut source = source(BlockBatch { blocks: vec![], reorged: false, sink_blue_score: 0, pruning_point: [0; 32] });
        source.identity.genesis = [0; 32];
        assert!(matches!(wallet.sync_once(&source, &store).await, Err(SdkError::WrongNetwork)));
    }

    #[tokio::test]
    async fn explicit_reorg_never_appends_to_stale_orchard_tree() {
        let store = MemoryStore::default();
        let mut wallet = Wallet::from_seed(WalletConfig::mainnet("alice"), [7; 32]).unwrap();
        let batch = BlockBatch { blocks: vec![], reorged: true, sink_blue_score: 50, pruning_point: [4; 32] };
        match wallet.sync_once(&source(batch), &store).await {
            Err(SdkError::ReorgRequiresRecovery { pruning_point, .. }) => assert_eq!(pruning_point, [4; 32]),
            other => panic!("expected reorg recovery error, got {other:?}"),
        }
        assert_eq!(wallet.cursor(), None);
    }
}
