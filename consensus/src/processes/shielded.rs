//! Consensus driver for the shielded state transition (PLAN §2.4).
//!
//! Binds the rocksdb-backed shielded stores ([`crate::model::stores::shielded`])
//! to the store-agnostic state transition in `kaspa-shielded-core`. The virtual
//! processor uses [`ShieldedStateManager::apply_blocks`] to advance the shielded
//! state over a run of accepted chain blocks, in GHOSTDAG accepted order, and to
//! persist the result (frontier, nullifiers, supply totals, finalized anchor)
//! atomically in a single write batch.
//!
//! The unbounded, append-only nullifier set is never loaded into memory: the
//! finalized membership check goes straight to rocksdb, layered with the
//! nullifiers accepted earlier in the same run (so a double-spend across two
//! blocks in one virtual update is still caught).

use std::sync::Arc;

use kaspa_database::prelude::{CachePolicy, StoreError, StoreResult, DB};
use kaspa_shielded_core::nullifier::{MemNullifierSet, NullifierBytes, NullifierSet};
use kaspa_shielded_core::state::{apply_chain_block_to, BlockShieldedOutcome, CoinbaseMint, ShieldedStateError, ShieldedTx};
use kaspa_shielded_core::tree::{GlobalTree, NoteCommitmentTree};
use kaspa_shielded_core::turnstile::SupplyLedger;
use rocksdb::WriteBatch;

use crate::model::stores::shielded::{
    DbNullifierSetStore, DbShieldedAnchorsStore, DbShieldedSupplyStore, DbShieldedTreeStore, NullifierSetStore,
    NullifierSetStoreReader, ShieldedAnchorsStoreReader, ShieldedSupplyStoreReader, ShieldedTreeStoreReader, SupplyTotals,
};

/// A run of accepted chain blocks to apply: each is its optional coinbase mint
/// and its shielded transactions in accepted order.
pub type ShieldedBlock = (Option<CoinbaseMint>, Vec<ShieldedTx>);

/// Error advancing the shielded state.
#[derive(Debug)]
pub enum ShieldedManagerError {
    /// The block produced an invalid shielded state (turnstile / full tree).
    /// The block must be rejected.
    State(ShieldedStateError),
    /// A storage error (treated as fatal by the caller, as elsewhere in consensus).
    Store(StoreError),
}

impl From<ShieldedStateError> for ShieldedManagerError {
    fn from(e: ShieldedStateError) -> Self {
        Self::State(e)
    }
}
impl From<StoreError> for ShieldedManagerError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// A finalized nullifier set layered over the persisted store plus the
/// nullifiers accepted earlier in the current run (PLAN §2.4: cross-block
/// double-spends within one virtual update must be caught).
struct LayeredNullifierSet<'a> {
    store: &'a DbNullifierSetStore,
    pending: &'a MemNullifierSet,
}

impl NullifierSet for LayeredNullifierSet<'_> {
    fn contains(&self, nf: &NullifierBytes) -> bool {
        // A store read failing is an unrecoverable consensus IO error, consistent
        // with how the rest of the pipeline treats store reads.
        self.pending.contains(nf) || self.store.contains(nf).expect("nullifier store read failed")
    }
}

/// Drives and persists the shielded state transition.
#[derive(Clone)]
pub struct ShieldedStateManager {
    nullifiers: DbNullifierSetStore,
    tree_store: DbShieldedTreeStore,
    supply_store: DbShieldedSupplyStore,
    anchors_store: DbShieldedAnchorsStore,
}

impl ShieldedStateManager {
    /// Construct over the consensus database. `anchor_depth` is the size of the
    /// finalized-anchor window (PLAN §2.5).
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy, anchor_depth: u32) -> Self {
        Self {
            nullifiers: DbNullifierSetStore::new(Arc::clone(&db), cache_policy),
            tree_store: DbShieldedTreeStore::new(Arc::clone(&db)),
            supply_store: DbShieldedSupplyStore::new(Arc::clone(&db)),
            anchors_store: DbShieldedAnchorsStore::new(db, anchor_depth),
        }
    }

    /// Read-only access to the nullifier store (for validation / queries).
    pub fn nullifiers(&self) -> &DbNullifierSetStore {
        &self.nullifiers
    }

    /// The current persisted anchor (root of the global note-commitment tree).
    pub fn current_anchor(&self) -> StoreResult<[u8; 32]> {
        let tree = self.load_tree()?;
        Ok(tree.anchor().to_bytes())
    }

    fn load_tree(&self) -> StoreResult<GlobalTree> {
        let state = self.tree_store.get()?;
        // A non-canonical persisted frontier means database corruption.
        Ok(GlobalTree::from_state(&state).expect("persisted shielded frontier is corrupt"))
    }

    fn load_supply(&self) -> StoreResult<SupplyLedger> {
        let t = self.supply_store.get()?;
        Ok(SupplyLedger::from_totals(t.cumulative_coinbase, t.cumulative_fees))
    }

    /// Apply a run of accepted chain blocks (in GHOSTDAG order) and stage the
    /// resulting state into `batch`. Returns the per-block outcomes (notably which
    /// transactions survived conflict resolution). On a [`ShieldedManagerError::State`]
    /// the batch is left without shielded writes and the caller must reject the block.
    pub fn apply_blocks(
        &mut self,
        batch: &mut WriteBatch,
        blocks: &[ShieldedBlock],
    ) -> Result<Vec<BlockShieldedOutcome>, ShieldedManagerError> {
        let mut tree = self.load_tree()?;
        let mut supply = self.load_supply()?;
        let mut anchors = self.anchors_store.get()?;

        let mut pending = MemNullifierSet::new();
        let mut all_new: Vec<NullifierBytes> = Vec::new();
        let mut outcomes = Vec::with_capacity(blocks.len());

        for (coinbase, txs) in blocks {
            let outcome = {
                let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
                apply_chain_block_to(&finalized, &mut tree, &mut supply, coinbase.as_ref(), txs)?
            };
            for nf in &outcome.new_nullifiers {
                pending.insert(*nf);
                all_new.push(*nf);
            }
            anchors.push(outcome.anchor.to_bytes());
            outcomes.push(outcome);
        }

        // Persist the advanced state atomically into the caller's batch.
        self.tree_store.set_batch(batch, &tree.to_state())?;
        self.supply_store.set_batch(
            batch,
            &SupplyTotals { cumulative_coinbase: supply.cumulative_coinbase(), cumulative_fees: supply.cumulative_fees() },
        )?;
        for nf in all_new {
            self.nullifiers.insert_batch(batch, nf)?;
        }
        self.anchors_store.set_batch(batch, &anchors)?;

        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;
    use kaspa_shielded_core::ExtractedNoteCommitment;

    fn cmx(n: u32) -> ExtractedNoteCommitment {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        Option::from(ExtractedNoteCommitment::from_bytes(&b)).expect("canonical")
    }

    fn nf(n: u8) -> NullifierBytes {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    fn stx(nfs: &[u8], cmxs: &[u32], fee: u64) -> ShieldedTx {
        ShieldedTx { nullifiers: nfs.iter().map(|&n| nf(n)).collect(), commitments: cmxs.iter().map(|&c| cmx(c)).collect(), fee }
    }

    fn coinbase(subsidy: u64, c: u32) -> CoinbaseMint {
        CoinbaseMint { subsidy, commitment: cmx(c) }
    }

    /// End-to-end through rocksdb: a parallel double-spend across two accepted
    /// blocks resolves to one survivor, the state persists, and a fresh manager
    /// loaded from the same database sees the identical anchor and still rejects
    /// a later reuse of the spent nullifier.
    #[test]
    fn persists_and_resolves_double_spend_across_sessions() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);

        let mut batch = WriteBatch::default();
        let outcomes = mgr
            .apply_blocks(
                &mut batch,
                &[
                    (Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]),
                    (Some(coinbase(50, 20)), vec![stx(&[1], &[200], 5)]), // reuses nf(1)
                ],
            )
            .unwrap();
        db.write(batch).unwrap();

        assert_eq!(outcomes[0].accepted, vec![0], "first spend of nf(1) wins");
        assert!(outcomes[1].accepted.is_empty(), "second spend of nf(1) dropped");
        let anchor_after = outcomes[1].anchor.to_bytes();

        // Fresh manager loaded from the same DB: identical persisted anchor.
        let mut mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        assert_eq!(mgr2.current_anchor().unwrap(), anchor_after);
        assert!(mgr2.nullifiers().contains(&nf(1)).unwrap(), "spent nullifier persisted");

        // A later block reusing nf(1) is still caught against the persisted set.
        let mut batch2 = WriteBatch::default();
        let later = mgr2.apply_blocks(&mut batch2, &[(None, vec![stx(&[1], &[300], 0)])]).unwrap();
        assert!(later[0].accepted.is_empty(), "double-spend caught across sessions");
    }

    /// Spending more than was ever minted is rejected (turnstile) and surfaced as
    /// a state error so the caller rejects the block.
    #[test]
    fn rejects_overspend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mut mgr = ShieldedStateManager::new(db, CachePolicy::Count(64), 100);
        let mut batch = WriteBatch::default();
        let res = mgr.apply_blocks(&mut batch, &[(Some(coinbase(10, 1)), vec![stx(&[7], &[2], 11)])]);
        assert!(matches!(res, Err(ShieldedManagerError::State(ShieldedStateError::Turnstile(_)))));
    }
}
