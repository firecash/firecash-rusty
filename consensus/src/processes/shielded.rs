//! Consensus driver for the shielded state transition (PLAN §2.4), reorg-safe.
//!
//! Binds the per-chain-block shielded stores ([`crate::model::stores::shielded`])
//! to the store-agnostic state transition in `kaspa-shielded-core`. The virtual
//! processor advances the shielded state along the selected chain by applying a
//! run of accepted chain blocks ([`ShieldedStateManager::apply_chain`]) and, on
//! reorg, reverting the abandoned branch ([`ShieldedStateManager::revert_chain`]).
//!
//! Reorg safety (decision D10): the note-commitment tree frontier and the
//! turnstile totals are snapshotted per chain block, so extending a block loads
//! its selected parent's snapshot. The global nullifier set is append-only for
//! the selected chain; each block records the nullifiers it added so a reorg can
//! remove them. The unbounded nullifier set is never loaded into memory — the
//! finalized membership check goes straight to rocksdb, layered with nullifiers
//! accepted earlier in the same run.

use std::sync::Arc;

use kaspa_database::prelude::{CachePolicy, StoreError, StoreResult, DB};
use kaspa_hashes::Hash;
use kaspa_shielded_core::nullifier::{MemNullifierSet, NullifierBytes, NullifierSet};
use kaspa_shielded_core::state::{apply_chain_block_to, BlockShieldedOutcome, CoinbaseMint, ShieldedStateError, ShieldedTx};
use kaspa_shielded_core::tree::{GlobalTree, NoteCommitmentTree};
use kaspa_shielded_core::turnstile::SupplyLedger;
use rocksdb::WriteBatch;

use crate::model::stores::shielded::{
    DbNullifierDiffStore, DbNullifierSetStore, DbShieldedAnchorsStore, DbShieldedSupplyStore, DbShieldedTreeStore,
    NullifierDiffStoreReader, NullifierSetStore, NullifierSetStoreReader, ShieldedSupplyStoreReader, ShieldedTreeStoreReader,
    SupplyTotals,
};

/// One accepted chain block's shielded input: its hash, its selected parent's
/// hash (whose snapshot we extend), its optional coinbase mint, and its shielded
/// transactions in accepted order.
pub struct ChainBlockInput {
    pub block: Hash,
    pub selected_parent: Hash,
    pub coinbase: Option<CoinbaseMint>,
    pub txs: Vec<ShieldedTx>,
}

/// Error advancing the shielded state.
#[derive(Debug)]
pub enum ShieldedManagerError {
    /// Invalid shielded state (turnstile / full tree) — the block must be rejected.
    State(ShieldedStateError),
    /// A storage error (fatal, as elsewhere in consensus).
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

/// A finalized nullifier set layered over the persisted global set plus the
/// nullifiers accepted earlier in the current run (so cross-block double-spends
/// within one virtual update are caught).
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

/// Drives and persists the shielded state transition, reorg-safely.
#[derive(Clone)]
pub struct ShieldedStateManager {
    nullifiers: DbNullifierSetStore,
    nullifier_diffs: DbNullifierDiffStore,
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
            nullifier_diffs: DbNullifierDiffStore::new(Arc::clone(&db), cache_policy),
            tree_store: DbShieldedTreeStore::new(Arc::clone(&db), cache_policy),
            supply_store: DbShieldedSupplyStore::new(Arc::clone(&db), cache_policy),
            anchors_store: DbShieldedAnchorsStore::new(db, anchor_depth),
        }
    }

    /// Read-only access to the nullifier store (for validation / queries).
    pub fn nullifiers(&self) -> &DbNullifierSetStore {
        &self.nullifiers
    }

    /// The anchor (global tree root) as of a given chain block.
    pub fn anchor_at(&self, block: Hash) -> StoreResult<[u8; 32]> {
        Ok(self.load_tree(block)?.anchor().to_bytes())
    }

    fn load_tree(&self, block: Hash) -> StoreResult<GlobalTree> {
        let state = self.tree_store.get(block)?;
        Ok(GlobalTree::from_state(&state).expect("persisted shielded frontier is corrupt"))
    }

    fn load_supply(&self, block: Hash) -> StoreResult<SupplyLedger> {
        let t = self.supply_store.get(block)?;
        Ok(SupplyLedger::from_totals(t.cumulative_coinbase, t.cumulative_fees))
    }

    /// Apply a run of accepted chain blocks (in GHOSTDAG order, each extending
    /// its selected parent) and stage the resulting state into `batch`. The run
    /// must be contiguous: block `i`'s selected parent is either already
    /// committed or block `i-1` in this run.
    ///
    /// Returns per-block outcomes (notably which transactions survived conflict
    /// resolution). On a [`ShieldedManagerError::State`] the caller rejects the
    /// offending block; earlier blocks' staged writes remain in `batch` and the
    /// caller decides whether to apply or drop the batch.
    pub fn apply_chain(
        &self,
        batch: &mut WriteBatch,
        blocks: &[ChainBlockInput],
    ) -> Result<Vec<BlockShieldedOutcome>, ShieldedManagerError> {
        // In-run snapshots so block i+1 sees block i's effects without needing the
        // batch to be committed first.
        let mut tree_by_block: std::collections::HashMap<Hash, GlobalTree> = std::collections::HashMap::new();
        let mut supply_by_block: std::collections::HashMap<Hash, SupplyLedger> = std::collections::HashMap::new();
        let mut pending = MemNullifierSet::new();
        let mut outcomes = Vec::with_capacity(blocks.len());

        for input in blocks {
            // Load the selected parent's state (from this run, else from the store).
            let mut tree = match tree_by_block.get(&input.selected_parent) {
                Some(t) => t.clone(),
                None => self.load_tree(input.selected_parent)?,
            };
            let mut supply = match supply_by_block.get(&input.selected_parent) {
                Some(s) => s.clone(),
                None => self.load_supply(input.selected_parent)?,
            };

            let outcome = {
                let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
                apply_chain_block_to(&finalized, &mut tree, &mut supply, input.coinbase.as_ref(), &input.txs)?
            };

            // Stage persistence for this block.
            self.tree_store.set_batch(batch, input.block, tree.to_state())?;
            self.supply_store.set_batch(
                batch,
                input.block,
                SupplyTotals { cumulative_coinbase: supply.cumulative_coinbase(), cumulative_fees: supply.cumulative_fees() },
            )?;
            self.nullifier_diffs.set_batch(batch, input.block, outcome.new_nullifiers.clone())?;
            for nf in &outcome.new_nullifiers {
                pending.insert(*nf);
                self.nullifiers.insert_batch(batch, *nf)?;
            }

            tree_by_block.insert(input.block, tree);
            supply_by_block.insert(input.block, supply);
            outcomes.push(outcome);
        }

        Ok(outcomes)
    }

    /// Revert a set of chain blocks abandoned by a reorg: remove the nullifiers
    /// they added from the global set, and drop their per-block snapshots.
    pub fn revert_chain(&self, batch: &mut WriteBatch, blocks: &[Hash]) -> StoreResult<()> {
        for &block in blocks {
            for nf in self.nullifier_diffs.get(block)? {
                self.nullifiers.delete_batch(batch, nf)?;
            }
            self.nullifier_diffs.delete_batch(batch, block)?;
            self.tree_store.delete_batch(batch, block)?;
            self.supply_store.delete_batch(batch, block)?;
        }
        Ok(())
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

    fn h(n: u8) -> Hash {
        Hash::from_bytes([n; 32])
    }

    /// A contiguous chain of two blocks with a parallel double-spend resolves to
    /// one survivor, persists per-block, and a fresh manager sees the identical
    /// anchor at the tip and rejects later reuse across sessions.
    #[test]
    fn apply_chain_persists_and_resolves_double_spend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);

        let genesis = h(0);
        let b1 = h(1);
        let b2 = h(2);
        let mut batch = WriteBatch::default();
        let outcomes = mgr
            .apply_chain(
                &mut batch,
                &[
                    ChainBlockInput { block: b1, selected_parent: genesis, coinbase: Some(coinbase(50, 10)), txs: vec![stx(&[1], &[100], 5)] },
                    ChainBlockInput { block: b2, selected_parent: b1, coinbase: Some(coinbase(50, 20)), txs: vec![stx(&[1], &[200], 5)] },
                ],
            )
            .unwrap();
        db.write(batch).unwrap();

        assert_eq!(outcomes[0].accepted, vec![0], "first spend of nf(1) wins");
        assert!(outcomes[1].accepted.is_empty(), "second spend of nf(1) dropped");
        let tip_anchor = outcomes[1].anchor.to_bytes();

        // Fresh manager from the same DB: identical persisted anchor at the tip.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        assert_eq!(mgr2.anchor_at(b2).unwrap(), tip_anchor);
        assert!(mgr2.nullifiers().contains(&nf(1)).unwrap());

        // A later block reusing nf(1) is still caught against the persisted set.
        let mut b3 = WriteBatch::default();
        let later = mgr2
            .apply_chain(&mut b3, &[ChainBlockInput { block: h(3), selected_parent: b2, coinbase: None, txs: vec![stx(&[1], &[300], 0)] }])
            .unwrap();
        assert!(later[0].accepted.is_empty(), "double-spend caught across sessions");
    }

    /// Reverting a block removes the nullifiers it added, so the same nullifier
    /// can be spent again on the new branch (reorg correctness).
    #[test]
    fn revert_removes_block_nullifiers() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        let b1 = h(1);

        let mut batch = WriteBatch::default();
        mgr.apply_chain(
            &mut batch,
            &[ChainBlockInput { block: b1, selected_parent: h(0), coinbase: Some(coinbase(10, 1)), txs: vec![stx(&[1], &[100], 0)] }],
        )
        .unwrap();
        db.write(batch).unwrap();
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap());

        // Reorg abandons b1.
        let mut rb = WriteBatch::default();
        mgr.revert_chain(&mut rb, &[b1]).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "reverted nullifier removed");

        // The new branch can now spend nf(1).
        let mut nb = WriteBatch::default();
        let out = mgr
            .apply_chain(&mut nb, &[ChainBlockInput { block: h(9), selected_parent: h(0), coinbase: Some(coinbase(10, 2)), txs: vec![stx(&[1], &[101], 0)] }])
            .unwrap();
        assert_eq!(out[0].accepted, vec![0], "spend of reverted nullifier accepted on new branch");
    }

    /// Spending more than was ever minted is rejected (turnstile).
    #[test]
    fn rejects_overspend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(db, CachePolicy::Count(64), 100);
        let mut batch = WriteBatch::default();
        let res = mgr.apply_chain(
            &mut batch,
            &[ChainBlockInput { block: h(1), selected_parent: h(0), coinbase: Some(coinbase(10, 1)), txs: vec![stx(&[7], &[2], 11)] }],
        );
        assert!(matches!(res, Err(ShieldedManagerError::State(ShieldedStateError::Turnstile(_)))));
    }
}
