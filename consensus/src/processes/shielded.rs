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
use kaspa_shielded_core::tree::{FrontierState, GlobalTree, NoteCommitmentTree};
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
/// A computed (not-yet-persisted) shielded transition for one chain block.
///
/// Produced by [`ShieldedStateManager::compute`] in the validation phase and
/// persisted by [`ShieldedStateManager::persist`] in the commit phase.
pub struct ComputedBlockShielded {
    /// The global note-commitment tree frontier after this block.
    pub frontier_state: FrontierState,
    /// The turnstile cumulative totals after this block.
    pub supply_totals: SupplyTotals,
    /// Conflict-resolution outcome: surviving txs, new nullifiers, new anchor.
    pub outcome: BlockShieldedOutcome,
}

impl ComputedBlockShielded {
    /// The anchor (global tree root) as of this block.
    pub fn anchor(&self) -> [u8; 32] {
        self.outcome.anchor.to_bytes()
    }
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

    /// Validate and compute one chain block's shielded transition against its
    /// selected parent's persisted state, **without** persisting (used in the
    /// validation phase, `verify_expected_utxo_state`). The finalized nullifier
    /// check reads the global set, which — because each chain block is committed
    /// before the next is validated — already reflects the selected-parent chain.
    pub fn compute(
        &self,
        selected_parent: Hash,
        coinbase: Option<&CoinbaseMint>,
        txs: &[ShieldedTx],
    ) -> Result<ComputedBlockShielded, ShieldedManagerError> {
        let mut tree = self.load_tree(selected_parent)?;
        let mut supply = self.load_supply(selected_parent)?;
        let pending = MemNullifierSet::new();
        let outcome = {
            let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
            apply_chain_block_to(&finalized, &mut tree, &mut supply, coinbase, txs)?
        };
        Ok(ComputedBlockShielded {
            frontier_state: tree.to_state(),
            supply_totals: SupplyTotals {
                cumulative_coinbase: supply.cumulative_coinbase(),
                cumulative_fees: supply.cumulative_fees(),
            },
            outcome,
        })
    }

    /// Persist a freshly validated block's shielded transition into `batch` and
    /// add its nullifiers to the global set (commit phase). Only non-trivial
    /// state is written, so a chain with no shielded activity incurs no shielded
    /// writes and no behavioural change.
    pub fn persist(&self, batch: &mut WriteBatch, block: Hash, computed: &ComputedBlockShielded) -> StoreResult<()> {
        if computed.frontier_state.size > 0 {
            self.tree_store.set_batch(batch, block, computed.frontier_state.clone())?;
        }
        if computed.supply_totals.cumulative_coinbase > 0 || computed.supply_totals.cumulative_fees > 0 {
            self.supply_store.set_batch(batch, block, computed.supply_totals)?;
        }
        if !computed.outcome.new_nullifiers.is_empty() {
            self.nullifier_diffs.set_batch(batch, block, computed.outcome.new_nullifiers.clone())?;
            for nf in &computed.outcome.new_nullifiers {
                self.nullifiers.insert_batch(batch, *nf)?;
            }
        }
        Ok(())
    }

    /// Re-add a chain block's nullifiers to the global set when it rejoins the
    /// selected chain on a reorg up-walk, reading its stored per-block diff. (The
    /// per-block frontier/supply snapshots are intrinsic and already persisted.)
    pub fn apply_nullifiers_from_store(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        for nf in self.nullifier_diffs.get(block)? {
            self.nullifiers.insert_batch(batch, nf)?;
        }
        Ok(())
    }

    /// Remove a chain block's nullifiers from the global set when it leaves the
    /// selected chain on a reorg down-walk, reading its stored per-block diff. The
    /// per-block snapshots are retained for a possible rejoin.
    pub fn revert_nullifiers_from_store(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        for nf in self.nullifier_diffs.get(block)? {
            self.nullifiers.delete_batch(batch, nf)?;
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

    /// Commit one block (compute → persist → write), mirroring the per-block
    /// flow the virtual processor uses (each block's batch is written before the
    /// next block is validated).
    fn commit_block(
        mgr: &ShieldedStateManager,
        db: &Arc<DB>,
        block: Hash,
        parent: Hash,
        coinbase: Option<CoinbaseMint>,
        txs: Vec<ShieldedTx>,
    ) -> ComputedBlockShielded {
        let computed = mgr.compute(parent, coinbase.as_ref(), &txs).unwrap();
        let mut batch = WriteBatch::default();
        mgr.persist(&mut batch, block, &computed).unwrap();
        db.write(batch).unwrap();
        computed
    }

    /// A chain of two blocks with a parallel double-spend resolves to one
    /// survivor, persists per-block, and a fresh manager sees the identical
    /// anchor at the tip and rejects later reuse across sessions.
    #[test]
    fn per_block_commit_persists_and_resolves_double_spend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        let (genesis, b1, b2) = (h(0), h(1), h(2));

        let c1 = commit_block(&mgr, &db, b1, genesis, Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        assert_eq!(c1.outcome.accepted, vec![0], "first spend of nf(1) wins");

        // b2 (parent b1) reuses nf(1); compute reads the persisted global set.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 20)), vec![stx(&[1], &[200], 5)]);
        assert!(c2.outcome.accepted.is_empty(), "second spend of nf(1) dropped");
        let tip_anchor = c2.anchor();

        // Fresh manager from the same DB: identical persisted anchor at the tip.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        assert_eq!(mgr2.anchor_at(b2).unwrap(), tip_anchor);
        assert!(mgr2.nullifiers().contains(&nf(1)).unwrap());

        // A later block reusing nf(1) is still caught against the persisted set.
        let c3 = mgr2.compute(b2, None, &[stx(&[1], &[300], 0)]).unwrap();
        assert!(c3.outcome.accepted.is_empty(), "double-spend caught across sessions");
    }

    /// Reverting a block removes the nullifiers it added, so the same nullifier
    /// can be spent again on the new branch (reorg correctness).
    #[test]
    fn revert_removes_block_nullifiers() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        let b1 = h(1);

        commit_block(&mgr, &db, b1, h(0), Some(coinbase(10, 1)), vec![stx(&[1], &[100], 0)]);
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap());

        // Reorg abandons b1: remove its nullifiers from the global set.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, b1).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "reverted nullifier removed");

        // The new branch can now spend nf(1).
        let c = mgr.compute(h(0), Some(&coinbase(10, 2)), &[stx(&[1], &[101], 0)]).unwrap();
        assert_eq!(c.outcome.accepted, vec![0], "spend of reverted nullifier accepted on new branch");
    }

    /// A block that rejoins the selected chain has its nullifiers re-added from
    /// its persisted per-block diff (reorg up-walk).
    #[test]
    fn rejoin_re_adds_nullifiers_from_store() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64), 100);
        let b1 = h(1);

        commit_block(&mgr, &db, b1, h(0), Some(coinbase(10, 1)), vec![stx(&[1], &[100], 0)]);
        // Reorg out, then back in.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, b1).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap());

        let mut ab = WriteBatch::default();
        mgr.apply_nullifiers_from_store(&mut ab, b1).unwrap();
        db.write(ab).unwrap();
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap(), "rejoined block's nullifiers restored");
    }

    /// Spending more than was ever minted is rejected (turnstile) at compute time.
    #[test]
    fn rejects_overspend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = ShieldedStateManager::new(db, CachePolicy::Count(64), 100);
        let res = mgr.compute(h(0), Some(&coinbase(10, 1)), &[stx(&[7], &[2], 11)]);
        assert!(matches!(res, Err(ShieldedManagerError::State(ShieldedStateError::Turnstile(_)))));
    }
}
