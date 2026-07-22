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

use kaspa_consensus_core::tx::Transaction;
use kaspa_database::prelude::{CachePolicy, DB, StoreError, StoreResult};
use kaspa_hashes::Hash;
use kaspa_shielded_core::coinbase::{coinbase_note, derive_coinbase_note_desc};
use kaspa_shielded_core::nullifier::{MemNullifierSet, NullifierBytes, NullifierConflictResolver, NullifierSet};
#[cfg(test)]
use kaspa_shielded_core::state::CoinbaseNote;
use kaspa_shielded_core::state::{BlockShieldedOutcome, CoinbaseMint, ShieldedStateError, ShieldedTx, apply_chain_block_to};
use kaspa_shielded_core::tree::{FrontierState, GlobalTree, NoteCommitmentTree};
use kaspa_shielded_core::turnstile::SupplyLedger;
use rocksdb::WriteBatch;

use kaspa_muhash::MuHash;

use crate::model::stores::shielded::{
    AnchorBlockStoreReader, DbAnchorBlockStore, DbNullifierDiffStore, DbNullifierSetStore, DbShieldedNullifierMuHashStore,
    DbShieldedSupplyStore, DbShieldedTreeStore, NullifierDiffStoreReader, NullifierSetStore, NullifierSetStoreReader,
    ShieldedNullifierMuHashStoreReader, ShieldedSupplyStoreReader, ShieldedTreeStoreReader, SupplyTotals,
};

/// A computed (not-yet-persisted) shielded transition for one chain block.
///
/// Produced by [`ShieldedStateManager::compute`] in the validation phase and
/// persisted by [`ShieldedStateManager::persist`] in the commit phase.
pub struct ComputedBlockShielded {
    /// The global note-commitment tree frontier after this block.
    pub frontier_state: FrontierState,
    /// The turnstile cumulative totals after this block.
    pub supply_totals: SupplyTotals,
    /// The MuHash accumulator over the whole spent-nullifier set after this block
    /// (its selected parent's accumulator with this block's new nullifiers added).
    pub nullifier_muhash: MuHash,
    /// Conflict-resolution outcome: surviving txs, new nullifiers, new anchor.
    pub outcome: BlockShieldedOutcome,
}

impl ComputedBlockShielded {
    /// The anchor (global tree root) as of this block.
    pub fn anchor(&self) -> [u8; 32] {
        self.outcome.anchor.to_bytes()
    }

    /// The finalized 32-byte root of the nullifier-set accumulator after this block.
    pub fn nullifier_root(&self) -> [u8; 32] {
        let mut m = self.nullifier_muhash.clone();
        m.finalize().as_bytes().to_owned()
    }

    /// The canonical shielded state root after this block (PLAN §2.10): binds the
    /// note-commitment tree root, the nullifier-set accumulator, and the turnstile
    /// totals into one 32-byte commitment a block can attest to.
    pub fn state_root(&self) -> [u8; 32] {
        kaspa_shielded_core::commitment::shielded_state_root(
            &self.anchor(),
            &self.nullifier_root(),
            self.supply_totals.cumulative_coinbase,
            self.supply_totals.cumulative_fees,
        )
    }
}

/// Compact, verifiable summary of the shielded state at one chain block, used to
/// transfer that state to a fast-syncing node during pruning-point IBD (PLAN
/// §2.8/§2.9). The unbounded global nullifier *set* is streamed separately; this
/// metadata plus the streamed set fully determine the stores that
/// [`ShieldedStateManager::seed_pruning_point_shielded`] writes.
///
/// The declared `state_root` is recomputed on import and cross-checked against the
/// transferred parts. That is an internal-consistency check only — the true
/// consensus binding is the #24 coinbase commitment (`shielded_commitment =
/// state_root(selected_parent)`), which is enforced automatically when the pruning
/// point's first selected-chain child is validated: a peer that seeds wrong state
/// causes every real child of the pruning point to fail coinbase validation, so
/// the node makes no progress rather than adopting corrupt state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PruningPointShieldedMetadata {
    /// The global note-commitment tree frontier at the pruning point.
    pub frontier: FrontierState,
    /// Turnstile cumulative totals at the pruning point.
    pub supply: SupplyTotals,
    /// MuHash accumulator over the whole spent-nullifier set at the pruning point.
    pub nullifier_muhash: MuHash,
    /// Declared shielded state root at the pruning point (anchor + nullifier-set
    /// accumulator + turnstile totals), recomputed and cross-checked on import.
    pub state_root: [u8; 32],
}

impl PruningPointShieldedMetadata {
    /// Encode for the wire (bincode). Paired with [`Self::from_wire_bytes`].
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("shielded pruning-point metadata is serializable")
    }

    /// Decode from the wire.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("malformed shielded pruning-point metadata: {e}"))
    }

    /// The shielded state root implied by (frontier, supply, nullifier_muhash).
    fn recompute_state_root(frontier: &FrontierState, supply: &SupplyTotals, nullifier_muhash: &MuHash) -> [u8; 32] {
        let anchor = GlobalTree::from_state(frontier).expect("frontier corrupt").anchor().to_bytes();
        let nullifier_root = nullifier_muhash.clone().finalize().as_bytes().to_owned();
        kaspa_shielded_core::commitment::shielded_state_root(
            &anchor,
            &nullifier_root,
            supply.cumulative_coinbase,
            supply.cumulative_fees,
        )
    }
}

/// Error advancing the shielded state.
#[derive(Debug)]
pub enum ShieldedManagerError {
    /// Invalid shielded state (turnstile / full tree) — the block must be rejected.
    State(ShieldedStateError),
    /// A shielded-coinbase reward output did not encode a valid coinbase note
    /// (recipient shorter than an Orchard address, or not a canonical address) —
    /// the block must be rejected.
    MalformedCoinbaseNote(&'static str),
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

/// Build the shielded [`CoinbaseMint`] for a block from its coinbase transaction
/// (PLAN §2.7), on a `shielded_coinbase` network. Each coinbase output is a reward
/// for one mergeset block: its `value` is the public reward (subsidy + that
/// block's fees, already emission-checked by the coinbase verifier) and its
/// `script_public_key` script carries the recipient's 43-byte Orchard address.
///
/// The note's `(rho, rseed)` are **derived deterministically** from the coinbase
/// transaction id and the output index ([`derive_coinbase_note_desc`]), so every
/// node computes the identical note commitment and the recipient's wallet can
/// recompute the note to spend it. No transparent value is created — these outputs
/// are diverted into the shielded pool instead of the UTXO set.
pub fn build_coinbase_mint(coinbase_tx: &Transaction) -> Result<CoinbaseMint, ShieldedManagerError> {
    let txid = coinbase_tx.id();
    let mut notes = Vec::with_capacity(coinbase_tx.outputs.len());
    for (i, out) in coinbase_tx.outputs.iter().enumerate() {
        let script = out.script_public_key.script();
        if script.len() < 43 {
            return Err(ShieldedManagerError::MalformedCoinbaseNote("coinbase reward script too short for an Orchard address"));
        }
        let recipient: [u8; 43] = script[..43].try_into().expect("checked length >= 43");
        // Unique per-note seed: coinbase tx id || output index.
        let mut seed = Vec::with_capacity(32 + 4);
        seed.extend_from_slice(&txid.as_bytes());
        seed.extend_from_slice(&(i as u32).to_le_bytes());
        let desc = derive_coinbase_note_desc(recipient, &seed);
        let note = coinbase_note(&desc, out.value).map_err(|_| {
            ShieldedManagerError::MalformedCoinbaseNote("coinbase reward recipient is not a canonical Orchard address")
        })?;
        notes.push(note);
    }
    Ok(CoinbaseMint::new(notes))
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
    nullifier_muhash: DbShieldedNullifierMuHashStore,
    anchor_block: DbAnchorBlockStore,
}

impl ShieldedStateManager {
    /// Construct over the consensus database. Anchor-finality (maturity + canonical
    /// ancestry) is decided by the caller (virtual processor) using reachability and
    /// `shielded_anchor_depth`; this manager only records the anchor→block index.
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            nullifiers: DbNullifierSetStore::new(Arc::clone(&db), cache_policy),
            nullifier_diffs: DbNullifierDiffStore::new(Arc::clone(&db), cache_policy),
            tree_store: DbShieldedTreeStore::new(Arc::clone(&db), cache_policy),
            supply_store: DbShieldedSupplyStore::new(Arc::clone(&db), cache_policy),
            nullifier_muhash: DbShieldedNullifierMuHashStore::new(Arc::clone(&db), cache_policy),
            anchor_block: DbAnchorBlockStore::new(db, cache_policy),
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

    /// The global note-commitment tree **frontier** as of a given chain block — the
    /// checkpoint a light wallet fast-syncs from (`WalletDb::from_frontier`): it scans
    /// only blocks after this block, yet still witnesses its notes against the live
    /// tip. Returns the empty-tree frontier for blocks with no shielded state.
    pub fn frontier_at(&self, block: Hash) -> StoreResult<FrontierState> {
        self.tree_store.get(block)
    }

    /// The chain block whose shielded tree root equals `anchor`, if any block ever
    /// produced it (PLAN §2.5). The caller decides finality by checking that this
    /// block is a selected-chain ancestor of the spending block (reorg-safety) and
    /// at least `shielded_anchor_depth` deep (maturity). `None` means the anchor is
    /// not a real tree root of any block.
    pub fn anchor_source_block(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>> {
        self.anchor_block.get(anchor)
    }

    fn load_tree(&self, block: Hash) -> StoreResult<GlobalTree> {
        let state = self.tree_store.get(block)?;
        Ok(GlobalTree::from_state(&state).expect("persisted shielded frontier is corrupt"))
    }

    fn load_supply(&self, block: Hash) -> StoreResult<SupplyLedger> {
        let t = self.supply_store.get(block)?;
        Ok(SupplyLedger::from_totals(t.cumulative_coinbase, t.cumulative_fees))
    }

    /// The turnstile cumulative totals as of a given chain block (zero totals for
    /// blocks with no shielded state). Used by the pool-delta consensus check.
    pub fn supply_totals_at(&self, block: Hash) -> StoreResult<SupplyTotals> {
        self.supply_store.get(block)
    }

    /// Decide, in accepted order, which candidate shielded txs a chain block will
    /// actually APPLY — mirroring exactly the drop rules of the state transition:
    /// a spending tx whose anchor fails the caller's finality predicate (PLAN §2.5)
    /// is dropped, then first-in-accepted-order nullifier conflict resolution runs
    /// against the finalized set (PLAN §2.4). Returns a keep-mask aligned with `txs`.
    ///
    /// This exists so the coinbase can be built/verified from the *applied* fees
    /// only: a dropped spend never left the pool, so re-minting its fee in the
    /// coinbase would create unbacked supply (the F-01 inflation vector). It must
    /// be called against the same persisted nullifier state `compute` will see —
    /// i.e. with the selected-parent chain committed — which is the invariant the
    /// virtual processor already maintains for `compute` itself.
    pub fn partition_applied<F: FnMut(&ShieldedTx) -> bool>(&self, txs: &[ShieldedTx], mut anchor_final: F) -> Vec<bool> {
        let pending = MemNullifierSet::new();
        let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
        let mut resolver = NullifierConflictResolver::new(&finalized);
        txs.iter()
            .map(|stx| {
                (stx.nullifiers.is_empty() || anchor_final(stx)) && resolver.try_accept(stx.nullifiers.iter().copied()).is_ok()
            })
            .collect()
    }

    fn load_nullifier_muhash(&self, block: Hash) -> StoreResult<MuHash> {
        self.nullifier_muhash.get(block)
    }

    /// The canonical shielded state root (PLAN §2.10) as of a given chain block:
    /// binds the note-commitment tree root, the nullifier-set accumulator, and the
    /// turnstile totals. Used to attest a block's parent shielded state in the
    /// coinbase (a PoW-anchored commitment chain for fast/pruned sync).
    pub fn state_root_at(&self, block: Hash) -> StoreResult<[u8; 32]> {
        let anchor = self.load_tree(block)?.anchor().to_bytes();
        let mut m = self.load_nullifier_muhash(block)?;
        let nullifier_root = m.finalize().as_bytes().to_owned();
        let t = self.supply_store.get(block)?;
        Ok(kaspa_shielded_core::commitment::shielded_state_root(&anchor, &nullifier_root, t.cumulative_coinbase, t.cumulative_fees))
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
        // Anchor finality (maturity + canonical ancestry, PLAN §2.5) is checked by
        // the caller (virtual processor) before `compute`, since it needs
        // reachability and the spending block's blue score. Here we only apply the
        // transition against the selected parent's persisted state.
        let mut tree = self.load_tree(selected_parent)?;
        let mut supply = self.load_supply(selected_parent)?;
        let pending = MemNullifierSet::new();
        let outcome = {
            let finalized = LayeredNullifierSet { store: &self.nullifiers, pending: &pending };
            apply_chain_block_to(&finalized, &mut tree, &mut supply, coinbase, txs)?
        };
        // Advance the nullifier-set accumulator: the selected parent's snapshot
        // plus this block's newly spent nullifiers. MuHash is order-independent, so
        // this matches the set regardless of validation order and needs no separate
        // reorg handling (a reorg recomputes from the selected parent's snapshot).
        let mut nullifier_muhash = self.load_nullifier_muhash(selected_parent)?;
        for nf in &outcome.new_nullifiers {
            nullifier_muhash.add_element(nf);
        }
        Ok(ComputedBlockShielded {
            frontier_state: tree.to_state(),
            supply_totals: SupplyTotals {
                cumulative_coinbase: supply.cumulative_coinbase(),
                cumulative_fees: supply.cumulative_fees(),
            },
            nullifier_muhash,
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
            // Index this block's shielded tree root so spends can prove against it
            // (anchor-finality is decided at validation time via reachability + depth).
            // An anchor uniquely identifies (block, its history), so this is an
            // append-only map that needs no reorg reverting.
            self.anchor_block.set_batch(batch, computed.anchor(), block)?;
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
        // Snapshot the nullifier accumulator for *every* block once it is non-empty
        // (not only blocks that add nullifiers), so `state_root_at(block)` is
        // readable at any block — mirroring the frontier/supply snapshots. The
        // accumulator is add-only along a chain, so once non-empty it stays so.
        if computed.nullifier_muhash.clone().finalize() != kaspa_muhash::EMPTY_MUHASH {
            self.nullifier_muhash.set_batch(batch, block, computed.nullifier_muhash.clone())?;
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

    // ---------------------- Pruning-point IBD state transfer ----------------------

    /// Export the shielded metadata at `block` (a pruning point) for IBD transfer.
    /// Returns `None` when the block has no shielded state (empty pool — nothing to
    /// transfer). The caller streams the full global nullifier set separately via
    /// [`Self::nullifiers`]`().iter_all()`.
    pub fn export_pruning_point_shielded(&self, block: Hash) -> StoreResult<Option<PruningPointShieldedMetadata>> {
        let frontier = self.tree_store.get(block)?;
        if frontier.size == 0 {
            return Ok(None);
        }
        let supply = self.supply_store.get(block)?;
        let nullifier_muhash = self.nullifier_muhash.get(block)?;
        let state_root = PruningPointShieldedMetadata::recompute_state_root(&frontier, &supply, &nullifier_muhash);
        Ok(Some(PruningPointShieldedMetadata { frontier, supply, nullifier_muhash, state_root }))
    }

    /// Verify imported pruning-point shielded metadata against the streamed
    /// nullifier set: the set must reproduce the metadata's MuHash accumulator, and
    /// the declared state root must match the value recomputed from (frontier,
    /// supply, muhash). Internal consistency only — see
    /// [`PruningPointShieldedMetadata`] for how the consensus binding is enforced.
    pub fn verify_pruning_point_shielded<'a, I>(md: &PruningPointShieldedMetadata, nullifiers: I) -> Result<usize, String>
    where
        I: IntoIterator<Item = &'a [u8; 32]>,
    {
        // 1. The streamed set must reproduce the committed accumulator (MuHash is a
        //    multiset hash, so transfer order does not matter).
        let mut acc = MuHash::new();
        let mut count = 0usize;
        for nf in nullifiers {
            acc.add_element(nf);
            count += 1;
        }
        if acc.finalize() != md.nullifier_muhash.clone().finalize() {
            return Err(format!("streamed nullifier set ({count}) does not reproduce the committed accumulator"));
        }
        // 2. The declared state root must be consistent with the transferred parts.
        let recomputed =
            PruningPointShieldedMetadata::recompute_state_root(&md.frontier, &md.supply, &md.nullifier_muhash);
        if recomputed != md.state_root {
            return Err("declared shielded state root is inconsistent with (frontier, supply, nullifier_muhash)".to_string());
        }
        Ok(count)
    }

    /// Seed the shielded stores at the pruning point from verified imported state,
    /// so validation of the pruning point's descendants can proceed: they read
    /// `state_root_at(pruning_point)`, `frontier_at`, the global nullifier set, and
    /// the anchor→block index. Writes the same store shapes as [`Self::persist`]
    /// (no per-block nullifier diff — no reorg descends below a trusted pruning
    /// point). Call [`Self::verify_pruning_point_shielded`] first.
    pub fn seed_pruning_point_shielded<'a, I>(
        &self,
        batch: &mut WriteBatch,
        block: Hash,
        md: &PruningPointShieldedMetadata,
        nullifiers: I,
    ) -> StoreResult<()>
    where
        I: IntoIterator<Item = &'a [u8; 32]>,
    {
        // Per-block snapshots at the pruning point (mirrors `persist`).
        self.tree_store.set_batch(batch, block, md.frontier.clone())?;
        let anchor = GlobalTree::from_state(&md.frontier).expect("verified frontier").anchor().to_bytes();
        self.anchor_block.set_batch(batch, anchor, block)?;
        if md.supply.cumulative_coinbase > 0 || md.supply.cumulative_fees > 0 {
            self.supply_store.set_batch(batch, block, md.supply)?;
        }
        if md.nullifier_muhash.clone().finalize() != kaspa_muhash::EMPTY_MUHASH {
            self.nullifier_muhash.set_batch(batch, block, md.nullifier_muhash.clone())?;
        }
        // The whole append-only global membership set (unbounded, PLAN §2.9).
        for nf in nullifiers {
            self.nullifiers.insert_batch(batch, *nf)?;
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

    /// The empty-tree anchor (the finalized anchor of the genesis chain block).
    fn empty_anchor() -> [u8; 32] {
        kaspa_shielded_core::Anchor::empty_tree().to_bytes()
    }

    fn stx(nfs: &[u8], cmxs: &[u32], fee: u64) -> ShieldedTx {
        ShieldedTx {
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee,
            anchor: empty_anchor(),
        }
    }

    fn coinbase(value: u64, c: u32) -> CoinbaseMint {
        CoinbaseMint::new(vec![CoinbaseNote { value, commitment: cmx(c) }])
    }

    fn h(n: u8) -> Hash {
        Hash::from_bytes([n; 32])
    }

    /// A fresh manager. Anchor-finality (maturity + canonical ancestry) is enforced
    /// by the virtual processor via reachability, not by `compute`, so these unit
    /// tests exercise the transition/turnstile/nullifier logic directly.
    fn manager(db: &Arc<DB>) -> ShieldedStateManager {
        ShieldedStateManager::new(Arc::clone(db), CachePolicy::Count(64))
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
        let mgr = manager(&db);
        let (genesis, b1, b2) = (h(0), h(1), h(2));

        let c1 = commit_block(&mgr, &db, b1, genesis, Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        assert_eq!(c1.outcome.accepted, vec![0], "first spend of nf(1) wins");

        // b2 (parent b1) reuses nf(1); compute reads the persisted global set.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 20)), vec![stx(&[1], &[200], 5)]);
        assert!(c2.outcome.accepted.is_empty(), "second spend of nf(1) dropped");
        let tip_anchor = c2.anchor();

        // Fresh manager from the same DB: identical persisted anchor at the tip.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64));
        assert_eq!(mgr2.anchor_at(b2).unwrap(), tip_anchor);
        assert!(mgr2.nullifiers().contains(&nf(1)).unwrap());

        // A later block reusing nf(1) is still caught against the persisted set.
        let c3 = mgr2.compute(b2, None, &[stx(&[1], &[300], 0)]).unwrap();
        assert!(c3.outcome.accepted.is_empty(), "double-spend caught across sessions");
    }

    /// The shielded state root (PLAN §2.10) is persisted per block, reproduces
    /// exactly on a fresh manager, moves when a spend adds a nullifier, and its
    /// nullifier-accumulator component is empty until the first spend.
    #[test]
    fn state_root_commits_and_reproduces() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, b2, b3) = (h(1), h(2), h(3));

        // b1: coinbase only, no spend — nullifier accumulator is still empty.
        let c1 = commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 0)), vec![]);
        assert_eq!(c1.nullifier_root(), kaspa_muhash::EMPTY_MUHASH.as_bytes(), "no spend => empty accumulator");
        // compute-time root == the root recomputed from persisted stores.
        assert_eq!(c1.state_root(), mgr.state_root_at(b1).unwrap());

        // b2: coinbase + a spend — the accumulator (and thus the state root) moves.
        let c2 = commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        assert_ne!(c2.nullifier_root(), kaspa_muhash::EMPTY_MUHASH.as_bytes(), "spend populates accumulator");
        assert_ne!(c2.state_root(), c1.state_root(), "state root must advance");
        assert_eq!(c2.state_root(), mgr.state_root_at(b2).unwrap());

        // A fresh manager over the same DB reproduces both roots bit-for-bit.
        let mgr2 = ShieldedStateManager::new(Arc::clone(&db), CachePolicy::Count(64));
        assert_eq!(mgr2.state_root_at(b1).unwrap(), c1.state_root());
        assert_eq!(mgr2.state_root_at(b2).unwrap(), c2.state_root());

        // A no-spend child still carries the accumulator forward (readable at b3).
        let c3 = commit_block(&mgr, &db, b3, b2, Some(coinbase(50, 0)), vec![]);
        assert_eq!(c3.nullifier_root(), c2.nullifier_root(), "accumulator persists across a no-spend block");
        assert_eq!(mgr.state_root_at(b3).unwrap(), c3.state_root());
    }

    /// Pruning-point IBD transfer roundtrip (Tier-1 launch blocker): export the
    /// shielded state at a pruning point, verify + seed it into a fresh empty DB,
    /// and confirm the seeded node reproduces the state root, the anchor→block
    /// index, the frontier, the full nullifier membership, and still catches a
    /// double-spend of a pre-pruning nullifier while accepting a genuinely new one.
    #[test]
    fn pruning_point_shielded_export_seed_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (b1, b2, pp) = (h(1), h(2), h(3));

        // A small chain with three spends so the nullifier set is non-trivial.
        commit_block(&mgr, &db, b1, h(0), Some(coinbase(50, 10)), vec![stx(&[1], &[100], 5)]);
        commit_block(&mgr, &db, b2, b1, Some(coinbase(50, 20)), vec![stx(&[2], &[200], 5)]);
        let cpp = commit_block(&mgr, &db, pp, b2, Some(coinbase(50, 30)), vec![stx(&[3], &[300], 5)]);
        let pp_root = cpp.state_root();
        let pp_anchor = cpp.anchor();

        // Export at the pruning point + collect the full nullifier set.
        let md = mgr.export_pruning_point_shielded(pp).unwrap().expect("pp has shielded state");
        assert_eq!(md.state_root, pp_root, "exported root == the committed root");
        let nullifiers: Vec<[u8; 32]> = mgr.nullifiers().iter_all().map(|r| r.unwrap()).collect();
        assert_eq!(nullifiers.len(), 3, "three spends => three nullifiers");

        // Verify passes; a tampered supply (inconsistent root) and a short set fail.
        assert_eq!(ShieldedStateManager::verify_pruning_point_shielded(&md, nullifiers.iter()).unwrap(), 3);
        let mut bad = md.clone();
        bad.supply.cumulative_fees += 1;
        assert!(
            ShieldedStateManager::verify_pruning_point_shielded(&bad, nullifiers.iter()).is_err(),
            "inconsistent declared state root must be rejected"
        );
        assert!(
            ShieldedStateManager::verify_pruning_point_shielded(&md, nullifiers[..2].iter()).is_err(),
            "a short nullifier set must not reproduce the accumulator"
        );

        // Seed into a fresh, empty DB (the fast-syncing node).
        let (_lt2, db2) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let seeded = manager(&db2);
        let mut batch = WriteBatch::default();
        seeded.seed_pruning_point_shielded(&mut batch, pp, &md, nullifiers.iter()).unwrap();
        db2.write(batch).unwrap();

        // The seeded node reproduces the pruning point's shielded state exactly.
        assert_eq!(seeded.state_root_at(pp).unwrap(), pp_root, "seeded state root matches");
        assert_eq!(seeded.anchor_at(pp).unwrap(), pp_anchor);
        assert_eq!(seeded.frontier_at(pp).unwrap(), md.frontier);
        assert_eq!(seeded.anchor_source_block(&pp_anchor).unwrap(), Some(pp), "anchor→block index seeded");
        for spent in [1u8, 2, 3] {
            assert!(seeded.nullifiers().contains(&nf(spent)).unwrap(), "pre-pruning nullifier present");
        }

        // A descendant of the pruning point extends the tree and still catches a
        // re-spend of a pre-pruning nullifier against the seeded global set, while
        // accepting a genuinely new spend.
        let dbl = seeded.compute(pp, Some(&coinbase(50, 40)), &[stx(&[2], &[400], 5)]).unwrap();
        assert!(dbl.outcome.accepted.is_empty(), "re-spend of a pre-pruning nullifier dropped");
        let ok = seeded.compute(pp, Some(&coinbase(50, 41)), &[stx(&[9], &[401], 5)]).unwrap();
        assert_eq!(ok.outcome.accepted, vec![0], "a genuinely new spend is accepted on the seeded node");
    }

    /// Reverting a block removes the nullifiers it added, so the same nullifier
    /// can be spent again on the new branch (reorg correctness).
    #[test]
    fn revert_removes_block_nullifiers() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
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
        let mgr = manager(&db);
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

    /// Reorg with a shielded COINBASE: a coinbase mint on the abandoned branch
    /// must not leak into the competing branch's pool or anchor, and abandoning
    /// the branch must revert its nullifiers so the competing branch can re-spend
    /// the note. Because per-block frontier/supply snapshots are keyed by block
    /// hash, the competing branch loads its own selected-parent's state and never
    /// inherits the abandoned coinbase; only the global nullifier set is shared
    /// and is reverted via the per-block diff.
    #[test]
    fn reorg_isolates_and_reverts_shielded_coinbase() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let (genesis, branch_a, branch_b) = (h(0), h(1), h(2));

        // Branch A (from genesis): coinbase mints 100, a tx spends nf(1), fee 5.
        let ca = commit_block(&mgr, &db, branch_a, genesis, Some(coinbase(100, 10)), vec![stx(&[1], &[100], 5)]);
        assert_eq!(ca.outcome.accepted, vec![0]);
        assert!(mgr.nullifiers().contains(&nf(1)).unwrap());
        let pool_a = ca.supply_totals.cumulative_coinbase - ca.supply_totals.cumulative_fees;
        assert_eq!(pool_a, 100 - 5, "branch A pool = subsidy - fee");
        let anchor_a = ca.anchor();

        // Reorg abandons branch A: revert its nullifiers from the global set.
        let mut rb = WriteBatch::default();
        mgr.revert_nullifiers_from_store(&mut rb, branch_a).unwrap();
        db.write(rb).unwrap();
        assert!(!mgr.nullifiers().contains(&nf(1)).unwrap(), "abandoned coinbase-block's nullifier reverted");

        // Branch B (also from genesis): a DIFFERENT coinbase mints 100, and a tx
        // re-spends the SAME nf(1) (now allowed) with fee 7. compute() loads the
        // genesis (empty) snapshot as its parent — branch A's coinbase mint of 100
        // is NOT present.
        let cb = commit_block(&mgr, &db, branch_b, genesis, Some(coinbase(100, 20)), vec![stx(&[1], &[200], 7)]);
        assert_eq!(cb.outcome.accepted, vec![0], "reverted note re-spendable on the competing branch");

        // Isolation: branch B's pool is its own subsidy - fee, NOT A's mint too
        // (would be 200 - 12 if A had leaked). The abandoned coinbase carried no
        // value across the reorg.
        let pool_b = cb.supply_totals.cumulative_coinbase - cb.supply_totals.cumulative_fees;
        assert_eq!(pool_b, 100 - 7, "branch B pool excludes the abandoned branch's coinbase");

        // Distinct branches, distinct anchors: A's coinbase note never entered B's tree.
        assert_ne!(cb.anchor(), anchor_a, "competing branch has an independent anchor");
    }

    /// Spending more than was ever minted is rejected (turnstile) at compute time.
    #[test]
    fn rejects_overspend() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        let res = mgr.compute(h(0), Some(&coinbase(10, 1)), &[stx(&[7], &[2], 11)]);
        assert!(matches!(res, Err(ShieldedManagerError::State(ShieldedStateError::Turnstile(_)))));
    }

    /// THE make-or-break property (PLAN Phase 1) at the consensus-manager layer:
    /// when a chain block **merges two parallel blocks** that each spend the same
    /// shielded note, both of those spends land in that one chain block's accepted
    /// set and are resolved in a **single** store-backed `compute` call (this is
    /// exactly what the virtual processor does — `ctx.shielded_txs` gathers the
    /// whole mergeset, then one `compute` runs). Exactly one spend must survive,
    /// the nullifier must be recorded once, no value may be created, and — the
    /// determinism requirement — two independent nodes must compute the identical
    /// anchor from the identical accepted order.
    #[test]
    fn parallel_mergeset_double_spend_resolved_in_one_compute() {
        // Two independent "nodes", each with its own DB/manager, apply the identical
        // accepted order: a coinbase (mints 100) then two conflicting spends of nf(1)
        // — the first from merged block X, the second from merged block Y — plus one
        // independent spend of nf(2). GHOSTDAG fixed the order [X's tx, Y's tx, other].
        let build_tip = || {
            let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
            let mgr = manager(&db);
            // First, a coinbase-only block matures a note into the pool for nf(1)/nf(2)
            // to have been "minted" against (turnstile needs the pool funded).
            let c0 = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(100, 10)), vec![]);
            assert_eq!(c0.outcome.accepted.len(), 0);
            // The merging chain block h(2): its accepted set carries BOTH conflicting
            // spends of nf(1) (from the two parallel merged blocks) and an independent
            // spend of nf(2), all resolved in this one compute call.
            let computed = mgr
                .compute(
                    h(1),
                    None,
                    &[
                        stx(&[1], &[100], 5), // X's spend of nf(1) — first in order, wins
                        stx(&[1], &[200], 5), // Y's spend of nf(1) — dropped (double-spend)
                        stx(&[2], &[300], 5), // independent spend — survives
                    ],
                )
                .unwrap();
            // Release all DB references before `_lt` drops (its Drop asserts the DB has
            // no strong refs left); only the owned `computed` result escapes.
            drop(mgr);
            drop(db);
            computed
        };

        let a = build_tip();
        let b = build_tip();

        // Exactly one of the conflicting spends survives; the independent one also does.
        assert_eq!(a.outcome.accepted, vec![0, 2], "first spend of nf(1) wins, Y's is dropped, nf(2) survives");
        // The double-spent nullifier is recorded exactly once (plus nf(2) once).
        assert_eq!(a.outcome.new_nullifiers.len(), 2);
        // No value created: pool = coinbase(100) − fees(5 for tx0 + 5 for tx2); Y's
        // dropped tx contributes no fee.
        assert_eq!(a.supply_totals.cumulative_coinbase - a.supply_totals.cumulative_fees, 100 - 10);
        // Determinism: two independent nodes compute the identical anchor.
        assert_eq!(a.anchor(), b.anchor(), "identical anchor across nodes from identical accepted order");
    }

    /// F-01 regression, the partition rules: `partition_applied` must drop exactly
    /// what the state transition drops — spends against non-final anchors, and
    /// nullifier conflicts both against the persisted set and within the batch
    /// (first in accepted order wins) — while pure-output txs are always kept.
    #[test]
    fn partition_applied_mirrors_transition_drop_rules() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);

        // Persist a block spending nf(1) so the finalized set contains it.
        commit_block(&mgr, &db, h(1), h(0), Some(coinbase(100, 10)), vec![stx(&[1], &[100], 5)]);

        let bad_anchor = [0xbb; 32];
        let mut immature = stx(&[4], &[400], 9);
        immature.anchor = bad_anchor;
        let candidates = vec![
            stx(&[2], &[200], 5),  // fresh spend — kept
            stx(&[1], &[201], 5),  // conflicts with the PERSISTED nf(1) — dropped
            stx(&[2], &[202], 7),  // conflicts with the batch's first tx — dropped
            immature,              // spend against a non-final anchor — dropped
            stx(&[], &[203], 0),   // pure-output (no nullifiers): anchor rule exempt — kept
            stx(&[3], &[204], 2),  // independent spend — kept
        ];
        let keep = mgr.partition_applied(&candidates, |stx| stx.anchor != bad_anchor);
        assert_eq!(keep, vec![true, false, false, false, true, true]);

        // The transition applied to the FULL set accepts exactly the kept indices —
        // the partition is a faithful precomputation of the transition's drops.
        let computed = mgr.compute(h(1), None, &candidates).unwrap();
        let kept_indices: Vec<usize> = keep.iter().enumerate().filter(|(_, k)| **k).map(|(i, _)| i).collect();
        // `compute` has no anchor predicate (the caller pre-filters), so exclude
        // the anchor-dropped tx from the comparison by feeding the pre-filtered set.
        let anchor_ok: Vec<ShieldedTx> = candidates.iter().filter(|s| s.anchor != bad_anchor).cloned().collect();
        let computed_filtered = mgr.compute(h(1), None, &anchor_ok).unwrap();
        assert_eq!(computed_filtered.outcome.accepted.len(), kept_indices.len());
        // And on the full set the nullifier-only drops agree (indices 1 and 2 dropped).
        assert_eq!(computed.outcome.accepted, vec![0, 3, 4, 5], "nullifier rules agree with the mask (anchor rule aside)");
    }

    /// F-01 regression, the accounting: when a spend is dropped, the coinbase must
    /// re-mint only the APPLIED fees — then the pool grows by exactly the subsidy.
    /// The counterfactual shows the pre-fix behavior (coinbase re-mints the dropped
    /// fee too) inflates the pool by exactly that fee — which the new pool-delta
    /// consensus check rejects.
    #[test]
    fn dropped_spend_fee_is_not_reminted() {
        const SUBSIDY: u64 = 100;
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);

        // Fund the pool.
        let c1 = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(SUBSIDY, 10)), vec![]);
        let pool_before = c1.supply_totals.cumulative_coinbase - c1.supply_totals.cumulative_fees;

        // Two conflicting spends of nf(1) arrive in one mergeset: fees 5 and 7.
        let candidates = vec![stx(&[1], &[100], 5), stx(&[1], &[200], 7)];
        let keep = mgr.partition_applied(&candidates, |_| true);
        assert_eq!(keep, vec![true, false]);
        let applied: Vec<ShieldedTx> = candidates.iter().zip(&keep).filter(|(_, k)| **k).map(|(s, _)| s.clone()).collect();
        let applied_fees: u64 = applied.iter().map(|s| s.fee).sum();
        assert_eq!(applied_fees, 5);

        // COUNTERFACTUAL (the pre-fix coinbase), computed first — before h(2) is
        // committed, so nf(1) is not yet in the persisted set (`compute` does not
        // persist): re-minting the dropped fee too (subsidy + 5 + 7) inflates the
        // pool by the dropped 7 — silent unbacked supply. This is what
        // verify_expected_utxo_state's pool-delta check now turns into an
        // InvalidShieldedState rejection.
        let c_bad = mgr.compute(h(1), Some(&coinbase(SUBSIDY + 5 + 7, 21)), &applied).unwrap();
        let bad_pool = c_bad.supply_totals.cumulative_coinbase - c_bad.supply_totals.cumulative_fees;
        assert_eq!(bad_pool - pool_before, (SUBSIDY + 7) as u128, "the old behavior mints the dropped fee unbacked");

        // FIXED coinbase: subsidy + applied fees only. Pool grows by the subsidy.
        let c2 = commit_block(&mgr, &db, h(2), h(1), Some(coinbase(SUBSIDY + applied_fees, 20)), applied);
        let pool_after = c2.supply_totals.cumulative_coinbase - c2.supply_totals.cumulative_fees;
        assert_eq!(pool_after - pool_before, SUBSIDY as u128, "pool must grow by exactly the subsidy");
    }

    /// The anchor→block index records a block's tree root so a spend can later be
    /// resolved to its source block (finality/canonicality is then decided by the
    /// virtual processor via reachability + depth, tested at that layer).
    #[test]
    fn records_anchor_source_block() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let mgr = manager(&db);
        // Commit a coinbase-only block; its non-empty tree root is indexed to h(1).
        let computed = commit_block(&mgr, &db, h(1), h(0), Some(coinbase(10, 1)), vec![]);
        let anchor = computed.anchor();
        assert_eq!(mgr.anchor_source_block(&anchor).unwrap(), Some(h(1)));
        // An anchor no block produced is unknown.
        assert_eq!(mgr.anchor_source_block(&[0xabu8; 32]).unwrap(), None);
    }
}
