//! Consensus stores for the shielded pool (PLAN §3), reorg-safe.
//!
//! Because the virtual processor re-applies chain blocks across reorgs (see
//! decision D10 in DEVLOG), the append-only shielded state is keyed **per chain
//! block**, exactly like the transparent UTXO state:
//!
//! - [`DbShieldedTreeStore`] — the global note-commitment tree **frontier
//!   snapshot at each chain block** (keyed by block hash). To extend a block we
//!   load its selected parent's frontier; to reorg we just load the frontier at
//!   the new tip. No reversal of appends is needed (§2.9).
//! - [`DbNullifierSetStore`] — the global, append-only spent-nullifier set
//!   (membership), plus [`DbNullifierDiffStore`] recording the nullifiers added
//!   by each chain block so a reorg can remove an abandoned branch's nullifiers.
//! - [`DbShieldedSupplyStore`] — the turnstile cumulative totals snapshot at each
//!   chain block (§2.6).
//! - [`DbAnchorBlockStore`] — maps each shielded tree root (anchor) to the block
//!   that produced it, so anchor-finality is decided reorg-consistently at
//!   validation time (canonical ancestor + `shielded_anchor_depth` deep), §2.5.
//!
//! The append/conflict/turnstile logic lives in `kaspa-shielded-core`; these are
//! the rocksdb-backed persistence the virtual processor drives.

use std::fmt;
use std::sync::Arc;

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, DB, StoreError, StoreResult};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
use kaspa_math::Uint3072;
use kaspa_muhash::MuHash;
use kaspa_shielded_core::tree::FrontierState;
use kaspa_utils::mem_size::MemSizeEstimator;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

/// A nullifier as a database key: its canonical 32-byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NullifierKey(pub [u8; 32]);

impl AsRef<[u8]> for NullifierKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ----------------------------- Nullifier set -----------------------------

pub trait NullifierSetStoreReader {
    /// Whether this nullifier has already been spent (is in the global set).
    fn contains(&self, nullifier: &[u8; 32]) -> StoreResult<bool>;
}

pub trait NullifierSetStore: NullifierSetStoreReader {
    /// Insert a freshly spent nullifier into the global set.
    fn insert_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()>;
    /// Remove a nullifier (used when reverting an abandoned branch's block).
    fn delete_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()>;
}

/// rocksdb + cache implementation of the global, append-only nullifier set. The
/// value is a single marker byte; presence of the key means "spent".
#[derive(Clone)]
pub struct DbNullifierSetStore {
    db: Arc<DB>,
    access: CachedDbAccess<NullifierKey, u8>,
}

impl DbNullifierSetStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifiers.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }
}

impl NullifierSetStoreReader for DbNullifierSetStore {
    fn contains(&self, nullifier: &[u8; 32]) -> StoreResult<bool> {
        self.access.has(NullifierKey(*nullifier))
    }
}

impl NullifierSetStore for DbNullifierSetStore {
    fn insert_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), NullifierKey(nullifier), 1u8)
    }

    fn delete_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), NullifierKey(nullifier))
    }
}

// ------------------- Per-block nullifier additions (revert) ---------------

pub trait NullifierDiffStoreReader {
    /// The nullifiers added by a chain block (empty if none / unknown).
    fn get(&self, block: Hash) -> StoreResult<Vec<[u8; 32]>>;
}

/// Records, per chain block, the nullifiers it added to the global set, so a
/// reorg can remove an abandoned branch's nullifiers.
#[derive(Clone)]
pub struct DbNullifierDiffStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Vec<[u8; 32]>, BlockHasher>,
}

impl DbNullifierDiffStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifierDiffs.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, nullifiers: Vec<[u8; 32]>) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, nullifiers)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl NullifierDiffStoreReader for DbNullifierDiffStore {
    fn get(&self, block: Hash) -> StoreResult<Vec<[u8; 32]>> {
        match self.access.read(block) {
            Ok(v) => Ok(v),
            Err(StoreError::KeyNotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------- Global tree frontier --------------------------

/// Newtype wrapper so we can implement the foreign `MemSizeEstimator` trait for
/// the foreign `FrontierState` type (orphan rule). Serializes transparently.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoredFrontier(pub FrontierState);

impl MemSizeEstimator for StoredFrontier {}

pub trait ShieldedTreeStoreReader {
    /// The frontier snapshot at `block`, or the empty-tree frontier if absent
    /// (e.g. the parent of the first shielded block).
    fn get(&self, block: Hash) -> StoreResult<FrontierState>;
}

/// Per-chain-block frontier snapshots of the global note-commitment tree.
#[derive(Clone)]
pub struct DbShieldedTreeStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, StoredFrontier, BlockHasher>,
}

impl DbShieldedTreeStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedTreeFrontier.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, state: FrontierState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, StoredFrontier(state))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedTreeStoreReader for DbShieldedTreeStore {
    fn get(&self, block: Hash) -> StoreResult<FrontierState> {
        match self.access.read(block) {
            Ok(s) => Ok(s.0),
            Err(StoreError::KeyNotFound(_)) => Ok(FrontierState::default()),
            Err(e) => Err(e),
        }
    }
}

// ----------------------------- Turnstile ----------------------------------

/// Persisted cumulative totals backing the turnstile invariant (PLAN §2.6),
/// snapshotted at each chain block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyTotals {
    pub cumulative_coinbase: u128,
    pub cumulative_fees: u128,
}

impl MemSizeEstimator for SupplyTotals {}

pub trait ShieldedSupplyStoreReader {
    fn get(&self, block: Hash) -> StoreResult<SupplyTotals>;
}

/// Per-chain-block snapshots of the turnstile cumulative totals.
#[derive(Clone)]
pub struct DbShieldedSupplyStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, SupplyTotals, BlockHasher>,
}

impl DbShieldedSupplyStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedSupply.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, totals: SupplyTotals) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, totals)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedSupplyStoreReader for DbShieldedSupplyStore {
    fn get(&self, block: Hash) -> StoreResult<SupplyTotals> {
        match self.access.read(block) {
            Ok(t) => Ok(t),
            Err(StoreError::KeyNotFound(_)) => Ok(SupplyTotals::default()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------ Nullifier MuHash accumulator ------------------------

pub trait ShieldedNullifierMuHashStoreReader {
    /// The MuHash accumulator over all spent nullifiers as of the given chain
    /// block. A block with no shielded activity has never been written and
    /// inherits the empty accumulator, so `default` (empty) is returned.
    fn get(&self, block: Hash) -> StoreResult<MuHash>;
}

/// Per-chain-block snapshot of the [`MuHash`] accumulator over the global
/// spent-nullifier set (PLAN §2.2, §2.10).
///
/// Unlike [`DbNullifierDiffStore`] (which records per-block *diffs* so the flat
/// membership set can be reorged), this is an **absolute** snapshot of the
/// accumulator *value* as of each block — mirroring [`DbShieldedSupplyStore`] and
/// the frontier store. Because the accumulator only ever *adds* nullifiers along
/// a given chain (a reorg recomputes from the selected parent, never subtracts
/// from a snapshot), the stored value finalizes to a single field element and is
/// persisted as [`Uint3072`], exactly like the UTXO multiset. It lets the
/// shielded state root commit to double-spend prevention so a fast/pruned node
/// can trust the nullifier set at a checkpoint without replaying from genesis.
#[derive(Clone)]
pub struct DbShieldedNullifierMuHashStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, Uint3072, BlockHasher>,
}

impl DbShieldedNullifierMuHashStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedNullifierMuHash.into()),
        }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, block: Hash, muhash: MuHash) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), block, muhash.try_into().expect("nullifier muhash is add-only, so finalizes"))
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, block: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), block)
    }
}

impl ShieldedNullifierMuHashStoreReader for DbShieldedNullifierMuHashStore {
    fn get(&self, block: Hash) -> StoreResult<MuHash> {
        match self.access.read(block) {
            Ok(u) => Ok(u.into()),
            Err(StoreError::KeyNotFound(_)) => Ok(MuHash::new()),
            Err(e) => Err(e),
        }
    }
}

// ------------------------- Finalized anchor ring -------------------------

/// An anchor (global tree root) as a database key: its 32-byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AnchorKey(pub [u8; 32]);

impl AsRef<[u8]> for AnchorKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for AnchorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

pub trait AnchorBlockStoreReader {
    /// The chain block whose shielded tree root equals `anchor`, if any block ever
    /// produced it. `None` means no block did (the anchor is not a real tree root).
    fn get(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>>;
}

/// Maps each shielded tree root (anchor) to the block that produced it (PLAN §2.5).
///
/// An anchor is a collision-resistant hash of the entire note sequence up to a
/// block, so it uniquely identifies `(block, its selected-chain history)`. This
/// index lets anchor-finality be decided reorg-consistently at validation time:
/// a spend's anchor is acceptable iff its source block is a selected-chain
/// ancestor of the spending block **and** at least `shielded_anchor_depth` deep.
/// Because that canonicality is re-checked via reachability on every query, the
/// index itself is append-only and needs no reorg reverting — an anchor from an
/// abandoned branch simply fails the ancestor check.
#[derive(Clone)]
pub struct DbAnchorBlockStore {
    db: Arc<DB>,
    access: CachedDbAccess<AnchorKey, Hash>,
}

impl DbAnchorBlockStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedAnchors.into()) }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, anchor: [u8; 32], block: Hash) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), AnchorKey(anchor), block)
    }
}

impl AnchorBlockStoreReader for DbAnchorBlockStore {
    fn get(&self, anchor: &[u8; 32]) -> StoreResult<Option<Hash>> {
        match self.access.read(AnchorKey(*anchor)) {
            Ok(block) => Ok(Some(block)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_database::create_temp_db;
    use kaspa_database::prelude::ConnBuilder;

    #[test]
    fn anchor_block_index_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAnchorBlockStore::new(db.clone(), CachePolicy::Count(16));
        let anchor = [9u8; 32];
        let block = Hash::from_bytes([3u8; 32]);
        assert_eq!(store.get(&anchor).unwrap(), None);
        let mut b = WriteBatch::default();
        store.set_batch(&mut b, anchor, block).unwrap();
        db.write(b).unwrap();
        assert_eq!(store.get(&anchor).unwrap(), Some(block));
        assert_eq!(store.get(&[0u8; 32]).unwrap(), None);
    }

    #[test]
    fn nullifier_set_insert_delete_roundtrip() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbNullifierSetStore::new(db.clone(), CachePolicy::Count(16));
        let nf = [7u8; 32];
        assert!(!store.contains(&nf).unwrap());
        let mut b = WriteBatch::default();
        store.insert_batch(&mut b, nf).unwrap();
        db.write(b).unwrap();
        assert!(store.contains(&nf).unwrap());
        // Revert: deletion removes it again.
        let mut b2 = WriteBatch::default();
        store.delete_batch(&mut b2, nf).unwrap();
        db.write(b2).unwrap();
        assert!(!store.contains(&nf).unwrap());
    }

    #[test]
    fn frontier_store_is_block_keyed() {
        let (_lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbShieldedTreeStore::new(db.clone(), CachePolicy::Count(16));
        let block_a = Hash::from_bytes([1; 32]);
        let block_b = Hash::from_bytes([2; 32]);
        // Absent block -> empty frontier.
        assert_eq!(store.get(block_a).unwrap(), FrontierState::default());
        let fs = FrontierState { size: 3, leaf: Some([9; 32]), ommers: vec![[8; 32]] };
        let mut b = WriteBatch::default();
        store.set_batch(&mut b, block_a, fs.clone()).unwrap();
        db.write(b).unwrap();
        assert_eq!(store.get(block_a).unwrap(), fs);
        // A different block is independent.
        assert_eq!(store.get(block_b).unwrap(), FrontierState::default());
    }
}
