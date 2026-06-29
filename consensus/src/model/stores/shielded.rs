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
//! - [`DbShieldedAnchorsStore`] — a single ring buffer of recent finalized
//!   anchors at the virtual tip that spends reference (§2.5).
//!
//! The append/conflict/turnstile logic lives in `kaspa-shielded-core`; these are
//! the rocksdb-backed persistence the virtual processor drives.

use std::fmt;
use std::sync::Arc;

use kaspa_consensus_core::BlockHasher;
use kaspa_database::prelude::{
    BatchDbWriter, CachePolicy, CachedDbAccess, CachedDbItem, DirectDbWriter, StoreError, StoreResult, DB,
};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_hashes::Hash;
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
        Self {
            db: Arc::clone(&db),
            access: CachedDbAccess::new(db, cache_policy, DatabaseStorePrefixes::ShieldedTreeFrontier.into()),
        }
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

// ------------------------- Finalized anchor ring -------------------------

/// A bounded ring buffer of the most recent finalized anchors (PLAN §2.5). A
/// spend may prove against any anchor still present here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRingBuffer {
    /// Maximum number of anchors retained (the anchor-depth window).
    pub capacity: u32,
    /// Recent anchors, oldest first.
    pub anchors: Vec<[u8; 32]>,
}

impl AnchorRingBuffer {
    pub fn new(capacity: u32) -> Self {
        Self { capacity, anchors: Vec::new() }
    }

    /// Push a newly finalized anchor, evicting the oldest beyond `capacity`.
    pub fn push(&mut self, anchor: [u8; 32]) {
        self.anchors.push(anchor);
        let cap = self.capacity.max(1) as usize;
        if self.anchors.len() > cap {
            let overflow = self.anchors.len() - cap;
            self.anchors.drain(0..overflow);
        }
    }

    /// Whether `anchor` is within the current finalized window.
    pub fn contains(&self, anchor: &[u8; 32]) -> bool {
        self.anchors.iter().any(|a| a == anchor)
    }

    /// The most recent (tip) finalized anchor, if any.
    pub fn latest(&self) -> Option<&[u8; 32]> {
        self.anchors.last()
    }
}

pub trait ShieldedAnchorsStoreReader {
    fn get(&self) -> StoreResult<AnchorRingBuffer>;
}

/// Single-item store for the finalized-anchor ring buffer at the virtual tip.
#[derive(Clone)]
pub struct DbShieldedAnchorsStore {
    db: Arc<DB>,
    access: CachedDbItem<AnchorRingBuffer>,
    default_capacity: u32,
}

impl DbShieldedAnchorsStore {
    pub fn new(db: Arc<DB>, default_capacity: u32) -> Self {
        Self {
            db: Arc::clone(&db),
            access: CachedDbItem::new(db, DatabaseStorePrefixes::ShieldedAnchors.into()),
            default_capacity,
        }
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(Arc::clone(&self.db), self.default_capacity)
    }

    pub fn set_batch(&mut self, batch: &mut WriteBatch, ring: &AnchorRingBuffer) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), ring)
    }

    pub fn set(&mut self, ring: &AnchorRingBuffer) -> StoreResult<()> {
        self.access.write(DirectDbWriter::new(&self.db), ring)
    }
}

impl ShieldedAnchorsStoreReader for DbShieldedAnchorsStore {
    fn get(&self) -> StoreResult<AnchorRingBuffer> {
        match self.access.read() {
            Ok(ring) => Ok(ring),
            Err(StoreError::KeyNotFound(_)) => Ok(AnchorRingBuffer::new(self.default_capacity)),
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
    fn anchor_ring_evicts_oldest() {
        let mut r = AnchorRingBuffer::new(3);
        for i in 0u8..5 {
            r.push([i; 32]);
        }
        assert_eq!(r.anchors.len(), 3);
        assert!(!r.contains(&[0; 32]));
        assert!(r.contains(&[2; 32]));
        assert!(r.contains(&[4; 32]));
        assert_eq!(r.latest(), Some(&[4u8; 32]));
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
