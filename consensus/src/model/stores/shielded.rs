//! Consensus stores for the shielded pool (PLAN §3).
//!
//! Three pieces of order-sensitive global state plus the turnstile totals:
//!
//! - [`DbNullifierSetStore`] — the append-only set of spent nullifiers (§2.2).
//! - [`DbShieldedTreeStore`] — the persisted frontier of the global
//!   note-commitment tree (§2.9); a single item holding ~32 nodes.
//! - [`DbShieldedAnchorsStore`] — a ring buffer of recent finalized anchors that
//!   spends reference (§2.5).
//! - [`DbShieldedSupplyStore`] — cumulative coinbase/fee totals for the turnstile
//!   invariant (§2.6).
//!
//! The actual append/conflict/turnstile logic lives in `kaspa-shielded-core`;
//! these stores are the rocksdb-backed persistence the virtual processor drives.

use std::fmt;
use std::sync::Arc;

use kaspa_database::prelude::{BatchDbWriter, CachePolicy, CachedDbAccess, CachedDbItem, DirectDbWriter, StoreError, StoreResult, DB};
use kaspa_database::registry::DatabaseStorePrefixes;
use kaspa_shielded_core::tree::FrontierState;
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
    /// Whether this nullifier has already been spent.
    fn contains(&self, nullifier: &[u8; 32]) -> StoreResult<bool>;
}

pub trait NullifierSetStore: NullifierSetStoreReader {
    /// Insert a freshly spent nullifier (idempotent at the storage layer; the
    /// consensus layer rejects double-spends before reaching here).
    fn insert_batch(&self, batch: &mut WriteBatch, nullifier: [u8; 32]) -> StoreResult<()>;
}

/// rocksdb + cache implementation of the append-only nullifier set. The value is
/// a single marker byte; presence of the key means "spent".
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
}

// ------------------------- Global tree frontier --------------------------

pub trait ShieldedTreeStoreReader {
    /// The persisted frontier, or the empty-tree state if none has been written.
    fn get(&self) -> StoreResult<FrontierState>;
}

/// Single-item store holding the global note-commitment tree frontier.
#[derive(Clone)]
pub struct DbShieldedTreeStore {
    db: Arc<DB>,
    access: CachedDbItem<FrontierState>,
}

impl DbShieldedTreeStore {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbItem::new(db, DatabaseStorePrefixes::ShieldedTreeFrontier.into()) }
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(Arc::clone(&self.db))
    }

    pub fn set_batch(&mut self, batch: &mut WriteBatch, state: &FrontierState) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), state)
    }

    pub fn set(&mut self, state: &FrontierState) -> StoreResult<()> {
        self.access.write(DirectDbWriter::new(&self.db), state)
    }
}

impl ShieldedTreeStoreReader for DbShieldedTreeStore {
    fn get(&self) -> StoreResult<FrontierState> {
        match self.access.read() {
            Ok(state) => Ok(state),
            // Before the first shielded block the frontier is the empty tree.
            Err(StoreError::KeyNotFound(_)) => Ok(FrontierState::default()),
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

/// Single-item store for the finalized-anchor ring buffer.
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

// ----------------------------- Turnstile ----------------------------------

/// Persisted cumulative totals backing the turnstile invariant (PLAN §2.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyTotals {
    pub cumulative_coinbase: u128,
    pub cumulative_fees: u128,
}

pub trait ShieldedSupplyStoreReader {
    fn get(&self) -> StoreResult<SupplyTotals>;
}

/// Single-item store for the turnstile cumulative totals.
#[derive(Clone)]
pub struct DbShieldedSupplyStore {
    db: Arc<DB>,
    access: CachedDbItem<SupplyTotals>,
}

impl DbShieldedSupplyStore {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbItem::new(db, DatabaseStorePrefixes::ShieldedSupply.into()) }
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(Arc::clone(&self.db))
    }

    pub fn set_batch(&mut self, batch: &mut WriteBatch, totals: &SupplyTotals) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), totals)
    }
}

impl ShieldedSupplyStoreReader for DbShieldedSupplyStore {
    fn get(&self) -> StoreResult<SupplyTotals> {
        match self.access.read() {
            Ok(t) => Ok(t),
            Err(StoreError::KeyNotFound(_)) => Ok(SupplyTotals::default()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_ring_evicts_oldest() {
        let mut r = AnchorRingBuffer::new(3);
        for i in 0u8..5 {
            r.push([i; 32]);
        }
        // Capacity 3 retains the last three (2,3,4).
        assert_eq!(r.anchors.len(), 3);
        assert!(!r.contains(&[0; 32]));
        assert!(!r.contains(&[1; 32]));
        assert!(r.contains(&[2; 32]));
        assert!(r.contains(&[4; 32]));
        assert_eq!(r.latest(), Some(&[4u8; 32]));
    }
}
