//! The nullifier set and first-in-accepted-order conflict resolution
//! (PLAN §2.2, §2.4 steps 1–2).
//!
//! A nullifier is the unique, unlinkable tag revealed when a shielded note is
//! spent. The set of all nullifiers ever spent is **append-only** and must be
//! checkable forever: a repeat is a double-spend.
//!
//! On the DAG, nullifiers are *first-class conflict keys*, resolved exactly like
//! transparent UTXO double-spends: while the accepted transaction set is walked
//! in GHOSTDAG accepted order, the first transaction to reveal a given nullifier
//! wins; any later transaction reusing it is dropped. Because every honest node
//! walks the identical accepted order, every node accepts the identical set and
//! inserts the identical nullifiers.

use std::collections::HashSet;

use orchard::note::Nullifier;

/// A nullifier keyed by its canonical 32-byte encoding, for set membership.
///
/// We key on bytes rather than the `orchard::Nullifier` type so the set has a
/// stable, storable, hashable representation independent of curve internals.
pub type NullifierBytes = [u8; 32];

/// Canonical byte key for an Orchard nullifier.
pub fn key(nf: &Nullifier) -> NullifierBytes {
    nf.to_bytes()
}

/// Read access to the persistent, append-only nullifier set (PLAN §2.2).
///
/// The consensus layer implements this over its rocksdb store; tests and pure
/// logic use [`MemNullifierSet`].
pub trait NullifierSet {
    /// Whether this nullifier has already been spent (is in the finalized set).
    fn contains(&self, nf: &NullifierBytes) -> bool;
}

/// In-memory nullifier set — the reference behaviour the consensus store mirrors.
#[derive(Clone, Debug, Default)]
pub struct MemNullifierSet {
    set: HashSet<NullifierBytes>,
}

impl MemNullifierSet {
    /// A fresh, empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a nullifier. Returns `true` if newly inserted, `false` if it was
    /// already present (which, in consensus, would already have been rejected as
    /// a conflict before reaching insertion).
    pub fn insert(&mut self, nf: NullifierBytes) -> bool {
        self.set.insert(nf)
    }

    /// Insert all nullifiers from an iterator.
    pub fn extend<I: IntoIterator<Item = NullifierBytes>>(&mut self, iter: I) {
        self.set.extend(iter);
    }

    /// Number of spent nullifiers.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl NullifierSet for MemNullifierSet {
    fn contains(&self, nf: &NullifierBytes) -> bool {
        self.set.contains(nf)
    }
}

/// Why a transaction was rejected during nullifier conflict resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullifierConflict {
    /// The nullifier is already in the finalized set, or was accepted by an
    /// earlier transaction in this same accepted-order batch. First one wins.
    AlreadySpent(NullifierBytes),
    /// The same nullifier appears more than once within a single transaction
    /// (a malformed self-double-spend).
    DuplicateWithinTx(NullifierBytes),
}

/// Resolves nullifier conflicts while transactions are processed in GHOSTDAG
/// accepted order (PLAN §2.4 steps 1–2).
///
/// Usage: construct over the finalized set, then call [`try_accept`] for each
/// transaction's nullifiers **in accepted order**. Accepted transactions have
/// their nullifiers recorded; a conflicting transaction is rejected and records
/// nothing (the caller drops it, exactly as for a double-spent UTXO). After the
/// batch, [`into_accepted`] yields the nullifiers to insert into the finalized
/// set, in acceptance order.
///
/// [`try_accept`]: NullifierConflictResolver::try_accept
/// [`into_accepted`]: NullifierConflictResolver::into_accepted
pub struct NullifierConflictResolver<'a, S: NullifierSet + ?Sized> {
    finalized: &'a S,
    seen: HashSet<NullifierBytes>,
    accepted: Vec<NullifierBytes>,
}

impl<'a, S: NullifierSet + ?Sized> NullifierConflictResolver<'a, S> {
    /// Begin resolution against the given finalized set.
    pub fn new(finalized: &'a S) -> Self {
        Self { finalized, seen: HashSet::new(), accepted: Vec::new() }
    }

    /// Whether `nf` would conflict if a transaction tried to spend it now.
    pub fn conflicts(&self, nf: &NullifierBytes) -> bool {
        self.finalized.contains(nf) || self.seen.contains(nf)
    }

    /// Attempt to accept a transaction given its nullifiers (canonical bytes).
    ///
    /// All-or-nothing: if any nullifier conflicts with the finalized set, with a
    /// previously accepted transaction, or with another nullifier in the same
    /// transaction, the whole transaction is rejected and nothing is recorded.
    /// Otherwise every nullifier is recorded as spent.
    pub fn try_accept<I>(&mut self, tx_nullifiers: I) -> Result<(), NullifierConflict>
    where
        I: IntoIterator<Item = NullifierBytes>,
    {
        // Collect first so rejection leaves no partial state.
        let nfs: Vec<NullifierBytes> = tx_nullifiers.into_iter().collect();

        let mut within_tx: HashSet<NullifierBytes> = HashSet::with_capacity(nfs.len());
        for nf in &nfs {
            if !within_tx.insert(*nf) {
                return Err(NullifierConflict::DuplicateWithinTx(*nf));
            }
            if self.conflicts(nf) {
                return Err(NullifierConflict::AlreadySpent(*nf));
            }
        }

        for nf in nfs {
            self.seen.insert(nf);
            self.accepted.push(nf);
        }
        Ok(())
    }

    /// Convenience wrapper for `orchard::Nullifier` inputs.
    pub fn try_accept_nullifiers<'n, I>(&mut self, tx_nullifiers: I) -> Result<(), NullifierConflict>
    where
        I: IntoIterator<Item = &'n Nullifier>,
    {
        self.try_accept(tx_nullifiers.into_iter().map(key))
    }

    /// The nullifiers accepted so far, in acceptance order.
    pub fn accepted(&self) -> &[NullifierBytes] {
        &self.accepted
    }

    /// Consume the resolver, yielding the accepted nullifiers in acceptance order
    /// (ready to be inserted into the finalized set).
    pub fn into_accepted(self) -> Vec<NullifierBytes> {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nf(n: u8) -> NullifierBytes {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    #[test]
    fn distinct_transactions_all_accepted() {
        let finalized = MemNullifierSet::new();
        let mut r = NullifierConflictResolver::new(&finalized);
        assert!(r.try_accept([nf(1), nf(2)]).is_ok());
        assert!(r.try_accept([nf(3)]).is_ok());
        assert_eq!(r.accepted(), &[nf(1), nf(2), nf(3)]);
    }

    #[test]
    fn reused_nullifier_across_txs_is_dropped_first_wins() {
        let finalized = MemNullifierSet::new();
        let mut r = NullifierConflictResolver::new(&finalized);
        assert!(r.try_accept([nf(7)]).is_ok());
        // A later tx reusing nf(7) is rejected; first occurrence wins.
        assert_eq!(r.try_accept([nf(7)]), Err(NullifierConflict::AlreadySpent(nf(7))));
        // Rejection records nothing.
        assert_eq!(r.accepted(), &[nf(7)]);
    }

    #[test]
    fn rejection_is_all_or_nothing() {
        let finalized = MemNullifierSet::new();
        let mut r = NullifierConflictResolver::new(&finalized);
        r.try_accept([nf(1)]).unwrap();
        // tx spends a fresh nullifier AND a conflicting one -> whole tx dropped,
        // the fresh one must NOT be recorded.
        assert!(r.try_accept([nf(9), nf(1)]).is_err());
        assert_eq!(r.accepted(), &[nf(1)]);
        assert!(!r.conflicts(&nf(9)));
    }

    #[test]
    fn conflict_with_finalized_set() {
        let mut finalized = MemNullifierSet::new();
        finalized.insert(nf(5));
        let mut r = NullifierConflictResolver::new(&finalized);
        assert_eq!(r.try_accept([nf(5)]), Err(NullifierConflict::AlreadySpent(nf(5))));
    }

    #[test]
    fn duplicate_within_tx_rejected() {
        let finalized = MemNullifierSet::new();
        let mut r = NullifierConflictResolver::new(&finalized);
        assert_eq!(r.try_accept([nf(4), nf(4)]), Err(NullifierConflict::DuplicateWithinTx(nf(4))));
    }

    /// Phase-1 shape: two parallel blocks each carry a transaction spending the
    /// same note (same nullifier). Walked in accepted order, exactly one survives
    /// and the surviving nullifier is inserted once — no value can be double-spent.
    #[test]
    fn parallel_double_spend_exactly_one_survives() {
        let finalized = MemNullifierSet::new();
        let mut r = NullifierConflictResolver::new(&finalized);

        // Block X's tx (accepted first) and block Y's tx (accepted second) both
        // spend note with nullifier nf(42).
        let x_ok = r.try_accept([nf(42)]).is_ok();
        let y_ok = r.try_accept([nf(42)]).is_ok();

        assert!(x_ok, "first occurrence in accepted order wins");
        assert!(!y_ok, "second is rejected as a double-spend");
        assert_eq!(r.accepted(), &[nf(42)]);

        // Commit to finalized set: nf(42) present exactly once.
        let accepted = r.into_accepted(); // ends the borrow of `finalized`
        let mut finalized = finalized;
        finalized.extend(accepted);
        assert_eq!(finalized.len(), 1);
        assert!(finalized.contains(&nf(42)));
    }
}
