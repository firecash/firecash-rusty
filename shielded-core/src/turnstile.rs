//! The turnstile supply invariant (PLAN §2.6, §2.7).
//!
//! In an all-shielded chain there is no transparent ledger to cross-check, so
//! the supply invariant *is* the anti-inflation safety mechanism. It is a hard
//! consensus rule from commit one:
//!
//! ```text
//! total_value_in_shielded_pool == cumulative_coinbase_issued − cumulative_fees_paid
//! ```
//!
//! Two layers cooperate:
//!
//! - **Public ledger** ([`SupplyLedger`]): the integer accounting of subsidy
//!   minted into the pool (the one transparent seam, §2.7) and fees removed from
//!   it. The pool may never hold negative value — that would mean value was
//!   spent that was never issued.
//!
//! - **Homomorphic reconciliation** ([`reconcile`]): each Orchard action carries
//!   a value commitment `cv_net` to `(value_in − value_out)`. Summed over the
//!   whole accepted set, `Σ cv_net = commit(−pool_value, R)` for an aggregate
//!   trapdoor `R` (recovered from the bundles' binding signatures — wired in the
//!   validation task). Checking the homomorphic sum against the public pool
//!   value turns any inflation bug from "silent counterfeiting" into "the chain
//!   rejects", the only acceptable failure mode here.

use orchard::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum};

/// Why the turnstile invariant was violated. Any of these makes the resulting
/// state invalid: the block/virtual-state must be rejected (PLAN §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnstileViolation {
    /// Cumulative fees exceeded cumulative coinbase: the pool would hold
    /// negative value (value spent that was never issued).
    PoolUnderflow { coinbase: u128, fees: u128 },
    /// An accumulation overflowed (degenerate; treated as invalid).
    Overflow,
    /// The homomorphic value-commitment sum did not reconcile with the public
    /// net pool value — possible inflation.
    CommitmentMismatch,
}

/// The public supply ledger: subsidy minted into the shielded pool and fees
/// removed from it. The invariant is `pool = coinbase − fees ≥ 0`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupplyLedger {
    cumulative_coinbase: u128,
    cumulative_fees: u128,
}

impl SupplyLedger {
    /// A fresh ledger at genesis (nothing minted, nothing spent).
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a ledger from persisted cumulative totals.
    pub fn from_totals(cumulative_coinbase: u128, cumulative_fees: u128) -> Self {
        Self { cumulative_coinbase, cumulative_fees }
    }

    /// Mint a coinbase subsidy into the pool (§2.7). The subsidy is public and
    /// must already have been checked against the emission schedule by the caller.
    pub fn mint_coinbase(&mut self, subsidy: u64) -> Result<(), TurnstileViolation> {
        self.cumulative_coinbase =
            self.cumulative_coinbase.checked_add(subsidy as u128).ok_or(TurnstileViolation::Overflow)?;
        Ok(())
    }

    /// Remove fees from the pool (paid to the miner).
    pub fn collect_fees(&mut self, fee: u64) -> Result<(), TurnstileViolation> {
        self.cumulative_fees = self.cumulative_fees.checked_add(fee as u128).ok_or(TurnstileViolation::Overflow)?;
        Ok(())
    }

    /// Total subsidy ever minted into the pool.
    pub fn cumulative_coinbase(&self) -> u128 {
        self.cumulative_coinbase
    }

    /// Total fees ever removed from the pool.
    pub fn cumulative_fees(&self) -> u128 {
        self.cumulative_fees
    }

    /// The current shielded-pool value, `coinbase − fees`. Errors with
    /// [`TurnstileViolation::PoolUnderflow`] if fees exceed coinbase.
    pub fn pool_value(&self) -> Result<u128, TurnstileViolation> {
        self.cumulative_coinbase.checked_sub(self.cumulative_fees).ok_or(TurnstileViolation::PoolUnderflow {
            coinbase: self.cumulative_coinbase,
            fees: self.cumulative_fees,
        })
    }

    /// The hard consensus check (PLAN §2.6): the pool must be non-negative.
    pub fn check(&self) -> Result<(), TurnstileViolation> {
        self.pool_value().map(|_| ())
    }
}

/// The zero (no-blinding) value-commitment trapdoor.
pub fn zero_trapdoor() -> ValueCommitTrapdoor {
    // Orchard keeps `ValueCommitTrapdoor::zero()` crate-private; the all-zero
    // scalar is its canonical byte encoding.
    Option::from(ValueCommitTrapdoor::from_bytes([0u8; 32])).expect("zero scalar is canonical")
}

/// Build an Orchard [`ValueSum`] from a signed integer.
///
/// `ValueSum`'s own constructors are crate-private, so we go through the public
/// `NoteValue` subtraction, which yields exactly `a − b`.
fn value_sum(v: i64) -> ValueSum {
    if v >= 0 {
        NoteValue::from_raw(v as u64) - NoteValue::ZERO
    } else {
        // -v fits in u64 for all i64 except i64::MIN, which never occurs as a value.
        NoteValue::ZERO - NoteValue::from_raw(v.unsigned_abs())
    }
}

/// Pedersen value commitment to a signed value under a trapdoor: `[v]·V + [rcv]·R`.
pub fn commit(value: i64, rcv: ValueCommitTrapdoor) -> ValueCommitment {
    ValueCommitment::derive(value_sum(value), rcv)
}

/// Running homomorphic sum of net value commitments over the accepted set.
#[derive(Clone, Debug)]
pub struct ValueCommitmentAccumulator {
    sum: ValueCommitment,
}

impl ValueCommitmentAccumulator {
    /// An empty accumulator (commitment to zero with no blinding = identity).
    pub fn new() -> Self {
        Self { sum: commit(0, zero_trapdoor()) }
    }

    /// Add one action's net value commitment.
    pub fn add(&mut self, cv: &ValueCommitment) {
        self.sum = self.sum.clone() + cv;
    }

    /// The accumulated `Σ cv_net`.
    pub fn total(&self) -> &ValueCommitment {
        &self.sum
    }
}

impl Default for ValueCommitmentAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Reconcile the homomorphic sum of net value commitments with the public pool
/// value (PLAN §2.6).
///
/// Each action's `cv_net` commits to `(value_in − value_out)`, so over the whole
/// accepted set `Σ cv_net = commit(−pool_value, R)`, where `R` is the aggregate
/// value-commitment trapdoor recovered from the bundles' binding signatures.
/// Returns [`TurnstileViolation::CommitmentMismatch`] if they disagree.
pub fn reconcile(
    sum_cv: &ValueCommitment,
    pool_value: i64,
    aggregate_trapdoor: ValueCommitTrapdoor,
) -> Result<(), TurnstileViolation> {
    let expected = commit(-pool_value, aggregate_trapdoor);
    if sum_cv.to_bytes() == expected.to_bytes() {
        Ok(())
    } else {
        Err(TurnstileViolation::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trapdoor(seed: u8) -> ValueCommitTrapdoor {
        let mut b = [0u8; 32];
        b[0] = seed;
        Option::from(ValueCommitTrapdoor::from_bytes(b)).expect("canonical scalar")
    }

    #[test]
    fn ledger_tracks_pool_value() {
        let mut l = SupplyLedger::new();
        l.mint_coinbase(100).unwrap();
        l.collect_fees(30).unwrap();
        assert_eq!(l.pool_value().unwrap(), 70);
        assert!(l.check().is_ok());
    }

    #[test]
    fn ledger_rejects_spending_more_than_issued() {
        let mut l = SupplyLedger::new();
        l.mint_coinbase(100).unwrap();
        l.collect_fees(100).unwrap();
        assert_eq!(l.pool_value().unwrap(), 0);
        // One satoshi more than was ever issued -> pool underflow -> invalid state.
        l.collect_fees(1).unwrap();
        assert_eq!(l.check(), Err(TurnstileViolation::PoolUnderflow { coinbase: 100, fees: 101 }));
    }

    /// Value commitments are additively homomorphic in both value and trapdoor:
    /// commit(a, r1) + commit(b, r2) == commit(a + b, r1 + r2). This is what makes
    /// the chain-level reconciliation sound.
    #[test]
    fn value_commitments_are_homomorphic() {
        let r1 = trapdoor(7);
        let r2 = trapdoor(9);
        let lhs = commit(40, trapdoor(7)) + &commit(25, trapdoor(9));
        let rhs = commit(65, r1 + &r2);
        assert_eq!(lhs.to_bytes(), rhs.to_bytes());
    }

    /// The homomorphic turnstile check: the summed net value commitments
    /// reconcile with the public pool value, and a tampered pool value is caught.
    #[test]
    fn reconcile_detects_inflation() {
        // A step where the pool gains 40 net (e.g. coinbase 50, one fee 10).
        // The actions' cv_net sum commits to (inputs - outputs) = -40 under R.
        let pool_gain: i64 = 40;
        let sum_cv = commit(-pool_gain, trapdoor(5));

        // Honest: reconciles.
        assert!(reconcile(&sum_cv, pool_gain, trapdoor(5)).is_ok());
        // Inflated public claim: rejected.
        assert_eq!(reconcile(&sum_cv, pool_gain + 1, trapdoor(5)), Err(TurnstileViolation::CommitmentMismatch));
        // Wrong trapdoor: rejected.
        assert_eq!(reconcile(&sum_cv, pool_gain, trapdoor(6)), Err(TurnstileViolation::CommitmentMismatch));
    }

    #[test]
    fn accumulator_sums_commitments() {
        let mut acc = ValueCommitmentAccumulator::new();
        acc.add(&commit(10, trapdoor(1)));
        acc.add(&commit(-3, trapdoor(2)));
        // Equivalent single commitment to the net value/trapdoor.
        let expected = commit(7, trapdoor(1) + &trapdoor(2));
        assert_eq!(acc.total().to_bytes(), expected.to_bytes());
    }
}
