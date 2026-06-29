//! The shielded state transition (PLAN §2.4).
//!
//! This is the heart of the project: the per-chain-block update of the two
//! pieces of order-sensitive global state — the nullifier set and the global
//! note-commitment tree — applied strictly in GHOSTDAG **accepted order**, with
//! the turnstile invariant enforced after every step.
//!
//! It composes the three primitives ([`crate::tree`], [`crate::nullifier`],
//! [`crate::turnstile`]) into one function, [`ShieldedState::apply_chain_block`],
//! which mirrors exactly the five steps the virtual processor performs per
//! accepted chain block:
//!
//! 1. resolve nullifier conflicts (drop conflicting transactions, first wins);
//! 2. insert surviving nullifiers;
//! 3. append this block's chain-block subtree to the global tree → new anchor;
//! 4. check the turnstile invariant;
//! 5. (the caller publishes the new anchor into the finalized ring buffer).
//!
//! Keeping the algorithm here — pure and independent of rocksdb and the kaspa
//! pipeline — is what makes the make-or-break determinism property unit-testable
//! (see the parallel-double-spend test below and task #9).

use orchard::note::ExtractedNoteCommitment;
use orchard::tree::Anchor;

use crate::nullifier::{MemNullifierSet, NullifierBytes, NullifierConflictResolver, NullifierSet};
use crate::tree::{ChainBlockSubtree, GlobalTree, NoteCommitmentTree, TreeFull};
use crate::turnstile::{SupplyLedger, TurnstileViolation};

/// A transaction's shielded effects, extracted from its Orchard bundle, ready to
/// be applied in the order the consensus layer accepts it.
#[derive(Clone, Debug)]
pub struct ShieldedTx {
    /// Nullifiers revealed by the transaction's actions (conflict keys).
    pub nullifiers: Vec<NullifierBytes>,
    /// Note commitments created by the transaction's actions (tree leaves).
    pub commitments: Vec<ExtractedNoteCommitment>,
    /// Public fee paid by the transaction: value leaving the shielded pool to the
    /// miner. (Orchard `value_balance` for a pure shielded payment.)
    pub fee: u64,
}

/// A coinbase note minted into the pool — the one transparent seam (PLAN §2.7).
/// Its value is public and must already have been checked against the emission
/// schedule by the caller.
#[derive(Clone, Debug)]
pub struct CoinbaseMint {
    /// The block subsidy minted into the pool.
    pub subsidy: u64,
    /// The coinbase note commitment (added to the tree like any other leaf).
    pub commitment: ExtractedNoteCommitment,
}

/// Why a shielded state transition was rejected (an invalid state — the block /
/// virtual state must be rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedStateError {
    /// The turnstile supply invariant was violated.
    Turnstile(TurnstileViolation),
    /// The global note-commitment tree is full (2^32 leaves).
    TreeFull,
}

impl From<TurnstileViolation> for ShieldedStateError {
    fn from(v: TurnstileViolation) -> Self {
        ShieldedStateError::Turnstile(v)
    }
}

impl From<TreeFull> for ShieldedStateError {
    fn from(_: TreeFull) -> Self {
        ShieldedStateError::TreeFull
    }
}

/// The outcome of applying one chain block's shielded transactions.
#[derive(Clone, Debug)]
pub struct BlockShieldedOutcome {
    /// Indices into the input `txs` that survived conflict resolution.
    pub accepted: Vec<usize>,
    /// Nullifiers inserted into the finalized set, in acceptance order.
    pub new_nullifiers: Vec<NullifierBytes>,
    /// The chain-block subtree of accepted commitments (coinbase first).
    pub subtree: ChainBlockSubtree,
    /// The anchor after appending this block's subtree to the global tree.
    pub anchor: Anchor,
}

/// The mutable shielded consensus state, advanced in GHOSTDAG accepted order.
///
/// This in-memory form is the reference the rocksdb-backed stores mirror; the
/// virtual processor reconstructs it from the persisted frontier / nullifier set
/// / supply totals and applies blocks through it.
#[derive(Clone, Debug)]
pub struct ShieldedState {
    /// Spent-nullifier set (append-only).
    pub nullifiers: MemNullifierSet,
    /// Global note-commitment tree (append-only; only the frontier is retained).
    pub tree: GlobalTree,
    /// Turnstile supply ledger.
    pub supply: SupplyLedger,
}

impl ShieldedState {
    /// The genesis (empty) shielded state.
    pub fn new() -> Self {
        Self { nullifiers: MemNullifierSet::new(), tree: GlobalTree::new(), supply: SupplyLedger::new() }
    }

    /// The current anchor (root of the global note-commitment tree).
    pub fn anchor(&self) -> Anchor {
        self.tree.anchor()
    }

    /// Apply one accepted chain block's shielded effects (PLAN §2.4, steps 1–4).
    ///
    /// `coinbase` is the block's coinbase mint (if any); `txs` are the block's
    /// shielded transactions **in accepted order**. Conflicting transactions
    /// (those reusing an already-spent nullifier) are dropped — first occurrence
    /// in accepted order wins, exactly as for transparent UTXO double-spends.
    ///
    /// On success the state is advanced and a [`BlockShieldedOutcome`] is
    /// returned. On a turnstile violation or a full tree the state is left
    /// unchanged and an error is returned (the caller rejects the block).
    pub fn apply_chain_block(
        &mut self,
        coinbase: Option<&CoinbaseMint>,
        txs: &[ShieldedTx],
    ) -> Result<BlockShieldedOutcome, ShieldedStateError> {
        // ---- Phase 1: resolve conflicts & gather effects (immutable borrow) ----
        // Scope the resolver so its borrow of `self.nullifiers` ends before we mutate.
        let (accepted, new_nullifiers, subtree, total_fees, total_mint) = {
            let mut resolver = NullifierConflictResolver::new(&self.nullifiers);
            let mut subtree = ChainBlockSubtree::new();
            let mut accepted = Vec::new();
            let mut total_fees: u128 = 0;
            let mut total_mint: u128 = 0;

            // Coinbase is processed first: it has no nullifiers, mints subsidy, and
            // contributes its note commitment as the first leaf of the subtree.
            if let Some(cb) = coinbase {
                total_mint += cb.subsidy as u128;
                subtree.push(cb.commitment);
            }

            for (i, tx) in txs.iter().enumerate() {
                match resolver.try_accept(tx.nullifiers.iter().copied()) {
                    Ok(()) => {
                        for &cmx in &tx.commitments {
                            subtree.push(cmx);
                        }
                        total_fees += tx.fee as u128;
                        accepted.push(i);
                    }
                    // Conflicting transaction: dropped (double-spend), records nothing.
                    Err(_) => {}
                }
            }

            (accepted, resolver.into_accepted(), subtree, total_fees, total_mint)
        };

        // ---- Phase 2: commit effects to a working copy, then swap in on success ----
        // Work on clones so a turnstile/full-tree failure leaves `self` untouched.
        let mut tree = self.tree.clone();
        let mut supply = self.supply.clone();

        // Turnstile accounting (saturating into checked ops inside the ledger).
        if total_mint > 0 {
            // total_mint fits u64 in practice (single block subsidy); guard anyway.
            supply.mint_coinbase(u64::try_from(total_mint).map_err(|_| TurnstileViolation::Overflow)?)?;
        }
        if total_fees > 0 {
            supply.collect_fees(u64::try_from(total_fees).map_err(|_| TurnstileViolation::Overflow)?)?;
        }

        // Step 3: append this block's subtree to the global tree, producing the anchor.
        tree.append_subtree(&subtree)?;
        let anchor = tree.anchor();

        // Step 4: the turnstile invariant must hold after the update.
        supply.check()?;

        // All checks passed: commit.
        self.tree = tree;
        self.supply = supply;
        self.nullifiers.extend(new_nullifiers.iter().copied());

        Ok(BlockShieldedOutcome { accepted, new_nullifiers, subtree, anchor })
    }
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn tx(nfs: &[u8], cmxs: &[u32], fee: u64) -> ShieldedTx {
        ShieldedTx { nullifiers: nfs.iter().map(|&n| nf(n)).collect(), commitments: cmxs.iter().map(|&c| cmx(c)).collect(), fee }
    }

    /// THE make-or-break property (PLAN Phase 1 / task #9), at the algorithm
    /// level: two parallel chain blocks each spend the same shielded note. Once
    /// GHOSTDAG linearizes them, two independent nodes that apply that same
    /// accepted order must compute an identical anchor, exactly one spend
    /// survives, the nullifier is recorded once, and no value is created.
    #[test]
    fn parallel_double_spend_one_survives_identical_anchor_no_inflation() {
        // Note with nullifier nf(1) is spent by a tx in block X and by a tx in
        // block Y (produced in parallel). GHOSTDAG accepted order: [X, Y].
        // Each block also has a coinbase minting 50 and creating a coinbase note.
        let build = || {
            let mut st = ShieldedState::new();

            // Block X (accepted first): coinbase + tx spending nf(1), fee 5, new note cmx(100).
            let out_x = st
                .apply_chain_block(
                    Some(&CoinbaseMint { subsidy: 50, commitment: cmx(10) }),
                    &[tx(&[1], &[100], 5)],
                )
                .unwrap();
            assert_eq!(out_x.accepted, vec![0], "X's spend is the first occurrence -> accepted");

            // Block Y (accepted second): coinbase + tx ALSO spending nf(1), new note cmx(200).
            let out_y = st
                .apply_chain_block(
                    Some(&CoinbaseMint { subsidy: 50, commitment: cmx(20) }),
                    &[tx(&[1], &[200], 5)],
                )
                .unwrap();
            assert!(out_y.accepted.is_empty(), "Y's spend reuses nf(1) -> dropped as a double-spend");

            st
        };

        // Two independent "nodes" build from the same accepted order.
        let node_a = build();
        let node_b = build();

        // 1) Identical anchor across nodes.
        assert_eq!(node_a.anchor().to_bytes(), node_b.anchor().to_bytes());

        // 2) The double-spent nullifier is recorded exactly once.
        assert_eq!(node_a.nullifiers.len(), 1);
        assert!(node_a.nullifiers.contains(&nf(1)));

        // 3) No value created: pool = coinbase(100) - fees(5 from the single accepted tx).
        //    Block Y's tx was dropped, so its fee never applies.
        assert_eq!(node_a.supply.pool_value().unwrap(), 100 - 5);

        // 4) Tree holds: 2 coinbase notes + 1 accepted-tx note = 3 leaves.
        assert_eq!(node_a.tree.size(), 3);
    }

    /// Distinct spends in parallel blocks both survive, and the anchor is
    /// independent of which node assembled which block — it depends only on the
    /// accepted order, which GHOSTDAG fixes.
    #[test]
    fn distinct_parallel_spends_all_survive() {
        // fee 0: with no coinbase there is no pool to pay fees from (the turnstile
        // would correctly reject a fee here — covered by its own test).
        let mut st = ShieldedState::new();
        let a = st.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        assert_eq!(a.accepted, vec![0]);
        let b = st.apply_chain_block(None, &[tx(&[2], &[200], 0)]).unwrap();
        assert_eq!(b.accepted, vec![0]);
        assert_eq!(st.nullifiers.len(), 2);
        assert_eq!(st.tree.size(), 2);
    }

    /// A double-spend across blocks must not change the anchor relative to simply
    /// not including the conflicting transaction at all.
    #[test]
    fn dropped_double_spend_does_not_affect_anchor() {
        // With the conflicting tx present (but dropped):
        let mut with_conflict = ShieldedState::new();
        with_conflict.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        with_conflict.apply_chain_block(None, &[tx(&[1], &[200], 0)]).unwrap(); // dropped

        // Without the conflicting tx at all (second block empty):
        let mut without = ShieldedState::new();
        without.apply_chain_block(None, &[tx(&[1], &[100], 0)]).unwrap();
        without.apply_chain_block(None, &[]).unwrap();

        assert_eq!(with_conflict.anchor().to_bytes(), without.anchor().to_bytes());
        assert_eq!(with_conflict.tree.size(), without.tree.size());
    }

    /// Spending more than has been minted is rejected (turnstile), and the state
    /// is left unchanged on rejection.
    #[test]
    fn turnstile_rejects_overspend_and_preserves_state() {
        let mut st = ShieldedState::new();
        st.apply_chain_block(Some(&CoinbaseMint { subsidy: 10, commitment: cmx(1) }), &[]).unwrap();
        let anchor_before = st.anchor().to_bytes();

        // A block whose fees (11) exceed the pool (10) -> PoolUnderflow -> rejected.
        let err = st.apply_chain_block(None, &[tx(&[5], &[2], 11)]).unwrap_err();
        assert_eq!(err, ShieldedStateError::Turnstile(TurnstileViolation::PoolUnderflow { coinbase: 10, fees: 11 }));

        // State unchanged: anchor, nullifiers and tree are as before the bad block.
        assert_eq!(st.anchor().to_bytes(), anchor_before);
        assert!(!st.nullifiers.contains(&nf(5)));
        assert_eq!(st.tree.size(), 1);
    }
}
