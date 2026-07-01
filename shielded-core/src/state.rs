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

use crate::bundle::ShieldedBundle;
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
    /// The anchor the bundle's spends prove against. Must be a finalized anchor
    /// (PLAN §2.5); enforced by the consensus validation layer.
    pub anchor: [u8; 32],
}

/// Error extracting a [`ShieldedTx`] from an on-wire [`ShieldedBundle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleExtractError {
    /// A note commitment was not a canonical Pallas base-field encoding.
    NonCanonicalCommitment,
    /// A non-coinbase bundle declared a negative value balance, i.e. it claims to
    /// mint value into the pool — only the coinbase may do that (PLAN §2.7).
    MintingValueBalance,
}

impl ShieldedTx {
    /// Extract the consensus-relevant shielded effects from a parsed bundle.
    ///
    /// This is the bridge from the on-wire [`ShieldedBundle`] (carried in the tx
    /// payload) to the input of the state transition. It does **not** verify the
    /// proof or signatures (that is the validation layer's job, PLAN §3); it only
    /// decodes the fields the state transition consumes — nullifiers, note
    /// commitments, and the public fee.
    pub fn from_bundle(bundle: &ShieldedBundle) -> Result<Self, BundleExtractError> {
        let mut commitments = Vec::with_capacity(bundle.actions.len());
        for a in &bundle.actions {
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx))
                .ok_or(BundleExtractError::NonCanonicalCommitment)?;
            commitments.push(cmx);
        }
        let nullifiers = bundle.actions.iter().map(|a| a.nullifier).collect();
        // A normal shielded transaction's value balance is its (non-negative) fee.
        if bundle.value_balance < 0 {
            return Err(BundleExtractError::MintingValueBalance);
        }
        Ok(ShieldedTx { nullifiers, commitments, fee: bundle.value_balance as u64, anchor: bundle.anchor })
    }
}

/// A coinbase note minted into the pool — the one transparent seam (PLAN §2.7).
/// Its value is public and must already have been checked against the emission
/// schedule by the caller.
#[derive(Clone, Debug)]
pub struct CoinbaseMint {
    /// One coinbase note per rewarded mergeset block (PLAN §2.7). Kaspa pays each
    /// merged block's miner separately (subsidy + that block's fees), so a chain
    /// block's coinbase mints a *set* of notes rather than one.
    pub notes: Vec<CoinbaseNote>,
}

/// A single coinbase note minted into the pool: a **publicly stated value**
/// (the rewarded block's subsidy + fees) and its note commitment.
///
/// The value is public (verifiable against the emission schedule and the observed
/// fees) and the commitment binds it, so a miner cannot mint more than the value
/// consensus checked. Each note's value enters the turnstile as `cumulative_coinbase
/// += value`; because a shielded tx's fee is re-minted here (in the coinbase of the
/// block that merges it) after leaving the pool as `value_balance`, the pool nets to
/// the cumulative *subsidy* — all value stays shielded (PLAN §2.6, §2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseNote {
    /// The note's public value: the rewarded block's subsidy plus its fees.
    pub value: u64,
    /// The coinbase note commitment (added to the tree like any other leaf).
    pub commitment: ExtractedNoteCommitment,
}

impl CoinbaseMint {
    /// A coinbase mint of the given notes.
    pub fn new(notes: Vec<CoinbaseNote>) -> Self {
        Self { notes }
    }

    /// The total value minted by this coinbase across all its notes.
    pub fn total_value(&self) -> u128 {
        self.notes.iter().map(|n| n.value as u128).sum()
    }
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
        // Disjoint borrows of the three fields are permitted by direct field access.
        let outcome = apply_chain_block_to(&self.nullifiers, &mut self.tree, &mut self.supply, coinbase, txs)?;
        self.nullifiers.extend(outcome.new_nullifiers.iter().copied());
        Ok(outcome)
    }
}

/// Apply one accepted chain block against an arbitrary finalized nullifier set.
///
/// This is the store-agnostic core of the state transition. The finalized
/// nullifier set is read through the [`NullifierSet`] trait, so the live
/// consensus path can back it directly by rocksdb without ever loading the whole
/// (unbounded, append-only) set into memory. `tree` and `supply` are advanced
/// **only on success**; on rejection they are left untouched, and the caller is
/// responsible for inserting [`BlockShieldedOutcome::new_nullifiers`] into the
/// finalized set.
pub fn apply_chain_block_to<S: NullifierSet + ?Sized>(
    finalized: &S,
    tree: &mut GlobalTree,
    supply: &mut SupplyLedger,
    coinbase: Option<&CoinbaseMint>,
    txs: &[ShieldedTx],
) -> Result<BlockShieldedOutcome, ShieldedStateError> {
    // ---- Phase 1: resolve conflicts & gather effects ----
    let mut resolver = NullifierConflictResolver::new(finalized);
    let mut subtree = ChainBlockSubtree::new();
    let mut accepted = Vec::new();
    let mut total_fees: u128 = 0;
    let mut total_mint: u128 = 0;

    // Coinbase is processed first: it has no nullifiers, mints its notes' public
    // values, and contributes their commitments as the first leaves of the
    // subtree (in the coinbase's own note order, which every node recomputes
    // identically). Each note's value = a rewarded block's subsidy + fees, so
    // minting them re-mints the fees that left the pool as `value_balance` when
    // those blocks were accepted — the pool nets to the cumulative subsidy.
    if let Some(cb) = coinbase {
        for note in &cb.notes {
            total_mint += note.value as u128;
            subtree.push(note.commitment);
        }
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
    let new_nullifiers = resolver.into_accepted();

    // ---- Phase 2: commit effects to working copies, swap in on success ----
    let mut new_tree = tree.clone();
    let mut new_supply = supply.clone();

    if total_mint > 0 {
        new_supply.mint_coinbase(u64::try_from(total_mint).map_err(|_| TurnstileViolation::Overflow)?)?;
    }
    if total_fees > 0 {
        new_supply.collect_fees(u64::try_from(total_fees).map_err(|_| TurnstileViolation::Overflow)?)?;
    }

    // Step 3: append this block's subtree to the global tree, producing the anchor.
    new_tree.append_subtree(&subtree)?;
    let anchor = new_tree.anchor();

    // Step 4: the turnstile invariant must hold after the update.
    new_supply.check()?;

    // All checks passed: commit to the caller's tree/supply.
    *tree = new_tree;
    *supply = new_supply;

    Ok(BlockShieldedOutcome { accepted, new_nullifiers, subtree, anchor })
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
        ShieldedTx {
            nullifiers: nfs.iter().map(|&n| nf(n)).collect(),
            commitments: cmxs.iter().map(|&c| cmx(c)).collect(),
            fee,
            anchor: [0u8; 32],
        }
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
                    Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 50, commitment: cmx(10) }])),
                    &[tx(&[1], &[100], 5)],
                )
                .unwrap();
            assert_eq!(out_x.accepted, vec![0], "X's spend is the first occurrence -> accepted");

            // Block Y (accepted second): coinbase + tx ALSO spending nf(1), new note cmx(200).
            let out_y = st
                .apply_chain_block(
                    Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 50, commitment: cmx(20) }])),
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

    fn action(nf_seed: u8, cmx_n: u32) -> crate::bundle::ActionWire {
        use crate::bundle::sizes;
        let mut cmxb = [0u8; 32];
        cmxb[0..4].copy_from_slice(&cmx_n.to_le_bytes());
        crate::bundle::ActionWire {
            nullifier: nf(nf_seed),
            rk: [0; 32],
            cmx: cmxb,
            cv_net: [0; 32],
            ephemeral_key: [0; 32],
            enc_ciphertext: [0; sizes::ENC_CIPHERTEXT],
            out_ciphertext: [0; sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [0; sizes::SIG],
        }
    }

    #[test]
    fn extract_shielded_tx_from_bundle() {
        let bundle = ShieldedBundle {
            actions: vec![action(1, 100), action(2, 101)],
            flags: 0b11,
            value_balance: 7,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
        };
        let stx = ShieldedTx::from_bundle(&bundle).unwrap();
        assert_eq!(stx.nullifiers, vec![nf(1), nf(2)]);
        assert_eq!(stx.commitments.len(), 2);
        assert_eq!(stx.fee, 7);
    }

    #[test]
    fn extract_rejects_minting_value_balance() {
        let bundle = ShieldedBundle {
            actions: vec![],
            flags: 0,
            value_balance: -1,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
        };
        assert!(matches!(ShieldedTx::from_bundle(&bundle), Err(BundleExtractError::MintingValueBalance)));
    }

    #[test]
    fn extract_rejects_non_canonical_commitment() {
        let mut bad = action(1, 0);
        bad.cmx = [0xff; 32]; // not a canonical Pallas base-field element
        let bundle = ShieldedBundle {
            actions: vec![bad],
            flags: 0,
            value_balance: 0,
            anchor: [0; 32],
            proof: vec![],
            binding_sig: [0; 64],
        };
        assert!(matches!(ShieldedTx::from_bundle(&bundle), Err(BundleExtractError::NonCanonicalCommitment)));
    }

    /// Spending more than has been minted is rejected (turnstile), and the state
    /// is left unchanged on rejection.
    #[test]
    fn turnstile_rejects_overspend_and_preserves_state() {
        let mut st = ShieldedState::new();
        st.apply_chain_block(Some(&CoinbaseMint::new(vec![CoinbaseNote { value: 10, commitment: cmx(1) }])), &[]).unwrap();
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
