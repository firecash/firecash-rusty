//! ZKas shielded wallet glue (PLAN §2.10, blocker #2).
//!
//! [`kaspa_shielded_core::ShieldedAccount`] is a self-contained private wallet —
//! keys, a `zkas:` address, note discovery, and proven payments — but it
//! speaks in shielded primitives, not in the chain's transactions. This crate is
//! the thin, **consensus-coupled** layer that connects the account to real blocks
//! and transactions:
//!
//! - [`effects`] turns an accepted chain block (its coinbase + accepted
//!   transactions) into the note effects the account ingests, deriving coinbase
//!   notes byte-identically to consensus so a wallet discovers its mining reward;
//! - [`tx`] wraps a proven payment bundle into the canonical version-2 shielded
//!   [`Transaction`](kaspa_consensus_core::tx::Transaction) a node accepts, and
//!   exposes the sighash context the bundle must bind to.
//!
//! It deliberately depends only on `kaspa-consensus-core` (the transaction shape)
//! and `kaspa-shielded-core` (the shielded logic) — not on the full consensus or
//! RPC stack — so it stays a light, testable seam. An RPC-connected wallet binary
//! drives blocks in through [`ingest_block_effects`] and pushes payments out via
//! [`tx::payment_tx`] + `submitTransaction`.

pub mod effects;
pub mod tx;

pub use effects::{BlockShieldedEffects, EffectsError, block_effects, coinbase_note_descs, shielded_bundle};
pub use tx::{payment_tx, payment_tx_context};

use kaspa_shielded_core::ShieldedAccount;

/// Feed one accepted chain block's [`BlockShieldedEffects`] into an account so it
/// discovers its notes and advances its witnesses. A thin bridge over
/// [`ShieldedAccount::ingest_block`] that keeps the `&[&ShieldedBundle]` borrow
/// local to the call.
pub fn ingest_block_effects(account: &mut ShieldedAccount, effects: &BlockShieldedEffects) {
    account.ingest_block(&effects.coinbase, &effects.bundle_refs());
}

/// The complete wallet round trip through **real transactions** (circuit feature):
/// a coinbase transaction mints a note to Alice; the wallet extracts that block's
/// effects exactly as consensus would and Alice discovers her note; she builds a
/// payment to Bob bound to the canonical shielded-tx sighash context, and it is
/// wrapped into a version-2 [`Transaction`](kaspa_consensus_core::tx::Transaction);
/// that transaction's payload is extracted back out and applied by the shielded
/// state transition; both wallets ingest the resulting block and Bob receives the
/// amount while Alice keeps the change. This proves the glue in this crate closes
/// the loop between `ShieldedAccount` and the chain's transactions.
#[cfg(all(test, feature = "circuit"))]
mod circuit_tests {
    use super::*;
    use kaspa_addresses::Prefix;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput};
    use kaspa_shielded_core::bundle::ShieldedBundle;
    use kaspa_shielded_core::state::{ShieldedState, ShieldedTx};
    use kaspa_shielded_core::verify::{sighash, verify_bundle};
    use kaspa_shielded_core::{ShieldedAccount, coinbase::coinbase_mint};

    #[test]
    fn full_payment_through_real_transactions() {
        let net = [0x5cu8; 32];

        let mut alice = ShieldedAccount::from_seed([1u8; 32]).unwrap();
        let mut bob = ShieldedAccount::from_seed([2u8; 32]).unwrap();
        let bob_addr = bob.receiving_address(Prefix::Mainnet);

        // --- Block 1: a real coinbase transaction mints a reward to Alice. ---
        let value = 1_000_000u64;
        let alice_raw = kaspa_shielded_core::orchard_recipient_bytes(&alice.receiving_address(Prefix::Mainnet)).unwrap();
        let cb_tx = Transaction::new(
            1,
            vec![],
            vec![TransactionOutput::new(value, ScriptPublicKey::new(0, ScriptVec::from_slice(&alice_raw)))],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            vec![],
        );

        // Consensus applies the mint; the wallet extracts the SAME effects and scans.
        let eff = block_effects(&cb_tx, &[]).unwrap();
        let mut state = ShieldedState::new();
        state.apply_chain_block(Some(&coinbase_mint(&eff.coinbase).unwrap()), &[]).unwrap();
        ingest_block_effects(&mut alice, &eff);
        assert_eq!(alice.balance(), value as u128, "Alice discovered her coinbase note via block extraction");

        // --- Alice pays Bob, binding the bundle to the canonical shielded-tx context. ---
        let amount = 600_000u64;
        let fee = 10_000u64;
        let ctx = payment_tx_context();
        let payload = alice.create_payment(&bob_addr, amount, fee, &net, &ctx).expect("Alice builds a payment");

        // Wrap into a real submittable version-2 transaction, then pull the bundle
        // back out exactly as consensus does from the payload.
        let payment = payment_tx(payload);
        assert!(payment.is_shielded());
        assert_eq!(payment.shielded_sighash_context(), ctx, "the tx binds the same context Alice proved against");
        let bundle: ShieldedBundle = shielded_bundle(&payment).expect("the tx carries a valid bundle");

        // The bundle verifies against that context and its public fee is correct.
        let msg = sighash(&bundle, &net, &ctx);
        verify_bundle(&bundle, &msg).expect("payment bundle verifies");

        // --- Block 2: consensus accepts and applies Alice's payment tx. ---
        let stx = ShieldedTx::from_bundle(&bundle).unwrap();
        assert_eq!(stx.fee, fee);
        let out = state.apply_chain_block(None, &[stx]).unwrap();
        assert_eq!(out.accepted, vec![0], "the payment is accepted by the §2.4 transition");

        // --- Both wallets ingest block 2 (extracted from its transactions). ---
        let eff2 = block_effects(&coinbase_txless(), &[&payment]).unwrap();
        ingest_block_effects(&mut bob, &eff2);
        ingest_block_effects(&mut alice, &eff2);

        assert_eq!(bob.balance(), amount as u128, "Bob receives the private payment");
        assert_eq!(alice.balance(), (value - amount - fee) as u128, "Alice keeps the change");
        assert_eq!(bob.balance() + alice.balance(), (value - fee) as u128, "shielded value conserved");
    }

    /// A coinbase transaction with no outputs — block 2 in the test mints nothing.
    fn coinbase_txless() -> Transaction {
        Transaction::new(1, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, vec![])
    }
}
