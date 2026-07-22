//! Assembling a shielded payment into a submittable version-2 transaction (PLAN
//! §2.1/§2.10) — the other consensus-coupled half of the wallet.
//!
//! [`ShieldedAccount::create_payment`](kaspa_shielded_core::ShieldedAccount::create_payment)
//! returns the shielded-bundle wire bytes; consensus expects those bytes to ride
//! in the `payload` of a canonical shielded transaction shape: version
//! [`TX_VERSION_SHIELDED`], the native subnetwork, no transparent inputs or
//! outputs, zero lock-time and gas (the fee is the bundle's public value balance,
//! not a transparent output). This module builds that transaction.
//!
//! The subtlety is the sighash binding. The bundle's signatures commit to the
//! enclosing transaction's [`shielded_sighash_context`] so a valid bundle cannot be
//! lifted into a different transaction. That context is derived from version /
//! subnetwork / lock-time / gas — **none of which depend on the payload** — so a
//! wallet can compute the exact context up front with [`payment_tx_context`], prove
//! the bundle against it, then wrap the result with [`payment_tx`]. The
//! `context_is_payload_independent` test pins that these agree.

use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{TX_VERSION_SHIELDED, Transaction};

/// Build the canonical shielded payment transaction shape carrying `payload` (the
/// bundle wire bytes from `create_payment`): version-2, native subnetwork, no
/// transparent inputs/outputs, zero lock-time and gas. The returned transaction is
/// finalized (its id computed) and ready to submit over RPC.
pub fn payment_tx(payload: Vec<u8>) -> Transaction {
    Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, payload)
}

/// The `shielded_sighash_context` bytes a payment bundle must bind to — i.e. the
/// context of the transaction [`payment_tx`] will produce. Because the context is
/// independent of the payload, a wallet computes this **before** building the
/// bundle and passes it as the `tx_context` to
/// [`create_payment`](kaspa_shielded_core::ShieldedAccount::create_payment); the
/// bundle then verifies inside the transaction [`payment_tx`] assembles.
pub fn payment_tx_context() -> Vec<u8> {
    payment_tx(Vec::new()).shielded_sighash_context()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_tx_has_the_canonical_shielded_shape() {
        let tx = payment_tx(vec![7, 8, 9]);
        assert_eq!(tx.version, TX_VERSION_SHIELDED);
        assert!(tx.is_shielded(), "version-2, non-coinbase => shielded");
        assert!(tx.inputs.is_empty() && tx.outputs.is_empty(), "no transparent value");
        assert_eq!(tx.subnetwork_id, SUBNETWORK_ID_NATIVE);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.gas, 0);
        assert_eq!(tx.payload, vec![7, 8, 9]);
    }

    #[test]
    fn context_is_payload_independent() {
        // The context a wallet proves against (empty payload) equals the context of
        // the finished transaction (bundle payload). If this ever diverged, every
        // payment would fail sighash verification at the node.
        let ctx = payment_tx_context();
        let finished = payment_tx(vec![0xab; 900]);
        assert_eq!(ctx, finished.shielded_sighash_context());
    }

    /// The on-device signer (`zkas-signer`, compiled to WASM) cannot depend on
    /// consensus, so it PINS this context as a byte constant to recompute the sighash
    /// itself and refuse a malicious prover. If the shielded tx envelope ever changes,
    /// this fails — and `PAYMENT_TX_CONTEXT` in zkas-signer/src/lib.rs must be
    /// updated in lockstep, or on-device verification silently breaks every send.
    #[test]
    fn context_matches_the_pinned_signer_constant() {
        let mut pinned = [0u8; 38];
        pinned[0] = 2; // shielded tx version, LE u16; the rest of the envelope is zero
        assert_eq!(payment_tx_context(), pinned.to_vec(), "update PAYMENT_TX_CONTEXT in zkas-signer");
    }
}
