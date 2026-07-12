//! Turning an accepted chain block into the shielded effects a wallet ingests
//! (PLAN §2.10, blocker #2 — the consensus-coupled half of the wallet).
//!
//! [`ShieldedAccount::ingest_block`](kaspa_shielded_core::ShieldedAccount::ingest_block)
//! wants two things, in **consensus order**: the coinbase note descriptions this
//! block mints, and the shielded bundles it accepts. This module produces exactly
//! those from the block's transactions.
//!
//! The coinbase extraction is the correctness-critical seam: it must derive the
//! same `(recipient, rho, rseed)` per note that consensus's `build_coinbase_mint`
//! does, or a wallet silently fails to discover its own mining reward. Both derive
//! from the identical public inputs — the coinbase transaction id, the output
//! index, and the 43-byte Orchard address in the output script — via
//! [`derive_coinbase_note_desc`]. The `parity_with_consensus` test pins this: it
//! asserts our extraction reproduces exactly the notes the real consensus
//! `build_coinbase_mint` mints.

use kaspa_consensus_core::tx::Transaction;
use kaspa_shielded_core::bundle::ShieldedBundle;
use kaspa_shielded_core::coinbase::{CoinbaseNoteDesc, derive_coinbase_note_desc};

/// Length of the raw Orchard address a shielded coinbase output carries in its
/// script (the recipient of the mining reward). Matches consensus.
pub const ORCHARD_ADDRESS_LEN: usize = 43;

/// Why a block's shielded effects could not be extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectsError {
    /// A coinbase output's script is shorter than a 43-byte Orchard address, so it
    /// cannot carry a reward recipient. On a `shielded_coinbase` network every
    /// coinbase output must; a transparent-network coinbase trips this (the wallet
    /// is not meant to run against a transparent chain).
    ShortCoinbaseScript { output_index: usize, len: usize },
}

/// One accepted chain block's shielded effects, ready to feed
/// [`ShieldedAccount::ingest_block`](kaspa_shielded_core::ShieldedAccount::ingest_block).
///
/// Ordering mirrors the consensus state transition (PLAN §2.4): the coinbase notes
/// are appended to the tree first, then each accepted shielded bundle's outputs in
/// acceptance order — the same order [`WalletDb::ingest_block`] expects so
/// witnesses land at the right leaf positions.
#[derive(Debug, Clone, Default)]
pub struct BlockShieldedEffects {
    /// The coinbase notes minted by this block: `(description, public value)`.
    pub coinbase: Vec<(CoinbaseNoteDesc, u64)>,
    /// The shielded bundles this block accepted, in acceptance order.
    pub bundles: Vec<ShieldedBundle>,
}

impl BlockShieldedEffects {
    /// Borrow the bundles as the `&[&ShieldedBundle]` slice `ingest_block` takes.
    pub fn bundle_refs(&self) -> Vec<&ShieldedBundle> {
        self.bundles.iter().collect()
    }
}

/// Derive the coinbase note descriptions a shielded coinbase transaction mints,
/// mirroring consensus `build_coinbase_mint` **exactly**: for output `i`, the seed
/// is `coinbase_txid || (i as u32 little-endian)`, the recipient is the first 43
/// bytes of the output script, and the public value is `output.value` (the
/// emission- and fee-checked reward). See the module docs for why byte-parity here
/// is mandatory.
pub fn coinbase_note_descs(coinbase_tx: &Transaction) -> Result<Vec<(CoinbaseNoteDesc, u64)>, EffectsError> {
    let txid = coinbase_tx.id();
    let mut out = Vec::with_capacity(coinbase_tx.outputs.len());
    for (i, output) in coinbase_tx.outputs.iter().enumerate() {
        let script = output.script_public_key.script();
        if script.len() < ORCHARD_ADDRESS_LEN {
            return Err(EffectsError::ShortCoinbaseScript { output_index: i, len: script.len() });
        }
        let recipient: [u8; ORCHARD_ADDRESS_LEN] =
            script[..ORCHARD_ADDRESS_LEN].try_into().expect("checked len >= ORCHARD_ADDRESS_LEN");
        // Unique per-note seed: coinbase tx id || output index (must match consensus).
        let mut seed = Vec::with_capacity(32 + 4);
        seed.extend_from_slice(&txid.as_bytes());
        seed.extend_from_slice(&(i as u32).to_le_bytes());
        out.push((derive_coinbase_note_desc(recipient, &seed), output.value));
    }
    Ok(out)
}

/// Extract the shielded bundle carried by a version-2 shielded transaction's
/// `payload`. Returns `None` if `tx` is not a shielded transaction or its payload
/// is not a well-formed bundle (a transparent transaction costs only the cheap
/// version check).
pub fn shielded_bundle(tx: &Transaction) -> Option<ShieldedBundle> {
    if !tx.is_shielded() {
        return None;
    }
    ShieldedBundle::from_bytes(&tx.payload).ok()
}

/// Assemble one chain block's [`BlockShieldedEffects`] from its coinbase
/// transaction and its accepted transactions **in acceptance order**.
///
/// `coinbase_tx` is the block's coinbase (the first transaction); its outputs mint
/// the shielded reward. `accepted_txs` are the block's accepted transactions in the
/// order consensus applied them — only the shielded (version-2) ones contribute a
/// bundle, the rest are skipped. Pass an empty `accepted_txs` (or a coinbase with
/// no outputs) for a block with no such activity.
pub fn block_effects(coinbase_tx: &Transaction, accepted_txs: &[&Transaction]) -> Result<BlockShieldedEffects, EffectsError> {
    let coinbase = if coinbase_tx.outputs.is_empty() { Vec::new() } else { coinbase_note_descs(coinbase_tx)? };
    let bundles = accepted_txs.iter().filter_map(|tx| shielded_bundle(tx)).collect();
    Ok(BlockShieldedEffects { coinbase, bundles })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE};
    use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TX_VERSION_SHIELDED, Transaction, TransactionOutput};

    /// A 43-byte carrier script for a raw Orchard address, as `pay_to_shielded_address` produces.
    fn orchard_script(recipient: [u8; 43]) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient))
    }

    /// A shielded coinbase transaction rewarding `recipients` (one output each).
    fn coinbase_tx(recipients: &[([u8; 43], u64)]) -> Transaction {
        let outputs = recipients.iter().map(|(r, v)| TransactionOutput::new(*v, orchard_script(*r))).collect();
        Transaction::new(1, vec![], outputs, 0, SUBNETWORK_ID_COINBASE, 0, vec![])
    }

    /// A recognizable 43-byte "address" (not necessarily a canonical Orchard one —
    /// canonicity is only needed when we recompute the commitment, tested elsewhere).
    fn raw_addr(seed: u8) -> [u8; 43] {
        [seed; 43]
    }

    #[test]
    fn coinbase_descs_are_deterministic_and_per_output_unique() {
        let tx = coinbase_tx(&[(raw_addr(7), 500), (raw_addr(7), 500)]);
        let a = coinbase_note_descs(&tx).unwrap();
        assert_eq!(a.len(), 2);
        // Same recipient, but different output index => different (rho, rseed).
        assert_ne!(a[0].0, a[1].0, "per-output seed makes each coinbase note unique");
        assert_eq!(a[0].1, 500);
        // Deterministic: re-extracting the same tx yields identical descriptions.
        assert_eq!(coinbase_note_descs(&tx).unwrap(), a);
    }

    #[test]
    fn short_coinbase_script_is_rejected() {
        let tx = Transaction::new(
            1,
            vec![],
            vec![TransactionOutput::new(10, ScriptPublicKey::new(0, ScriptVec::from_slice(&[1u8; 20])))],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            vec![],
        );
        assert_eq!(coinbase_note_descs(&tx), Err(EffectsError::ShortCoinbaseScript { output_index: 0, len: 20 }));
    }

    #[test]
    fn shielded_bundle_ignores_transparent_txs() {
        // A transparent (version-1) tx carries no bundle even if its payload is nonempty.
        let transparent = Transaction::new(1, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![1, 2, 3]);
        assert!(shielded_bundle(&transparent).is_none());

        // A version-2 tx with a garbage payload is a shielded tx but has no valid bundle.
        let bad = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![0xff; 8]);
        assert!(bad.is_shielded());
        assert!(shielded_bundle(&bad).is_none());
    }

    /// The single-source-of-truth guarantee: our coinbase extraction reproduces
    /// **exactly** the notes the real consensus `build_coinbase_mint` mints — same
    /// count, same commitments — so a wallet and a full node agree on every leaf.
    #[test]
    fn parity_with_consensus() {
        use kaspa_consensus::processes::shielded::build_coinbase_mint;
        use kaspa_shielded_core::coinbase::coinbase_note_commitment;
        use kaspa_shielded_core::wallet::scan::address_bytes_from_seed;

        // Real canonical Orchard recipients (so the commitment recompute succeeds).
        let r0 = address_bytes_from_seed([21u8; 32]).unwrap();
        let r1 = address_bytes_from_seed([22u8; 32]).unwrap();
        let tx = coinbase_tx(&[(r0, 5_000_000_000), (r1, 1_234_567)]);

        let mint = build_coinbase_mint(&tx).expect("consensus builds the mint");
        let descs = coinbase_note_descs(&tx).expect("wallet extracts the descs");

        assert_eq!(descs.len(), mint.notes.len(), "same number of coinbase notes");
        for ((desc, value), note) in descs.iter().zip(mint.notes.iter()) {
            assert_eq!(*value, note.value, "same public value per note");
            let cmx = coinbase_note_commitment(desc, *value).expect("canonical note");
            assert_eq!(
                cmx.to_bytes(),
                note.commitment.to_bytes(),
                "wallet-extracted coinbase note commitment matches consensus byte-for-byte"
            );
        }
    }
}
