//! Merged-mining (AuxPoW) support — the data carried by a FireCash block that is
//! mined *on top of* a parent (Kaspa) kHeavyHash block instead of natively
//! (PLAN: merged mining, "Option 2" dual-acceptance). This module owns the
//! **structural** half of AuxPoW verification (commitment extraction + coinbase
//! Merkle inclusion); the **work** half (does the parent header's kHeavyHash clear
//! *our* target) lives in `kaspa_pow::auxpow`, since only that crate has the
//! kHeavyHash `State`.
//!
//! ## The binding chain
//!
//! A FireCash block is identified by its header hash `H_fc` (see
//! [`crate::hashing::header::hash`]) — which does **not** cover any AuxPoW data, so
//! it is a stable commitment. To prove that real kHeavyHash work was spent on this
//! exact block, the miner:
//!
//! 1. embeds `MERGE_MINE_MAGIC || H_fc` in the parent block's **coinbase payload**
//!    (Kaspa's coinbase `extra_data` is miner-controlled, so no Kaspa change is
//!    needed);
//! 2. mines the parent block with kHeavyHash.
//!
//! Verification then follows the chain
//! `pow(parent_header) → parent_header.hash_merkle_root → coinbase → H_fc`:
//! the parent header's PoW commits to its `hash_merkle_root`, the Merkle branch
//! ties the coinbase (leaf 0) to that root, and the coinbase payload commits to
//! `H_fc`. Nothing in the parent needs to be a *valid* Kaspa block — only that
//! enough kHeavyHash work, bound to `H_fc`, was performed. Keeping the coinbase +
//! Merkle structure is what lets the parent be a **real** Kaspa block (where the
//! only miner-writable slot is the coinbase), which is the whole point of merged
//! mining.
//!
//! ## Anti-ambiguity
//!
//! [`MERGE_MINE_MAGIC`] must appear in the coinbase payload **exactly once**. This
//! is the classic AuxPoW hardening (cf. the Bitcoin merged-mining tag rules): if a
//! miner could place two commitments, one parent PoW could be claimed by two
//! conflicting aux blocks. Zero or multiple occurrences ⇒ rejected. The rule errs
//! safe: an accidental second magic makes a block *invalid* (liveness), never
//! makes an invalid block *valid* (soundness).

use crate::{hashing, header::Header, tx::Transaction};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::Hash;
use serde::{Deserialize, Serialize};

/// The 4-byte tag that marks the 32-byte FireCash block commitment inside a parent
/// coinbase payload. "FireCash Merged Mining".
pub const MERGE_MINE_MAGIC: [u8; 4] = *b"FCMM";

/// The proof that a FireCash block was mined on top of a parent kHeavyHash block.
///
/// Travels alongside the FireCash header (it is deliberately *not* part of the
/// header hash `H_fc`, so the commitment stays stable). Derives borsh only, to
/// match [`Transaction`] and be storable / wire-serializable.
// `Header` implements neither `PartialEq` nor `Eq`, so `AuxPow` cannot derive them.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuxPow {
    /// The parent block header carrying the real kHeavyHash proof-of-work. Its
    /// cached `hash` is never trusted — [`kaspa_pow`] recomputes the PoW from the
    /// header fields.
    pub parent_header: Header,
    /// The parent block's coinbase transaction (leaf 0 of the parent Merkle tree),
    /// whose payload embeds `MERGE_MINE_MAGIC || H_fc`.
    pub parent_coinbase: Transaction,
    /// The Merkle branch from the coinbase (leaf index 0) up to
    /// `parent_header.hash_merkle_root`: the sequence of right-sibling hashes, one
    /// per tree level. Empty iff the parent block has a single transaction (the
    /// coinbase is then the root itself). Because the coinbase is always leaf 0, the
    /// accumulator is always the *left* child at every level — an attacker cannot
    /// pass off a non-leaf-0 transaction, since the fixed left-combine order would
    /// not reproduce the committed root.
    pub coinbase_merkle_branch: Vec<Hash>,
}

impl AuxPow {
    /// Extract the single 32-byte commitment tagged by [`MERGE_MINE_MAGIC`] in the
    /// parent coinbase payload. Returns `None` unless the magic occurs **exactly
    /// once** and is followed by a full 32 bytes.
    pub fn committed_hash(&self) -> Option<Hash> {
        let payload = self.parent_coinbase.payload.as_slice();
        let mut found: Option<Hash> = None;
        // Scan every position the 4-byte magic could start at. Requiring a unique
        // occurrence (across the whole payload) is what blocks the two-commitment
        // ambiguity attack, so we must count *all* magics, not stop at the first.
        let mut i = 0usize;
        while i + MERGE_MINE_MAGIC.len() <= payload.len() {
            if payload[i..i + MERGE_MINE_MAGIC.len()] == MERGE_MINE_MAGIC {
                // A second magic anywhere ⇒ ambiguous ⇒ reject.
                if found.is_some() {
                    return None;
                }
                let start = i + MERGE_MINE_MAGIC.len();
                let end = start + 32;
                if end > payload.len() {
                    // Magic present but truncated commitment ⇒ malformed ⇒ reject.
                    return None;
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&payload[start..end]);
                found = Some(Hash::from_bytes(bytes));
                // Continue scanning to ensure the magic is unique.
                i = start; // skip past the magic; overlap-free is fine for uniqueness
            } else {
                i += 1;
            }
        }
        found
    }

    /// Verify the coinbase is included under `parent_header.hash_merkle_root` by
    /// folding the branch as a pure left-path (coinbase = leaf 0), reproducing
    /// Kaspa's tx Merkle tree ([`crate::merkle::calc_hash_merkle_root`]).
    pub fn verify_coinbase_inclusion(&self) -> bool {
        let mut acc = hashing::tx::hash(&self.parent_coinbase);
        for sibling in &self.coinbase_merkle_branch {
            acc = kaspa_merkle::merkle_hash(acc, *sibling);
        }
        acc == self.parent_header.hash_merkle_root
    }

    /// The structural (PoW-independent) half of AuxPoW verification: the parent
    /// coinbase commits to `expected` (this block's `H_fc`) exactly once, **and**
    /// the coinbase is Merkle-included under the parent header. The remaining check
    /// — that the parent header's kHeavyHash clears our target — is done in
    /// [`kaspa_pow::auxpow`].
    pub fn verify_binding(&self, expected: Hash) -> bool {
        self.committed_hash() == Some(expected) && self.verify_coinbase_inclusion()
    }

    /// Build the coinbase payload bytes a miner should use: `prefix || MAGIC ||
    /// H_fc || suffix`. Helper for miners/tests; consensus never calls this.
    pub fn embed_commitment(prefix: &[u8], commitment: Hash, suffix: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(prefix.len() + MERGE_MINE_MAGIC.len() + 32 + suffix.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(&MERGE_MINE_MAGIC);
        out.extend_from_slice(&commitment.as_bytes());
        out.extend_from_slice(suffix);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::calc_hash_merkle_root;
    use crate::subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE};
    use crate::tx::Transaction;

    fn hfc() -> Hash {
        Hash::from_bytes([0xABu8; 32])
    }

    /// A coinbase whose payload carries exactly one MAGIC||H_fc, plus surrounding
    /// bytes (mimicking blue_score/subsidy/script + extra_data).
    fn coinbase_committing(commitment: Hash) -> Transaction {
        let payload = AuxPow::embed_commitment(&[1, 2, 3, 4, 5], commitment, &[9, 9]);
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload)
    }

    fn other_tx(tag: u8) -> Transaction {
        Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![tag; 8])
    }

    fn parent_with(coinbase: Transaction, others: Vec<Transaction>) -> (Header, Vec<Hash>) {
        let mut txs = vec![coinbase];
        txs.extend(others);
        let root = calc_hash_merkle_root(txs.iter());
        // Branch for leaf 0 (coinbase): right sibling at each level. For <=2 txs the
        // branch is [hash(tx1)] (or empty for a single tx). We only exercise the
        // 1- and 2-tx shapes here; deeper trees are covered in the pow crate's tests.
        let branch = match txs.len() {
            1 => vec![],
            2 => vec![hashing::tx::hash(&txs[1])],
            _ => unreachable!("test helper only builds 1- or 2-tx parents"),
        };
        let mut header = Header::from_precomputed_hash(Hash::from_bytes([0u8; 32]), vec![]);
        header.hash_merkle_root = root;
        (header, branch)
    }

    #[test]
    fn commitment_extracted_when_present_once() {
        let cb = coinbase_committing(hfc());
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), Some(hfc()));
    }

    #[test]
    fn commitment_absent_returns_none() {
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, vec![0u8; 40]);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None);
    }

    #[test]
    fn two_magics_is_ambiguous_and_rejected() {
        // prefix contains a MAGIC too → two occurrences → None.
        let mut payload = Vec::new();
        payload.extend_from_slice(&MERGE_MINE_MAGIC);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&MERGE_MINE_MAGIC);
        payload.extend_from_slice(&hfc().as_bytes());
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None, "two commitments must be rejected as ambiguous");
    }

    #[test]
    fn truncated_commitment_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&MERGE_MINE_MAGIC);
        payload.extend_from_slice(&[0u8; 10]); // fewer than 32 bytes follow
        let cb = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload);
        let aux = AuxPow {
            parent_header: Header::from_precomputed_hash(Default::default(), vec![]),
            parent_coinbase: cb,
            coinbase_merkle_branch: vec![],
        };
        assert_eq!(aux.committed_hash(), None);
    }

    #[test]
    fn single_tx_parent_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(aux.verify_coinbase_inclusion(), "single-tx: coinbase hash is the root");
        assert!(aux.verify_binding(hfc()));
    }

    #[test]
    fn two_tx_parent_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![other_tx(7)]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(aux.verify_coinbase_inclusion(), "two-tx: coinbase folds with sibling to the root");
        assert!(aux.verify_binding(hfc()));
    }

    #[test]
    fn tampered_branch_fails_inclusion() {
        let cb = coinbase_committing(hfc());
        let (header, _branch) = parent_with(cb.clone(), vec![other_tx(7)]);
        let bad = vec![Hash::from_bytes([0xFFu8; 32])];
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: bad };
        assert!(!aux.verify_coinbase_inclusion(), "a wrong sibling must not reproduce the root");
    }

    #[test]
    fn header_with_aux_pow_borsh_round_trip_and_stable_hash() {
        // Build a valid aux and attach it to a finalized header.
        let cb = coinbase_committing(hfc());
        let (parent, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: parent, parent_coinbase: cb, coinbase_merkle_branch: branch };

        let mut header = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([7u8; 32])]);
        header.finalize();
        let hash_before = header.hash;

        let header = header.with_aux_pow(aux);
        assert_eq!(header.hash, hash_before, "attaching the aux witness must not change H_fc");

        // The witness survives a borsh round-trip and the hash stays stable.
        let bytes = borsh::to_vec(&header).unwrap();
        let restored: Header = borsh::from_slice(&bytes).unwrap();
        assert_eq!(restored.hash, hash_before);
        let restored_aux = restored.aux_pow.as_ref().expect("aux survives borsh round-trip");
        assert_eq!(restored_aux.committed_hash(), Some(hfc()));

        // A native header serializes with no aux.
        let mut native = Header::from_precomputed_hash(Default::default(), vec![Hash::from_bytes([8u8; 32])]);
        native.finalize();
        let restored_native: Header = borsh::from_slice(&borsh::to_vec(&native).unwrap()).unwrap();
        assert!(restored_native.aux_pow.is_none());
    }

    #[test]
    fn binding_rejects_wrong_expected() {
        let cb = coinbase_committing(hfc());
        let (header, branch) = parent_with(cb.clone(), vec![]);
        let aux = AuxPow { parent_header: header, parent_coinbase: cb, coinbase_merkle_branch: branch };
        assert!(!aux.verify_binding(Hash::from_bytes([0x11u8; 32])), "commitment must equal the FireCash block hash");
    }
}
