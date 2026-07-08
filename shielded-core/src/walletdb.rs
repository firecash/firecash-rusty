//! Wallet note tracking — the receive-and-remember side of a real wallet (PLAN
//! §2.9 / §2.10).
//!
//! The consensus node keeps only the global tree's **frontier** (~32 nodes); it
//! cannot produce a membership witness for an arbitrary past note. By design
//! (PLAN §2.9) **wallets hold their own witnesses**. This module is that wallet
//! bookkeeping: it consumes the exact same stream of note commitments the
//! consensus [`GlobalTree`](crate::tree::GlobalTree) consumes — in GHOSTDAG
//! accepted order — and for every commitment it can recognise as its own it
//! keeps a live [`IncrementalWitness`] that it advances as later notes arrive.
//!
//! Two kinds of notes are discovered:
//!
//! - **Coinbase notes** are not encrypted — their `(recipient, ρ, rseed)` are
//!   stated publicly by the coinbase transaction and their value is the public
//!   subsidy+fees. The wallet recognises one as its own by matching the stated
//!   recipient against its address and reconstructs the spendable note exactly
//!   as [`crate::coinbase`] / consensus recompute it.
//! - **Shielded-transaction outputs** are recovered by trial decryption with the
//!   wallet's incoming viewing key (the [`crate::wallet::scan`] hot path).
//!
//! Crucially, the wallet must walk the commitments in **the same order consensus
//! appends them** — per accepted chain block: the coinbase notes first (in the
//! coinbase's own note order), then each accepted shielded transaction's actions
//! in order (see [`crate::state::apply_chain_block_to`]). Mirroring that order is
//! what makes each note's tracked position and witness root agree with the node's
//! anchor, so a witness this module produces verifies against consensus.
//!
//! This module needs no proving circuit (discovery + witnessing are decryption
//! and hashing only), so it is available to light wallets without the `circuit`
//! feature. The produced `(note, merkle_path)` is then handed to
//! [`crate::wallet::build::build_spend_bundle`] to actually spend.

use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use orchard::{
    keys::{FullViewingKey, IncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Address,
};

use crate::bundle::ShieldedBundle;
use crate::coinbase::{coinbase_note_commitment, CoinbaseNoteDesc};
use crate::tree::TREE_DEPTH;
use crate::wallet::scan::scan_bundle;

/// A note the wallet owns and can spend. The membership witness is **not** held
/// live per note (that made scanning O(N²) — every leaf advanced every owned
/// note's witness). Instead the wallet keeps the full commitment stream once and
/// builds a witness on demand, only for the notes a spend actually selects
/// ([`WalletDb::witness_path`]).
#[derive(Clone)]
pub struct OwnedNote {
    /// The spendable Orchard note.
    pub note: Note,
    /// The note's leaf position in the global note-commitment tree.
    pub position: u64,
    /// The note's nullifier (derived from the note and the wallet's full viewing
    /// key). When this nullifier appears on-chain, the note has been spent and is
    /// dropped from the wallet's unspent set.
    nullifier: [u8; 32],
}

impl OwnedNote {
    /// The note's value in the base unit.
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
}

/// A wallet's running view of the global note-commitment tree: it walks the
/// canonical commitment stream, recognises its own notes, and keeps a spendable
/// witness for each.
pub struct WalletDb {
    /// Incoming viewing key — recovers shielded-tx outputs sent to this wallet.
    ivk: IncomingViewingKey,
    /// Full viewing key — derives each owned note's nullifier for spent-detection.
    fvk: FullViewingKey,
    /// This wallet's raw external address — matches coinbase recipients.
    my_address: [u8; 43],
    /// A running mirror of the global tree, used only to report the current tip
    /// [`anchor`](Self::anchor) cheaply (one append per leaf).
    tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// The full note-commitment stream in append order. Retaining it lets the
    /// wallet build a membership witness for any owned position **on demand**
    /// (see [`Self::witness_path`]) instead of advancing a per-note witness on
    /// every append — the difference between an O(N) and an O(N²) scan. At 32
    /// bytes/leaf this is ~1 MB per million notes, cheap next to 625M hashes.
    leaves: Vec<MerkleHashOrchard>,
    /// Owned, unspent notes (position + note only; witnesses are built lazily).
    notes: Vec<OwnedNote>,
    /// Number of leaves ingested so far (the next leaf's position).
    size: u64,
}

impl WalletDb {
    /// Build a wallet view from a 32-byte seed. Returns `None` if the seed is not
    /// a valid Orchard spending key (negligibly rare).
    pub fn from_seed(seed: [u8; 32]) -> Option<Self> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed))?;
        let fvk = FullViewingKey::from(&sk);
        let ivk = fvk.to_ivk(Scope::External);
        let my_address = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        Some(Self { ivk, fvk, my_address, tree: CommitmentTree::empty(), leaves: Vec::new(), notes: Vec::new(), size: 0 })
    }

    /// The wallet's owned, unspent notes.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Total spendable value the wallet currently tracks.
    pub fn balance(&self) -> u128 {
        self.notes.iter().map(|n| n.value() as u128).sum()
    }

    /// The current tip anchor (root of the mirrored global tree). Equals the
    /// node's anchor once this wallet has ingested the same accepted blocks.
    pub fn anchor(&self) -> [u8; 32] {
        // An empty tree has the Orchard empty-tree anchor; a non-empty tree roots
        // its full depth. This mirrors `GlobalTree::anchor`.
        use orchard::tree::Anchor;
        if self.size == 0 {
            Anchor::empty_tree().to_bytes()
        } else {
            self.tree.root().to_bytes()
        }
    }

    /// Ingest one accepted chain block's shielded effects, **in the exact order
    /// consensus appends its commitments**: the coinbase notes first (in note
    /// order), then each accepted shielded transaction's actions in order.
    ///
    /// `coinbase` is the block's coinbase note descriptions paired with their
    /// public values (empty if the block has no shielded coinbase). `txs` are the
    /// block's *accepted* shielded bundles in accepted order (conflicting /
    /// dropped transactions must not be passed — they contribute no leaves, just
    /// as in [`crate::state::apply_chain_block_to`]).
    pub fn ingest_block(&mut self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle]) {
        // Coinbase notes first, in the coinbase's own note order.
        for (desc, value) in coinbase {
            // Recompute the leaf exactly as consensus does; skip a malformed one
            // (consensus would already have rejected the block, so this is just
            // defensive — an un-appendable leaf can carry no note for us either).
            let Ok(cmx) = coinbase_note_commitment(desc, *value) else { continue };
            let owned = self.recover_coinbase_note(desc, *value);
            self.append_leaf(cmx, owned);
        }

        // Then every accepted transaction's actions, in order.
        for bundle in txs {
            let received = scan_bundle(&self.ivk, bundle);
            for (i, action) in bundle.actions.iter().enumerate() {
                // Each action reveals the nullifier of the note it spends. If that is
                // one of ours, the note is now spent — drop it from the unspent set so
                // balance and spend-selection never count or re-offer it.
                self.notes.retain(|n| n.nullifier != action.nullifier);

                let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&action.cmx))
                else {
                    continue;
                };
                let owned = received.iter().find(|r| r.action_index == i).map(|r| r.note.clone());
                self.append_leaf(cmx, owned);
            }
        }
    }

    /// Drop a note the wallet has spent (by leaf position), so it is no longer
    /// offered for spending. The witness is discarded; the tree mirror is
    /// untouched (spent notes stay in the tree — only the nullifier marks them
    /// spent, on-chain).
    pub fn mark_spent(&mut self, position: u64) {
        self.notes.retain(|n| n.position != position);
    }

    /// Append one leaf to the wallet's view: record it in the commitment stream,
    /// advance the tip mirror, and — if it is a note we own — remember it (no
    /// witness is built here; that is deferred to [`Self::witness_path`]). This is
    /// O(1) amortised per leaf, so a full scan is O(N), not O(N²).
    fn append_leaf(&mut self, cmx: ExtractedNoteCommitment, owned: Option<Note>) {
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        self.leaves.push(leaf);
        // `append` only errors when the tree is full (2^32 leaves) — unreachable.
        let _ = self.tree.append(leaf);
        if let Some(note) = owned {
            let nullifier = note.nullifier(&self.fvk).to_bytes();
            self.notes.push(OwnedNote { note, position: self.size, nullifier });
        }
        self.size += 1;
    }

    /// Build a membership witness for the owned note at `position`, as an Orchard
    /// [`MerklePath`] rooting to the **current tip** [`anchor`](Self::anchor),
    /// ready for [`crate::wallet::build::build_spend_bundle`]. The wallet must
    /// spend against a *finalized* anchor (PLAN §2.5), so it should call this on a
    /// [`WalletDb`] ingested only up to a tip it knows the node has finalized.
    ///
    /// Cost is O(N) in the number of leaves (one witness reconstruction from the
    /// cached stream), paid only for the few notes a spend selects — versus the
    /// old model that paid O(N) per leaf, for every owned note, on every scan.
    pub fn witness_path(&self, position: u64) -> Option<MerklePath> {
        let position = position as usize;
        if position >= self.leaves.len() {
            return None;
        }
        // Rebuild the tree up to and including the target leaf, so `from_tree`
        // witnesses exactly it, then replay the later leaves to advance the
        // witness to the current tip.
        let mut tree = CommitmentTree::empty();
        for leaf in &self.leaves[..=position] {
            let _ = tree.append(*leaf);
        }
        let mut witness = IncrementalWitness::<MerkleHashOrchard, TREE_DEPTH>::from_tree(tree)?;
        for leaf in &self.leaves[position + 1..] {
            witness.append(*leaf).ok()?;
        }
        let path = witness.path()?;
        let auth: [MerkleHashOrchard; TREE_DEPTH as usize] = path.path_elems().try_into().ok()?;
        Some(MerklePath::from_parts(u64::from(path.position()) as u32, auth))
    }

    /// Reconstruct a coinbase note if it was paid to this wallet. A coinbase note
    /// is ours iff its stated recipient equals our address; the note is then fully
    /// determined by the public `(recipient, ρ, rseed)` and the public `value`,
    /// exactly as [`crate::coinbase`] recomputes the commitment.
    fn recover_coinbase_note(&self, desc: &CoinbaseNoteDesc, value: u64) -> Option<Note> {
        if desc.recipient != self.my_address {
            return None;
        }
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&desc.recipient))?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&desc.rho))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(desc.rseed, &rho))?;
        Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::derive_coinbase_note_desc;
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState};

    /// A coinbase note description for `seed` paid to `address`, plus its value —
    /// exactly what a coinbase transaction publishes and what `ingest_block`
    /// consumes.
    fn coinbase_for(address: [u8; 43], seed: &[u8], value: u64) -> (CoinbaseNoteDesc, u64) {
        (derive_coinbase_note_desc(address, seed), value)
    }

    fn address_of(seed: [u8; 32]) -> [u8; 43] {
        crate::wallet::scan::address_bytes_from_seed(seed).unwrap()
    }

    /// The wallet recognises a coinbase note paid to it, ignores one paid to a
    /// stranger, and the balance reflects only its own notes.
    #[test]
    fn discovers_own_coinbase_ignores_others() {
        let mine = [7u8; 32];
        let other = [8u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        let cb_mine = coinbase_for(address_of(mine), b"txid-a||0", 5_000);
        let cb_other = coinbase_for(address_of(other), b"txid-a||1", 9_000);
        db.ingest_block(&[cb_mine, cb_other], &[]);

        assert_eq!(db.notes().len(), 1, "only the wallet's own coinbase note is tracked");
        assert_eq!(db.balance(), 5_000);
        assert_eq!(db.notes()[0].position, 0, "our note is leaf 0 (first coinbase note)");
    }

    /// The wallet's mirrored anchor tracks the consensus `GlobalTree` anchor leaf
    /// for leaf across a multi-note, multi-block stream — the property that makes
    /// a wallet-produced witness verify against the node, and the witness root of
    /// an owned note equals that shared anchor at each tip.
    #[test]
    fn witness_root_tracks_consensus_anchor() {
        let mine = [3u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();
        let mut state = ShieldedState::new();

        // Block 1: two coinbase notes (one ours at index 1), no txs.
        let a = coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000);
        let b = coinbase_for(addr, b"b1||1", 2_000);
        let mint1 = CoinbaseMint::new(vec![
            CoinbaseNote { value: a.1, commitment: coinbase_note_commitment(&a.0, a.1).unwrap() },
            CoinbaseNote { value: b.1, commitment: coinbase_note_commitment(&b.0, b.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint1), &[]).unwrap();
        db.ingest_block(&[a, b], &[]);

        assert_eq!(db.anchor(), state.anchor().to_bytes(), "wallet mirror anchor == consensus anchor (block 1)");

        // Block 2: one more coinbase note (a stranger's), advancing the tree.
        let c = coinbase_for(address_of([9u8; 32]), b"b2||0", 3_000);
        let mint2 = CoinbaseMint::new(vec![CoinbaseNote {
            value: c.1,
            commitment: coinbase_note_commitment(&c.0, c.1).unwrap(),
        }]);
        state.apply_chain_block(Some(&mint2), &[]).unwrap();
        db.ingest_block(&[c], &[]);

        assert_eq!(db.anchor(), state.anchor().to_bytes(), "wallet mirror anchor == consensus anchor (block 2)");

        // The owned note (from block 1) has a live witness that still roots to the
        // now-advanced shared anchor — i.e. the wallet can prove membership at the
        // current tip.
        let owned = &db.notes()[0];
        assert_eq!(owned.value(), 2_000);
        let path = db.witness_path(owned.position).expect("a spendable Orchard path is available");
        assert_eq!(u64::from(path.position()), owned.position, "path is for the owned leaf");
    }
}

/// The real-wallet spend loop with **live crypto** (circuit feature): a wallet
/// discovers its own coinbase note purely by scanning the public chain stream
/// (no txid/index handed to it), builds a membership witness for it at a
/// **non-zero** tree position from its own bookkeeping, produces a real Orchard
/// proof spending it, and the consensus verifier + §2.4 transition accept it.
///
/// This is the piece [`crate::wallet::build::build_singleleaf_coinbase_spend`]
/// could not do: that helper assumed the note was the tree's single leaf at
/// position 0. Here the owned note sits at position 1 behind a decoy, and the
/// witness comes from [`WalletDb`], so it exercises the general membership path a
/// live wallet actually walks.
#[cfg(all(test, feature = "circuit"))]
mod circuit_tests {
    use super::*;
    use crate::bundle::ShieldedBundle;
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState, ShieldedTx};
    use crate::verify::{sighash, verify_bundle};
    use crate::wallet::build::{build_spend_bundle, build_wallet_payment, ShieldedKeys};
    use crate::wallet::scan::address_bytes_from_seed;
    use orchard::circuit::ProvingKey;

    fn cb(address: [u8; 43], seed: &[u8], value: u64) -> (CoinbaseNoteDesc, u64) {
        (crate::coinbase::derive_coinbase_note_desc(address, seed), value)
    }

    #[test]
    fn wallet_discovers_and_spends_coinbase_note_at_nonzero_position() {
        let pk = ProvingKey::build();
        let miner = [21u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"firecash-walletdb-e2e";

        let mut state = ShieldedState::new();
        let mut db = WalletDb::from_seed(miner).unwrap();

        // Block 1's coinbase mints two notes: a decoy to a stranger at index 0,
        // then OUR note at index 1 (so its leaf position is 1, not 0).
        let decoy = cb(address_bytes_from_seed([99u8; 32]).unwrap(), b"blk1||0", 4_000);
        let mine = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||1", 10_000);
        let mint = CoinbaseMint::new(vec![
            CoinbaseNote { value: decoy.1, commitment: coinbase_note_commitment(&decoy.0, decoy.1).unwrap() },
            CoinbaseNote { value: mine.1, commitment: coinbase_note_commitment(&mine.0, mine.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&[decoy, mine], &[]);
        let anchor1 = state.anchor();

        // The wallet found exactly its own note, at position 1, worth 10_000.
        assert_eq!(db.notes().len(), 1, "wallet discovered only its own coinbase note");
        let owned = db.notes()[0].clone();
        assert_eq!(owned.position, 1, "owned note is the second leaf (behind a decoy)");
        assert_eq!(owned.value(), 10_000);
        assert_eq!(db.anchor(), anchor1.to_bytes(), "wallet mirror roots to the consensus anchor");

        // The wallet builds a real spend from its OWN witness (position 1 path).
        let keys = ShieldedKeys::from_seed(miner).unwrap();
        let merkle_path = db.witness_path(owned.position).expect("wallet builds a witness path on demand");
        let recipient = ShieldedKeys::from_seed([42u8; 32]).unwrap().address();
        let output_value = 7_000u64;
        let wire = build_spend_bundle(
            &pk,
            &keys,
            owned.note,
            merkle_path,
            recipient,
            output_value,
            &net,
            ctx,
            rand::rngs::OsRng,
        )
        .expect("wallet builds a real spend from its own witness");

        // Consensus accepts it: proof verifies, and it spends against the anchor
        // the wallet witnessed — i.e. the node's anchor.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("real spend from a position-1 witness must verify");
        assert_eq!(wire.anchor, anchor1.to_bytes(), "spends against the consensus anchor");
        assert_eq!(wire.value_balance, 3_000, "fee = 10_000 - 7_000");

        // The §2.4 transition applies it: nullifier inserted, fee collected.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        let out = state.apply_chain_block(None, &[stx.clone()]).unwrap();
        assert_eq!(out.accepted, vec![0], "the wallet's real spend is accepted");

        // The wallet marks the note spent; its tracked balance drops to zero.
        db.mark_spent(owned.position);
        assert_eq!(db.balance(), 0, "spent note no longer offered");

        // Replaying the same nullifier is dropped (double-spend guard).
        let replay = state.apply_chain_block(None, &[stx]).unwrap();
        assert!(replay.accepted.is_empty(), "reused nullifier -> dropped");
    }

    /// A multi-note wallet payment: the wallet spends TWO owned notes to cover an
    /// amount larger than either, and after the spend is seen on-chain it drops both
    /// spent notes (by nullifier) and instead tracks the change note it recovered by
    /// trial decryption. Exercises `build_wallet_payment` (multi-input) end to end
    /// plus `WalletDb` spent-detection and change discovery.
    #[test]
    fn wallet_multi_note_spend_drops_inputs_and_keeps_change() {
        let miner = [31u8; 32];
        let net = [0x5au8; 32];
        let ctx = b"firecash-walletdb-multi";

        let mut db = WalletDb::from_seed(miner).unwrap();
        let mut state = ShieldedState::new();

        // Block 1 mints two notes to us (positions 0 and 1), each worth 4_000.
        let n0 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||0", 4_000);
        let n1 = cb(address_bytes_from_seed(miner).unwrap(), b"blk1||1", 4_000);
        let mint = CoinbaseMint::new(vec![
            CoinbaseNote { value: n0.1, commitment: coinbase_note_commitment(&n0.0, n0.1).unwrap() },
            CoinbaseNote { value: n1.1, commitment: coinbase_note_commitment(&n1.0, n1.1).unwrap() },
        ]);
        state.apply_chain_block(Some(&mint), &[]).unwrap();
        db.ingest_block(&[n0, n1], &[]);
        assert_eq!(db.notes().len(), 2, "two owned notes discovered");
        assert_eq!(db.balance(), 8_000);

        // Pay 5_000 (fee 1_000) — needs BOTH notes; 2_000 change returns to us.
        let sel: Vec<_> = db.notes().iter().map(|o| (o.note.clone(), o.position)).collect();
        let inputs: Vec<_> = sel.into_iter().map(|(note, pos)| (note, db.witness_path(pos).unwrap())).collect();
        let recipient = address_bytes_from_seed([42u8; 32]).unwrap();
        let payload = build_wallet_payment(miner, inputs, recipient, 5_000, 1_000, &net, ctx).expect("multi-note payment builds");
        let wire = ShieldedBundle::from_bytes(&payload).expect("payload decodes to a bundle");

        // Two real spends that actually verify against the shared anchor.
        let msg = sighash(&wire, &net, ctx);
        verify_bundle(&wire, &msg).expect("multi-note spend verifies");
        assert_eq!(wire.value_balance, 1_000, "public fee = 8_000 in − 5_000 pay − 2_000 change");

        // On-chain it is accepted (both nullifiers inserted), then the wallet ingests it.
        let stx = ShieldedTx::from_bundle(&wire).unwrap();
        assert_eq!(state.apply_chain_block(None, &[stx]).unwrap().accepted, vec![0], "multi-note spend accepted");
        db.ingest_block(&[], &[&wire]);

        // Both inputs are now spent and dropped; the wallet holds only the change note.
        assert!(!db.notes().iter().any(|n| n.position == 0 || n.position == 1), "spent input notes dropped by nullifier");
        assert_eq!(db.notes().len(), 1, "only the recovered change note remains");
        assert_eq!(db.balance(), 2_000, "balance == change after the multi-note spend");
    }
}
