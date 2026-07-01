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

/// A note the wallet owns and can spend, together with the live witness that
/// proves its membership at the current tip of the global tree.
#[derive(Clone)]
pub struct OwnedNote {
    /// The spendable Orchard note.
    pub note: Note,
    /// The note's leaf position in the global note-commitment tree.
    pub position: u64,
    /// Live membership witness, advanced as later notes are appended.
    witness: IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>,
}

impl OwnedNote {
    /// The note's value in the base unit.
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }

    /// The current membership witness as an Orchard [`MerklePath`], ready to hand
    /// to [`crate::wallet::build::build_spend_bundle`]. The path roots to the
    /// current tip anchor (equal to [`Self::anchor`]); the wallet must spend it
    /// against a **finalized** anchor (PLAN §2.5), so it should build the path
    /// from a tip it knows the node has finalized.
    pub fn merkle_path(&self) -> Option<MerklePath> {
        let path = self.witness.path()?;
        let auth: [MerkleHashOrchard; TREE_DEPTH as usize] = path.path_elems().try_into().ok()?;
        let position = u64::from(path.position()) as u32;
        Some(MerklePath::from_parts(position, auth))
    }

    /// The anchor (global-tree root) this note's witness currently roots to.
    pub fn anchor(&self) -> [u8; 32] {
        self.witness.root().to_bytes()
    }
}

/// A wallet's running view of the global note-commitment tree: it walks the
/// canonical commitment stream, recognises its own notes, and keeps a spendable
/// witness for each.
pub struct WalletDb {
    /// Incoming viewing key — recovers shielded-tx outputs sent to this wallet.
    ivk: IncomingViewingKey,
    /// This wallet's raw external address — matches coinbase recipients.
    my_address: [u8; 43],
    /// A full mirror of the global tree, needed to seed each new witness at the
    /// moment its note becomes the most-recent leaf.
    tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// Owned, unspent notes with their live witnesses.
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
        Some(Self { ivk, my_address, tree: CommitmentTree::empty(), notes: Vec::new(), size: 0 })
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

    /// Append one leaf to the mirrored tree, advancing every existing witness and
    /// — if the leaf is a note we own — seeding a fresh witness for it.
    fn append_leaf(&mut self, cmx: ExtractedNoteCommitment, owned: Option<Note>) {
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        // Every already-tracked note gains this leaf as a future sibling. `append`
        // only errors when the tree is full (2^32 leaves) — unreachable in practice.
        for on in &mut self.notes {
            let _ = on.witness.append(leaf);
        }
        let _ = self.tree.append(leaf);
        if let Some(note) = owned {
            // The tree's most-recent leaf is now this note, so `from_tree`
            // witnesses exactly it.
            let witness = IncrementalWitness::from_tree(self.tree.clone())
                .expect("tree is non-empty immediately after appending a leaf");
            self.notes.push(OwnedNote { note, position: self.size, witness });
        }
        self.size += 1;
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
        assert_eq!(owned.anchor(), state.anchor().to_bytes(), "owned note witness roots to the current anchor");
        assert!(owned.merkle_path().is_some(), "a spendable Orchard path is available");
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
    use crate::state::{CoinbaseMint, CoinbaseNote, ShieldedState, ShieldedTx};
    use crate::verify::{sighash, verify_bundle};
    use crate::wallet::build::{build_spend_bundle, ShieldedKeys};
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
        let ctx = b"kasprivate-walletdb-e2e";

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
        assert_eq!(owned.anchor(), anchor1.to_bytes(), "wallet witness roots to the consensus anchor");

        // The wallet builds a real spend from its OWN witness (position 1 path).
        let keys = ShieldedKeys::from_seed(miner).unwrap();
        let merkle_path = owned.merkle_path().expect("wallet has a live witness path");
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
}
