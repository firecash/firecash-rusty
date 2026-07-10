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

use incrementalmerkletree::frontier::{CommitmentTree, Frontier};
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
use crate::tree::{FrontierState, GlobalTree, TREE_DEPTH};
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
    /// [`anchor`](Self::anchor) cheaply (one append per leaf). Initialised from
    /// [`base_frontier`](Self::base_frontier), so it already reflects everything up
    /// to the fast-sync checkpoint before any leaf is ingested.
    tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// The checkpoint frontier the wallet's stream starts from — empty for a
    /// genesis/position-0 (full-scan) start, or a node-supplied frontier when the
    /// wallet fast-syncs ([`Self::from_frontier`]). Its ommers are exactly the
    /// left-hand authentication path, so the wallet can witness any note appended
    /// after the checkpoint **without** holding a single pre-checkpoint leaf.
    base_frontier: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    /// Absolute position of the wallet's first *stored* leaf: the number of leaves
    /// already summarised by `base_frontier`. 0 for a full-scan wallet. Owned-note
    /// positions and `size` are absolute (this base + an index into `leaves`).
    base_size: u64,
    /// The note-commitment stream **after** `base_size`, in append order. Retaining
    /// it lets the wallet build a membership witness for any owned position **on
    /// demand** (see [`Self::witness_path`]) instead of advancing a per-note witness
    /// on every append — the difference between an O(N) and an O(N²) scan. At 32
    /// bytes/leaf this is ~1 MB per million notes, cheap next to 625M hashes.
    leaves: Vec<MerkleHashOrchard>,
    /// Owned, unspent notes (absolute position + note only; witnesses are built lazily).
    notes: Vec<OwnedNote>,
    /// Number of leaves ingested so far, absolute (`base_size + leaves.len()`) — the
    /// next leaf's position.
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
        Some(Self {
            ivk,
            fvk,
            my_address,
            tree: CommitmentTree::empty(),
            base_frontier: Frontier::empty(),
            base_size: 0,
            leaves: Vec::new(),
            notes: Vec::new(),
            size: 0,
        })
    }

    /// Build a wallet that **fast-syncs** from a checkpoint frontier: the tree starts
    /// at the checkpoint's leaf count, and only leaves appended *after* the checkpoint
    /// are scanned and stored — so sync cost is O(blocks since the checkpoint), not
    /// O(whole chain). Owned notes therefore live at absolute positions ≥ the
    /// checkpoint size; a wallet that may hold notes *older* than the checkpoint must
    /// instead full-scan via [`Self::from_seed`]. Returns `None` on a bad seed or an
    /// internally inconsistent frontier.
    ///
    /// `checkpoint` is a node-supplied [`FrontierState`] for a finalized block; the
    /// wallet then scans that block → tip. Witnesses built afterwards root to the
    /// live tip anchor exactly as a full-scan wallet's do (the checkpoint frontier
    /// supplies every left sibling the witness needs).
    pub fn from_frontier(seed: [u8; 32], checkpoint: &FrontierState) -> Option<Self> {
        let mut db = Self::from_seed(seed)?;
        let gt = GlobalTree::from_state(checkpoint).ok()?;
        db.base_frontier = gt.frontier().clone();
        db.base_size = gt.size();
        db.tree = CommitmentTree::from_frontier(&db.base_frontier);
        db.size = db.base_size;
        Some(db)
    }

    /// The wallet's owned, unspent notes.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Number of leaves in the cached commitment stream (== notes ingested so far).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Absolute number of leaves the wallet's tree spans (`base_size + leaf_count`) —
    /// i.e. the next leaf's position. This is the wallet's mirror of the global tree
    /// size; recording it after each ingested block yields the block→leaf boundary a
    /// spend needs to root at a matured anchor without a rescan.
    pub fn size(&self) -> u64 {
        self.size
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
        self.witness_path_at(position, self.size)
    }

    /// Like [`Self::witness_path`], but roots the witness to the tree state after
    /// exactly `matured_leaves` **absolute** leaves — a *past* (matured) anchor —
    /// instead of the live tip. This lets a caller spend against a finalized anchor
    /// using the wallet's already-maintained leaf stream, with **no chain rescan**:
    /// pass the leaf count recorded at a block that is `shielded_anchor_depth` deep.
    ///
    /// Returns `None` if the note has not yet entered the `matured_leaves` prefix, if
    /// `matured_leaves` precedes the fast-sync base, or if it exceeds what the wallet
    /// has ingested. The resulting path's root equals the tree root at that matured
    /// block, which consensus accepts as a finalized anchor (`is_shielded_anchor_final`).
    pub fn witness_path_at(&self, position: u64, matured_leaves: u64) -> Option<MerklePath> {
        // Both absolute; the wallet only stores leaves after `base_size`.
        let rel = position.checked_sub(self.base_size)? as usize;
        let matured_rel = matured_leaves.checked_sub(self.base_size)? as usize;
        // The note must sit strictly inside the matured prefix, and we must hold it.
        if rel >= matured_rel || matured_rel > self.leaves.len() {
            return None;
        }
        // Rebuild the tree from the checkpoint frontier up to and including the target
        // leaf, so `from_tree` witnesses exactly it, then replay the later leaves — but
        // only up to `matured_rel`, so the witness roots at the matured anchor, not the
        // tip. For a full-scan wallet the base frontier is empty, so this reduces to
        // rebuilding from genesis.
        let mut tree = CommitmentTree::from_frontier(&self.base_frontier);
        for leaf in &self.leaves[..=rel] {
            tree.append(*leaf).ok()?;
        }
        let mut witness = IncrementalWitness::<MerkleHashOrchard, TREE_DEPTH>::from_tree(tree)?;
        for leaf in &self.leaves[rel + 1..matured_rel] {
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

    /// Serialize the wallet's **scanned state** — the fast-sync base frontier, the
    /// post-checkpoint commitment stream, and the owned notes — into a compact,
    /// versioned blob. This is a checkpoint a caller (e.g. `firecash-walletd`)
    /// persists so a restart resumes from here instead of re-scanning. No secrets are
    /// written: the viewing keys and address are re-derived from the seed on load, so
    /// only public chain-derived state lives in the blob. The mirror `tree` is omitted
    /// — it is rebuilt from the base frontier + `leaves` on load.
    ///
    /// Layout (little-endian): `[version:u8][base_size:u64]
    /// [base:0 | 1 (base_leaf:32)(n_ommers:u64)(ommer:32)*] [size:u64]
    /// [n_leaves:u64](leaf:32)* [n_notes:u64]
    /// (position:u64, nullifier:32, recipient:43, value:u64, rho:32, rseed:32)*`.
    pub fn to_checkpoint(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.leaves.len() * 32 + self.notes.len() * 123);
        out.push(CHECKPOINT_VERSION);
        // Fast-sync base: absolute base size, then the base frontier (empty ⇒ tag 0).
        out.extend_from_slice(&self.base_size.to_le_bytes());
        match self.base_frontier.value() {
            None => out.push(0),
            Some(nef) => {
                out.push(1);
                out.extend_from_slice(&nef.leaf().to_bytes());
                out.extend_from_slice(&(nef.ommers().len() as u64).to_le_bytes());
                for o in nef.ommers() {
                    out.extend_from_slice(&o.to_bytes());
                }
            }
        }
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&(self.leaves.len() as u64).to_le_bytes());
        for leaf in &self.leaves {
            out.extend_from_slice(&leaf.to_bytes());
        }
        out.extend_from_slice(&(self.notes.len() as u64).to_le_bytes());
        for n in &self.notes {
            out.extend_from_slice(&n.position.to_le_bytes());
            out.extend_from_slice(&n.nullifier);
            out.extend_from_slice(&n.note.recipient().to_raw_address_bytes());
            out.extend_from_slice(&n.note.value().inner().to_le_bytes());
            out.extend_from_slice(&n.note.rho().to_bytes());
            out.extend_from_slice(n.note.rseed().as_bytes());
        }
        out
    }

    /// Rebuild a wallet from its `seed` plus a checkpoint blob previously produced by
    /// [`Self::to_checkpoint`]. Returns `None` if the seed is not a valid Orchard key,
    /// or the blob is malformed / a different version / has trailing bytes — in which
    /// case the caller should discard it and fall back to a full rescan. The tip
    /// mirror `tree` is reconstructed from the base frontier + `leaves` (O(N) hashing,
    /// no network and no trial-decryption — far cheaper than re-fetching the chain).
    pub fn from_checkpoint(seed: [u8; 32], bytes: &[u8]) -> Option<Self> {
        let mut db = Self::from_seed(seed)?;
        let mut r = Cursor { buf: bytes, pos: 0 };
        if r.u8()? != CHECKPOINT_VERSION {
            return None;
        }
        let base_size = r.u64()?;
        let base_frontier = match r.u8()? {
            0 => Frontier::empty(),
            1 => {
                let leaf = r.arr::<32>()?;
                let n_ommers = r.u64()? as usize;
                let mut ommers = Vec::with_capacity(n_ommers);
                for _ in 0..n_ommers {
                    ommers.push(r.arr::<32>()?);
                }
                // Reuse the node-side frontier reconstruction (validates consistency).
                let fs = FrontierState { size: base_size, leaf: Some(leaf), ommers };
                GlobalTree::from_state(&fs).ok()?.frontier().clone()
            }
            _ => return None,
        };
        db.base_frontier = base_frontier;
        db.base_size = base_size;
        db.tree = CommitmentTree::from_frontier(&db.base_frontier);

        let size = r.u64()?;
        let n_leaves = r.u64()? as usize;
        db.leaves.reserve(n_leaves);
        for _ in 0..n_leaves {
            let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&r.arr()?))?;
            // `append` only errors on a full (2^32-leaf) tree — unreachable here.
            let _ = db.tree.append(leaf);
            db.leaves.push(leaf);
        }
        let n_notes = r.u64()? as usize;
        for _ in 0..n_notes {
            let position = r.u64()?;
            let nullifier = r.arr::<32>()?;
            let recipient = r.arr::<43>()?;
            let value = r.u64()?;
            let rho = Option::<Rho>::from(Rho::from_bytes(&r.arr()?))?;
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(r.arr()?, &rho))?;
            let addr = Option::<Address>::from(Address::from_raw_address_bytes(&recipient))?;
            let note = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed))?;
            db.notes.push(OwnedNote { note, position, nullifier });
        }
        if !r.done() {
            return None;
        }
        db.size = size;
        Some(db)
    }
}

/// Checkpoint format version. Bump on any layout change so an old blob is rejected
/// (triggering a clean rescan) rather than silently misread. v2 added the fast-sync
/// base frontier.
const CHECKPOINT_VERSION: u8 = 2;

/// A minimal forward byte-reader for [`WalletDb::from_checkpoint`]: every read is
/// bounds-checked and returns `None` past the end, so a truncated or corrupt blob
/// fails cleanly instead of panicking.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn done(&self) -> bool {
        self.pos == self.buf.len()
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

    /// A checkpoint round-trips: reloading a wallet from `to_checkpoint` reproduces
    /// balance, owned-note positions, the tip anchor, and — the strongest check —
    /// the exact spend witness, all without re-scanning the chain. This is what lets
    /// `firecash-walletd` resume after a restart instead of rescanning from birthday.
    #[test]
    fn checkpoint_roundtrips_state_and_witness() {
        let mine = [5u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();

        // A multi-block stream with our notes at non-zero positions behind decoys.
        db.ingest_block(&[coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000), coinbase_for(addr, b"b1||1", 2_000)], &[]);
        db.ingest_block(&[coinbase_for(addr, b"b2||0", 4_000), coinbase_for(address_of([9u8; 32]), b"b2||1", 3_000)], &[]);

        let blob = db.to_checkpoint();
        let restored = WalletDb::from_checkpoint(mine, &blob).expect("checkpoint reloads");

        assert_eq!(restored.balance(), db.balance(), "balance survives the round-trip");
        assert_eq!(restored.balance(), 6_000);
        assert_eq!(restored.notes().len(), db.notes().len(), "owned-note count matches");
        assert_eq!(restored.anchor(), db.anchor(), "tip anchor is reconstructed from the leaf stream");
        assert_eq!(restored.size, db.size, "leaf count matches");

        // Each owned note reconstructs to the same position and an identical witness
        // root — i.e. the reloaded wallet can still spend exactly as before.
        for (a, b) in restored.notes().iter().zip(db.notes()) {
            assert_eq!(a.position, b.position);
            assert_eq!(a.value(), b.value());
            let pa = restored.witness_path(a.position).expect("restored witness");
            let pb = db.witness_path(b.position).expect("original witness");
            let cmx_a = ExtractedNoteCommitment::from(a.note.commitment());
            let cmx_b = ExtractedNoteCommitment::from(b.note.commitment());
            assert_eq!(pa.root(cmx_a), pb.root(cmx_b), "restored spend witness roots to the same anchor");
        }

        // A corrupt / truncated blob is rejected (caller then does a clean rescan).
        assert!(WalletDb::from_checkpoint(mine, &blob[..blob.len() - 1]).is_none(), "truncated blob rejected");
        let mut bad = blob.clone();
        bad[0] = 0xFF;
        assert!(WalletDb::from_checkpoint(mine, &bad).is_none(), "wrong version rejected");
    }

    /// **Protocol fast-sync equivalence.** A wallet that starts from a node-supplied
    /// checkpoint frontier and scans only the blocks *after* it produces exactly the
    /// same balance, absolute note positions, tip anchor, and — critically — spend
    /// witnesses as a wallet that full-scanned from genesis. This is what makes wallet
    /// sync O(blocks since checkpoint) instead of O(chain) without weakening spends.
    #[test]
    fn fast_sync_from_frontier_matches_full_scan() {
        use crate::tree::{ChainBlockSubtree, GlobalTree, NoteCommitmentTree};

        let mine = [11u8; 32];
        let addr = address_of(mine);

        // Apply one coinbase-only block to the consensus tree and to each wallet given.
        fn apply(gt: &mut GlobalTree, wallets: &mut [&mut WalletDb], blk: &[(CoinbaseNoteDesc, u64)]) {
            let mut st = ChainBlockSubtree::new();
            for (d, v) in blk {
                st.push(coinbase_note_commitment(d, *v).unwrap());
            }
            gt.append_subtree(&st).unwrap();
            for w in wallets {
                w.ingest_block(blk, &[]);
            }
        }

        let mut gt = GlobalTree::new();
        let mut full = WalletDb::from_seed(mine).unwrap();

        // Pre-checkpoint blocks: only strangers' notes, so the wallet owns nothing
        // before the checkpoint (the precondition for a complete fast-sync).
        let pre = [
            vec![coinbase_for(address_of([1u8; 32]), b"p0||0", 100), coinbase_for(address_of([2u8; 32]), b"p0||1", 100)],
            vec![coinbase_for(address_of([3u8; 32]), b"p1||0", 100)],
        ];
        for blk in &pre {
            apply(&mut gt, &mut [&mut full], blk);
        }

        // Checkpoint the frontier here and start a fast-sync wallet from it.
        let checkpoint = gt.to_state();
        let mut fast = WalletDb::from_frontier(mine, &checkpoint).unwrap();
        assert_eq!(fast.anchor(), full.anchor(), "fast-sync begins at the checkpoint anchor");
        assert_eq!(fast.size, checkpoint.size, "fast-sync starts at the checkpoint leaf count");

        // Post-checkpoint blocks: the wallet's own notes at non-zero absolute
        // positions, behind decoys. Both wallets ingest these.
        let post = [
            vec![coinbase_for(address_of([4u8; 32]), b"q0||0", 100), coinbase_for(addr, b"q0||1", 2_000)],
            vec![coinbase_for(addr, b"q1||0", 3_000), coinbase_for(address_of([5u8; 32]), b"q1||1", 100)],
        ];
        for blk in &post {
            apply(&mut gt, &mut [&mut full, &mut fast], blk);
        }

        // Equivalence across every spend-relevant quantity.
        assert_eq!(fast.balance(), full.balance(), "same balance");
        assert_eq!(fast.balance(), 5_000);
        assert_eq!(fast.anchor(), full.anchor(), "same tip anchor");
        assert_eq!(fast.anchor(), gt.anchor().to_bytes(), "== consensus anchor");
        assert_eq!(fast.notes().len(), full.notes().len());
        for (a, b) in fast.notes().iter().zip(full.notes()) {
            assert_eq!(a.position, b.position, "same absolute leaf position");
            assert_eq!(a.value(), b.value());
            let pa = fast.witness_path(a.position).expect("fast-sync witness");
            let pb = full.witness_path(b.position).expect("full-scan witness");
            let cmx = ExtractedNoteCommitment::from(a.note.commitment());
            assert_eq!(pa.root(cmx), pb.root(cmx), "identical witness root at the tip");
        }

        // The fast-sync wallet's v2 checkpoint carries the base frontier, so it too
        // reloads and can still witness.
        let blob = fast.to_checkpoint();
        let reloaded = WalletDb::from_checkpoint(mine, &blob).expect("v2 checkpoint reloads");
        assert_eq!(reloaded.balance(), fast.balance());
        assert_eq!(reloaded.anchor(), fast.anchor());
        let n = &reloaded.notes()[0];
        assert!(reloaded.witness_path(n.position).is_some(), "reloaded fast-sync wallet still witnesses");
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
