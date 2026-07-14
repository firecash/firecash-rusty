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
    Address,
    keys::{FullViewingKey, IncomingViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use std::cell::OnceCell;
use std::collections::HashSet;

use crate::bundle::ShieldedBundle;
use crate::coinbase::{CoinbaseNoteDesc, coinbase_note_commitment};
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

/// The balance effect of blocks too close to the tip to be safely ingested — value
/// arriving and owned value being spent. Reported as *pending* (0-conf); see
/// [`WalletDb::preview_block`].
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview {
    pub incoming: u128,
    pub outgoing: u128,
}

impl Preview {
    /// Fold another block's preview into this one.
    pub fn add(&mut self, other: Preview) {
        self.incoming += other.incoming;
        self.outgoing += other.outgoing;
    }
    pub fn is_zero(&self) -> bool {
        self.incoming == 0 && self.outgoing == 0
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
    leaves: Vec<[u8; 32]>,
    /// The leaf stream decoded to curve points, built on first use.
    ///
    /// A `MerkleHashOrchard` is a Pallas point, so turning a stored leaf back into one
    /// is a point *decompression* — ~0.68 ms each, ~136 s for a 200K-leaf chain. Doing
    /// that eagerly on restore was over half of the multi-minute window in which a
    /// restarted daemon showed every user an empty wallet. Nothing about a balance, a
    /// note, or the tip anchor needs curve points; only rebuilding a spend witness
    /// does. So the stream is *stored* as bytes (restoring it is a memcpy) and decoded
    /// lazily, once, when a witness actually needs it — and `warm_leaves` lets the
    /// daemon do that off the request path so a send never waits on it either.
    decoded: OnceCell<Vec<MerkleHashOrchard>>,
    /// Owned, unspent notes (absolute position + note only; witnesses are built lazily).
    notes: Vec<OwnedNote>,
    /// Number of leaves ingested so far, absolute (`base_size + leaves.len()`) — the
    /// next leaf's position.
    size: u64,
    /// Live membership witnesses for owned notes, held at exactly
    /// [`witnessed_upto`](Self::witnessed_upto) leaves — i.e. **lagging at the matured
    /// anchor**, which is where a spend must root anyway. Rebuilding a witness on
    /// demand costs a full replay of the leaf stream (Sinsemilla hashing: ~21s over a
    /// 174K-leaf chain, *per note* — the dominant cost of a send, dwarfing the ~7s
    /// Halo 2 proof). Advancing these incrementally as the wallet syncs makes a spend's
    /// witness lookup O(1).
    witnesses: Vec<(u64, IncrementalWitness<MerkleHashOrchard, TREE_DEPTH>)>,
    /// The tree at exactly `witnessed_upto` leaves — the state a newly matured note's
    /// witness is snapshotted from. (`tree` mirrors the *tip*; this one lags.)
    lag_tree: CommitmentTree<MerkleHashOrchard, TREE_DEPTH>,
    /// Absolute leaf count `witnesses` / `lag_tree` include.
    witnessed_upto: u64,
    /// Every nullifier revealed by an **applied** bundle in this wallet's stream.
    /// Mirrors the consensus drop rule (PLAN §2.4): a bundle any of whose
    /// nullifiers was already spent is DROPPED — it appends no leaves. Without
    /// this, a shielded tx that the UTXO layer accepted twice (it has no
    /// transparent inputs, so nothing conflicts there — observed live when two
    /// parallel DAG blocks both carried the same tx) double-counts its outputs
    /// and shifts every later leaf position off the consensus tree.
    spent_nullifiers: HashSet<[u8; 32]>,
}

/// How many owned notes keep a live witness. Beyond this, advancing every witness on
/// every leaf would reintroduce the O(N·k) scan that once made a wallet op take 33
/// minutes; the excess notes fall back to the on-demand rebuild.
const MAX_LIVE_WITNESSES: usize = 256;

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
            decoded: OnceCell::new(),
            notes: Vec::new(),
            size: 0,
            witnesses: Vec::new(),
            lag_tree: CommitmentTree::empty(),
            witnessed_upto: 0,
            spent_nullifiers: HashSet::new(),
        })
    }

    /// Build a **watch-only** wallet view from a serialized full viewing key
    /// (`ak ‖ nk ‖ rivk`, 96 bytes). This holds **no spend authority**: it scans and
    /// recognises the wallet's notes, tracks balances, and can build a spend *proof*
    /// (via [`crate::wallet::build::prepare_payment`]), but it cannot authorize a
    /// spend — that signature must come from the device holding the seed. This is the
    /// server side of the non-custodial (mobile) wallet: the daemon syncs with only
    /// the FVK, so a server compromise cannot move funds. Returns `None` if the bytes
    /// are not a valid full viewing key.
    pub fn from_fvk(fvk_bytes: &[u8; 96]) -> Option<Self> {
        let fvk = FullViewingKey::from_bytes(fvk_bytes)?;
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
            decoded: OnceCell::new(),
            notes: Vec::new(),
            size: 0,
            witnesses: Vec::new(),
            lag_tree: CommitmentTree::empty(),
            witnessed_upto: 0,
            spent_nullifiers: HashSet::new(),
        })
    }

    /// This wallet's full viewing key. Grants viewing (not spend) capability; the
    /// non-custodial payment builder needs it to construct the proof.
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// This wallet's receive address, as raw Orchard address bytes. Derived from the
    /// viewing key, so a watch-only wallet knows it too.
    pub fn my_address_bytes(&self) -> [u8; 43] {
        self.my_address
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
        db.apply_frontier(checkpoint)?;
        Some(db)
    }

    /// Rebase a **freshly constructed** wallet (no leaves ingested yet) onto a
    /// node-supplied checkpoint frontier — the fast-sync start shared by the
    /// seed ([`Self::from_frontier`]) and watch-only ([`Self::from_fvk`]) paths.
    /// Returns `None` on an inconsistent frontier or if leaves were already
    /// ingested (the base must precede all stored leaves).
    pub fn apply_frontier(&mut self, checkpoint: &FrontierState) -> Option<()> {
        if !self.leaves.is_empty() || self.base_size != 0 {
            return None;
        }
        let gt = GlobalTree::from_state(checkpoint).ok()?;
        self.base_frontier = gt.frontier().clone();
        self.base_size = gt.size();
        self.tree = CommitmentTree::from_frontier(&self.base_frontier);
        self.lag_tree = CommitmentTree::from_frontier(&self.base_frontier);
        self.witnessed_upto = self.base_size;
        self.witnesses.clear();
        self.size = self.base_size;
        Some(())
    }

    /// The wallet's owned, unspent notes.
    pub fn notes(&self) -> &[OwnedNote] {
        &self.notes
    }

    /// Absolute position of the first leaf this wallet actually scanned: 0 for a
    /// full-scan wallet, or the fast-sync checkpoint's leaf count. Notes minted
    /// *before* this base are invisible to the wallet — a caller deciding whether
    /// a fast-synced view is complete for a given wallet birthday needs this.
    pub fn base_size(&self) -> u64 {
        self.base_size
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
        if self.size == 0 { Anchor::empty_tree().to_bytes() } else { self.tree.root().to_bytes() }
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
        self.ingest_bundles(txs);
    }

    /// Like [`Self::ingest_block`], but the caller has **already computed** each
    /// coinbase note's leaf commitment. A coinbase note's `cmx` is a pure function
    /// of its public description and value ([`coinbase_note_commitment`]) — the same
    /// for every wallet — so when many wallets ingest the same chain-block stream
    /// (a public daemon under a mass rescan), computing that Sinsemilla commitment
    /// once and sharing it removes the dominant per-wallet-per-block cost. The
    /// caller must supply exactly the notes [`ingest_block`] would keep, in the same
    /// order (skip a note whose `coinbase_note_commitment` errors), so the leaf
    /// stream is byte-identical to the non-shared path.
    pub fn ingest_block_precomputed(&mut self, coinbase: &[(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)], txs: &[&ShieldedBundle]) {
        for (desc, value, cmx) in coinbase {
            let owned = self.recover_coinbase_note(desc, *value);
            self.append_leaf(*cmx, owned);
        }
        self.ingest_bundles(txs);
    }

    /// Ingest every accepted transaction's actions, in order — applying the same
    /// drop rule as the consensus transition: a bundle whose nullifier was already
    /// spent in this stream appends nothing (see `spent_nullifiers`). Shared by both
    /// ingest paths above.
    fn ingest_bundles(&mut self, txs: &[&ShieldedBundle]) {
        for bundle in txs {
            if bundle.actions.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            let received = scan_bundle(&self.ivk, bundle);
            for (i, action) in bundle.actions.iter().enumerate() {
                // Each action reveals the nullifier of the note it spends. If that is
                // one of ours, the note is now spent — drop it from the unspent set so
                // balance and spend-selection never count or re-offer it.
                self.notes.retain(|n| n.nullifier != action.nullifier);
                self.spent_nullifiers.insert(action.nullifier);

                let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&action.cmx)) else {
                    continue;
                };
                let owned = received.iter().find(|r| r.action_index == i).map(|r| r.note.clone());
                self.append_leaf(cmx, owned);
            }
        }
    }

    /// What an **unsettled** block would do to this wallet's balance, without touching
    /// any state.
    ///
    /// The wallet cannot *ingest* a block within the reorg margin of the tip: its
    /// commitment tree is append-only, so a leaf appended from a block that is later
    /// reorged out could never be removed, and every later note's position would shift
    /// off the consensus tree. That safety rule is why a payment took ~3 minutes to
    /// appear even though the chain had confirmed it in one second.
    ///
    /// But "cannot append it" is not "cannot look at it". Trial-decrypting the block
    /// tells us the value arriving and the owned notes being spent, with no leaf, no
    /// position, and no tree mutation — so it is free of the reorg hazard entirely. The
    /// caller reports this as *pending* (0-conf) and the number is superseded by the
    /// real one when the block settles and is ingested for real. Worst case a reorg
    /// drops it and the pending figure simply disappears — the same contract every
    /// 0-conf balance in every chain has.
    pub fn preview_block(&self, coinbase: &[(CoinbaseNoteDesc, u64)], txs: &[&ShieldedBundle]) -> Preview {
        let mut p = Preview::default();
        for (desc, value) in coinbase {
            if self.recover_coinbase_note(desc, *value).is_some() {
                p.incoming += *value as u128;
            }
        }
        for bundle in txs {
            // Same drop rule as ingest: a bundle re-spending an already-spent nullifier
            // appends nothing, so it must not be previewed either.
            if bundle.actions.iter().any(|a| self.spent_nullifiers.contains(&a.nullifier)) {
                continue;
            }
            // An action reveals the nullifier of the note it spends: if it is one of
            // ours, that value is on its way out (this is what makes a *sender* see the
            // spend immediately).
            for action in &bundle.actions {
                if let Some(n) = self.notes.iter().find(|n| n.nullifier == action.nullifier) {
                    p.outgoing += n.value() as u128;
                }
            }
            // ...and anything decryptable to our ivk is on its way in — a payment to us,
            // or our own change coming back.
            for r in scan_bundle(&self.ivk, bundle) {
                p.incoming += r.note.value().inner() as u128;
            }
        }
        p
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
    /// Advance the live witnesses (and the tree they hang off) to exactly
    /// `target_leaves` absolute leaves — the **matured** leaf count a spend must root
    /// at. The sync loop calls this as it ingests, so by the time the user presses
    /// Send, every spendable note's witness already exists and
    /// [`witness_path_at`](Self::witness_path_at) is a lookup instead of a full
    /// Sinsemilla replay of the chain.
    ///
    /// Costs one tree append per leaf plus one witness append per live witness — all
    /// O(1) amortized — so a full sync stays linear. Witnesses are only held for the
    /// first [`MAX_LIVE_WITNESSES`] owned notes; a wallet with more than that (a miner
    /// accumulating thousands of coinbase notes) falls back to the on-demand rebuild
    /// for the excess rather than paying `k` appends per leaf forever.
    pub fn advance_witnesses(&mut self, target_leaves: u64) {
        self.advance_witnesses_capped(target_leaves, u64::MAX);
    }

    /// [`Self::advance_witnesses`] but advancing at most `max_leaves` this call, so the
    /// work is bounded and the caller can spread a large catch-up across sync passes
    /// (yielding between them) instead of one multi-second burst that starves the HTTP
    /// handler. Returns `true` if there is still more to advance toward `target_leaves`.
    pub fn advance_witnesses_capped(&mut self, target_leaves: u64, max_leaves: u64) -> bool {
        let full_target = target_leaves.min(self.size);
        let start = self.witnessed_upto.max(self.base_size);
        if full_target <= start {
            return false;
        }
        let target = full_target.min(start.saturating_add(max_leaves));
        let more = target < full_target;
        self.advance_witnesses_range(start, target);
        more
    }

    fn advance_witnesses_range(&mut self, start: u64, target: u64) {
        if target <= start {
            return;
        }
        // A spent note's witness is dead weight — drop it before advancing the rest.
        let live: HashSet<u64> = self.notes.iter().map(|n| n.position).collect();
        self.witnesses.retain(|(pos, _)| live.contains(pos));

        for abs in start..target {
            let Some(&leaf) = self.decoded_leaves().get((abs - self.base_size) as usize) else { break };
            // Every already-open witness must see every later leaf...
            for (_, w) in self.witnesses.iter_mut() {
                let _ = w.append(leaf);
            }
            // ...and the lagging tree, which is what a newly matured note's witness is
            // snapshotted from (it then witnesses exactly the leaf just appended).
            let _ = self.lag_tree.append(leaf);
            if live.contains(&abs) && self.witnesses.len() < MAX_LIVE_WITNESSES {
                if let Some(w) = IncrementalWitness::from_tree(self.lag_tree.clone()) {
                    self.witnesses.push((abs, w));
                }
            }
        }
        self.witnessed_upto = target;
    }

    /// The live witness for `position`, if one is held **at exactly** `matured_leaves`.
    fn live_witness_path(&self, position: u64, matured_leaves: u64) -> Option<MerklePath> {
        if self.witnessed_upto != matured_leaves {
            return None;
        }
        let (_, w) = self.witnesses.iter().find(|(p, _)| *p == position)?;
        let path = w.path()?;
        let auth: [MerkleHashOrchard; TREE_DEPTH as usize] = path.path_elems().try_into().ok()?;
        Some(MerklePath::from_parts(u64::from(path.position()) as u32, auth))
    }

    /// The leaf stream as curve points, decoding it on first use (see `decoded`).
    /// Returns an empty slice if any leaf fails to decode — impossible for bytes we
    /// wrote ourselves, and failing closed makes a witness build return `None` (a clean
    /// send error) rather than silently root to a wrong tree.
    fn decoded_leaves(&self) -> &[MerkleHashOrchard] {
        self.decoded.get_or_init(|| {
            self.leaves
                .iter()
                .map(|b| Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(b)))
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default()
        })
    }

    /// Decode the leaf stream now, so a later spend doesn't pay for it. The daemon calls
    /// this on a blocking thread right after loading a wallet: the wallet is usable
    /// (balance, notes, receive) the instant it restores, and the curve points are ready
    /// by the time anyone spends.
    pub fn warm_leaves(&self) {
        let _ = self.decoded_leaves();
    }

    fn append_leaf(&mut self, cmx: ExtractedNoteCommitment, owned: Option<Note>) {
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        self.leaves.push(leaf.to_bytes());
        // Keep an already-materialised cache in step rather than invalidating it — a
        // synced wallet appends a few leaves a second and must not re-decode the chain.
        if let Some(d) = self.decoded.get_mut() {
            d.push(leaf);
        }
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
        // Fast path: the sync loop already advanced a live witness to this exact
        // matured cutoff, so the path is a lookup rather than a full replay.
        if let Some(path) = self.live_witness_path(position, matured_leaves) {
            return Some(path);
        }
        // Both absolute; the wallet only stores leaves after `base_size`.
        let rel = position.checked_sub(self.base_size)? as usize;
        let matured_rel = matured_leaves.checked_sub(self.base_size)? as usize;
        // The note must sit strictly inside the matured prefix, and we must hold it.
        let leaves = self.decoded_leaves();
        if rel >= matured_rel || matured_rel > leaves.len() {
            return None;
        }
        // Rebuild the tree from the checkpoint frontier up to and including the target
        // leaf, so `from_tree` witnesses exactly it, then replay the later leaves — but
        // only up to `matured_rel`, so the witness roots at the matured anchor, not the
        // tip. For a full-scan wallet the base frontier is empty, so this reduces to
        // rebuilding from genesis.
        let mut tree = CommitmentTree::from_frontier(&self.base_frontier);
        for leaf in &leaves[..=rel] {
            tree.append(*leaf).ok()?;
        }
        let mut witness = IncrementalWitness::<MerkleHashOrchard, TREE_DEPTH>::from_tree(tree)?;
        for leaf in &leaves[rel + 1..matured_rel] {
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
        write_frontier(&mut out, &self.base_frontier);
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&(self.leaves.len() as u64).to_le_bytes());
        for leaf in &self.leaves {
            out.extend_from_slice(leaf);
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
        // v3: the spent-nullifier set, sorted for a canonical encoding.
        let mut nfs: Vec<&[u8; 32]> = self.spent_nullifiers.iter().collect();
        nfs.sort();
        out.extend_from_slice(&(nfs.len() as u64).to_le_bytes());
        for nf in nfs {
            out.extend_from_slice(nf);
        }
        // v4: the **tip** frontier — the mirror tree summarised in O(1). Without it a
        // restore has to replay every leaf back through Sinsemilla to rebuild `tree`,
        // which is minutes of CPU per wallet and is why a daemon restart showed every
        // user `0 balance / 0 notes / syncing 0%` until their wallet finished reloading.
        // Same encoding as the base frontier above.
        write_frontier(&mut out, &self.tree.to_frontier());
        out
    }

    /// Rebuild a wallet from its `seed` plus a checkpoint blob previously produced by
    /// [`Self::to_checkpoint`]. Returns `None` if the seed is not a valid Orchard key,
    /// or the blob is malformed / a different version / has trailing bytes — in which
    /// case the caller should discard it and fall back to a full rescan. The tip
    /// mirror `tree` is reconstructed from the base frontier + `leaves` (O(N) hashing,
    /// no network and no trial-decryption — far cheaper than re-fetching the chain).
    pub fn from_checkpoint(seed: [u8; 32], bytes: &[u8]) -> Option<Self> {
        Self::restore(Self::from_seed(seed)?, bytes, None)
    }

    /// [`Self::from_checkpoint`] with the tip tree supplied by the caller.
    ///
    /// A wallet's mirror tree at its cursor block *is* the consensus note-commitment
    /// tree at that block — same leaves, same order. So a node can hand us that tree's
    /// frontier directly (`GetShieldedTreeState` at the cursor) and the restore skips
    /// the leaf replay entirely. This is what makes restoring an **old (v3)** checkpoint
    /// O(1) as well, instead of ~60s of Sinsemilla per wallet — without which upgrading
    /// the format would strand every existing wallet in a multi-hour reload.
    ///
    /// The frontier is accepted only if it describes exactly as many leaves as the
    /// checkpoint claims; on any mismatch we fall back to rebuilding from the stream, so
    /// a wrong or stale frontier can never silently install a wrong tree.
    pub fn from_checkpoint_with_tip(seed: [u8; 32], bytes: &[u8], tip: &FrontierState) -> Option<Self> {
        Self::restore(Self::from_seed(seed)?, bytes, Some(tip))
    }

    pub fn from_checkpoint_fvk_with_tip(fvk_bytes: &[u8; 96], bytes: &[u8], tip: &FrontierState) -> Option<Self> {
        Self::restore(Self::from_fvk(fvk_bytes)?, bytes, Some(tip))
    }

    /// [`Self::from_checkpoint`] for a **watch-only** wallet: the checkpoint blob holds
    /// no key material (only tree + notes), so it restores identically under a full
    /// viewing key. This is what lets a daemon resume syncing a non-custodial wallet
    /// across restarts without ever having seen the seed.
    pub fn from_checkpoint_fvk(fvk_bytes: &[u8; 96], bytes: &[u8]) -> Option<Self> {
        Self::restore(Self::from_fvk(fvk_bytes)?, bytes, None)
    }

    fn restore(mut db: Self, bytes: &[u8], tip: Option<&FrontierState>) -> Option<Self> {
        let mut r = Cursor { buf: bytes, pos: 0 };
        // v3 blobs are still accepted so that shipping v4 does not force every live
        // wallet into a full rescan; they simply pay the old O(N) tree rebuild once and
        // are rewritten as v4 by the next checkpoint.
        let version = r.u8()?;
        if version != CHECKPOINT_VERSION && version != CHECKPOINT_VERSION_V3 {
            return None;
        }
        let base_size = r.u64()?;
        let base_frontier = read_frontier(&mut r, base_size)?;
        db.base_frontier = base_frontier;
        db.base_size = base_size;
        db.lag_tree = CommitmentTree::from_frontier(&db.base_frontier);
        db.witnessed_upto = base_size;
        db.witnesses.clear();
        db.tree = CommitmentTree::from_frontier(&db.base_frontier);

        let size = r.u64()?;
        let n_leaves = r.u64()? as usize;
        db.leaves.reserve(n_leaves);
        for _ in 0..n_leaves {
            // Stored verbatim — no point decompression here; that is what makes a restore
            // a memcpy instead of minutes of curve arithmetic.
            db.leaves.push(r.arr::<32>()?);
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
        let n_nfs = r.u64()? as usize;
        for _ in 0..n_nfs {
            db.spent_nullifiers.insert(r.arr::<32>()?);
        }
        // The tip mirror tree. v4 carries it as a frontier, so restoring it is O(1) —
        // no hashing at all. A v3 blob has no such field, so fall back to replaying the
        // leaf stream (O(N) Sinsemilla), which is what every restore used to cost.
        db.tree = if version == CHECKPOINT_VERSION {
            let tip = read_frontier(&mut r, size)?;
            CommitmentTree::from_frontier(&tip)
        } else if let Some(fs) = tip.filter(|fs| fs.size == size) {
            // A v3 blob carries no tip frontier, but the caller got one from the node for
            // exactly this cursor — same tree, so use it and skip the replay.
            CommitmentTree::from_frontier(GlobalTree::from_state(fs).ok()?.frontier())
        } else {
            let mut tree = CommitmentTree::from_frontier(&db.base_frontier);
            for leaf in db.decoded_leaves() {
                // `append` only errors on a full (2^32-leaf) tree — unreachable here.
                let _ = tree.append(*leaf);
            }
            tree
        };
        if !r.done() {
            return None;
        }
        db.size = size;
        Some(db)
    }
}

/// Serialize a frontier: `0` for empty, else `1 ‖ leaf(32) ‖ n_ommers(u64) ‖ ommer(32)*`.
fn write_frontier(out: &mut Vec<u8>, f: &Frontier<MerkleHashOrchard, TREE_DEPTH>) {
    match f.value() {
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
}

/// Inverse of [`write_frontier`]. `size` is the absolute leaf count the frontier
/// summarises; it pins the frontier's position, and reusing the node-side
/// reconstruction ([`GlobalTree::from_state`]) revalidates that the ommers are
/// consistent with it, so a corrupt blob fails cleanly rather than yielding a wrong tree.
fn read_frontier(r: &mut Cursor<'_>, size: u64) -> Option<Frontier<MerkleHashOrchard, TREE_DEPTH>> {
    match r.u8()? {
        0 => Some(Frontier::empty()),
        1 => {
            let leaf = r.arr::<32>()?;
            let n_ommers = r.u64()? as usize;
            let mut ommers = Vec::with_capacity(n_ommers);
            for _ in 0..n_ommers {
                ommers.push(r.arr::<32>()?);
            }
            let fs = FrontierState { size, leaf: Some(leaf), ommers };
            Some(GlobalTree::from_state(&fs).ok()?.frontier().clone())
        }
        _ => None,
    }
}

/// Checkpoint format version. Bump on any layout change so an old blob is rejected
/// (triggering a clean rescan) rather than silently misread. v2 added the fast-sync
/// base frontier; v3 the spent-nullifier set (bundle drop rule) — v2 trees may have
/// double-applied bundles, so they must rescan. v4 appends the tip frontier, making a
/// restore O(1) instead of an O(N) Sinsemilla replay.
const CHECKPOINT_VERSION: u8 = 4;
/// v4 is a pure suffix of v3, so v3 blobs still restore correctly (paying the old O(N)
/// tree rebuild once). Reading them is what lets the v4 binary deploy without forcing
/// every live wallet into a full rescan from birthday.
const CHECKPOINT_VERSION_V3: u8 = 3;

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

    /// `ingest_block_precomputed` (the shared-cache path) must produce a wallet
    /// state byte-identical to `ingest_block` (the recompute path): same owned
    /// notes, positions, balance, and tip anchor. This is the correctness guarantee
    /// that lets the daemon compute each block's coinbase commitments once and share
    /// them across the whole wallet cohort.
    #[test]
    fn precomputed_ingest_matches_recompute() {
        let mine = [7u8; 32];
        let other = [8u8; 32];

        // A stream of blocks, each with a couple of coinbase notes (some ours, some
        // a stranger's), so the leaf order and ownership both get exercised.
        let blocks: Vec<Vec<(CoinbaseNoteDesc, u64)>> = (0..25u32)
            .map(|b| {
                vec![
                    coinbase_for(address_of(mine), format!("txid-{b}||0").as_bytes(), 1_000 + b as u64),
                    coinbase_for(address_of(other), format!("txid-{b}||1").as_bytes(), 7_000),
                ]
            })
            .collect();

        let mut recompute = WalletDb::from_seed(mine).unwrap();
        let mut shared = WalletDb::from_seed(mine).unwrap();
        for block in &blocks {
            recompute.ingest_block(block, &[]);
            // The daemon-side precompute: derive each coinbase leaf commitment once,
            // dropping any that would not commit (exactly ingest_block's skip rule).
            let pre: Vec<(CoinbaseNoteDesc, u64, ExtractedNoteCommitment)> = block
                .iter()
                .filter_map(|(d, v)| coinbase_note_commitment(d, *v).ok().map(|cmx| (d.clone(), *v, cmx)))
                .collect();
            shared.ingest_block_precomputed(&pre, &[]);
        }

        assert_eq!(recompute.balance(), shared.balance(), "balances match");
        assert_eq!(recompute.notes().len(), shared.notes().len(), "same note count");
        assert_eq!(
            recompute.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            shared.notes().iter().map(|n| n.position).collect::<Vec<_>>(),
            "same leaf positions",
        );
        assert_eq!(recompute.size(), shared.size(), "same leaf count");
        assert_eq!(recompute.anchor(), shared.anchor(), "identical tip anchor");
    }

    /// A **watch-only** wallet loaded from just the FVK discovers exactly the same
    /// owned notes, positions, balance and tip anchor as the seed wallet — proving the
    /// non-custodial server can sync with no spend authority.
    #[test]
    fn watch_only_fvk_sees_same_notes_as_seed() {
        let mine = [7u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(mine)).unwrap();
        let fvk_bytes = FullViewingKey::from(&sk).to_bytes();

        let mut seed_db = WalletDb::from_seed(mine).unwrap();
        let mut watch_db = WalletDb::from_fvk(&fvk_bytes).unwrap();

        // Same block stream into both: our notes at index 1 of each block, behind decoys.
        let blocks = [
            (coinbase_for(address_of([1u8; 32]), b"b1||0", 1_000), coinbase_for(address_of(mine), b"b1||1", 2_000)),
            (coinbase_for(address_of([9u8; 32]), b"b2||0", 3_000), coinbase_for(address_of(mine), b"b2||1", 4_000)),
        ];
        for (a, b) in blocks {
            seed_db.ingest_block(&[a.clone(), b.clone()], &[]);
            watch_db.ingest_block(&[a, b], &[]);
        }

        assert_eq!(watch_db.balance(), seed_db.balance());
        assert_eq!(watch_db.balance(), 6_000, "both owned notes discovered watch-only");
        assert_eq!(watch_db.notes().len(), seed_db.notes().len());
        assert_eq!(watch_db.anchor(), seed_db.anchor(), "same tip anchor");
        for (w, s) in watch_db.notes().iter().zip(seed_db.notes()) {
            assert_eq!(w.position, s.position);
            assert_eq!(w.value(), s.value());
            // The watch-only wallet can build the identical spend witness (a proof
            // input) — it just can't sign the spend.
            let pw = watch_db.witness_path(w.position).expect("watch-only witness");
            let ps = seed_db.witness_path(s.position).expect("seed witness");
            let cw = ExtractedNoteCommitment::from(w.note.commitment());
            let cs = ExtractedNoteCommitment::from(s.note.commitment());
            assert_eq!(pw.root(cw), ps.root(cs), "identical witness root");
        }
        // The FVK the watch-only wallet exposes matches the seed's FVK.
        assert_eq!(watch_db.fvk().to_bytes(), fvk_bytes);
    }

    /// The live (incrementally advanced) witness must be byte-for-byte the witness the
    /// on-demand rebuild produces — a spend roots at it, so any divergence would mint an
    /// unspendable note. Checked at several maturity cutoffs, with our notes interleaved
    /// among other people's leaves.
    #[test]
    fn live_witness_matches_rebuilt_witness() {
        let mine = [21u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        // 12 blocks; ours at blocks 2, 5 and 9, each behind a stranger's note.
        for b in 0..12u8 {
            let tag = [b, b, b, b];
            let theirs = coinbase_for(address_of([b.wrapping_add(1); 32]), &tag, 100 + b as u64);
            if b == 2 || b == 5 || b == 9 {
                let ours = coinbase_for(address_of(mine), &[b, 9, 9, 9], 1_000 + b as u64);
                db.ingest_block(&[theirs, ours], &[]);
            } else {
                db.ingest_block(&[theirs], &[]);
            }
        }
        assert_eq!(db.notes().len(), 3);

        // Cutoffs inside the stream (a matured anchor always lags the tip).
        let n = db.size();
        for cutoff in [n - 3, n - 1, n] {
            // Rebuild-only reference (a pristine wallet replaying the same stream never
            // calls advance_witnesses, so it always takes the on-demand path).
            let mut fresh = WalletDb::from_seed(mine).unwrap();
            fresh.leaves = db.leaves.clone();
            fresh.notes = db.notes.to_vec();
            fresh.size = db.size;
            fresh.tree = db.tree.clone();

            let mut live = WalletDb::from_seed(mine).unwrap();
            live.leaves = db.leaves.clone();
            live.notes = db.notes.to_vec();
            live.size = db.size;
            live.tree = db.tree.clone();
            live.advance_witnesses(cutoff);

            for n in db.notes() {
                if n.position >= cutoff {
                    continue;
                }
                let want = fresh.witness_path_at(n.position, cutoff).expect("rebuilt witness");
                let got = live.witness_path_at(n.position, cutoff).expect("live witness");
                let cm = ExtractedNoteCommitment::from(n.note.commitment());
                assert_eq!(got.root(cm), want.root(cm), "same anchor at cutoff {cutoff}, position {}", n.position);
                assert_eq!(got.auth_path(), want.auth_path(), "same authentication path");
            }
        }
    }

    /// A checkpoint carries tree + notes but no key material, so a watch-only wallet
    /// resumes from one exactly as the seed wallet does. This is what lets a daemon
    /// that has never seen the seed restart without rescanning the chain.
    #[test]
    fn watch_only_resumes_from_checkpoint() {
        let mine = [11u8; 32];
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(mine)).unwrap();
        let fvk_bytes = FullViewingKey::from(&sk).to_bytes();

        let mut db = WalletDb::from_fvk(&fvk_bytes).unwrap();
        db.ingest_block(&[coinbase_for(address_of([3u8; 32]), b"c||0", 500), coinbase_for(address_of(mine), b"c||1", 7_000)], &[]);
        db.ingest_block(&[coinbase_for(address_of(mine), b"d||0", 1_500)], &[]);

        let restored = WalletDb::from_checkpoint_fvk(&fvk_bytes, &db.to_checkpoint()).expect("watch-only checkpoint restores");

        assert_eq!(restored.balance(), db.balance());
        assert_eq!(restored.balance(), 8_500);
        assert_eq!(restored.size(), db.size());
        assert_eq!(restored.anchor(), db.anchor(), "same tree state");
        for (r, o) in restored.notes().iter().zip(db.notes()) {
            assert_eq!(r.position, o.position);
            assert_eq!(r.value(), o.value());
        }
        // A seed-keyed restore of the same blob agrees — the blob is key-agnostic.
        let as_seed = WalletDb::from_checkpoint(mine, &db.to_checkpoint()).expect("seed restore");
        assert_eq!(as_seed.balance(), restored.balance());
        assert_eq!(as_seed.anchor(), restored.anchor());
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
        let mint2 = CoinbaseMint::new(vec![CoinbaseNote { value: c.1, commitment: coinbase_note_commitment(&c.0, c.1).unwrap() }]);
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

    /// A bundle the UTXO layer accepted twice (same tx carried by two parallel
    /// DAG blocks — it has no transparent inputs, so nothing conflicts there)
    /// must be APPLIED once: the second occurrence's nullifiers are already
    /// spent, so the consensus transition drops it. The wallet mirrors that —
    /// no phantom balance, no extra leaves shifting later positions.
    #[test]
    fn double_accepted_bundle_is_dropped() {
        use crate::bundle::{ActionWire, sizes};

        let mine = [7u8; 32];
        let mut db = WalletDb::from_seed(mine).unwrap();

        // A synthetic spending bundle (opaque to this wallet — decrypt finds
        // nothing, which is irrelevant to the drop rule).
        let action = ActionWire {
            nullifier: [9u8; 32],
            rk: [1u8; sizes::FIELD],
            cmx: [2u8; sizes::FIELD],
            cv_net: [3u8; sizes::FIELD],
            ephemeral_key: [4u8; sizes::FIELD],
            enc_ciphertext: [5u8; sizes::ENC_CIPHERTEXT],
            out_ciphertext: [6u8; sizes::OUT_CIPHERTEXT],
            spend_auth_sig: [7u8; sizes::SIG],
        };
        let bundle = ShieldedBundle {
            actions: vec![action],
            flags: 0b11,
            value_balance: 0,
            anchor: [0u8; 32],
            proof: vec![],
            binding_sig: [0u8; sizes::SIG],
        };

        // First acceptance appends its commitment; the duplicate appends nothing.
        db.ingest_block(&[], &[&bundle]);
        assert_eq!(db.size(), 1, "first acceptance appended one leaf");
        db.ingest_block(&[], &[&bundle]);
        assert_eq!(db.size(), 1, "duplicate acceptance dropped (no extra leaf)");

        // The drop rule survives a checkpoint round-trip (v3 persists the set).
        let blob = db.to_checkpoint();
        let mut restored = WalletDb::from_checkpoint(mine, &blob).expect("v3 checkpoint reloads");
        restored.ingest_block(&[], &[&bundle]);
        assert_eq!(restored.size(), 1, "drop rule persists across restarts");
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

    /// Measures what the v4 tip frontier actually buys, at live chain scale. Not run by
    /// default (it builds a 200K-leaf tree): `cargo test -p kaspa-shielded-core --release
    /// -- --ignored --nocapture restore_cost`.
    #[test]
    #[ignore]
    fn restore_cost_v3_vs_v4() {
        const LEAVES: usize = 200_000; // ~ the live chain's note-commitment count
        let mine = [11u8; 32];
        let addr = address_of(mine);
        let theirs = address_of([12u8; 32]);
        let mut db = WalletDb::from_seed(mine).unwrap();
        // Only a small fraction of the chain's notes are ours — the shape of a real
        // wallet. (Owning *every* leaf would make the restore a measure of note
        // reconstruction, not of the leaf stream, and flatter the result.)
        for i in 0..LEAVES {
            let to = if i % 1000 == 0 { addr } else { theirs };
            db.ingest_block(&[coinbase_for(to, &i.to_le_bytes(), 1)], &[]);
        }
        assert_eq!(db.notes().len(), LEAVES / 1000);

        let v4 = db.to_checkpoint();
        let mut suffix = Vec::new();
        write_frontier(&mut suffix, &db.tree.to_frontier());
        let mut v3 = v4[..v4.len() - suffix.len()].to_vec();
        v3[0] = CHECKPOINT_VERSION_V3;

        let t = std::time::Instant::now();
        let a = WalletDb::from_checkpoint(mine, &v3).unwrap();
        let v3_ms = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let b = WalletDb::from_checkpoint(mine, &v4).unwrap();
        let v4_ms = t.elapsed().as_millis();

        assert_eq!(a.anchor(), b.anchor(), "both restores rebuild the same tree");
        println!("restore of {LEAVES} leaves: v3 (leaf replay) {v3_ms} ms -> v4 (frontier) {v4_ms} ms");
    }

    /// **v3 checkpoints still restore.** v4 appends the tip frontier so a restore can
    /// rebuild the mirror tree in O(1) instead of replaying every leaf through
    /// Sinsemilla. That change may not orphan the checkpoints already on disk: if the
    /// v4 binary rejected them, deploying it would force every live hosted wallet into
    /// a full rescan from birthday — the exact multi-minute "0 balance / 0 notes"
    /// blackout the change exists to prevent. A v3 blob is a v4 blob minus that
    /// trailing frontier, and must reload to an identical wallet.
    #[test]
    fn v3_checkpoint_still_restores_and_matches_v4() {
        let mine = [7u8; 32];
        let addr = address_of(mine);
        let mut db = WalletDb::from_seed(mine).unwrap();
        db.ingest_block(&[coinbase_for(address_of([2u8; 32]), b"b1||0", 500), coinbase_for(addr, b"b1||1", 1_500)], &[]);
        db.ingest_block(&[coinbase_for(addr, b"b2||0", 2_500)], &[]);

        let v4 = db.to_checkpoint();
        assert_eq!(v4[0], CHECKPOINT_VERSION, "fresh checkpoints are written as v4");

        // Reconstruct the v3 encoding: identical bytes, minus the trailing tip frontier.
        let mut suffix = Vec::new();
        write_frontier(&mut suffix, &db.tree.to_frontier());
        let mut v3 = v4[..v4.len() - suffix.len()].to_vec();
        v3[0] = CHECKPOINT_VERSION_V3;

        let from_v3 = WalletDb::from_checkpoint(mine, &v3).expect("v3 checkpoint still reloads");
        let from_v4 = WalletDb::from_checkpoint(mine, &v4).expect("v4 checkpoint reloads");

        // The O(1) path and the O(N) replay must agree on every part of the tree state.
        assert_eq!(from_v3.anchor(), db.anchor(), "v3 replay rebuilds the tip anchor");
        assert_eq!(from_v4.anchor(), db.anchor(), "v4 frontier rebuilds the same tip anchor");
        assert_eq!(from_v4.size, from_v3.size);
        assert_eq!(from_v4.balance(), from_v3.balance());

        // And a spend witness built from the O(1)-restored tree still roots correctly.
        let n = from_v4.notes()[0].position;
        let p4 = from_v4.witness_path(n).expect("witness from v4 restore");
        let p3 = from_v3.witness_path(n).expect("witness from v3 restore");
        let cmx = ExtractedNoteCommitment::from(from_v4.notes()[0].note.commitment());
        assert_eq!(p4.root(cmx), p3.root(cmx), "identical spend witness either way");

        // Appending after an O(1) restore must continue the same tree, not a fresh one.
        let mut a = from_v4;
        let mut b = from_v3;
        let blk = [coinbase_for(addr, b"b3||0", 900)];
        a.ingest_block(&blk, &[]);
        b.ingest_block(&blk, &[]);
        assert_eq!(a.anchor(), b.anchor(), "post-restore appends agree");
        assert_eq!(a.anchor(), { db.ingest_block(&blk, &[]); db.anchor() }, "and match the never-restarted wallet");
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
    use crate::wallet::build::{ShieldedKeys, build_spend_bundle, build_wallet_payment};
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
        let wire = build_spend_bundle(&pk, &keys, owned.note, merkle_path, recipient, output_value, &net, ctx, rand::rngs::OsRng)
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
