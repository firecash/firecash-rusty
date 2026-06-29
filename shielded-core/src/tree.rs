//! The three-tier note-commitment tree (PLAN §2.3).
//!
//! # Design (decision D5 in DEVLOG)
//!
//! The **global** tree is the canonical depth-32 Orchard note-commitment tree
//! over individual extracted note commitments (`cmx`). Keeping it Orchard-shaped
//! is what lets the stock Orchard spend circuit verify membership against our
//! anchors — we do not invent a new tree the circuit can't prove against.
//!
//! The three tiers are an engineering decomposition for *parallel insertion* on
//! the BlockDAG, not three different hash structures:
//!
//! - **Bundle subtree** — a single transaction's new commitments. Built by the
//!   wallet; no consensus involvement; order-independent.
//! - **Chain-block subtree** ([`ChainBlockSubtree`]) — the ordered batch of a
//!   block's commitments, collected with zero contention while blocks are
//!   processed in parallel.
//! - **Global tree** ([`GlobalTree`]) — advanced *only* by appending chain-block
//!   batches in GHOSTDAG accepted order (the one serialized operation, done in
//!   the virtual processor). We retain only the append-only **frontier**
//!   (~32 nodes); wallets hold their own witnesses (PLAN §2.9).
//!
//! Because the global append order is exactly the GHOSTDAG accepted order, every
//! honest node computes an identical anchor — that determinism is what the
//! Phase-1 make-or-break test checks.

use core::fmt;

use incrementalmerkletree::frontier::Frontier;
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard},
    NOTE_COMMITMENT_TREE_DEPTH,
};

/// Depth of the Orchard note-commitment tree (32).
pub const TREE_DEPTH: u8 = NOTE_COMMITMENT_TREE_DEPTH as u8;

/// Error returned when appending to a tree that already holds `2^32` leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeFull;

impl fmt::Display for TreeFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("note commitment tree is full (2^32 leaves)")
    }
}

impl std::error::Error for TreeFull {}

/// Abstraction over the note-commitment accumulator.
///
/// Keeping the consensus integration behind this trait means the membership
/// argument can be swapped later (e.g. FCMP++ / Curve Trees) without touching
/// the virtual processor (PLAN §1, future direction).
pub trait NoteCommitmentTree {
    /// Append a note commitment as the next leaf, in canonical (consensus) order.
    fn append(&mut self, cmx: ExtractedNoteCommitment) -> Result<(), TreeFull>;

    /// The current anchor (root) of the tree.
    fn anchor(&self) -> Anchor;

    /// Number of leaves appended so far.
    fn size(&self) -> u64;
}

/// A chain block's note commitments, collected in block-local order during
/// (parallel, contention-free) block processing.
///
/// This is order-independent *across* blocks: only the order in which whole
/// subtrees are appended to the [`GlobalTree`] — the GHOSTDAG accepted order —
/// is consensus-relevant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainBlockSubtree {
    commitments: Vec<ExtractedNoteCommitment>,
}

impl ChainBlockSubtree {
    /// An empty subtree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a note commitment to this block's batch, preserving order.
    pub fn push(&mut self, cmx: ExtractedNoteCommitment) {
        self.commitments.push(cmx);
    }

    /// The commitments carried by this block, in block-local order.
    pub fn commitments(&self) -> &[ExtractedNoteCommitment] {
        &self.commitments
    }

    /// Number of commitments in this subtree.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Whether this subtree carries no commitments.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }
}

/// The global note-commitment tree: an append-only Orchard tree that retains
/// only its frontier. Advanced strictly in GHOSTDAG accepted order.
#[derive(Clone, Debug)]
pub struct GlobalTree {
    frontier: Frontier<MerkleHashOrchard, TREE_DEPTH>,
    size: u64,
}

impl GlobalTree {
    /// A fresh, empty global tree.
    pub fn new() -> Self {
        Self { frontier: Frontier::empty(), size: 0 }
    }

    /// Append an entire chain-block subtree (a block's commitments, in order).
    ///
    /// The caller is responsible for invoking this in GHOSTDAG accepted order.
    /// On overflow the tree is left having appended the leaves that did fit; the
    /// 2^32 bound is far beyond any reachable chain, so this is a safety guard,
    /// not an operational path.
    pub fn append_subtree(&mut self, subtree: &ChainBlockSubtree) -> Result<(), TreeFull> {
        for &cmx in subtree.commitments() {
            self.append(cmx)?;
        }
        Ok(())
    }
}

impl Default for GlobalTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteCommitmentTree for GlobalTree {
    fn append(&mut self, cmx: ExtractedNoteCommitment) -> Result<(), TreeFull> {
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        if self.frontier.append(leaf) {
            self.size += 1;
            Ok(())
        } else {
            Err(TreeFull)
        }
    }

    fn anchor(&self) -> Anchor {
        match self.frontier.value() {
            // The empty-tree anchor is well-defined and used for coinbase-only
            // bundles (Orchard `Anchor::empty_tree`).
            None => Anchor::empty_tree(),
            Some(_) => Anchor::from(self.frontier.root()),
        }
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a canonical extracted note commitment from a small integer. Small
    /// little-endian values are valid Pallas base-field encodings, which is all
    /// we need for deterministic, distinct test leaves.
    fn cmx(n: u32) -> ExtractedNoteCommitment {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        Option::from(ExtractedNoteCommitment::from_bytes(&b)).expect("canonical encoding")
    }

    fn subtree(ns: &[u32]) -> ChainBlockSubtree {
        let mut s = ChainBlockSubtree::new();
        for &n in ns {
            s.push(cmx(n));
        }
        s
    }

    #[test]
    fn empty_anchor_matches_orchard_empty_tree() {
        assert_eq!(GlobalTree::new().anchor().to_bytes(), Anchor::empty_tree().to_bytes());
        assert_eq!(GlobalTree::new().size(), 0);
    }

    /// The core determinism property (PLAN §2.4): two nodes that assemble
    /// chain-block subtrees differently in parallel, but append to the global
    /// tree in the SAME GHOSTDAG accepted order, derive an identical anchor.
    #[test]
    fn anchor_is_deterministic_for_a_fixed_global_order() {
        let block_a = subtree(&[1, 2, 3]);
        let block_b = subtree(&[4, 5]);

        // Node 1: append whole subtrees, in accepted order [A, B].
        let mut t1 = GlobalTree::new();
        t1.append_subtree(&block_a).unwrap();
        t1.append_subtree(&block_b).unwrap();

        // Node 2: same global leaf order, appended leaf-by-leaf.
        let mut t2 = GlobalTree::new();
        for n in [1, 2, 3, 4, 5] {
            t2.append(cmx(n)).unwrap();
        }

        assert_eq!(t1.anchor().to_bytes(), t2.anchor().to_bytes());
        assert_eq!(t1.size(), 5);
        assert_eq!(t2.size(), 5);
    }

    /// Appending the same commitments in a different global order yields a
    /// different anchor — as required for an order-sensitive vector commitment.
    #[test]
    fn anchor_depends_on_global_order() {
        let mut t1 = GlobalTree::new();
        for n in [1, 2, 3, 4, 5] {
            t1.append(cmx(n)).unwrap();
        }
        let mut t2 = GlobalTree::new();
        for n in [4, 5, 1, 2, 3] {
            t2.append(cmx(n)).unwrap();
        }
        assert_ne!(t1.anchor().to_bytes(), t2.anchor().to_bytes());
    }

    /// The anchor advances as leaves are added.
    #[test]
    fn anchor_changes_on_append() {
        let mut t = GlobalTree::new();
        let a0 = t.anchor().to_bytes();
        t.append(cmx(42)).unwrap();
        let a1 = t.anchor().to_bytes();
        assert_ne!(a0, a1);
    }
}
