//! Canonical shielded state root (PLAN §2.10).
//!
//! A single 32-byte digest binding the three pieces of shielded consensus state
//! that a fast-syncing or pruned node cannot otherwise verify without replaying
//! every block from genesis:
//!
//! - the **note-commitment tree root** (`anchor`) — commits to the full note
//!   history, so received notes and spend witnesses are trustworthy;
//! - the **nullifier-set accumulator root** (`nullifier_root`, a MuHash over all
//!   spent nullifiers) — commits to double-spend prevention across a checkpoint;
//! - the **turnstile cumulative totals** — commit to value conservation
//!   (shielded pool == cumulative coinbase − cumulative fees, §2.6).
//!
//! This digest is what a block commits to (via the coinbase, itself bound by the
//! header's `hash_merkle_root` and thus by proof-of-work), forming a PoW-anchored
//! chain of shielded state roots.

use blake2b_simd::Params;

/// Personalization for the shielded state root hash (blake2b personal is ≤16 bytes).
const STATE_ROOT_PERSONAL: &[u8; 16] = b"firecash_shldrt0";

/// The canonical 32-byte shielded state root (see module docs). Deterministic in
/// its four inputs and independent of evaluation order — the accumulator inputs
/// (`anchor`, `nullifier_root`) are themselves order-independent set commitments.
pub fn shielded_state_root(
    anchor: &[u8; 32],
    nullifier_root: &[u8; 32],
    cumulative_coinbase: u128,
    cumulative_fees: u128,
) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(STATE_ROOT_PERSONAL).to_state();
    h.update(anchor);
    h.update(nullifier_root);
    h.update(&cumulative_coinbase.to_le_bytes());
    h.update(&cumulative_fees.to_le_bytes());
    let mut root = [0u8; 32];
    root.copy_from_slice(h.finalize().as_bytes());
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0x11; 32];
    const N: [u8; 32] = [0x22; 32];

    #[test]
    fn deterministic() {
        assert_eq!(shielded_state_root(&A, &N, 7, 3), shielded_state_root(&A, &N, 7, 3));
    }

    #[test]
    fn sensitive_to_every_field() {
        let base = shielded_state_root(&A, &N, 7, 3);
        assert_ne!(base, shielded_state_root(&[0x12; 32], &N, 7, 3), "anchor must matter");
        assert_ne!(base, shielded_state_root(&A, &[0x23; 32], 7, 3), "nullifier root must matter");
        assert_ne!(base, shielded_state_root(&A, &N, 8, 3), "cumulative coinbase must matter");
        assert_ne!(base, shielded_state_root(&A, &N, 7, 4), "cumulative fees must matter");
    }

    #[test]
    fn coinbase_and_fees_are_not_interchangeable() {
        // Guards against a swapped-argument / concatenation-ambiguity bug where
        // (coinbase=a, fees=b) would collide with (coinbase=b, fees=a).
        assert_ne!(shielded_state_root(&A, &N, 5, 9), shielded_state_root(&A, &N, 9, 5));
    }
}
