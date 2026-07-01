// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;
use std::sync::{Arc, OnceLock};

use kaspa_consensus_core::{hashing, header::Header, BlockLevel};
use kaspa_hashes::{FishHashContext, PowB3Hash, PowFishHash};
use kaspa_math::Uint256;

/// The process-wide FishHash light cache (~75MB), built once on first use. It is
/// sufficient to *verify* blocks (dataset items are recomputed on demand); miners
/// build the ~4.6GB full dataset separately. Building it is expensive (seconds in
/// release, much longer in debug), hence the one-time lazy init.
static LIGHT_CONTEXT: OnceLock<Arc<FishHashContext>> = OnceLock::new();

/// Fetch (lazily building) the shared FishHash light context used for verification.
pub fn light_context() -> Arc<FishHashContext> {
    LIGHT_CONTEXT.get_or_init(|| Arc::new(FishHashContext::new(false, None))).clone()
}

/// State is an intermediate data structure with pre-computed values to speed up mining.
pub struct State {
    pub(crate) target: Uint256,
    // Blake3 pre-hash absorbing PRE_POW_HASH || TIME || 32 zero byte padding; without NONCE.
    pub(crate) hasher: PowB3Hash,
    // The FishHash context used for the memory-hard step. `None` means the caller
    // requested `skip_proof_of_work` (tests): a cheap deterministic fallback is used
    // instead of the real, expensive kernel, so the light cache is never built.
    pub(crate) fish_context: Option<Arc<FishHashContext>>,
}

impl State {
    /// Build a verification state that runs the real FishHashPlus PoW.
    #[inline]
    pub fn new(header: &Header) -> Self {
        Self::with_context(header, Some(light_context()))
    }

    /// Build a state that skips the real PoW (for `skip_proof_of_work`): the pow
    /// value is a cheap hash, adequate for deterministic block-level math in tests.
    #[inline]
    pub fn new_skip_pow(header: &Header) -> Self {
        Self::with_context(header, None)
    }

    #[inline]
    pub fn with_context(header: &Header, fish_context: Option<Arc<FishHashContext>>) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        // Zero out the time and nonce.
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        // PRE_POW_HASH || TIME || 32 zero byte padding || NONCE
        let hasher = PowB3Hash::new(pre_pow_hash, header.timestamp);
        Self { target, hasher, fish_context }
    }

    #[inline]
    #[must_use]
    /// PRE_POW_HASH || TIME || 32 zero byte padding || NONCE, then FishHashPlus.
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        // Hasher already contains PRE_POW_HASH || TIME || 32 zero byte padding; so only the NONCE is missing.
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let final_hash = match &self.fish_context {
            // KarlsenHashV2: pre-hash -> FishHashPlus kernel -> final blake3 wrap.
            Some(ctx) => PowB3Hash::hash(PowFishHash::fishhashplus_kernel(&hash, ctx)),
            // skip_proof_of_work: a cheap deterministic value with no real PoW security.
            None => PowB3Hash::hash(hash),
        };
        Uint256::from_le_bytes(final_hash.as_bytes())
    }

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        // The pow hash must be less or equal than the claimed target.
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel, skip_pow: bool) -> BlockLevel {
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level, skip_pow);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel, skip_pow: bool) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = if skip_pow { State::new_skip_pow(header) } else { State::new(header) };
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
