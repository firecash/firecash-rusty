//! The proof-of-work search core (PLAN §1 — FishHashPlus / KarlsenHashV2 PoW).
//!
//! This is deliberately thin: it runs the **same** [`kaspa_pow::State`] the
//! consensus layer uses to *verify* a block. A nonce this module accepts is one
//! the node accepts by construction — there is no second PoW implementation that
//! could drift from consensus. The miner's only job is to search the nonce space
//! for a value whose FishHashPlus output meets the header's target.
//!
//! [`solve_range`] is the pure, single-threaded primitive (unit-tested here);
//! [`mine_header`] fans it out across worker threads with early-exit, striping the
//! nonce space so no two workers test the same nonce.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use kaspa_consensus_core::header::Header;
use kaspa_hashes::FishHashContext;
use kaspa_pow::State;

/// How many nonces a worker checks between polls of the shared stop flag. Small
/// enough to abandon a stale template promptly, large enough that the atomic load
/// is negligible against the memory-hard hash.
const STOP_POLL_STRIDE: u64 = 512;

/// Build the PoW [`State`] for `header`. With `full_ctx = None` the shared light
/// verification cache is used (correct, but recomputes dataset items on demand —
/// fine to bootstrap a low-difficulty chain); pass a prebuilt full-dataset context
/// for the fast memory-hard path.
pub fn build_state(header: &Header, full_ctx: Option<Arc<FishHashContext>>) -> State {
    match full_ctx {
        Some(ctx) => State::with_context(header, Some(ctx)),
        None => State::new(header),
    }
}

/// Search nonces `[start, start + count)` for one whose PoW meets `state`'s target,
/// returning the first winner or `None` if the range is exhausted. Uses
/// [`State::check_pow`], so a returned nonce satisfies the exact consensus check.
pub fn solve_range(state: &State, start: u64, count: u64) -> Option<u64> {
    let end = start.saturating_add(count);
    (start..end).find(|&nonce| state.check_pow(nonce).0)
}

/// Search the nonce space for `header` across `threads` workers until a valid nonce
/// is found or `stop` is set (e.g. the template went stale). Workers stripe the
/// space from a random base so restarts don't re-test the same nonces first.
/// Returns the winning nonce, or `None` if `stop` fired before a solution.
pub fn mine_header(header: &Header, full_ctx: Option<Arc<FishHashContext>>, threads: usize, stop: &AtomicBool) -> Option<u64> {
    // Fast path: an already-stale template. Return before building the (possibly
    // expensive) PoW state so a caller that races the stop flag pays nothing.
    if stop.load(Ordering::Relaxed) {
        return None;
    }
    let threads = threads.max(1);
    let base: u64 = rand::random();
    let state = build_state(header, full_ctx);
    let found = AtomicU64::new(0);
    let has_found = AtomicBool::new(false);

    std::thread::scope(|scope| {
        for t in 0..threads {
            let (state, found, has_found) = (&state, &found, &has_found);
            scope.spawn(move || {
                // Worker `t` tests base + t, base + t + threads, base + t + 2*threads, ...
                let mut nonce = base.wrapping_add(t as u64);
                let step = threads as u64;
                // Start at the stride so the stop flag is checked before the first hash.
                let mut since_poll = STOP_POLL_STRIDE;
                loop {
                    if since_poll >= STOP_POLL_STRIDE {
                        since_poll = 0;
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                    }
                    if state.check_pow(nonce).0 {
                        found.store(nonce, Ordering::SeqCst);
                        has_found.store(true, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        return;
                    }
                    since_poll += 1;
                    nonce = nonce.wrapping_add(step);
                }
            });
        }
    });

    has_found.load(Ordering::SeqCst).then(|| found.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::header::Header;
    use kaspa_hashes::Hash;

    /// A header with the given compact `bits`, using the cheap skip-PoW hash so the
    /// test never builds the 75MB FishHash cache or runs the memory-hard kernel —
    /// the nonce-search logic is identical regardless of which hash backs `State`.
    fn header_with_bits(bits: u32) -> Header {
        Header::new_finalized(
            1,
            vec![vec![Hash::from_bytes([1u8; 32])]].try_into().unwrap(),
            Hash::from_bytes([0u8; 32]),
            Hash::from_bytes([0u8; 32]),
            Hash::from_bytes([0u8; 32]),
            123_456,
            bits,
            0,
            0,
            0.into(),
            0,
            Hash::from_bytes([0u8; 32]),
        )
    }

    /// With a near-maximal target (very easy), a short search finds a nonce, and
    /// that nonce independently satisfies the consensus `check_pow`.
    #[test]
    fn solve_range_finds_a_valid_nonce_for_easy_target() {
        // bits = 0x207fffff => target ~= 0x7fffff << 232 (~2^255): ~half of all
        // nonces pass, so a 1024-wide search essentially always finds one.
        let header = header_with_bits(0x207f_ffff);
        let state = State::new_skip_pow(&header);
        let nonce = solve_range(&state, 0, 1024).expect("easy target => a nonce is found");
        assert!(state.check_pow(nonce).0, "the returned nonce passes the consensus PoW check");
    }

    /// With target 0 (impossible), a bounded search exhausts the range and reports
    /// no solution rather than returning a bad nonce.
    #[test]
    fn solve_range_returns_none_when_target_is_unreachable() {
        // bits = 0 => target 0; a 256-bit PoW hash is never <= 0 in practice.
        let header = header_with_bits(0);
        let state = State::new_skip_pow(&header);
        assert_eq!(solve_range(&state, 0, 4096), None, "unreachable target => no nonce");
    }

    /// The parallel driver honours the stop flag: a pre-set stop returns `None`
    /// immediately, before building the PoW state or hashing (so this stays cheap
    /// and never touches the FishHash cache). The winning-nonce path is covered by
    /// `solve_range_finds_a_valid_nonce_for_easy_target` — `mine_header` runs the
    /// same `check_pow` primitive, just striped across threads.
    #[test]
    fn mine_header_respects_a_preset_stop_flag() {
        let header = header_with_bits(0x207f_ffff);
        let stop = AtomicBool::new(true);
        assert_eq!(mine_header(&header, None, 2, &stop), None, "a pre-set stop flag aborts before any hashing");
    }

    /// End-to-end **real PoW**: run the actual FishHashPlus light kernel (builds the
    /// ~75MB cache, then the memory-hard hash) and confirm the parallel miner finds
    /// a nonce that satisfies the genuine consensus `check_pow` — i.e. it mines a
    /// real block, not a skip-PoW placeholder. Ignored by default because building
    /// the cache + hashing is slow in debug; run explicitly with
    /// `cargo test -p kaspa-miner -- --ignored --nocapture`.
    #[test]
    #[ignore = "slow: builds the real FishHash cache + runs the memory-hard kernel"]
    fn mine_header_finds_a_real_fishhash_block() {
        // Easiest target (~2^255): ~half of nonces win, so a handful of real hashes
        // suffice once the cache is built.
        let header = header_with_bits(0x207f_ffff);
        let stop = AtomicBool::new(false);
        let nonce = mine_header(&header, None, num_cpus::get(), &stop).expect("real FishHash miner finds a block");
        // Verify against a freshly built consensus verification State (the node's path).
        assert!(State::new(&header).check_pow(nonce).0, "mined nonce passes the real consensus FishHashPlus check");
    }
}
