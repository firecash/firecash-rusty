use crate::model::stores::{
    block_window_cache::BlockWindowHeap,
    ghostdag::{GhostdagData, GhostdagStoreReader},
    headers::HeaderStoreReader,
};
use kaspa_consensus_core::{
    BlockHashSet, BlueWorkType, MAX_WORK_LEVEL,
    config::params::MAX_DIFFICULTY_TARGET_AS_F64,
    errors::difficulty::{DifficultyError, DifficultyResult},
};
use kaspa_hashes::Hash;
use kaspa_math::{Uint256, Uint320};
use std::{
    cmp::{Ordering, max, min},
    ops::Deref,
    sync::Arc,
};

use super::ghostdag::ordering::SortableBlock;
use itertools::Itertools;

trait DifficultyManagerExtension {
    fn headers_store(&self) -> &dyn HeaderStoreReader;

    #[inline]
    #[must_use]
    fn internal_calc_daa_score(&self, ghostdag_data: &GhostdagData, mergeset_non_daa: &BlockHashSet) -> u64 {
        let sp_daa_score = self.headers_store().get_daa_score(ghostdag_data.selected_parent).unwrap();
        sp_daa_score + (ghostdag_data.mergeset_size() - mergeset_non_daa.len()) as u64
    }

    fn get_difficulty_blocks(&self, window: &BlockWindowHeap) -> Vec<DifficultyBlock> {
        window
            .iter()
            .map(|item| {
                let data = self.headers_store().get_compact_header_data(item.0.hash).unwrap();
                DifficultyBlock { timestamp: data.timestamp, bits: data.bits, sortable_block: item.0.clone() }
            })
            .collect()
    }

    fn internal_estimate_network_hashes_per_second(&self, window: &BlockWindowHeap) -> DifficultyResult<u64> {
        // TODO: perhaps move this const
        const MIN_WINDOW_SIZE: usize = 1000;
        let window_size = window.len();
        if window_size < MIN_WINDOW_SIZE {
            return Err(DifficultyError::UnderMinWindowSizeAllowed(window_size, MIN_WINDOW_SIZE));
        }
        let difficulty_blocks = self.get_difficulty_blocks(window);
        let (min_ts, max_ts) = difficulty_blocks.iter().map(|x| x.timestamp).minmax().into_option().unwrap();
        if min_ts == max_ts {
            return Err(DifficultyError::EmptyTimestampRange);
        }
        let window_duration = (max_ts - min_ts) / 1000; // Divided by 1000 to convert milliseconds to seconds
        if window_duration == 0 {
            return Ok(0);
        }

        let (min_blue_work, max_blue_work) =
            difficulty_blocks.iter().map(|x| x.sortable_block.blue_work).minmax().into_option().unwrap();

        Ok(((max_blue_work - min_blue_work) / window_duration).as_u64())
    }

    #[inline]
    fn check_min_difficulty_window_size(difficulty_window_size: usize, min_difficulty_window_size: usize) {
        assert!(
            min_difficulty_window_size <= difficulty_window_size,
            "min_difficulty_window_size {} is expected to be <= difficulty_window_size {}",
            min_difficulty_window_size,
            difficulty_window_size
        );
    }
}

fn _hash_suffix(n: f64) -> (f64, &'static str) {
    match n {
        n if n < 1_000.0 => (n, "hash/block"),
        n if n < 1_000_000.0 => (n / 1_000.0, "Khash/block"),
        n if n < 1_000_000_000.0 => (n / 1_000_000.0, "Mhash/block"),
        n if n < 1_000_000_000_000.0 => (n / 1_000_000_000.0, "Ghash/block"),
        n if n < 1_000_000_000_000_000.0 => (n / 1_000_000_000_000.0, "Thash/block"),
        n if n < 1_000_000_000_000_000_000.0 => (n / 1_000_000_000_000_000.0, "Phash/block"),
        n => (n / 1_000_000_000_000_000_000.0, "Ehash/block"),
    }
}

fn _difficulty_desc(target: Uint320) -> String {
    let difficulty = MAX_DIFFICULTY_TARGET_AS_F64 / target.as_f64();
    let hashrate = difficulty * 2.0;
    let (rate, suffix) = _hash_suffix(hashrate);
    format!("{:.2} {}", rate, suffix)
}

/// The hardest target the launch difficulty ceiling is allowed to reach before it
/// is lifted entirely (≈ 2^32). Kept well above 0 so the ceiling never degenerates
/// into forbidding all blocks; in practice the pure DAA takes over long before this
/// floor is hit, the moment the ceiling drops below real network difficulty.
const RAMP_TARGET_FLOOR_BITS: u32 = 32;

/// A difficulty manager based on sampled block windows, implementing [KIP-0004](https://github.com/kaspanet/kips/blob/master/kip-0004.md)
#[derive(Clone)]
pub struct SampledDifficultyManager<T: HeaderStoreReader, U: GhostdagStoreReader> {
    headers_store: Arc<T>,
    _ghostdag_store: Arc<U>,
    genesis_hash: Hash,
    genesis_bits: u32,
    /// The genesis target as a full integer (= `from_compact_target_bits(genesis_bits)`).
    /// This is the super-easy low-difficulty-start target the launch schedule pins to and ramps from.
    genesis_target: Uint256,
    max_difficulty_target: Uint320,
    difficulty_window_size: usize,
    min_difficulty_window_size: usize,
    difficulty_sample_rate: u64,
    target_time_per_block: u64,
    /// ZKas launch difficulty schedule (blue-score units). While
    /// `blue_score <= low_difficulty_end_blue_score` difficulty is pinned to `genesis_target`
    /// (super-easy, CPU-mineable low-difficulty start). Between there and `ramp_end_blue_score` the
    /// difficulty *ceiling* tightens geometrically toward real difficulty. At/after
    /// `ramp_end_blue_score` the ceiling is removed and the pure DAA governs, so
    /// post-launch blocks are **not** easily mined. `ramp_end_blue_score == 0` disables
    /// the schedule entirely (identical to upstream KIP-0004 behaviour).
    low_difficulty_end_blue_score: u64,
    ramp_end_blue_score: u64,
}

impl<T: HeaderStoreReader, U: GhostdagStoreReader> SampledDifficultyManager<T, U> {
    pub fn new(
        headers_store: Arc<T>,
        ghostdag_store: Arc<U>,
        genesis_hash: Hash,
        genesis_bits: u32,
        max_difficulty_target: Uint256,
        difficulty_window_size: usize,
        min_difficulty_window_size: usize,
        difficulty_sample_rate: u64,
        target_time_per_block: u64,
        low_difficulty_end_blue_score: u64,
        ramp_end_blue_score: u64,
    ) -> Self {
        Self::check_min_difficulty_window_size(difficulty_window_size, min_difficulty_window_size);
        Self {
            headers_store,
            _ghostdag_store: ghostdag_store,
            genesis_hash,
            genesis_bits,
            genesis_target: Uint256::from_compact_target_bits(genesis_bits),
            max_difficulty_target: max_difficulty_target.into(),
            difficulty_window_size,
            min_difficulty_window_size,
            difficulty_sample_rate,
            target_time_per_block,
            low_difficulty_end_blue_score,
            ramp_end_blue_score,
        }
    }

    #[inline]
    #[must_use]
    pub fn difficulty_full_window_size(&self) -> u64 {
        self.difficulty_window_size as u64 * self.difficulty_sample_rate
    }

    /// Returns the DAA window lowest accepted blue score
    #[inline]
    #[must_use]
    pub fn lowest_daa_blue_score(&self, ghostdag_data: &GhostdagData) -> u64 {
        let difficulty_full_window_size = self.difficulty_full_window_size();
        ghostdag_data.blue_score.max(difficulty_full_window_size) - difficulty_full_window_size
    }

    #[inline]
    #[must_use]
    pub fn calc_daa_score(&self, ghostdag_data: &GhostdagData, mergeset_non_daa: &BlockHashSet) -> u64 {
        self.internal_calc_daa_score(ghostdag_data, mergeset_non_daa)
    }

    pub fn calc_daa_score_and_mergeset_non_daa_blocks(
        &self,
        ghostdag_data: &GhostdagData,
        store: &(impl GhostdagStoreReader + ?Sized),
    ) -> (u64, BlockHashSet) {
        let lowest_daa_blue_score = self.lowest_daa_blue_score(ghostdag_data);
        let mergeset_non_daa: BlockHashSet =
            ghostdag_data.unordered_mergeset().filter(|hash| store.get_blue_score(*hash).unwrap() < lowest_daa_blue_score).collect();
        (self.internal_calc_daa_score(ghostdag_data, &mergeset_non_daa), mergeset_non_daa)
    }

    /// Returns the required difficulty bits for a block whose GHOSTDAG data is
    /// `ghostdag_data`, applying the KIP-0004 sampled DAA and then, during the
    /// launch window, the ZKas difficulty ceiling (see [`Self::launch_min_target`]).
    pub fn calculate_difficulty_bits(&self, window: &BlockWindowHeap, ghostdag_data: &GhostdagData) -> u32 {
        let base_bits = self.calculate_base_difficulty_bits(window, ghostdag_data);
        match self.launch_min_target(ghostdag_data.blue_score) {
            // Past the launch window (schedule ran and is finished): pure DAA, BUT never let
            // difficulty drop back below the launch floor — otherwise, if the DAA ever
            // mis-measures (e.g. a fragmented DAG makes the selected chain look slow), it can
            // spiral difficulty all the way down to the trivial minimum and never recover.
            // The floor is `genesis_target` (the easy-start difficulty): after the easy window
            // the chain can rise above it freely, but can never become *easier* than it again.
            None if self.ramp_end_blue_score > 0 => {
                let daa_target = Uint256::from_compact_target_bits(base_bits);
                // Smaller target = harder; cap the target at genesis so difficulty >= genesis.
                min(daa_target, self.genesis_target).compact_target_bits()
            }
            // Schedule disabled entirely (ramp_end == 0): upstream KIP-0004 pure DAA.
            None => base_bits,
            // Launch window: cap the difficulty from above by flooring the target. Taking the
            // *larger* (=easier) of the DAA target and the ceiling target keeps difficulty at
            // or below the scheduled ceiling. Once the ceiling drops below the DAA target the
            // DAA target wins and difficulty tracks the real network again.
            Some(min_target) => {
                let daa_target = Uint256::from_compact_target_bits(base_bits);
                max(daa_target, min_target).compact_target_bits()
            }
        }
    }

    /// The launch difficulty **ceiling**, expressed as a floor on the block target, for a
    /// block at blue score `blue_score`. Returns `None` when the schedule is disabled
    /// (`ramp_end_blue_score == 0`) or already finished (`blue_score >= ramp_end_blue_score`),
    /// in which case the pure DAA governs.
    ///
    /// - **Low-difficulty start** (`blue_score <= low_difficulty_end_blue_score`): pinned to `genesis_target`
    ///   (super-easy), so the chain is CPU-mineable regardless of the DAA / hashrate.
    /// - **Ramp** (`low_difficulty_end < blue_score < ramp_end`): the ceiling target is
    ///   `genesis_target >> shift`, where `shift` grows linearly from 0 to
    ///   `genesis_target.bits() - RAMP_TARGET_FLOOR_BITS` across the ramp — i.e. the ceiling
    ///   **difficulty** roughly doubles per unit of `shift`, climbing geometrically from
    ///   super-easy toward the hard floor. The pure DAA takes over the instant this ceiling
    ///   drops below real network difficulty.
    fn launch_min_target(&self, blue_score: u64) -> Option<Uint256> {
        launch_min_target(self.genesis_target, self.low_difficulty_end_blue_score, self.ramp_end_blue_score, blue_score)
    }

    fn calculate_base_difficulty_bits(&self, window: &BlockWindowHeap, ghostdag_data: &GhostdagData) -> u32 {
        let mut difficulty_blocks = self.get_difficulty_blocks(window);

        // Until there are enough blocks for a valid calculation the difficulty should remain constant.
        if difficulty_blocks.len() < self.min_difficulty_window_size {
            let selected_parent = ghostdag_data.selected_parent;
            if selected_parent == self.genesis_hash {
                return self.genesis_bits;
            }

            // We will use the selected parent as a source for the difficulty bits
            return self.headers_store.get_bits(selected_parent).unwrap();
        }

        let (min_ts_index, max_ts_index) = difficulty_blocks.iter().position_minmax().into_option().unwrap();

        let min_ts = difficulty_blocks[min_ts_index].timestamp;
        let max_ts = difficulty_blocks[max_ts_index].timestamp;

        // We remove the minimal block because we want the average target for the internal window.
        difficulty_blocks.swap_remove(min_ts_index);

        // We need Uint320 to avoid overflow when summing and multiplying by the window size.
        let difficulty_blocks_len = difficulty_blocks.len() as u64;
        let targets_sum: Uint320 =
            difficulty_blocks.into_iter().map(|diff_block| Uint320::from(Uint256::from_compact_target_bits(diff_block.bits))).sum();
        let average_target = targets_sum / difficulty_blocks_len;
        let measured_duration = max(max_ts - min_ts, 1);
        let expected_duration = self.target_time_per_block * self.difficulty_sample_rate * difficulty_blocks_len; // This does differ from FullDifficultyManager version
        let new_target = average_target * measured_duration / expected_duration;

        Uint256::try_from(new_target.min(self.max_difficulty_target)).expect("max target < Uint256::MAX").compact_target_bits()
    }

    pub fn estimate_network_hashes_per_second(&self, window: &BlockWindowHeap) -> DifficultyResult<u64> {
        self.internal_estimate_network_hashes_per_second(window)
    }
}

impl<T: HeaderStoreReader, U: GhostdagStoreReader> DifficultyManagerExtension for SampledDifficultyManager<T, U> {
    fn headers_store(&self) -> &dyn HeaderStoreReader {
        self.headers_store.deref()
    }
}

/// Pure implementation of the ZKas launch difficulty ceiling (see
/// [`SampledDifficultyManager::launch_min_target`]). Kept free-standing so it can be
/// unit-tested without a store-backed manager. Returns the floor on the block target
/// (= ceiling on difficulty) at `blue_score`, or `None` when the schedule is disabled
/// (`ramp_end == 0`) or finished (`blue_score >= ramp_end`).
fn launch_min_target(genesis_target: Uint256, low_difficulty_end: u64, ramp_end: u64, blue_score: u64) -> Option<Uint256> {
    if ramp_end == 0 || blue_score >= ramp_end {
        return None;
    }
    if blue_score <= low_difficulty_end {
        return Some(genesis_target);
    }
    // ramp_end > low_difficulty_end is guaranteed by construction (ramp_end =
    // low_difficulty_end + ramp_blocks, ramp_blocks > 0), so the span is > 0.
    let ramp_span = ramp_end - low_difficulty_end;
    let into_ramp = blue_score - low_difficulty_end;
    let total_shift = genesis_target.bits().saturating_sub(RAMP_TARGET_FLOOR_BITS);
    // Proportional shift in [0, total_shift]; u128 math avoids overflow, and clamping
    // below 256 keeps the right-shift within Uint256 (the debug assert guards >= BITS).
    let shift = ((total_shift as u128 * into_ramp as u128) / ramp_span as u128).min(255) as u32;
    Some(genesis_target >> shift)
}

pub fn calc_work(bits: u32) -> BlueWorkType {
    let target = Uint256::from_compact_target_bits(bits);
    // Source: https://github.com/bitcoin/bitcoin/blob/2e34374bf3e12b37b0c66824a6c998073cdfab01/src/chain.cpp#L131
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.

    let res = (!target / (target + 1)) + 1;
    res.try_into().expect("Work should not exceed 2**192")
}

pub fn level_work(level: u8, max_block_level: u8) -> BlueWorkType {
    // Need to make a special condition for level 0 to ensure true work is always used
    if level == 0 {
        return 0.into();
    }
    // We use 256 here so the result corresponds to the work at the level from calc_level_from_pow
    let exp = (level as u32) + 256 - (max_block_level as u32);
    BlueWorkType::from_u64(1) << exp.min(MAX_WORK_LEVEL as u32)
}

#[derive(Eq)]
struct DifficultyBlock {
    timestamp: u64,
    bits: u32,
    sortable_block: SortableBlock,
}

impl PartialEq for DifficultyBlock {
    fn eq(&self, other: &Self) -> bool {
        // If the sortable blocks are equal the timestamps and bits that are associated with the block are equal for sure.
        self.sortable_block == other.sortable_block
    }
}

impl PartialOrd for DifficultyBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DifficultyBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp).then_with(|| self.sortable_block.cmp(&other.sortable_block))
    }
}

#[cfg(test)]
mod tests {
    use kaspa_consensus_core::{BlockLevel, BlueWorkType, MAX_WORK_LEVEL};
    use kaspa_math::{Uint256, Uint320};
    use kaspa_pow::calc_level_from_pow;

    use crate::processes::difficulty::{calc_work, level_work};
    use kaspa_utils::hex::ToHex;

    #[test]
    fn test_target_levels() {
        let max_block_level: BlockLevel = 225;
        for level in 1..=max_block_level {
            // required pow for level
            let level_target = (Uint320::from_u64(1) << (max_block_level - level).max(MAX_WORK_LEVEL) as u32) - Uint320::from_u64(1);
            let level_target = Uint256::from_be_bytes(level_target.to_be_bytes()[8..40].try_into().unwrap());
            let calculated_level = calc_level_from_pow(level_target, max_block_level);

            let true_level_work = calc_work(level_target.compact_target_bits());
            let calc_level_work = level_work(level, max_block_level);

            // A "good enough" estimate of level work is within 1% diff from work with actual level target
            // It's hard to calculate percentages with these large numbers, so to get around using floats
            // we multiply the difference by 100. if the result is <= the calc_level_work it means
            // difference must have been less than 1%
            let (percent_diff, overflowed) = (true_level_work - calc_level_work).overflowing_mul(BlueWorkType::from_u64(100));
            let is_good_enough = percent_diff <= calc_level_work;

            println!("Level {}:", level);
            println!(
                "    data | {} | {} | {} / {} |",
                level_target.compact_target_bits(),
                level_target.bits(),
                calculated_level,
                max_block_level
            );
            println!("    pow  | {}", level_target.to_hex());
            println!("    work | 0000000000000000{}", true_level_work.to_hex());
            println!("  lvwork | 0000000000000000{}", calc_level_work.to_hex());
            println!(" diff<1% | {}", !overflowed && (is_good_enough));

            assert!(is_good_enough);
        }
    }

    #[test]
    fn test_base_level_work() {
        // Expect that at level 0, the level work is always 0
        assert_eq!(BlueWorkType::from(0), level_work(0, 255));
    }

    use super::launch_min_target;

    // Mainnet-like schedule: a super-easy genesis target, 50k blocks pinned, then a
    // ~1-day (864k block) ramp.
    const GENESIS_BITS: u32 = 0x207f_ffff; // ~2^255, the easiest practical target
    const LOW_DIFF_END: u64 = 50_000;
    const RAMP_END: u64 = 50_000 + 864_000;

    fn genesis_target() -> Uint256 {
        Uint256::from_compact_target_bits(GENESIS_BITS)
    }

    /// A `ramp_end == 0` schedule is disabled everywhere → the pure DAA always governs.
    #[test]
    fn disabled_schedule_never_caps() {
        let g = genesis_target();
        for blue in [0u64, 1, 50_000, 1_000_000, u64::MAX] {
            assert_eq!(launch_min_target(g, 0, 0, blue), None, "disabled schedule must never cap (blue={blue})");
        }
    }

    /// Throughout the low-difficulty start the ceiling is pinned to the (super-easy)
    /// genesis target, so blocks stay CPU-mineable regardless of the DAA.
    #[test]
    fn low_difficulty_start_is_pinned_to_genesis() {
        let g = genesis_target();
        for blue in [0u64, 1, 25_000, LOW_DIFF_END] {
            assert_eq!(launch_min_target(g, LOW_DIFF_END, RAMP_END, blue), Some(g), "start must pin to genesis (blue={blue})");
        }
    }

    /// During the ramp the ceiling target strictly decreases (difficulty strictly
    /// increases) as blue score grows, and always stays at or below the genesis target.
    #[test]
    fn ramp_tightens_monotonically() {
        let g = genesis_target();
        let mut prev = g;
        let mut seen_change = false;
        let mut blue = LOW_DIFF_END + 1;
        while blue < RAMP_END {
            let t = launch_min_target(g, LOW_DIFF_END, RAMP_END, blue).expect("inside ramp => Some");
            assert!(t <= g, "ceiling target never exceeds genesis (blue={blue})");
            assert!(t <= prev, "ceiling target must be non-increasing across the ramp (blue={blue})");
            if t < prev {
                seen_change = true;
            }
            prev = t;
            blue += 40_000; // sample the ramp
        }
        assert!(seen_change, "difficulty must actually rise during the ramp");
    }

    /// At and past the ramp end the ceiling is lifted (`None`) so the pure DAA sets the
    /// real difficulty — post-launch blocks are not held artificially easy.
    #[test]
    fn ceiling_is_lifted_after_ramp() {
        let g = genesis_target();
        for blue in [RAMP_END, RAMP_END + 1, RAMP_END + 10_000_000] {
            assert_eq!(launch_min_target(g, LOW_DIFF_END, RAMP_END, blue), None, "post-ramp must defer to DAA (blue={blue})");
        }
    }

    /// The very last block of the ramp must have a much harder ceiling than the start,
    /// so the hand-off to the DAA cannot leave difficulty near the trivial genesis level.
    #[test]
    fn ramp_end_is_far_harder_than_start() {
        let g = genesis_target();
        let near_end = launch_min_target(g, LOW_DIFF_END, RAMP_END, RAMP_END - 1).expect("inside ramp => Some");
        // Target shrank by many orders of magnitude (difficulty rose by the same factor).
        assert!(near_end < (g >> 64), "by ramp end the difficulty ceiling must be astronomically higher than genesis");
    }
}
