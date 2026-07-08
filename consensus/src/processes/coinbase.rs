use kaspa_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
    config::params::{ForkActivation, ForkedParam},
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    subnets,
    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
};
use std::convert::TryInto;

use crate::{constants, model::stores::ghostdag::GhostdagData};

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
const LENGTH_OF_SHIELDED_COMMITMENT: usize = 32;
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize = LENGTH_OF_BLUE_SCORE
    + LENGTH_OF_SUBSIDY
    + LENGTH_OF_SHIELDED_COMMITMENT
    + LENGTH_OF_SCRIPT_PUB_KEY_VERSION
    + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60
const SECONDS_PER_MONTH: u64 = 2629800;

// firecash monetary policy: the block subsidy follows the shape of Kaspa's `SUBSIDY_BY_MONTH_TABLE`
// but with two firecash-specific transforms:
//   1. It halves every 3 months instead of every 12. Kaspa's table encodes a smooth decay with
//      `LEGACY_MONTHS_PER_HALVING` (=12) monthly steps per halving; we traverse it
//      `LEGACY_MONTHS_PER_HALVING / SUBSIDY_HALVING_INTERVAL_MONTHS` = 4× faster so a full halving
//      takes 3 months.
//   2. Every table value is scaled by `REWARD_SCALE_NUM / REWARD_SCALE_DEN` (then divided by BPS),
//      setting the initial 10-BPS reward to 6 FC/block (44 FC × 3/22 = 6 FC) instead of 44.
// Once the curve decays below the tail floor, a two-step tail subsidy is paid forever: the curve
// crosses 0.6 FC around month 10, so `TAIL_SUBSIDY_INITIAL_SOMPI` (0.6 FC) is paid up to real month
// `TAIL_STEP_DOWN_MONTH` (=24), after which it steps down to `TAIL_SUBSIDY_FINAL_SOMPI` (0.3 FC) and
// that floor is paid forever. See the tail-constant docs below.
const SUBSIDY_HALVING_INTERVAL_MONTHS: u64 = 3;
// The number of monthly table steps that constitute one halving in Kaspa's original table.
const LEGACY_MONTHS_PER_HALVING: u64 = 12;

// firecash reward scale (see monetary-policy note above): each Kaspa table value is multiplied by
// REWARD_SCALE_NUM/REWARD_SCALE_DEN before the BPS division. 3/22 sets the initial 10-BPS subsidy to
// 6 FC/block (44 FC × 3/22).
const REWARD_SCALE_NUM: u64 = 3;
const REWARD_SCALE_DEN: u64 = 22;

// Convert a raw Kaspa 1-BPS monthly-table value into the firecash per-block subsidy for `bps`:
// apply the reward scale, then divide by BPS. u128 intermediate avoids overflow.
#[inline]
fn scaled_subsidy(table_value: u64, bps: u64) -> u64 {
    ((table_value.div_ceil(bps) as u128) * REWARD_SCALE_NUM as u128 / REWARD_SCALE_DEN as u128) as u64
}

// Two-step perpetual tail emission (firecash): once the deflationary curve decays below the tail
// floor, every rewarded block keeps paying a fixed tail subsidy forever, funding long-term miner
// security after the main emission curve is effectively exhausted. The tail steps down once:
//   * `TAIL_SUBSIDY_INITIAL_SOMPI` = 0.6 FC/block, paid until real month `TAIL_STEP_DOWN_MONTH`.
//     The 6 FC/3-month-halving curve crosses 0.6 FC around month 10, so this floor governs the
//     reward from ≈month 10 through month 24. At 10 BPS: 6 FC/s ≈ 189M FC/year.
//   * `TAIL_SUBSIDY_FINAL_SOMPI` = 0.3 FC/block, paid forever from month `TAIL_STEP_DOWN_MONTH` on.
//     At 10 BPS: 3 FC/s ≈ 95M FC/year (the perpetual long-run inflation floor).
// Both are absolute per-rewarded-block amounts, independent of BPS.
const TAIL_SUBSIDY_INITIAL_SOMPI: u64 = 60_000_000;
const TAIL_SUBSIDY_FINAL_SOMPI: u64 = 30_000_000;
// Real (calendar) month at which the tail steps down from the initial floor to the final floor.
const TAIL_STEP_DOWN_MONTH: u64 = 24;

pub const SUBSIDY_BY_MONTH_TABLE_SIZE: usize = 426;
pub type SubsidyByMonthTable = [u64; SUBSIDY_BY_MONTH_TABLE_SIZE];

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    deflationary_phase_daa_score: u64,
    pre_deflationary_phase_base_subsidy: u64,
    bps_history: ForkedParam<u64>,
    toccata_activation: ForkActivation,

    /// Precomputed subsidy by month tables (for before and after the Crescendo hardfork)
    subsidy_by_month_table_before: SubsidyByMonthTable,
    subsidy_by_month_table_after: SubsidyByMonthTable,

    /// The crescendo activation DAA score where BPS increased from 1 to 10.
    /// This score is required here long-term (and not only for the actual forking), in
    /// order to correctly determine the subsidy month from the live DAA score of the network   
    crescendo_activation_daa_score: u64,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        bps_history: ForkedParam<u64>,
        toccata_activation: ForkActivation,
    ) -> Self {
        // Precomputed subsidy by month table for the actual block per second rate.
        // Values are rounded up per BPS (keeping the same number of rewarding months as the original
        // 1 BPS table) and then scaled by the firecash reward scale (see `scaled_subsidy`).
        let subsidy_by_month_table_before: SubsidyByMonthTable =
            core::array::from_fn(|i| scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], bps_history.before()));
        let subsidy_by_month_table_after: SubsidyByMonthTable =
            core::array::from_fn(|i| scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], bps_history.after()));
        Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            deflationary_phase_daa_score,
            pre_deflationary_phase_base_subsidy,
            bps_history,
            toccata_activation,
            subsidy_by_month_table_before,
            subsidy_by_month_table_after,
            crescendo_activation_daa_score: bps_history.activation().daa_score(),
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn bps(&self) -> ForkedParam<u64> {
        self.bps_history
    }

    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        daa_score: u64,
        miner_data: MinerData<T>,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
        shielded_commitment: [u8; 32],
    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
        let mut outputs = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1); // + 1 for possible red reward

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            if reward_data.subsidy + reward_data.total_fees > 0 {
                outputs
                    .push(TransactionOutput::new(reward_data.subsidy + reward_data.total_fees, reward_data.script_public_key.clone()));
            }
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block)
        let mut red_reward = 0u64;

        for red in ghostdag_data.mergeset_reds.iter() {
            let reward_data = mergeset_rewards.get(red).unwrap();
            if mergeset_non_daa.contains(red) {
                red_reward += reward_data.total_fees;
            } else {
                red_reward += reward_data.subsidy + reward_data.total_fees;
            }
        }

        if red_reward > 0 {
            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
        }

        // Build the current block's payload
        let subsidy = self.calc_block_subsidy(daa_score);
        let payload =
            self.serialize_coinbase_payload(&CoinbaseData { blue_score: ghostdag_data.blue_score, subsidy, shielded_commitment, miner_data })?;

        let tx_version =
            if self.toccata_activation.is_active(daa_score) { constants::TX_VERSION_TOCCATA } else { constants::TX_VERSION };

        Ok(CoinbaseTransactionTemplate {
            tx: Transaction::new(tx_version, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
            has_red_reward: red_reward > 0,
        })
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.shielded_commitment.iter().copied())                                    // Shielded state root          (32)
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep blue score, subsidy and the shielded commitment (all independent of miner data).
        // Note that truncate does not modify capacity, so the usual case where the payloads are
        // the same size will not trigger a reallocation
        payload.truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_SHIELDED_COMMITMENT);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let shielded_commitment: [u8; 32] = parser.take(LENGTH_OF_SHIELDED_COMMITMENT).try_into().unwrap();
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData { blue_score, subsidy, shielded_commitment, miner_data: MinerData { script_public_key, extra_data } })
    }

    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Perpetual tail: once the deflationary curve decays below the tail floor, every rewarded
        // block keeps paying the (time-dependent) tail subsidy forever (see the const docs).
        self.curve_subsidy(daa_score).max(self.tail_subsidy(daa_score))
    }

    /// The two-step perpetual tail floor for a given DAA score: `TAIL_SUBSIDY_INITIAL_SOMPI`
    /// (0.6 FC) up to real month `TAIL_STEP_DOWN_MONTH`, then `TAIL_SUBSIDY_FINAL_SOMPI` (0.3 FC)
    /// forever. Assumes `daa_score >= deflationary_phase_daa_score`.
    fn tail_subsidy(&self, daa_score: u64) -> u64 {
        // `subsidy_month` returns the table index, which advances `LEGACY_MONTHS_PER_HALVING /
        // SUBSIDY_HALVING_INTERVAL_MONTHS` (=4)× faster than real calendar months; convert back.
        let real_month = self.subsidy_month(daa_score) * SUBSIDY_HALVING_INTERVAL_MONTHS / LEGACY_MONTHS_PER_HALVING;
        if real_month < TAIL_STEP_DOWN_MONTH {
            TAIL_SUBSIDY_INITIAL_SOMPI
        } else {
            TAIL_SUBSIDY_FINAL_SOMPI
        }
    }

    /// The deflationary-curve subsidy *without* the perpetual tail floor. Decays to 0 once the
    /// 426-entry monthly table is exhausted. Assumes `daa_score >= deflationary_phase_daa_score`.
    fn curve_subsidy(&self, daa_score: u64) -> u64 {
        let subsidy_month = self.subsidy_month(daa_score) as usize;
        let subsidy_table = if self.bps_history.activation().is_active(daa_score) {
            &self.subsidy_by_month_table_after
        } else {
            &self.subsidy_by_month_table_before
        };
        subsidy_table[subsidy_month.min(subsidy_table.len() - 1)]
    }

    /// Get the subsidy month as function of the current DAA score.
    ///
    /// Note that this function is called only if daa_score >= self.deflationary_phase_daa_score
    fn subsidy_month(&self, daa_score: u64) -> u64 {
        let seconds_since_deflationary_phase_started = if self.crescendo_activation_daa_score < self.deflationary_phase_daa_score {
            // crescendo_activation < deflationary_phase <= daa_score (activated before deflation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.after()
        } else if daa_score < self.crescendo_activation_daa_score {
            // deflationary_phase <= daa_score < crescendo_activation (pre activation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
        } else {
            // Else - deflationary_phase <= crescendo_activation <= daa_score.
            // Count seconds differently before and after Crescendo activation
            (self.crescendo_activation_daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
                + (daa_score - self.crescendo_activation_daa_score) / self.bps_history.after()
        };

        // Traverse Kaspa's monthly table `LEGACY_MONTHS_PER_HALVING / SUBSIDY_HALVING_INTERVAL_MONTHS`×
        // faster so the subsidy halves every `SUBSIDY_HALVING_INTERVAL_MONTHS` (=3) months. u128 math
        // avoids overflow for far-future DAA scores; the index is clamped to the table in the caller.
        ((seconds_since_deflationary_phase_started as u128 * LEGACY_MONTHS_PER_HALVING as u128)
            / (SECONDS_PER_MONTH as u128 * SUBSIDY_HALVING_INTERVAL_MONTHS as u128)) as u64
    }

    #[cfg(test)]
    pub fn legacy_calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Note that this calculation implicitly assumes that block per second = 1 (by assuming daa score diff is in second units).
        // Like `subsidy_month`, the monthly table is traversed 4× faster so the subsidy halves every
        // `SUBSIDY_HALVING_INTERVAL_MONTHS` (=3) months instead of the original 12.
        let table_index = ((daa_score - self.deflationary_phase_daa_score) as u128 * LEGACY_MONTHS_PER_HALVING as u128
            / (SECONDS_PER_MONTH as u128 * SUBSIDY_HALVING_INTERVAL_MONTHS as u128)) as u64;
        assert!(table_index <= usize::MAX as u64);
        let table_index: usize = table_index as usize;
        // 1-BPS curve value with the firecash reward scale applied (no tail floor; used for tests).
        let table_value =
            if table_index >= SUBSIDY_BY_MONTH_TABLE.len() { *SUBSIDY_BY_MONTH_TABLE.last().unwrap() } else { SUBSIDY_BY_MONTH_TABLE[table_index] };
        scaled_subsidy(table_value, 1)
    }
}

/*
    This table was pre-calculated by calling `calcDeflationaryPeriodBlockSubsidyFloatCalc` (in kaspad-go) for all months until reaching 0 subsidy.
    To regenerate this table, run `TestBuildSubsidyTable` in coinbasemanager_test.go (note the `deflationaryPhaseBaseSubsidy` therein).
    These values represent the reward per second for each month (= reward per block for 1 BPS).
*/
#[rustfmt::skip]
const SUBSIDY_BY_MONTH_TABLE: [u64; 426] = [
	44000000000, 41530469757, 39199543598, 36999442271, 34922823143, 32962755691, 31112698372, 29366476791, 27718263097, 26162556530, 24694165062, 23308188075, 22000000000, 20765234878, 19599771799, 18499721135, 17461411571, 16481377845, 15556349186, 14683238395, 13859131548, 13081278265, 12347082531, 11654094037, 11000000000,
	10382617439, 9799885899, 9249860567, 8730705785, 8240688922, 7778174593, 7341619197, 6929565774, 6540639132, 6173541265, 5827047018, 5500000000, 5191308719, 4899942949, 4624930283, 4365352892, 4120344461, 3889087296, 3670809598, 3464782887, 3270319566, 3086770632, 2913523509, 2750000000, 2595654359,
	2449971474, 2312465141, 2182676446, 2060172230, 1944543648, 1835404799, 1732391443, 1635159783, 1543385316, 1456761754, 1375000000, 1297827179, 1224985737, 1156232570, 1091338223, 1030086115, 972271824, 917702399, 866195721, 817579891, 771692658, 728380877, 687500000, 648913589, 612492868,
	578116285, 545669111, 515043057, 486135912, 458851199, 433097860, 408789945, 385846329, 364190438, 343750000, 324456794, 306246434, 289058142, 272834555, 257521528, 243067956, 229425599, 216548930, 204394972, 192923164, 182095219, 171875000, 162228397, 153123217, 144529071,
	136417277, 128760764, 121533978, 114712799, 108274465, 102197486, 96461582, 91047609, 85937500, 81114198, 76561608, 72264535, 68208638, 64380382, 60766989, 57356399, 54137232, 51098743, 48230791, 45523804, 42968750, 40557099, 38280804, 36132267, 34104319,
	32190191, 30383494, 28678199, 27068616, 25549371, 24115395, 22761902, 21484375, 20278549, 19140402, 18066133, 17052159, 16095095, 15191747, 14339099, 13534308, 12774685, 12057697, 11380951, 10742187, 10139274, 9570201, 9033066, 8526079, 8047547,
	7595873, 7169549, 6767154, 6387342, 6028848, 5690475, 5371093, 5069637, 4785100, 4516533, 4263039, 4023773, 3797936, 3584774, 3383577, 3193671, 3014424, 2845237, 2685546, 2534818, 2392550, 2258266, 2131519, 2011886, 1898968,
	1792387, 1691788, 1596835, 1507212, 1422618, 1342773, 1267409, 1196275, 1129133, 1065759, 1005943, 949484, 896193, 845894, 798417, 753606, 711309, 671386, 633704, 598137, 564566, 532879, 502971, 474742, 448096,
	422947, 399208, 376803, 355654, 335693, 316852, 299068, 282283, 266439, 251485, 237371, 224048, 211473, 199604, 188401, 177827, 167846, 158426, 149534, 141141, 133219, 125742, 118685, 112024, 105736,
	99802, 94200, 88913, 83923, 79213, 74767, 70570, 66609, 62871, 59342, 56012, 52868, 49901, 47100, 44456, 41961, 39606, 37383, 35285, 33304, 31435, 29671, 28006, 26434, 24950,
	23550, 22228, 20980, 19803, 18691, 17642, 16652, 15717, 14835, 14003, 13217, 12475, 11775, 11114, 10490, 9901, 9345, 8821, 8326, 7858, 7417, 7001, 6608, 6237, 5887,
	5557, 5245, 4950, 4672, 4410, 4163, 3929, 3708, 3500, 3304, 3118, 2943, 2778, 2622, 2475, 2336, 2205, 2081, 1964, 1854, 1750, 1652, 1559, 1471, 1389,
	1311, 1237, 1168, 1102, 1040, 982, 927, 875, 826, 779, 735, 694, 655, 618, 584, 551, 520, 491, 463, 437, 413, 389, 367, 347, 327,
	309, 292, 275, 260, 245, 231, 218, 206, 194, 183, 173, 163, 154, 146, 137, 130, 122, 115, 109, 103, 97, 91, 86, 81, 77,
	73, 68, 65, 61, 57, 54, 51, 48, 45, 43, 40, 38, 36, 34, 32, 30, 28, 27, 25, 24, 22, 21, 20, 19, 18,
	17, 16, 15, 14, 13, 12, 12, 11, 10, 10, 9, 9, 8, 8, 7, 7, 6, 6, 6, 5, 5, 5, 4, 4, 4,
	4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET_PARAMS;
    use kaspa_consensus_core::{
        config::params::{ForkActivation, Params, SIMNET_PARAMS},
        constants::SOMPI_PER_KASPA,
        network::{NetworkId, NetworkType},
        tx::scriptvec,
    };

    #[test]
    fn calc_high_bps_total_rewards_delta() {
        let legacy_cbm = create_legacy_manager();
        let pre_deflationary_rewards = legacy_cbm.pre_deflationary_phase_base_subsidy * legacy_cbm.deflationary_phase_daa_score;
        let total_rewards: u64 = pre_deflationary_rewards + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| x * SECONDS_PER_MONTH).sum::<u64>();
        let testnet_11_bps = SIMNET_PARAMS.bps();
        // Reference per-block reward for each month = firecash-scaled, BPS-rounded table value.
        let total_high_bps_rewards_rounded_up: u64 = pre_deflationary_rewards
            + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| scaled_subsidy(*x, testnet_11_bps) * testnet_11_bps * SECONDS_PER_MONTH).sum::<u64>();

        let cbm = create_manager(&SIMNET_PARAMS);
        let total_high_bps_rewards: u64 = pre_deflationary_rewards
            + cbm.subsidy_by_month_table_before.iter().map(|x| x * SECONDS_PER_MONTH * cbm.bps().before()).sum::<u64>();
        assert_eq!(total_high_bps_rewards_rounded_up, total_high_bps_rewards, "scaled subsidy adjusted to bps must match the precomputed table");

        let delta = total_high_bps_rewards as i64 - total_rewards as i64;

        println!("Total rewards: {} sompi => {} KAS", total_rewards, total_rewards / SOMPI_PER_KASPA);
        println!("Total high bps rewards: {} sompi => {} KAS", total_high_bps_rewards, total_high_bps_rewards / SOMPI_PER_KASPA);
        println!("Delta: {} sompi => {} KAS", delta, delta / SOMPI_PER_KASPA as i64);
    }

    #[test]
    fn subsidy_by_month_table_test() {
        let cbm = create_legacy_manager();
        cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
            assert_eq!(scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], 1), *x, "for 1 BPS, scaled const table and precomputed values must match");
        });

        for network_id in NetworkId::iter() {
            let cbm = create_manager(&network_id.into());
            cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], cbm.bps().before()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
            cbm.subsidy_by_month_table_after.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    scaled_subsidy(SUBSIDY_BY_MONTH_TABLE[i], cbm.bps().after()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
        }
    }

    /// Takes over 60 seconds, run with the following command line:
    /// `cargo test --release --package kaspa-consensus --lib -- processes::coinbase::tests::verify_crescendo_emission_schedule --exact --nocapture --ignored`
    #[test]
    #[ignore = "long"]
    fn verify_crescendo_emission_schedule() {
        // No need to loop over all nets since the relevant params are only
        // deflation and activation DAA scores (and the test is long anyway)
        for network_id in [NetworkId::new(NetworkType::Mainnet)] {
            let mut params: Params = network_id.into();
            params.crescendo_activation = ForkActivation::never();
            let cbm = create_manager(&params);
            let (baseline_epochs, baseline_total) = calculate_emission(cbm);

            let mut activations = vec![10000, 33444444, 120727479];
            for network_id in NetworkId::iter() {
                let activation = Params::from(network_id).crescendo_activation;
                if activation != ForkActivation::never() && activation != ForkActivation::always() {
                    activations.push(activation.daa_score());
                }
            }

            // Loop over a few random activation points + specified activation points for all nets
            for activation in activations {
                params.crescendo_activation = ForkActivation::new(activation);
                let cbm = create_manager(&params);
                let (new_epochs, new_total) = calculate_emission(cbm);

                // Epochs only represents the number of times the subsidy changed (lower after activation due to rounding)
                println!("BASELINE:\t{}\tepochs, total emission: {}", baseline_epochs, baseline_total);
                println!("CRESCENDO:\t{}\tepochs, total emission: {}, activation: {}", new_epochs, new_total, activation);

                let diff = (new_total as i64 - baseline_total as i64) / SOMPI_PER_KASPA as i64;
                assert!(diff.abs() <= 51, "activation: {}", activation);
                println!("DIFF (KAS): {}", diff);
            }
        }
    }

    fn calculate_emission(cbm: CoinbaseManager) -> (u64, u64) {
        let activation = cbm.bps().activation().daa_score();
        let mut current = 0;
        let mut total = 0;
        let mut epoch = 0u64;
        // Use the tail-free curve subsidy for finite-emission accounting: with the perpetual tail
        // floor `calc_block_subsidy` never reaches 0, so this loop would not terminate.
        let mut prev = cbm.curve_subsidy(0);
        loop {
            let subsidy = cbm.curve_subsidy(current);
            // Pre activation we expect the legacy calc (1bps)
            if current < activation {
                assert_eq!(cbm.legacy_calc_block_subsidy(current), subsidy);
            }
            if subsidy == 0 {
                break;
            }
            total += subsidy;
            if subsidy != prev {
                println!("epoch: {}, subsidy: {}", epoch, subsidy);
                prev = subsidy;
                epoch += 1;
            }
            current += 1;
        }

        (epoch, total)
    }

    #[test]
    fn subsidy_test() {
        const PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY: u64 = 50000000000;
        const DEFLATIONARY_PHASE_INITIAL_SUBSIDY: u64 = 44000000000;
        const SECONDS_PER_MONTH: u64 = 2629800;
        // firecash halves every 3 months (see SUBSIDY_HALVING_INTERVAL_MONTHS).
        const SECONDS_PER_HALVING: u64 = SECONDS_PER_MONTH * 3;

        for network_id in NetworkId::iter() {
            let mut params: Params = network_id.into();
            if params.crescendo_activation != ForkActivation::always() {
                // We test activation scenarios in verify_crescendo_emission_schedule
                params.crescendo_activation = ForkActivation::never();
            }
            let cbm = create_manager(&params);
            let bps = params.bps_history().before();

            let pre_deflationary_phase_base_subsidy = PRE_DEFLATIONARY_PHASE_BASE_SUBSIDY / bps;
            // Initial deflationary subsidy carries the firecash reward scale (see `scaled_subsidy`).
            let deflationary_phase_initial_subsidy = scaled_subsidy(DEFLATIONARY_PHASE_INITIAL_SUBSIDY, bps);
            let blocks_per_halving = SECONDS_PER_HALVING * bps;

            struct Test {
                name: &'static str,
                daa_score: u64,
                expected: u64,
            }

            let mut tests = vec![
                Test {
                    name: "first mined block",
                    daa_score: 1,
                    expected: if params.deflationary_phase_daa_score > 0 {
                        pre_deflationary_phase_base_subsidy
                    } else {
                        deflationary_phase_initial_subsidy
                    },
                },
                Test {
                    name: "start of deflationary phase",
                    daa_score: params.deflationary_phase_daa_score,
                    expected: deflationary_phase_initial_subsidy,
                },
                Test {
                    name: "after one halving",
                    daa_score: params.deflationary_phase_daa_score + blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 2,
                },
                Test {
                    name: "after 2 halvings",
                    daa_score: params.deflationary_phase_daa_score + 2 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 4,
                },
                Test {
                    name: "after 5 halvings",
                    daa_score: params.deflationary_phase_daa_score + 5 * blocks_per_halving,
                    expected: deflationary_phase_initial_subsidy / 32,
                },
                Test {
                    // Far past the tail crossover (32 halvings = month 96): the curve value here is
                    // a tiny fraction of a sompi after scaling, so the perpetual tail floor is what
                    // actually gets paid — here the final 0.3 FC floor (applied via the
                    // `.max(cbm.tail_subsidy(..))` below, which is past `TAIL_STEP_DOWN_MONTH`).
                    name: "after 32 halvings",
                    daa_score: params.deflationary_phase_daa_score + 32 * blocks_per_halving,
                    expected: scaled_subsidy(DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 2_u64.pow(32), bps),
                },
                Test {
                    name: "just before subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 35 * blocks_per_halving,
                    expected: scaled_subsidy(1, bps),
                },
                Test {
                    name: "after subsidy depleted (curve → 0, tail takes over)",
                    daa_score: params.deflationary_phase_daa_score + 36 * blocks_per_halving,
                    expected: 0,
                },
            ];

            if params.deflationary_phase_daa_score > 0 {
                tests.push(Test {
                    name: "before deflationary phase",
                    daa_score: params.deflationary_phase_daa_score - 1,
                    expected: pre_deflationary_phase_base_subsidy,
                });
            }

            for t in tests {
                // The live subsidy is floored at the two-step perpetual tail; once the curve decays
                // below the tail floor (the deep-halving cases, and even "after 5 halvings" where the
                // scaled curve is already under 0.6 FC) the tail is what actually gets paid. The floor
                // itself is time-dependent (0.6 FC before month 24, 0.3 FC after). The tail (like
                // `subsidy_month`) is only defined once the deflationary phase has started; before it,
                // the flat pre-deflationary base subsidy is paid and no tail floor applies.
                let expected_live = if t.daa_score < params.deflationary_phase_daa_score {
                    t.expected
                } else {
                    t.expected.max(cbm.tail_subsidy(t.daa_score))
                };
                assert_eq!(cbm.calc_block_subsidy(t.daa_score), expected_live, "{} test '{}' failed", network_id, t.name);
                if bps == 1 {
                    // legacy_calc_block_subsidy is the tail-free curve, so it matches the raw expectation.
                    assert_eq!(cbm.legacy_calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                }
            }
        }
    }

    #[test]
    fn payload_serialization_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3];
        let data = CoinbaseData {
            blue_score: 56,
            subsidy: 44000000000,
            // A non-trivial commitment so the round-trip actually exercises the 32 bytes.
            shielded_commitment: core::array::from_fn(|i| i as u8 ^ 0xa5),
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data as &[u8],
            },
        };

        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
        // The commitment occupies exactly 32 bytes between subsidy and the script-pub-key version.
        assert_eq!(&payload[LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY..][..32], &data.shielded_commitment);
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data, deserialized_data);
    }

    #[test]
    fn modify_payload_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3, 23, 98];
        let data = CoinbaseData {
            blue_score: 56345,
            subsidy: 44000000000,
            shielded_commitment: [0x5c; 32],
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data,
            },
        };

        let data2 = CoinbaseData {
            blue_score: data.blue_score,
            subsidy: data.subsidy,
            // The commitment is not miner data, so `modify_coinbase_payload` must preserve it.
            shielded_commitment: data.shielded_commitment,
            miner_data: MinerData {
                // Modify only miner data
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
            },
        };

        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data2, deserialized_data);
    }

    #[test]
    fn expected_coinbase_transaction_selects_version_by_toccata_activation() {
        let mut params = MAINNET_PARAMS.clone();
        params.toccata_activation = ForkActivation::new(100);
        let cbm = create_manager(&params);
        let miner_data = MinerData::new(ScriptPublicKey::new(0, scriptvec![1, 2, 3]), vec![4, 5, 6]);
        let ghostdag_data = GhostdagData::default();
        let mergeset_rewards = Default::default();
        let mergeset_non_daa = Default::default();

        let pre_activation = cbm
            .expected_coinbase_transaction(99, miner_data.clone(), &ghostdag_data, &mergeset_rewards, &mergeset_non_daa, [0u8; 32])
            .unwrap();
        let post_activation = cbm
            .expected_coinbase_transaction(100, miner_data, &ghostdag_data, &mergeset_rewards, &mergeset_non_daa, [0u8; 32])
            .unwrap();

        assert_eq!(pre_activation.tx.version, constants::TX_VERSION);
        assert_eq!(post_activation.tx.version, constants::TX_VERSION_TOCCATA);
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(
            params.coinbase_payload_script_public_key_max_len,
            params.max_coinbase_payload_len,
            params.deflationary_phase_daa_score,
            params.pre_deflationary_phase_base_subsidy,
            params.bps_history(),
            params.toccata_activation,
        )
    }

    /// Return a CoinbaseManager with legacy golang 1 BPS properties
    fn create_legacy_manager() -> CoinbaseManager {
        CoinbaseManager::new(150, 204, 15778800 - 259200, 50000000000, ForkedParam::new_const(1), ForkActivation::never())
    }
}
