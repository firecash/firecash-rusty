use crate::Hash;

#[cfg(feature = "std")]
pub use fishhash::{calculate_dataset_item_1024, FishHashContext, Hash1024, HashData, PowB3Hash, PowFishHash};

#[derive(Clone)]
pub struct PowHash([u64; 25]);

#[derive(Clone)]
pub struct KHeavyHash;

impl PowHash {
    // The initial state of `cSHAKE256("ProofOfWorkHash")`
    // [10] -> 1123092876221303310 ^ 0x04(padding byte) = 1123092876221303306
    // [16] -> 10306167911662716186 ^ 0x8000000000000000(final padding) = 1082795874807940378
    #[rustfmt::skip]
    const INITIAL_STATE: [u64; 25] = [
        1242148031264380989, 3008272977830772284, 2188519011337848018, 1992179434288343456, 8876506674959887717,
        5399642050693751366, 1745875063082670864, 8605242046444978844, 17936695144567157056, 3343109343542796272,
        1123092876221303306, 4963925045340115282, 17037383077651887893, 16629644495023626889, 12833675776649114147,
        3784524041015224902, 1082795874807940378, 13952716920571277634, 13411128033953605860, 15060696040649351053,
        9928834659948351306, 5237849264682708699, 12825353012139217522, 6706187291358897596, 196324915476054915,
    ];
    #[inline]
    pub fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        let mut start = Self::INITIAL_STATE;
        for (pre_pow_word, state_word) in pre_pow_hash.iter_le_u64().zip(start.iter_mut()) {
            *state_word ^= pre_pow_word;
        }
        start[4] ^= timestamp;
        Self(start)
    }

    #[inline(always)]
    pub fn finalize_with_nonce(mut self, nonce: u64) -> Hash {
        self.0[9] ^= nonce;
        keccak256::f1600(&mut self.0);
        Hash::from_le_u64(self.0[..4].try_into().unwrap())
    }
}

impl KHeavyHash {
    // The initial state of `cSHAKE256("HeavyHash")`
    // [4] -> 16654558671554924254 ^ 0x04(padding byte) = 16654558671554924250
    // [16] -> 9793466274154320918 ^ 0x8000000000000000(final padding) = 570094237299545110
    #[rustfmt::skip]
    const INITIAL_STATE: [u64; 25] = [
        4239941492252378377, 8746723911537738262, 8796936657246353646, 1272090201925444760, 16654558671554924250,
        8270816933120786537, 13907396207649043898, 6782861118970774626, 9239690602118867528, 11582319943599406348,
        17596056728278508070, 15212962468105129023, 7812475424661425213, 3370482334374859748, 5690099369266491460,
        8596393687355028144, 570094237299545110, 9119540418498120711, 16901969272480492857, 13372017233735502424,
        14372891883993151831, 5171152063242093102, 10573107899694386186, 6096431547456407061, 1592359455985097269,
    ];
    #[inline]
    pub fn hash(in_hash: Hash) -> Hash {
        let mut state = Self::INITIAL_STATE;
        for (pre_pow_word, state_word) in in_hash.iter_le_u64().zip(state.iter_mut()) {
            *state_word ^= pre_pow_word;
        }
        keccak256::f1600(&mut state);
        Hash::from_le_u64(state[..4].try_into().unwrap())
    }
}

// ===========================================================================
// FishHashPlus (KarlsenHashV2) — a memory-hard, ASIC-resistant, Ethash-derived
// proof-of-work. Ported from rusty-karlsen (which itself derives from the
// Iron Fish `fish-hash-plus` reference). firecash uses this instead of
// kHeavyHash so mining is GPU-centric. The "Plus" variant is the XOR-folded
// `mix_group` index derivation in the kernel (fully ASIC-resistant hardening).
//
// The light cache is ~75MB; the full dataset is ~4.6GB. Verifying nodes run in
// light mode (dataset items recomputed on the fly from the cache); only miners
// build the full dataset. The default seed matches the FishHash whitepaper.
//
// Requires std (threads, heap, timing), so the whole module is gated on `std`.
// ===========================================================================
#[cfg(feature = "std")]
mod fishhash {
use crate::Hash;
use alloc::{boxed::Box, vec, vec::Vec};
use log::info;
use std::ops::BitXor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tiny_keccak::Hasher;

const FNV_PRIME: u32 = 0x01000193;
const FULL_DATASET_ITEM_PARENTS: u32 = 512;
const NUM_DATASET_ACCESSES: u32 = 32;
const LIGHT_CACHE_ROUNDS: i32 = 3;
const LIGHT_CACHE_NUM_ITEMS: u32 = 1179641;
const FULL_DATASET_NUM_ITEMS: u32 = 37748717;

#[rustfmt::skip]
const SEED: [u8; 32] = [
    0xeb, 0x01, 0x63, 0xae, 0xf2, 0xab, 0x1c, 0x5a,
    0x66, 0x31, 0x0c, 0x1c, 0x14, 0xd6, 0x0f, 0x42,
    0x55, 0xa9, 0xb3, 0x9b, 0x0e, 0xdf, 0x26, 0x53,
    0x98, 0x44, 0xf1, 0x17, 0xad, 0x67, 0x21, 0x19,
];

const SIZE_U32: usize = std::mem::size_of::<u32>();
const SIZE_U64: usize = std::mem::size_of::<u64>();

pub trait HashData {
    fn new() -> Self;
    fn from_hash(hash: &Hash) -> Self;
    fn as_bytes(&self) -> &[u8];
    fn as_bytes_mut(&mut self) -> &mut [u8];

    #[inline(always)]
    fn get_as_u32(&self, index: usize) -> u32 {
        u32::from_le_bytes(self.as_bytes()[index * SIZE_U32..index * SIZE_U32 + SIZE_U32].try_into().unwrap())
    }

    #[inline(always)]
    fn set_as_u32(&mut self, index: usize, value: u32) {
        self.as_bytes_mut()[index * SIZE_U32..index * SIZE_U32 + SIZE_U32].copy_from_slice(&value.to_le_bytes())
    }

    #[inline(always)]
    fn get_as_u64(&self, index: usize) -> u64 {
        u64::from_le_bytes(self.as_bytes()[index * SIZE_U64..index * SIZE_U64 + SIZE_U64].try_into().unwrap())
    }

    #[inline(always)]
    fn set_as_u64(&mut self, index: usize, value: u64) {
        self.as_bytes_mut()[index * SIZE_U64..index * SIZE_U64 + SIZE_U64].copy_from_slice(&value.to_le_bytes())
    }
}

#[derive(Debug)]
pub struct Hash256([u8; 32]);

impl HashData for Hash256 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 32])
    }
    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        Self(hash.0)
    }
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Hash512([u8; 64]);

impl HashData for Hash512 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 64])
    }
    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        let mut result = Self::new();
        let (first_half, _) = result.0.split_at_mut(hash.0.len());
        first_half.copy_from_slice(&hash.0);
        result
    }
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl BitXor<&Hash512> for &Hash512 {
    type Output = Hash512;
    #[inline(always)]
    fn bitxor(self, rhs: &Hash512) -> Self::Output {
        let mut hash = Hash512::new();
        for i in 0..64 {
            hash.0[i] = self.0[i] ^ rhs.0[i]
        }
        hash
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Hash1024([u8; 128]);

impl HashData for Hash1024 {
    #[inline(always)]
    fn new() -> Self {
        Self([0; 128])
    }
    #[inline(always)]
    fn from_hash(hash: &Hash) -> Self {
        let mut result = Self::new();
        let (first_half, _) = result.0.split_at_mut(hash.0.len());
        first_half.copy_from_slice(&hash.0);
        result
    }
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline(always)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Hash1024 {
    #[inline(always)]
    fn from_512s(first: &Hash512, second: &Hash512) -> Self {
        let mut hash = Self::new();
        let (first_half, second_half) = hash.0.split_at_mut(first.0.len());
        first_half.copy_from_slice(&first.0);
        second_half.copy_from_slice(&second.0);
        hash
    }
}

/// Precomputed FishHash data. `light_cache` (~75MB) is always present and is
/// sufficient to verify (dataset items are recomputed on demand). `full_dataset`
/// (~4.6GB) is only built by miners for speed.
pub struct FishHashContext {
    light_cache: Box<[Hash512]>,
    full_dataset: Option<Box<[Hash1024]>>,
}

impl FishHashContext {
    /// Build a new context. `full` builds the ~4.6GB dataset (miner-only); nodes
    /// pass `false`. `seed` defaults to the FishHash whitepaper seed.
    pub fn new(full: bool, seed: Option<[u8; 32]>) -> Self {
        let mut light_cache = vec![Hash512::new(); LIGHT_CACHE_NUM_ITEMS as usize].into_boxed_slice();
        build_light_cache(&mut light_cache, seed.unwrap_or(SEED));

        let full_dataset = if full {
            let mut dataset = vec![Hash1024::new(); FULL_DATASET_NUM_ITEMS as usize].into_boxed_slice();
            Self::prebuild_full_dataset(&mut dataset, &light_cache, num_cpus::get());
            Some(dataset)
        } else {
            None
        };

        FishHashContext { light_cache, full_dataset }
    }

    pub fn prebuild_full_dataset(full_dataset: &mut [Hash1024], light_cache: &[Hash512], num_threads: usize) {
        info!("prebuilding fishhash dataset using {} threads", num_threads);
        let start = std::time::Instant::now();
        let total_items = full_dataset.len();
        let progress = Arc::new(AtomicUsize::new(0));
        let num_threads = num_threads.max(1);

        std::thread::scope(|scope| {
            let batch_size = full_dataset.len().div_ceil(num_threads);
            let mut threads = Vec::with_capacity(num_threads);
            for (index, chunk) in full_dataset.chunks_mut(batch_size).enumerate() {
                let start = index * batch_size;
                let progress = Arc::clone(&progress);
                threads.push(scope.spawn(move || {
                    build_dataset_segment(chunk, light_cache, start, progress, total_items);
                }));
            }
            for handle in threads {
                handle.join().unwrap();
            }
        });
        info!("prebuilding fishhash dataset done in {:.1}s", start.elapsed().as_secs_f64());
    }
}

fn build_dataset_segment(
    dataset_slice: &mut [Hash1024],
    light_cache: &[Hash512],
    start: usize,
    progress: Arc<AtomicUsize>,
    total_items: usize,
) {
    for (index, item) in dataset_slice.iter_mut().enumerate() {
        *item = calculate_dataset_item_1024(light_cache, start + index);
        let done = progress.fetch_add(1, Ordering::Relaxed) + 1;
        if done % 4_000_000 == 0 {
            info!("prebuilding fishhash dataset: {}% ({}/{})", done * 100 / total_items, done, total_items);
        }
    }
}

#[inline(always)]
fn fnv1(u: u32, v: u32) -> u32 {
    u.wrapping_mul(FNV_PRIME) ^ v
}

#[inline(always)]
fn fnv1_512(u: Hash512, v: Hash512) -> Hash512 {
    let mut r = Hash512::new();
    for i in 0..r.0.len() / SIZE_U32 {
        r.set_as_u32(i, fnv1(u.get_as_u32(i), v.get_as_u32(i)));
    }
    r
}

#[inline]
pub fn calculate_dataset_item_1024(light_cache: &[Hash512], index: usize) -> Hash1024 {
    let seed0 = (index * 2) as u32;
    let seed1 = seed0 + 1;

    let mut mix0 = light_cache[(seed0 % LIGHT_CACHE_NUM_ITEMS) as usize];
    let mut mix1 = light_cache[(seed1 % LIGHT_CACHE_NUM_ITEMS) as usize];

    let mix0_seed = mix0.get_as_u32(0) ^ seed0;
    let mix1_seed = mix1.get_as_u32(0) ^ seed1;
    mix0.set_as_u32(0, mix0_seed);
    mix1.set_as_u32(0, mix1_seed);

    keccak_in_place(&mut mix0.0);
    keccak_in_place(&mut mix1.0);

    let num_words: u32 = (std::mem::size_of_val(&mix0) / SIZE_U32) as u32;
    for j in 0..FULL_DATASET_ITEM_PARENTS {
        let t0 = fnv1(seed0 ^ j, mix0.get_as_u32((j % num_words) as usize));
        let t1 = fnv1(seed1 ^ j, mix1.get_as_u32((j % num_words) as usize));
        mix0 = fnv1_512(mix0, light_cache[(t0 % LIGHT_CACHE_NUM_ITEMS) as usize]);
        mix1 = fnv1_512(mix1, light_cache[(t1 % LIGHT_CACHE_NUM_ITEMS) as usize]);
    }

    keccak_in_place(&mut mix0.0);
    keccak_in_place(&mut mix1.0);

    Hash1024::from_512s(&mix0, &mix1)
}

#[derive(Clone)]
pub struct PowFishHash;

impl PowFishHash {
    /// The FishHashPlus kernel: seed (a 32-byte hash) → 32-byte mix hash.
    pub fn fishhashplus_kernel(seed: &Hash, context: &FishHashContext) -> Hash {
        let seed_hash512 = Hash512::from_hash(seed);
        let mut mix = Hash1024::from_512s(&seed_hash512, &seed_hash512);

        for i in 0..NUM_DATASET_ACCESSES {
            let mut mix_group: [u32; 8] = [0; 8];
            for (c, mix_group_elem) in mix_group.iter_mut().enumerate() {
                *mix_group_elem =
                    mix.get_as_u32(4 * c) ^ mix.get_as_u32(4 * c + 1) ^ mix.get_as_u32(4 * c + 2) ^ mix.get_as_u32(4 * c + 3);
            }

            let p0 = (mix_group[0] ^ mix_group[3] ^ mix_group[6]) % FULL_DATASET_NUM_ITEMS;
            let p1 = (mix_group[1] ^ mix_group[4] ^ mix_group[7]) % FULL_DATASET_NUM_ITEMS;
            let p2 = (mix_group[2] ^ mix_group[5] ^ i) % FULL_DATASET_NUM_ITEMS;

            let fetch0 = lookup(context, p0 as usize);
            let mut fetch1 = lookup(context, p1 as usize);
            let mut fetch2 = lookup(context, p2 as usize);

            for j in 0..32 {
                fetch1.set_as_u32(j, fnv1(mix.get_as_u32(j), fetch1.get_as_u32(j)));
                fetch2.set_as_u32(j, mix.get_as_u32(j) ^ fetch2.get_as_u32(j));
            }

            for j in 0..16 {
                mix.set_as_u64(j, fetch0.get_as_u64(j).wrapping_mul(fetch1.get_as_u64(j)).wrapping_add(fetch2.get_as_u64(j)));
            }
        }

        // Collapse the 1024-bit mix into 32 bytes.
        let mut mix_hash = Hash256::new();
        let num_words = std::mem::size_of_val(&mix) / SIZE_U32;
        for i in (0..num_words).step_by(4) {
            let h1 = fnv1(mix.get_as_u32(i), mix.get_as_u32(i + 1));
            let h2 = fnv1(h1, mix.get_as_u32(i + 2));
            let h3 = fnv1(h2, mix.get_as_u32(i + 3));
            mix_hash.set_as_u32(i / 4, h3);
        }

        Hash::from_bytes(mix_hash.0)
    }
}

#[inline]
fn lookup(context: &FishHashContext, index: usize) -> Hash1024 {
    match &context.full_dataset {
        Some(dataset) => dataset[index],
        None => calculate_dataset_item_1024(&context.light_cache, index),
    }
}

fn build_light_cache(cache: &mut [Hash512], seed: [u8; 32]) {
    let mut item: Hash512 = Hash512::new();
    keccak(&mut item.0, &seed);
    cache[0] = item;

    for cache_item in cache.iter_mut().take(LIGHT_CACHE_NUM_ITEMS as usize).skip(1) {
        keccak_in_place(&mut item.0);
        *cache_item = item;
    }

    for _ in 0..LIGHT_CACHE_ROUNDS {
        for i in 0..LIGHT_CACHE_NUM_ITEMS {
            let t: u32 = cache[i as usize].get_as_u32(0);
            let v: u32 = t % LIGHT_CACHE_NUM_ITEMS;
            let w: u32 = (LIGHT_CACHE_NUM_ITEMS.wrapping_add(i.wrapping_sub(1))) % LIGHT_CACHE_NUM_ITEMS;
            let x = &cache[v as usize] ^ &cache[w as usize];
            keccak(&mut cache[i as usize].0, &x.0);
        }
    }
}

/// Keccak-512 (legacy, 0x01 padding — matches tiny-keccak `v512`).
#[inline(always)]
pub fn keccak(out: &mut [u8], data: &[u8]) {
    let mut hasher = tiny_keccak::Keccak::v512();
    hasher.update(data);
    hasher.finalize(out);
}

#[inline(always)]
pub fn keccak_in_place(data: &mut [u8]) {
    let mut hasher = tiny_keccak::Keccak::v512();
    hasher.update(data);
    hasher.finalize(data);
}

/// Blake3-based PoW hasher used by the FishHashPlus wiring (KarlsenHashV2): the
/// pre-hash absorbs PRE_POW_HASH || TIME || 32 zero bytes || NONCE, and the
/// same primitive is reused for the final wrap of the kernel output.
#[derive(Clone)]
pub struct PowB3Hash {
    hasher: blake3::Hasher,
}

impl PowB3Hash {
    #[inline(always)]
    pub fn new(pre_pow_hash: Hash, timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pre_pow_hash.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&[0u8; 32]);
        Self { hasher }
    }

    #[inline(always)]
    pub fn finalize_with_nonce(mut self, nonce: u64) -> Hash {
        self.hasher.update(&nonce.to_le_bytes());
        Hash::from_bytes(*self.hasher.finalize().as_bytes())
    }

    #[inline(always)]
    pub fn hash(input_hash: Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input_hash.as_bytes());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}
} // mod fishhash

mod keccak256 {
    #[cfg(any(not(target_arch = "x86_64"), feature = "no-asm"))]
    #[inline(always)]
    pub(super) fn f1600(state: &mut [u64; 25]) {
        keccak::f1600(state);
    }

    #[cfg(all(target_arch = "x86_64", not(feature = "no-asm")))]
    #[inline(always)]
    pub(super) fn f1600(state: &mut [u64; 25]) {
        unsafe extern "C" {
            fn KeccakF1600(state: &mut [u64; 25]);
        }
        unsafe { KeccakF1600(state) }
    }
}

#[cfg(test)]
mod tests {
    use super::{KHeavyHash, PowHash};
    use crate::Hash;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{CShake256, CShake256Core};

    const PROOF_OF_WORK_DOMAIN: &[u8] = b"ProofOfWorkHash";
    const HEAVY_HASH_DOMAIN: &[u8] = b"HeavyHash";

    #[test]
    fn test_pow_hash() {
        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash([42; 32]);
        let hasher = PowHash::new(pre_pow_hash, timestamp);
        let hash1 = hasher.finalize_with_nonce(nonce);

        let hasher = CShake256::from_core(CShake256Core::new(PROOF_OF_WORK_DOMAIN))
            .chain(pre_pow_hash.0)
            .chain(timestamp.to_le_bytes())
            .chain([0u8; 32])
            .chain(nonce.to_le_bytes());
        let mut hash2 = [0u8; 32];
        hasher.finalize_xof().read(&mut hash2);
        assert_eq!(Hash(hash2), hash1);
    }

    #[test]
    fn test_heavy_hash() {
        let val = Hash([42; 32]);
        let hash1 = KHeavyHash::hash(val);

        let hasher = CShake256::from_core(CShake256Core::new(HEAVY_HASH_DOMAIN)).chain(val.0);
        let mut hash2 = [0u8; 32];
        hasher.finalize_xof().read(&mut hash2);
        assert_eq!(Hash(hash2), hash1);
    }

    // FishHashPlus (KarlsenHashV2) known-answer tests. Vectors are taken verbatim
    // from rusty-karlsen; a match proves this port is byte-for-byte identical to
    // the reference implementation.
    use super::{FishHashContext, PowB3Hash, PowFishHash};

    #[test]
    fn test_powb3hash() {
        let timestamp: u64 = 5435345234;
        let nonce: u64 = 432432432;
        let pre_pow_hash = Hash::from_bytes([42; 32]);
        let hash1 = PowB3Hash::new(pre_pow_hash, timestamp).finalize_with_nonce(nonce);

        #[rustfmt::skip]
        let expected = [
            0xf0, 0xaf, 0xbc, 0xd9, 0x40, 0x1f, 0x24, 0xcf, 0x83, 0x74, 0x41, 0x8e, 0x39, 0x1e, 0x14, 0x58,
            0xa6, 0xdf, 0x76, 0x45, 0x44, 0x1d, 0xd5, 0xdc, 0x9c, 0xfe, 0x8d, 0xc9, 0xe7, 0x61, 0xe6, 0x7d,
        ];
        assert_eq!(hash1.as_bytes(), expected, "PowB3Hash output changed!");
    }

    #[test]
    fn test_powfishhash() {
        // Light context (~75MB, a few seconds to build) is enough to verify.
        let context = FishHashContext::new(false, None);
        #[rustfmt::skip]
        let input_hash = Hash::from_bytes([
            0xf0, 0xaf, 0xbc, 0xd9, 0x40, 0x1f, 0x24, 0xcf, 0x83, 0x74, 0x41, 0x8e, 0x39, 0x1e, 0x14, 0x58,
            0xa6, 0xdf, 0x76, 0x45, 0x44, 0x1d, 0xd5, 0xdc, 0x9c, 0xfe, 0x8d, 0xc9, 0xe7, 0x61, 0xe6, 0x7d,
        ]);
        let out = PowFishHash::fishhashplus_kernel(&input_hash, &context);
        #[rustfmt::skip]
        let expected = [
            0xf5, 0x7e, 0x96, 0xfd, 0x7f, 0xef, 0x6a, 0xcc, 0xc5, 0xda, 0xac, 0xc9, 0xea, 0xa1, 0xd0, 0x12,
            0xf9, 0x14, 0x5d, 0xa6, 0x14, 0x88, 0xd8, 0x84, 0xa8, 0xfa, 0x4c, 0xe6, 0xb5, 0x72, 0x88, 0xbe,
        ];
        assert_eq!(out.as_bytes(), expected, "FishHash output changed!");

        // Full three-step KarlsenHashV2: pre-hash → kernel → final blake3 wrap.
        let final_hash = PowB3Hash::hash(out);
        #[rustfmt::skip]
        let expected_final = [
            0x71, 0xe8, 0xa7, 0xff, 0x50, 0xf4, 0xeb, 0xa6, 0x7f, 0xbf, 0x00, 0xaf, 0x44, 0x9c, 0x12, 0xe6,
            0xe7, 0x4b, 0x1e, 0xdf, 0xc1, 0x57, 0x7b, 0x59, 0xc4, 0x1c, 0x77, 0x92, 0x2e, 0x54, 0x6f, 0x87,
        ];
        assert_eq!(final_hash.as_bytes(), expected_final, "final KarlsenHashV2 output changed!");
    }
}
