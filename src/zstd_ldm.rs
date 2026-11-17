//! Long-distance matching: a port of `lib/compress/zstd_ldm.c` of zstd v1.5.7, as the
//! compressor uses it on its own (for the optimal strategies when the window is 128 MB or
//! more), with no dictionary.
//!
//! Before each block is compressed, it splits the source where a rolling hash of the last
//! bytes ("gear" hash) has its top bits clear, keeps the place of each split in a table by
//! the XXH64 hash of the bytes before it, and where a split's bytes are there before, makes
//! a match of them, as long as it goes both ways. The optimal parser takes those matches as
//! candidates of its own.

// (The arithmetic is written as the original has it.)
#![allow(clippy::implicit_saturating_sub, clippy::manual_is_multiple_of)]

use super::common::{read32, read64};
use super::zstd_compress::{
    CompressionParameters, HASH_READ_SIZE, RawSeq, Window, ZSTD_WINDOW_START_INDEX, count,
};

const LDM_BUCKET_SIZE_LOG: u32 = 4;
const LDM_MIN_MATCH_LENGTH: u32 = 64;
const ZSTD_LDM_BUCKETSIZELOG_MAX: u32 = 8;
const ZSTD_HASHLOG_MIN: u32 = 6;
const ZSTD_HASHLOG_MAX: u32 = 30;
/// `LDM_BATCH_SIZE`: the most splits worked on at once.
const LDM_BATCH_SIZE: usize = 64;

/// `ZSTD_ldm_gearTab`.
#[rustfmt::skip]
const GEAR_TAB: [u64; 256] = [
    0xf5b8f72c5f77775c, 0x84935f266b7ac412, 0xb647ada9ca730ccc, 0xb065bb4b114fb1de,
    0x34584e7e8c3a9fd0, 0x4e97e17c6ae26b05, 0x3a03d743bc99a604, 0xcecd042422c4044f,
    0x76de76c58524259e, 0x9c8528f65badeaca, 0x86563706e2097529, 0x2902475fa375d889,
    0xafb32a9739a5ebe6, 0xce2714da3883e639, 0x21eaf821722e69e, 0x37b628620b628,
    0x49a8d455d88caf5, 0x8556d711e6958140, 0x4f7ae74fc605c1f, 0x829f0c3468bd3a20,
    0x4ffdc885c625179e, 0x8473de048a3daf1b, 0x51008822b05646b2, 0x69d75d12b2d1cc5f,
    0x8c9d4a19159154bc, 0xc3cc10f4abbd4003, 0xd06ddc1cecb97391, 0xbe48e6e7ed80302e,
    0x3481db31cee03547, 0xacc3f67cdaa1d210, 0x65cb771d8c7f96cc, 0x8eb27177055723dd,
    0xc789950d44cd94be, 0x934feadc3700b12b, 0x5e485f11edbdf182, 0x1e2e2a46fd64767a,
    0x2969ca71d82efa7c, 0x9d46e9935ebbba2e, 0xe056b67e05e6822b, 0x94d73f55739d03a0,
    0xcd7010bdb69b5a03, 0x455ef9fcd79b82f4, 0x869cb54a8749c161, 0x38d1a4fa6185d225,
    0xb475166f94bbe9bb, 0xa4143548720959f1, 0x7aed4780ba6b26ba, 0xd0ce264439e02312,
    0x84366d746078d508, 0xa8ce973c72ed17be, 0x21c323a29a430b01, 0x9962d617e3af80ee,
    0xab0ce91d9c8cf75b, 0x530e8ee6d19a4dbc, 0x2ef68c0cf53f5d72, 0xc03a681640a85506,
    0x496e4e9f9c310967, 0x78580472b59b14a0, 0x273824c23b388577, 0x66bf923ad45cb553,
    0x47ae1a5a2492ba86, 0x35e304569e229659, 0x4765182a46870b6f, 0x6cbab625e9099412,
    0xddac9a2e598522c1, 0x7172086e666624f2, 0xdf5003ca503b7837, 0x88c0c1db78563d09,
    0x58d51865acfc289d, 0x177671aec65224f1, 0xfb79d8a241e967d7, 0x2be1e101cad9a49a,
    0x6625682f6e29186b, 0x399553457ac06e50, 0x35dffb4c23abb74, 0x429db2591f54aade,
    0xc52802a8037d1009, 0x6acb27381f0b25f3, 0xf45e2551ee4f823b, 0x8b0ea2d99580c2f7,
    0x3bed519cbcb4e1e1, 0xff452823dbb010a, 0x9d42ed614f3dd267, 0x5b9313c06257c57b,
    0xa114b8008b5e1442, 0xc1fe311c11c13d4b, 0x66e8763ea34c5568, 0x8b982af1c262f05d,
    0xee8876faaa75fbb7, 0x8a62a4d0d172bb2a, 0xc13d94a3b7449a97, 0x6dbbba9dc15d037c,
    0xc786101f1d92e0f1, 0xd78681a907a0b79b, 0xf61aaf2962c9abb9, 0x2cfd16fcd3cb7ad9,
    0x868c5b6744624d21, 0x25e650899c74ddd7, 0xba042af4a7c37463, 0x4eb1a539465a3eca,
    0xbe09dbf03b05d5ca, 0x774e5a362b5472ba, 0x47a1221229d183cd, 0x504b0ca18ef5a2df,
    0xdffbdfbde2456eb9, 0x46cd2b2fbee34634, 0xf2aef8fe819d98c3, 0x357f5276d4599d61,
    0x24a5483879c453e3, 0x88026889192b4b9, 0x28da96671782dbec, 0x4ef37c40588e9aaa,
    0x8837b90651bc9fb3, 0xc164f741d3f0e5d6, 0xbc135a0a704b70ba, 0x69cd868f7622ada,
    0xbc37ba89e0b9c0ab, 0x47c14a01323552f6, 0x4f00794bacee98bb, 0x7107de7d637a69d5,
    0x88af793bb6f2255e, 0xf3c6466b8799b598, 0xc288c616aa7f3b59, 0x81ca63cf42fca3fd,
    0x88d85ace36a2674b, 0xd056bd3792389e7, 0xe55c396c4e9dd32d, 0xbefb504571e6c0a6,
    0x96ab32115e91e8cc, 0xbf8acb18de8f38d1, 0x66dae58801672606, 0x833b6017872317fb,
    0xb87c16f2d1c92864, 0xdb766a74e58b669c, 0x89659f85c61417be, 0xc8daad856011ea0c,
    0x76a4b565b6fe7eae, 0xa469d085f6237312, 0xaaf0365683a3e96c, 0x4dbb746f8424f7b8,
    0x638755af4e4acc1, 0x3d7807f5bde64486, 0x17be6d8f5bbb7639, 0x903f0cd44dc35dc,
    0x67b672eafdf1196c, 0xa676ff93ed4c82f1, 0x521d1004c5053d9d, 0x37ba9ad09ccc9202,
    0x84e54d297aacfb51, 0xa0b4b776a143445, 0x820d471e20b348e, 0x1874383cb83d46dc,
    0x97edeec7a1efe11c, 0xb330e50b1bdc42aa, 0x1dd91955ce70e032, 0xa514cdb88f2939d5,
    0x2791233fd90db9d3, 0x7b670a4cc50f7a9b, 0x77c07d2a05c6dfa5, 0xe3778b6646d0a6fa,
    0xb39c8eda47b56749, 0x933ed448addbef28, 0xaf846af6ab7d0bf4, 0xe5af208eb666e49,
    0x5e6622f73534cd6a, 0x297daeca42ef5b6e, 0x862daef3d35539a6, 0xe68722498f8e1ea9,
    0x981c53093dc0d572, 0xfa09b0bfbf86fbf5, 0x30b1e96166219f15, 0x70e7d466bdc4fb83,
    0x5a66736e35f2a8e9, 0xcddb59d2b7c1baef, 0xd6c7d247d26d8996, 0xea4e39eac8de1ba3,
    0x539c8bb19fa3aff2, 0x9f90e4c5fd508d8, 0xa34e5956fbaf3385, 0x2e2f8e151d3ef375,
    0x173691e9b83faec1, 0xb85a8d56bf016379, 0x8382381267408ae3, 0xb90f901bbdc0096d,
    0x7c6ad32933bcec65, 0x76bb5e2f2c8ad595, 0x390f851a6cf46d28, 0xc3e6064da1c2da72,
    0xc52a0c101cfa5389, 0xd78eaf84a3fbc530, 0x3781b9e2288b997e, 0x73c2f6dea83d05c4,
    0x4228e364c5b5ed7, 0x9d7a3edf0da43911, 0x8edcfeda24686756, 0x5e7667a7b7a9b3a1,
    0x4c4f389fa143791d, 0xb08bc1023da7cddc, 0x7ab4be3ae529b1cc, 0x754e6132dbe74ff9,
    0x71635442a839df45, 0x2f6fb1643fbe52de, 0x961e0a42cf7a8177, 0xf3b45d83d89ef2ea,
    0xee3de4cf4a6e3e9b, 0xcd6848542c3295e7, 0xe4cee1664c78662f, 0x9947548b474c68c4,
    0x25d73777a5ed8b0b, 0xc915b1d636b7fc, 0x21c2ba75d9b0d2da, 0x5f6b5dcf608a64a1,
    0xdcf333255ff9570c, 0x633b922418ced4ee, 0xc136dde0b004b34a, 0x58cc83b05d4b2f5a,
    0x5eb424dda28e42d2, 0x62df47369739cd98, 0xb4e0b42485e4ce17, 0x16e1f0c1f9a8d1e7,
    0x8ec3916707560ebf, 0x62ba6e2df2cc9db3, 0xcbf9f4ff77d83a16, 0x78d9d7d07d2bbcc4,
    0xef554ce1e02c41f4, 0x8d7581127eccf94d, 0xa9b53336cb3c8a05, 0x38c42c0bf45c4f91,
    0x640893cdf4488863, 0x80ec34bc575ea568, 0x39f324f5b48eaa40, 0xe9d9ed1f8eff527f,
    0x9224fc058cc5a214, 0xbaba00b04cfe7741, 0x309a9f120fcf52af, 0xa558f3ec65626212,
    0x424bec8b7adabe2f, 0x41622513a6aea433, 0xb88da2d5324ca798, 0xd287733b245528a4,
    0x9a44697e6d68aec3, 0x7b1093be2f49bb28, 0x50bbec632e3d8aad, 0x6cd90723e1ea8283,
    0x897b9e7431b02bf3, 0x219efdcb338a7047, 0x3b0311f0a27c0656, 0xdb17bf91c0db96e7,
    0x8cd4fd6b4e85a5b2, 0xfab071054ba6409d, 0x40d6fe831fa9dfd9, 0xaf358debad7d791e,
    0xeb8d0e25a65e3e58, 0xbbcbd3df14e08580, 0xcf751f27ecdab2b, 0x2b4da14f2613d8f4,
];

/// `XXH64`, of `input` with `seed`.
pub(crate) fn xxh64(input: &[u8], seed: u64) -> u64 {
    const P1: u64 = 0x9E3779B185EBCA87;
    const P2: u64 = 0xC2B2AE3D27D4EB4F;
    const P3: u64 = 0x165667B19E3779F9;
    const P4: u64 = 0x85EBCA77C2B2AE63;
    const P5: u64 = 0x27D4EB2F165667C5;
    fn round(acc: u64, input: u64) -> u64 {
        acc.wrapping_add(input.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    }
    fn merge_round(acc: u64, val: u64) -> u64 {
        (acc ^ round(0, val)).wrapping_mul(P1).wrapping_add(P4)
    }
    let len = input.len();
    let mut p = 0usize;
    let mut h64;
    if len >= 32 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);
        while p + 32 <= len {
            v1 = round(v1, read64(input, p));
            v2 = round(v2, read64(input, p + 8));
            v3 = round(v3, read64(input, p + 16));
            v4 = round(v4, read64(input, p + 24));
            p += 32;
        }
        h64 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h64 = merge_round(h64, v1);
        h64 = merge_round(h64, v2);
        h64 = merge_round(h64, v3);
        h64 = merge_round(h64, v4);
    } else {
        h64 = seed.wrapping_add(P5);
    }
    h64 = h64.wrapping_add(len as u64);
    while p + 8 <= len {
        let k1 = round(0, read64(input, p));
        h64 ^= k1;
        h64 = h64.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        p += 8;
    }
    if p + 4 <= len {
        h64 ^= u64::from(read32(input, p)).wrapping_mul(P1);
        h64 = h64.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        p += 4;
    }
    while p < len {
        h64 ^= u64::from(input[p]).wrapping_mul(P5);
        h64 = h64.rotate_left(11).wrapping_mul(P1);
        p += 1;
    }
    // avalanche
    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(P2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(P3);
    h64 ^= h64 >> 32;
    h64
}

/// `ldmParams_t`, as `ZSTD_ldm_adjustParameters` makes them of the compression parameters.
#[derive(Clone, Copy)]
pub(crate) struct LdmParams {
    pub(crate) window_log: u32,
    pub(crate) hash_log: u32,
    pub(crate) bucket_size_log: u32,
    pub(crate) min_match_length: u32,
    pub(crate) hash_rate_log: u32,
}

impl LdmParams {
    /// `ZSTD_ldm_adjustParameters`, from parameters of none of their own.
    pub(crate) fn new(cparams: &CompressionParameters) -> LdmParams {
        let window_log = cparams.window_log;
        let strategy = cparams.strategy as u32;
        // mapping from [fast, rate7] to [btultra2, rate4]
        let hash_rate_log = 7 - (strategy / 3);
        let hash_log = window_log
            .saturating_sub(hash_rate_log)
            .clamp(ZSTD_HASHLOG_MIN, ZSTD_HASHLOG_MAX);
        let mut min_match_length = LDM_MIN_MATCH_LENGTH;
        if strategy >= 8 {
            // ZSTD_btultra
            min_match_length /= 2;
        }
        let bucket_size_log = strategy
            .clamp(LDM_BUCKET_SIZE_LOG, ZSTD_LDM_BUCKETSIZELOG_MAX)
            .min(hash_log);
        LdmParams {
            window_log,
            hash_log,
            bucket_size_log,
            min_match_length,
            hash_rate_log,
        }
    }
}

/// `ldmEntry_t`.
#[derive(Clone, Copy, Default)]
struct LdmEntry {
    offset: u32,
    checksum: u32,
}

/// `ldmRollingHashState_t`.
struct RollingHashState {
    rolling: u64,
    stop_mask: u64,
}

impl RollingHashState {
    /// `ZSTD_ldm_gear_init`: a state that honors the settings in `params`.
    fn new(params: &LdmParams) -> RollingHashState {
        let max_bits_in_mask = params.min_match_length.min(64);
        let hash_rate_log = params.hash_rate_log;
        // The choice of the splitting criterion is subject to two conditions:
        //   1. it has to trigger on average every 2^(hashRateLog) bytes;
        //   2. ideally, it has to depend on a window of minMatchLength bytes.
        // In the gear hash algorithm, bit n depends on the last n bytes; so in order to
        // obtain a good quality splitting criterion it is preferable to use bits with high
        // weight. To match condition 1 we use a mask with hashRateLog bits set and, because
        // of the previous remark, we make sure these bits have the highest possible weight
        // while still respecting condition 2.
        let stop_mask = if hash_rate_log > 0 && hash_rate_log <= max_bits_in_mask {
            ((1u64 << hash_rate_log) - 1) << (max_bits_in_mask - hash_rate_log)
        } else {
            // In this degenerate case we simply honor the hash rate.
            (1u64 << hash_rate_log) - 1
        };
        RollingHashState {
            rolling: u64::from(!0u32),
            stop_mask,
        }
    }

    // (`ZSTD_ldm_gear_reset` works out a hash of the bytes it is given and keeps nothing of
    // it: it leaves the state as it is.)

    /// `ZSTD_ldm_gear_feed`: the split points found in `data` into `splits`, until all of it
    /// is hashed or there are `LDM_BATCH_SIZE` of them. The answer is how many bytes were
    /// hashed.
    fn feed(
        &mut self,
        data: &[u8],
        splits: &mut [usize; LDM_BATCH_SIZE],
        num_splits: &mut usize,
    ) -> usize {
        let mut hash = self.rolling;
        let mask = self.stop_mask;
        let mut n = 0;
        while n < data.len() {
            hash = (hash << 1).wrapping_add(GEAR_TAB[data[n] as usize]);
            n += 1;
            if hash & mask == 0 {
                splits[*num_splits] = n;
                *num_splits += 1;
                if *num_splits == LDM_BATCH_SIZE {
                    break;
                }
            }
        }
        self.rolling = hash;
        n
    }
}

/// A source too long for the table of matches the original makes room for
/// (`ERROR(dstSize_tooSmall)`).
#[derive(Debug)]
pub(crate) struct OutOfSequences;

/// `ldmState_t`.
pub(crate) struct LdmState {
    pub(crate) params: LdmParams,
    window: Window,
    hash_table: Vec<LdmEntry>,
    bucket_offsets: Vec<u8>,
    /// `maxNbLdmSequences`: the most matches a block can have.
    pub(crate) max_nb_seq: usize,
}

impl LdmState {
    /// The state `ZSTD_resetCCtx_internal` makes, for blocks of up to `block_size` bytes.
    pub(crate) fn new(cparams: &CompressionParameters, block_size: usize) -> LdmState {
        let params = LdmParams::new(cparams);
        let num_buckets = 1usize << (params.hash_log - params.bucket_size_log);
        LdmState {
            params,
            // (`ZSTD_window_init`, then `ZSTD_window_update` with the source.)
            window: Window {
                base: ZSTD_WINDOW_START_INDEX,
                dict_limit: ZSTD_WINDOW_START_INDEX,
                low_limit: ZSTD_WINDOW_START_INDEX,
            },
            hash_table: vec![LdmEntry::default(); 1usize << params.hash_log],
            bucket_offsets: vec![0; num_buckets],
            max_nb_seq: block_size / params.min_match_length as usize,
        }
    }

    /// `ZSTD_ldm_insertEntry`: insert the entry with corresponding hash into the hash table.
    fn insert_entry(&mut self, hash: usize, entry: LdmEntry) {
        let bucket_size_log = self.params.bucket_size_log;
        let offset = self.bucket_offsets[hash] as usize;
        self.hash_table[(hash << bucket_size_log) + offset] = entry;
        self.bucket_offsets[hash] = ((offset + 1) & ((1usize << bucket_size_log) - 1)) as u8;
    }

    /// `ZSTD_ldm_generateSequences_internal`: the matches of the chunk
    /// `src[istart..istart + src_size]` onto `sequences`. The answer is the size of the
    /// literals after the last.
    fn generate_sequences_internal(
        &mut self,
        sequences: &mut Vec<RawSeq>,
        src: &[u8],
        istart: usize,
        src_size: usize,
    ) -> Result<usize, OutOfSequences> {
        // LDM parameters
        let min_match_length = self.params.min_match_length as usize;
        let ents_per_bucket = 1usize << self.params.bucket_size_log;
        let h_bits = self.params.hash_log - self.params.bucket_size_log;
        // Prefix parameters (there is no extDict)
        let dict_limit = self.window.dict_limit;
        let lowest_index = dict_limit;
        let base = self.window.base as usize;
        let low_prefix_ptr = dict_limit as usize - base;
        // Input bounds
        let iend = istart + src_size;
        let ilimit = iend as isize - HASH_READ_SIZE as isize;
        // Input positions
        let mut anchor = istart;
        let mut ip = istart;
        // Arrays for staged-processing
        let mut splits = [0usize; LDM_BATCH_SIZE];
        let mut candidates = [(0usize, 0usize, 0u32); LDM_BATCH_SIZE]; // split, hash, checksum

        if src_size < min_match_length {
            return Ok(iend - anchor);
        }

        // Initialize the rolling hash state with the first minMatchLength bytes.
        let mut hash_state = RollingHashState::new(&self.params);
        ip += min_match_length;

        while (ip as isize) < ilimit {
            let mut num_splits = 0usize;
            let hashed = hash_state.feed(&src[ip..ilimit as usize], &mut splits, &mut num_splits);

            for n in 0..num_splits {
                let split = ip + splits[n] - min_match_length;
                let xxhash = xxh64(&src[split..split + min_match_length], 0);
                let hash = (xxhash as u32 & ((1u32 << h_bits) - 1)) as usize;
                candidates[n] = (split, hash, (xxhash >> 32) as u32);
            }

            for &(split, hash, checksum) in &candidates[..num_splits] {
                let mut forward_match_length = 0usize;
                let mut best_match_length = 0usize;
                let mut best_entry: Option<LdmEntry> = None;
                let bucket = hash << self.params.bucket_size_log;
                let new_entry = LdmEntry {
                    offset: (split + base) as u32,
                    checksum,
                };

                // If a split point would generate a sequence overlapping with the previous
                // one, we merely register it in the hash table and move on.
                if split < anchor {
                    self.insert_entry(hash, new_entry);
                    continue;
                }

                let mut backward_match_length = 0usize;
                for cur in &self.hash_table[bucket..bucket + ents_per_bucket] {
                    if cur.checksum != checksum || cur.offset <= lowest_index {
                        continue;
                    }
                    let p_match = cur.offset as usize - base;
                    let cur_forward_match_length = count(src, split, p_match, iend);
                    if cur_forward_match_length < min_match_length {
                        continue;
                    }
                    // `ZSTD_ldm_countBackwardsMatch`.
                    let cur_backward_match_length = {
                        let (mut p_in, mut p_match) = (split, p_match);
                        let mut match_length = 0usize;
                        while p_in > anchor
                            && p_match > low_prefix_ptr
                            && src[p_in - 1] == src[p_match - 1]
                        {
                            p_in -= 1;
                            p_match -= 1;
                            match_length += 1;
                        }
                        match_length
                    };
                    let cur_total_match_length =
                        cur_forward_match_length + cur_backward_match_length;

                    if cur_total_match_length > best_match_length {
                        best_match_length = cur_total_match_length;
                        forward_match_length = cur_forward_match_length;
                        backward_match_length = cur_backward_match_length;
                        best_entry = Some(*cur);
                    }
                }

                // No match found -- insert an entry into the hash table and process the next
                // candidate match.
                let Some(best_entry) = best_entry else {
                    self.insert_entry(hash, new_entry);
                    continue;
                };

                // Match found
                let offset = (split + base) as u32 - best_entry.offset;
                let m_length = forward_match_length + backward_match_length;
                {
                    // Out of sequence storage
                    if sequences.len() == self.max_nb_seq {
                        return Err(OutOfSequences);
                    }
                    sequences.push(RawSeq {
                        lit_length: (split - backward_match_length - anchor) as u32,
                        match_length: m_length as u32,
                        offset,
                    });
                }

                // Insert the current entry into the hash table --- it must be done after the
                // previous block to avoid clobbering bestEntry.
                self.insert_entry(hash, new_entry);

                anchor = split + forward_match_length;

                // If we find a match that ends after the data that we've hashed then we have
                // a repeating, overlapping, pattern. E.g. all zeros. If one repetition of the
                // pattern matches our `stopMask` then all repetitions will. We don't need to
                // insert them all into out table, only the first one. So skip over
                // overlapping matches. This is a major speed boost (20x) for compressing a
                // single byte repeated, when that byte ends up in the table.
                if anchor > ip + hashed {
                    // (`ZSTD_ldm_gear_reset`, which changes nothing.)
                    // Continue the outer loop at anchor (ip + hashed == anchor).
                    ip = anchor - hashed;
                    break;
                }
            }

            ip += hashed;
        }

        Ok(iend - anchor)
    }

    /// `ZSTD_ldm_generateSequences`: the long-distance matches of the block
    /// `src[istart..istart + src_size]`, in `sequences`.
    pub(crate) fn generate_sequences(
        &mut self,
        sequences: &mut Vec<RawSeq>,
        src: &[u8],
        istart: usize,
        src_size: usize,
    ) -> Result<(), OutOfSequences> {
        let max_dist = 1u32 << self.params.window_log;
        let iend = istart + src_size;
        const K_MAX_CHUNK_SIZE: usize = 1 << 20;
        let nb_chunks =
            (src_size / K_MAX_CHUNK_SIZE) + usize::from(src_size % K_MAX_CHUNK_SIZE != 0);
        let mut leftover_size = 0usize;

        // The input could be very large (in zstdmt), so it must be broken up into chunks to
        // enforce the maximum distance and handle overflow correction.
        let mut chunk = 0;
        while chunk < nb_chunks && sequences.len() < self.max_nb_seq {
            let chunk_start = istart + chunk * K_MAX_CHUNK_SIZE;
            let remaining = iend - chunk_start;
            let chunk_end = if remaining < K_MAX_CHUNK_SIZE {
                iend
            } else {
                chunk_start + K_MAX_CHUNK_SIZE
            };
            let chunk_size = chunk_end - chunk_start;
            let prev_size = sequences.len();

            // 1. (Overflow correction: the indices of a source this port takes stay far from
            // where they would need to be brought down.)
            // 2. We enforce the maximum offset allowed (`ZSTD_window_enforceMaxDist`, with no
            // dictionary).
            {
                let block_end_idx = (chunk_end + self.window.base as usize) as u32;
                if block_end_idx > max_dist {
                    let new_low_limit = block_end_idx - max_dist;
                    if self.window.low_limit < new_low_limit {
                        self.window.low_limit = new_low_limit;
                    }
                    if self.window.dict_limit < self.window.low_limit {
                        self.window.dict_limit = self.window.low_limit;
                    }
                }
            }
            // 3. Generate the sequences for the chunk, and get newLeftoverSize.
            let new_leftover_size =
                self.generate_sequences_internal(sequences, src, chunk_start, chunk_size)?;
            // 4. We add the leftover literals from previous iterations to the first newly
            // generated sequence, or add the `newLeftoverSize` if none are generated.
            if prev_size < sequences.len() {
                sequences[prev_size].lit_length += leftover_size as u32;
                leftover_size = new_leftover_size;
            } else {
                leftover_size += chunk_size;
            }
            chunk += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::xxh64;

    #[test]
    fn xxh64_gives_the_known_hashes() {
        assert_eq!(xxh64(b"", 0), 0xEF46DB3751D8E999);
        assert_eq!(xxh64(b"a", 0), 0xD24EC4F1A98C6E5B);
        assert_eq!(xxh64(b"abc", 0), 0x44BC2CF5AD770999);
        assert_eq!(
            xxh64(b"Nobody inspects the spammish repetition", 0),
            0xFBCEA83C8A378BF1
        );
    }
}
