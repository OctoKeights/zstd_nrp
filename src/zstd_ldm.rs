//! Long-distance matching: a port of `lib/compress/zstd_ldm.c` of zstd v1.5.7, as the
//! compressor uses it on its own (for the optimal strategies when the window is 128 MB or
//! more), with no dictionary.
//!
//! Before each block is compressed, it splits the source where a rolling hash of the last
//! bytes ("gear" hash) has its top bits clear, keeps the place of each split in a table by
//! the XXH64 hash of the bytes before it, and where a split's bytes are there before, makes
//! a match of them, as long as it goes both ways. The optimal parser takes those matches as
//! candidates of its own.

use alloc::vec;
use alloc::vec::Vec;

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
    0xf5b8_f72c_5f77_775c, 0x8493_5f26_6b7a_c412, 0xb647_ada9_ca73_0ccc, 0xb065_bb4b_114f_b1de,
    0x3458_4e7e_8c3a_9fd0, 0x4e97_e17c_6ae2_6b05, 0x3a03_d743_bc99_a604, 0xcecd_0424_22c4_044f,
    0x76de_76c5_8524_259e, 0x9c85_28f6_5bad_eaca, 0x8656_3706_e209_7529, 0x2902_475f_a375_d889,
    0xafb3_2a97_39a5_ebe6, 0xce27_14da_3883_e639, 0x021e_af82_1722_e69e, 0x0003_7b62_8620_b628,
    0x049a_8d45_5d88_caf5, 0x8556_d711_e695_8140, 0x04f7_ae74_fc60_5c1f, 0x829f_0c34_68bd_3a20,
    0x4ffd_c885_c625_179e, 0x8473_de04_8a3d_af1b, 0x5100_8822_b056_46b2, 0x69d7_5d12_b2d1_cc5f,
    0x8c9d_4a19_1591_54bc, 0xc3cc_10f4_abbd_4003, 0xd06d_dc1c_ecb9_7391, 0xbe48_e6e7_ed80_302e,
    0x3481_db31_cee0_3547, 0xacc3_f67c_daa1_d210, 0x65cb_771d_8c7f_96cc, 0x8eb2_7177_0557_23dd,
    0xc789_950d_44cd_94be, 0x934f_eadc_3700_b12b, 0x5e48_5f11_edbd_f182, 0x1e2e_2a46_fd64_767a,
    0x2969_ca71_d82e_fa7c, 0x9d46_e993_5ebb_ba2e, 0xe056_b67e_05e6_822b, 0x94d7_3f55_739d_03a0,
    0xcd70_10bd_b69b_5a03, 0x455e_f9fc_d79b_82f4, 0x869c_b54a_8749_c161, 0x38d1_a4fa_6185_d225,
    0xb475_166f_94bb_e9bb, 0xa414_3548_7209_59f1, 0x7aed_4780_ba6b_26ba, 0xd0ce_2644_39e0_2312,
    0x8436_6d74_6078_d508, 0xa8ce_973c_72ed_17be, 0x21c3_23a2_9a43_0b01, 0x9962_d617_e3af_80ee,
    0xab0c_e91d_9c8c_f75b, 0x530e_8ee6_d19a_4dbc, 0x2ef6_8c0c_f53f_5d72, 0xc03a_6816_40a8_5506,
    0x496e_4e9f_9c31_0967, 0x7858_0472_b59b_14a0, 0x2738_24c2_3b38_8577, 0x66bf_923a_d45c_b553,
    0x47ae_1a5a_2492_ba86, 0x35e3_0456_9e22_9659, 0x4765_182a_4687_0b6f, 0x6cba_b625_e909_9412,
    0xddac_9a2e_5985_22c1, 0x7172_086e_6666_24f2, 0xdf50_03ca_503b_7837, 0x88c0_c1db_7856_3d09,
    0x58d5_1865_acfc_289d, 0x1776_71ae_c652_24f1, 0xfb79_d8a2_41e9_67d7, 0x2be1_e101_cad9_a49a,
    0x6625_682f_6e29_186b, 0x3995_5345_7ac0_6e50, 0x035d_ffb4_c23a_bb74, 0x429d_b259_1f54_aade,
    0xc528_02a8_037d_1009, 0x6acb_2738_1f0b_25f3, 0xf45e_2551_ee4f_823b, 0x8b0e_a2d9_9580_c2f7,
    0x3bed_519c_bcb4_e1e1, 0x0ff4_5282_3dbb_010a, 0x9d42_ed61_4f3d_d267, 0x5b93_13c0_6257_c57b,
    0xa114_b800_8b5e_1442, 0xc1fe_311c_11c1_3d4b, 0x66e8_763e_a34c_5568, 0x8b98_2af1_c262_f05d,
    0xee88_76fa_aa75_fbb7, 0x8a62_a4d0_d172_bb2a, 0xc13d_94a3_b744_9a97, 0x6dbb_ba9d_c15d_037c,
    0xc786_101f_1d92_e0f1, 0xd786_81a9_07a0_b79b, 0xf61a_af29_62c9_abb9, 0x2cfd_16fc_d3cb_7ad9,
    0x868c_5b67_4462_4d21, 0x25e6_5089_9c74_ddd7, 0xba04_2af4_a7c3_7463, 0x4eb1_a539_465a_3eca,
    0xbe09_dbf0_3b05_d5ca, 0x774e_5a36_2b54_72ba, 0x47a1_2212_29d1_83cd, 0x504b_0ca1_8ef5_a2df,
    0xdffb_dfbd_e245_6eb9, 0x46cd_2b2f_bee3_4634, 0xf2ae_f8fe_819d_98c3, 0x357f_5276_d459_9d61,
    0x24a5_4838_79c4_53e3, 0x0880_2688_9192_b4b9, 0x28da_9667_1782_dbec, 0x4ef3_7c40_588e_9aaa,
    0x8837_b906_51bc_9fb3, 0xc164_f741_d3f0_e5d6, 0xbc13_5a0a_704b_70ba, 0x069c_d868_f762_2ada,
    0xbc37_ba89_e0b9_c0ab, 0x47c1_4a01_3235_52f6, 0x4f00_794b_acee_98bb, 0x7107_de7d_637a_69d5,
    0x88af_793b_b6f2_255e, 0xf3c6_466b_8799_b598, 0xc288_c616_aa7f_3b59, 0x81ca_63cf_42fc_a3fd,
    0x88d8_5ace_36a2_674b, 0x0d05_6bd3_7923_89e7, 0xe55c_396c_4e9d_d32d, 0xbefb_5045_71e6_c0a6,
    0x96ab_3211_5e91_e8cc, 0xbf8a_cb18_de8f_38d1, 0x66da_e588_0167_2606, 0x833b_6017_8723_17fb,
    0xb87c_16f2_d1c9_2864, 0xdb76_6a74_e58b_669c, 0x8965_9f85_c614_17be, 0xc8da_ad85_6011_ea0c,
    0x76a4_b565_b6fe_7eae, 0xa469_d085_f623_7312, 0xaaf0_3656_83a3_e96c, 0x4dbb_746f_8424_f7b8,
    0x0638_755a_f4e4_acc1, 0x3d78_07f5_bde6_4486, 0x17be_6d8f_5bbb_7639, 0x0903_f0cd_44dc_35dc,
    0x67b6_72ea_fdf1_196c, 0xa676_ff93_ed4c_82f1, 0x521d_1004_c505_3d9d, 0x37ba_9ad0_9ccc_9202,
    0x84e5_4d29_7aac_fb51, 0x0a0b_4b77_6a14_3445, 0x0820_d471_e20b_348e, 0x1874_383c_b83d_46dc,
    0x97ed_eec7_a1ef_e11c, 0xb330_e50b_1bdc_42aa, 0x1dd9_1955_ce70_e032, 0xa514_cdb8_8f29_39d5,
    0x2791_233f_d90d_b9d3, 0x7b67_0a4c_c50f_7a9b, 0x77c0_7d2a_05c6_dfa5, 0xe377_8b66_46d0_a6fa,
    0xb39c_8eda_47b5_6749, 0x933e_d448_addb_ef28, 0xaf84_6af6_ab7d_0bf4, 0x0e5a_f208_eb66_6e49,
    0x5e66_22f7_3534_cd6a, 0x297d_aeca_42ef_5b6e, 0x862d_aef3_d355_39a6, 0xe687_2249_8f8e_1ea9,
    0x981c_5309_3dc0_d572, 0xfa09_b0bf_bf86_fbf5, 0x30b1_e961_6621_9f15, 0x70e7_d466_bdc4_fb83,
    0x5a66_736e_35f2_a8e9, 0xcddb_59d2_b7c1_baef, 0xd6c7_d247_d26d_8996, 0xea4e_39ea_c8de_1ba3,
    0x539c_8bb1_9fa3_aff2, 0x09f9_0e4c_5fd5_08d8, 0xa34e_5956_fbaf_3385, 0x2e2f_8e15_1d3e_f375,
    0x1736_91e9_b83f_aec1, 0xb85a_8d56_bf01_6379, 0x8382_3812_6740_8ae3, 0xb90f_901b_bdc0_096d,
    0x7c6a_d329_33bc_ec65, 0x76bb_5e2f_2c8a_d595, 0x390f_851a_6cf4_6d28, 0xc3e6_064d_a1c2_da72,
    0xc52a_0c10_1cfa_5389, 0xd78e_af84_a3fb_c530, 0x3781_b9e2_288b_997e, 0x73c2_f6de_a83d_05c4,
    0x0422_8e36_4c5b_5ed7, 0x9d7a_3edf_0da4_3911, 0x8edc_feda_2468_6756, 0x5e76_67a7_b7a9_b3a1,
    0x4c4f_389f_a143_791d, 0xb08b_c102_3da7_cddc, 0x7ab4_be3a_e529_b1cc, 0x754e_6132_dbe7_4ff9,
    0x7163_5442_a839_df45, 0x2f6f_b164_3fbe_52de, 0x961e_0a42_cf7a_8177, 0xf3b4_5d83_d89e_f2ea,
    0xee3d_e4cf_4a6e_3e9b, 0xcd68_4854_2c32_95e7, 0xe4ce_e166_4c78_662f, 0x9947_548b_474c_68c4,
    0x25d7_3777_a5ed_8b0b, 0x00c9_15b1_d636_b7fc, 0x21c2_ba75_d9b0_d2da, 0x5f6b_5dcf_608a_64a1,
    0xdcf3_3325_5ff9_570c, 0x633b_9224_18ce_d4ee, 0xc136_dde0_b004_b34a, 0x58cc_83b0_5d4b_2f5a,
    0x5eb4_24dd_a28e_42d2, 0x62df_4736_9739_cd98, 0xb4e0_b424_85e4_ce17, 0x16e1_f0c1_f9a8_d1e7,
    0x8ec3_9167_0756_0ebf, 0x62ba_6e2d_f2cc_9db3, 0xcbf9_f4ff_77d8_3a16, 0x78d9_d7d0_7d2b_bcc4,
    0xef55_4ce1_e02c_41f4, 0x8d75_8112_7ecc_f94d, 0xa9b5_3336_cb3c_8a05, 0x38c4_2c0b_f45c_4f91,
    0x6408_93cd_f448_8863, 0x80ec_34bc_575e_a568, 0x39f3_24f5_b48e_aa40, 0xe9d9_ed1f_8eff_527f,
    0x9224_fc05_8cc5_a214, 0xbaba_00b0_4cfe_7741, 0x309a_9f12_0fcf_52af, 0xa558_f3ec_6562_6212,
    0x424b_ec8b_7ada_be2f, 0x4162_2513_a6ae_a433, 0xb88d_a2d5_324c_a798, 0xd287_733b_2455_28a4,
    0x9a44_697e_6d68_aec3, 0x7b10_93be_2f49_bb28, 0x50bb_ec63_2e3d_8aad, 0x6cd9_0723_e1ea_8283,
    0x897b_9e74_31b0_2bf3, 0x219e_fdcb_338a_7047, 0x3b03_11f0_a27c_0656, 0xdb17_bf91_c0db_96e7,
    0x8cd4_fd6b_4e85_a5b2, 0xfab0_7105_4ba6_409d, 0x40d6_fe83_1fa9_dfd9, 0xaf35_8deb_ad7d_791e,
    0xeb8d_0e25_a65e_3e58, 0xbbcb_d3df_14e0_8580, 0x0cf7_51f2_7ecd_ab2b, 0x2b4d_a14f_2613_d8f4,
];

/// `XXH64`, of `input` with `seed`.
pub(crate) fn xxh64(input: &[u8], seed: u64) -> u64 {
    const P1: u64 = 0x9E37_79B1_85EB_CA87;
    const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const P3: u64 = 0x1656_67B1_9E37_79F9;
    const P4: u64 = 0x85EB_CA77_C2B2_AE63;
    const P5: u64 = 0x27D4_EB2F_1656_67C5;
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

/// Streaming `XXH64` state, producing the exact same digest as [`xxh64`].
#[cfg(feature = "std")]
#[derive(Clone)]
pub(crate) struct Xxh64State {
    total_len: u64,
    seed: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    buf: [u8; 32],
    buf_len: usize,
}

#[cfg(feature = "std")]
impl Xxh64State {
    const P1: u64 = 0x9E37_79B1_85EB_CA87;
    const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const P3: u64 = 0x1656_67B1_9E37_79F9;
    const P4: u64 = 0x85EB_CA77_C2B2_AE63;
    const P5: u64 = 0x27D4_EB2F_1656_67C5;

    #[inline]
    fn round(acc: u64, input: u64) -> u64 {
        acc.wrapping_add(input.wrapping_mul(Self::P2))
            .rotate_left(31)
            .wrapping_mul(Self::P1)
    }

    #[inline]
    fn merge_round(acc: u64, val: u64) -> u64 {
        (acc ^ Self::round(0, val))
            .wrapping_mul(Self::P1)
            .wrapping_add(Self::P4)
    }

    pub(crate) fn new(seed: u64) -> Self {
        Self {
            total_len: 0,
            seed,
            v1: seed.wrapping_add(Self::P1).wrapping_add(Self::P2),
            v2: seed.wrapping_add(Self::P2),
            v3: seed,
            v4: seed.wrapping_sub(Self::P1),
            buf: [0; 32],
            buf_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        if self.buf_len + input.len() < 32 {
            self.buf[self.buf_len..self.buf_len + input.len()].copy_from_slice(input);
            self.buf_len += input.len();
            return;
        }
        if self.buf_len > 0 {
            let take = 32 - self.buf_len;
            self.buf[self.buf_len..32].copy_from_slice(&input[..take]);
            let block = self.buf;
            self.v1 = Self::round(self.v1, read64(&block, 0));
            self.v2 = Self::round(self.v2, read64(&block, 8));
            self.v3 = Self::round(self.v3, read64(&block, 16));
            self.v4 = Self::round(self.v4, read64(&block, 24));
            self.buf_len = 0;
            input = &input[take..];
        }
        let mut p = 0usize;
        while p + 32 <= input.len() {
            self.v1 = Self::round(self.v1, read64(input, p));
            self.v2 = Self::round(self.v2, read64(input, p + 8));
            self.v3 = Self::round(self.v3, read64(input, p + 16));
            self.v4 = Self::round(self.v4, read64(input, p + 24));
            p += 32;
        }
        let rem = &input[p..];
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    pub(crate) fn finish(&self) -> u64 {
        let mut h64 = if self.total_len >= 32 {
            let mut acc = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));
            acc = Self::merge_round(acc, self.v1);
            acc = Self::merge_round(acc, self.v2);
            acc = Self::merge_round(acc, self.v3);
            acc = Self::merge_round(acc, self.v4);
            acc
        } else {
            self.seed.wrapping_add(Self::P5)
        };
        h64 = h64.wrapping_add(self.total_len);
        let tail = &self.buf[..self.buf_len];
        let mut p = 0usize;
        while p + 8 <= tail.len() {
            let k1 = Self::round(0, read64(tail, p));
            h64 ^= k1;
            h64 = h64
                .rotate_left(27)
                .wrapping_mul(Self::P1)
                .wrapping_add(Self::P4);
            p += 8;
        }
        if p + 4 <= tail.len() {
            h64 ^= u64::from(read32(tail, p)).wrapping_mul(Self::P1);
            h64 = h64
                .rotate_left(23)
                .wrapping_mul(Self::P2)
                .wrapping_add(Self::P3);
            p += 4;
        }
        while p < tail.len() {
            h64 ^= u64::from(tail[p]).wrapping_mul(Self::P5);
            h64 = h64.rotate_left(11).wrapping_mul(Self::P1);
            p += 1;
        }
        h64 ^= h64 >> 33;
        h64 = h64.wrapping_mul(Self::P2);
        h64 ^= h64 >> 29;
        h64 = h64.wrapping_mul(Self::P3);
        h64 ^= h64 >> 32;
        h64
    }
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
        const K_MAX_CHUNK_SIZE: usize = 1 << 20;
        let max_dist = 1u32 << self.params.window_log;
        let iend = istart + src_size;
        let nb_chunks = src_size.div_ceil(K_MAX_CHUNK_SIZE);
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
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
        assert_eq!(
            xxh64(b"Nobody inspects the spammish repetition", 0),
            0xFBCE_A83C_8A37_8BF1
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn streaming_xxh64_matches_oneshot_for_all_chunk_sizes() {
        use super::Xxh64State;
        let data: alloc::vec::Vec<u8> = (0..300u32).map(|i| (i.wrapping_mul(37)) as u8).collect();
        for len in [0, 1, 3, 4, 7, 8, 15, 31, 32, 33, 63, 64, 65, 129, 300] {
            let expected = xxh64(&data[..len], 0);
            for step in [1, 2, 5, 7, 16, 31, 32, 33, 64] {
                let mut state = Xxh64State::new(0);
                for chunk in data[..len].chunks(step) {
                    state.update(chunk);
                }
                assert_eq!(state.finish(), expected, "len={len}, step={step}");
            }
        }
    }
}
