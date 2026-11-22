//! Bytes to a Zstandard frame: a port of part of `lib/compress/zstd_compress.c` and
//! `lib/compress/zstd_compress_internal.h` of zstd v1.5.7, the compressor that the `zstd`
//! program and libzstd are.
//!
//! [`compress`] gives the bytes that `ZSTD_compress` gives for the same source and level,
//! into an output of `ZSTD_compressBound` bytes, as a 64-bit build has it. What is ported
//! is the path of that one call: one frame from a source that is all there, with the size
//! of the content in its header, no checksum and no dictionary.
//!
//! Every level is ported, with the nine strategies the original has for finding matches:
//! `ZSTD_fast` and `ZSTD_dfast` (`zstd_fast`, `zstd_double_fast`), the greedy and lazy ones
//! with their hash chains, rows and binary tree (`zstd_lazy`), and the optimal ones
//! (`zstd_opt`); with what the slower ones take besides: the splitting of a block in two
//! where the estimates say that comes out smaller, and long-distance matching
//! (`zstd_ldm`) for a window of 128 MB or more.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use super::clevels::{ZSTD_CLEVEL_DEFAULT, ZSTD_DEFAULT_CPARAMETERS, ZSTD_MAX_CLEVEL};
use super::common::{
    CError, CResult, highbit32, is_rle, read16, read32, read64, write_le24, write_le32,
};
use super::fse_compress::FseCTable;
use super::hist;
use super::huf_compress::{HufCompressTables, HufRepeat};
use super::zstd_compress_literals::{
    HufCTables, LiteralOptions, build_block_entropy_stats_literals, compress_literals,
    estimate_block_size_literal,
};
use super::zstd_compress_sequences::{
    self as sequences, CodedSymbols, FseRepeat, LITERAL_LENGTHS, LL_FSE_LOG, MATCH_LENGTHS, MAX_LL,
    MAX_ML, MAX_OFF, MAX_SEQ, ML_FSE_LOG, OFF_FSE_LOG, OFFSETS, SymbolType, TableState,
};
use super::zstd_double_fast::compress_block_double_fast;
use super::zstd_fast::compress_block_fast;
use super::zstd_lazy::{SearchMethod, compress_block_lazy};
use super::zstd_ldm::LdmState;
use super::zstd_opt::{compress_block_btultra2, compress_block_opt};
use super::zstd_presplit::split_block;
use super::{CompressError, Level};

// From `lib/zstd.h` and `lib/common/zstd_internal.h`.
const ZSTD_MAGICNUMBER: u32 = 0xFD2F_B528;
const ZSTD_WINDOWLOG_MAX: u32 = 31;
const ZSTD_WINDOWLOG_ABSOLUTEMIN: u32 = 10;
const ZSTD_HASHLOG_MIN: u32 = 6;
const ZSTD_BLOCKSIZE_MAX: usize = 1 << 17;
const ZSTD_TARGETLENGTH_MAX: i32 = ZSTD_BLOCKSIZE_MAX as i32;
const ZSTD_FRAMEHEADERSIZE_MAX: usize = 18;
const ZSTD_BLOCK_HEADER_SIZE: usize = 3;
const MIN_CBLOCK_SIZE: usize = 1 /* litCSize */ + 1 /* RLE or RAW */;
const MINMATCH: usize = 3;
const LONGNBSEQ: usize = 0x7F00;
const BT_RAW: u32 = 0;
const BT_RLE: u32 = 1;
const BT_COMPRESSED: u32 = 2;

/// `SymbolEncodingType_e`: how a table of a block comes.
pub(crate) const SET_BASIC: u32 = 0;
pub(crate) const SET_RLE: u32 = 1;
pub(crate) const SET_COMPRESSED: u32 = 2;
pub(crate) const SET_REPEAT: u32 = 3;

// From `lib/compress/zstd_compress_internal.h`.
pub(crate) const K_SEARCH_STRENGTH: u32 = 8;
pub(crate) const HASH_READ_SIZE: usize = 8;
const ZSTD_HASHLOG3_MAX: u32 = 17;
/// The index of the first byte of a source: indices 0 and 1 are kept for "no match".
pub(crate) const ZSTD_WINDOW_START_INDEX: u32 = 2;
const ZSTD_REP_NUM: u32 = 3;
pub(crate) const REPCODE1_TO_OFFBASE: u32 = 1;
const REP_START_VALUE: [u32; 3] = [1, 4, 8];
const SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO: usize = 20;

/// `OFFSET_TO_OFFBASE`.
#[inline]
pub(crate) fn offset_to_offbase(offset: u32) -> u32 {
    offset + ZSTD_REP_NUM
}

/// `ZSTD_strategy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Strategy {
    Fast = 1,
    Dfast = 2,
    Greedy = 3,
    Lazy = 4,
    Lazy2 = 5,
    Btlazy2 = 6,
    Btopt = 7,
    Btultra = 8,
    Btultra2 = 9,
}

/// `ZSTD_compressionParameters`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompressionParameters {
    /// The largest match distance: a larger one compresses more and uses more memory.
    pub(crate) window_log: u32,
    /// For `ZSTD_dfast`, the size of the table of short matches.
    pub(crate) chain_log: u32,
    /// The size of the table of matches.
    pub(crate) hash_log: u32,
    /// For the strategies that search: how hard to search.
    pub(crate) search_log: u32,
    /// Matches shorter than this are not looked for.
    pub(crate) min_match: u32,
    /// For `ZSTD_fast`, the acceleration; for the optimal strategies, the length of a match
    /// that is good enough to be taken at once.
    pub(crate) target_length: u32,
    pub(crate) strategy: Strategy,
}

/// `ZSTD_COMPRESSBOUND`: the most bytes a frame can take for a source of `src_size` bytes,
/// saturating at [`usize::MAX`] on overflow.
///
/// It is what [`compress`] gives its output to start with, as the bytes depend on the room
/// there is in a few places. Use [`checked_compress_bound`] to detect arithmetic overflow.
#[must_use]
pub const fn compress_bound(src_size: usize) -> usize {
    let margin = if src_size < (128 << 10) {
        ((128 << 10) - src_size) >> 11
    } else {
        0
    };
    src_size
        .saturating_add(src_size >> 8)
        .saturating_add(margin)
}

/// Checked version of [`compress_bound`]: returns `None` if computing the worst-case bound
/// overflows `usize`.
#[must_use]
pub const fn checked_compress_bound(src_size: usize) -> Option<usize> {
    let margin = if src_size < (128 << 10) {
        ((128 << 10) - src_size) >> 11
    } else {
        0
    };
    match src_size.checked_add(src_size >> 8) {
        Some(sum) => sum.checked_add(margin),
        None => None,
    }
}

/// Options for compressing a Zstandard frame with [`compress_with_options`] or
/// [`Compressor::compress_with_options`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CompressOptions {
    /// Compression level (defaults to [`Level::DEFAULT`]).
    pub level: Level,
    /// Whether to write the 32-bit `XXH64` content checksum at the end of the frame
    /// (defaults to `false`, matching `ZSTD_compress`).
    pub checksum: bool,
    /// Whether to record the uncompressed content size in the frame header
    /// (defaults to `true`, matching `ZSTD_compress`).
    pub include_content_size: bool,
}

impl Default for CompressOptions {
    fn default() -> Self {
        CompressOptions {
            level: Level::DEFAULT,
            checksum: false,
            include_content_size: true,
        }
    }
}

impl CompressOptions {
    /// Options at `level` with default framing (`checksum: false`,
    /// `include_content_size: true`).
    #[must_use]
    pub const fn new(level: Level) -> Self {
        CompressOptions {
            level,
            checksum: false,
            include_content_size: true,
        }
    }

    /// Sets the compression [`Level`].
    #[must_use]
    pub const fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Sets whether to write the 32-bit `XXH64` content checksum trailer.
    #[must_use]
    pub const fn with_checksum(mut self, checksum: bool) -> Self {
        self.checksum = checksum;
        self
    }

    /// Sets whether to write `Frame_Content_Size` in the frame header.
    #[must_use]
    pub const fn with_content_size(mut self, include_content_size: bool) -> Self {
        self.include_content_size = include_content_size;
        self
    }
}

/// `ZSTD_adjustCParams_internal`, for a source of a known size and no dictionary: the
/// tables are not made larger than the source can use.
fn adjust_cparams_internal(
    mut c_par: CompressionParameters,
    src_size: u64,
) -> CompressionParameters {
    const HASH_SIZE_MIN: u32 = 1 << ZSTD_HASHLOG_MIN;
    const MAX_WINDOW_RESIZE: u64 = 1 << (ZSTD_WINDOWLOG_MAX - 1);

    // Resize windowLog if the input is small enough, to use less memory.
    if src_size <= MAX_WINDOW_RESIZE {
        let t_size = src_size as u32;
        let src_log = if t_size < HASH_SIZE_MIN {
            ZSTD_HASHLOG_MIN
        } else {
            highbit32(t_size - 1) + 1
        };
        if c_par.window_log > src_log {
            c_par.window_log = src_log;
        }
    }
    {
        let dict_and_window_log = c_par.window_log;
        // `ZSTD_cycleLog`.
        let cycle_log =
            c_par.chain_log - u32::from(c_par.strategy as u32 >= Strategy::Btlazy2 as u32);
        if c_par.hash_log > dict_and_window_log + 1 {
            c_par.hash_log = dict_and_window_log + 1;
        }
        if cycle_log > dict_and_window_log {
            c_par.chain_log -= cycle_log - dict_and_window_log;
        }
    }

    if c_par.window_log < ZSTD_WINDOWLOG_ABSOLUTEMIN {
        // minimum wlog required for valid frame header
        c_par.window_log = ZSTD_WINDOWLOG_ABSOLUTEMIN;
    }

    // (The original then keeps the hash log of the strategies that search by rows under a
    // limit that no row of the table of levels reaches.)

    c_par
}

/// `ZSTD_getCParams_internal`, for a source of a known size and no dictionary: the
/// parameters of a level.
pub(crate) fn get_cparams_internal(
    compression_level: i32,
    src_size_hint: u64,
) -> CompressionParameters {
    let r_size = src_size_hint;
    let table_id = usize::from(r_size <= 256 * 1024)
        + usize::from(r_size <= 128 * 1024)
        + usize::from(r_size <= 16 * 1024);

    // Row.
    let row = if compression_level == 0 {
        ZSTD_CLEVEL_DEFAULT // 0 == default
    } else {
        // (Entry 0 is the baseline for the negative levels' fast mode.)
        compression_level.clamp(0, ZSTD_MAX_CLEVEL)
    };

    let (window_log, chain_log, hash_log, search_log, min_match, target_length, strategy) =
        ZSTD_DEFAULT_CPARAMETERS[table_id][row as usize];
    let mut cp = CompressionParameters {
        window_log,
        chain_log,
        hash_log,
        search_log,
        min_match,
        target_length,
        strategy,
    };
    // Acceleration factor.
    if compression_level < 0 {
        // `ZSTD_minCLevel` is `-ZSTD_TARGETLENGTH_MAX`.
        let clamped_compression_level = compression_level.max(-ZSTD_TARGETLENGTH_MAX);
        cp.target_length = (-clamped_compression_level) as u32;
    }
    // Refine parameters based on srcSize.
    adjust_cparams_internal(cp, src_size_hint)
}

/// `ZSTD_minGain`: what a block has to save to be kept compressed.
pub(crate) fn min_gain(src_size: usize, strat: Strategy) -> usize {
    let minlog = if strat as u32 >= Strategy::Btultra as u32 {
        strat as u32 - 1
    } else {
        6
    };
    (src_size >> minlog) + 2
}

/// `ZSTD_LLcode`: the code of a literals length.
pub(crate) fn ll_code(lit_length: u32) -> u32 {
    #[rustfmt::skip]
    const LL_CODE: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
        22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    ];
    const LL_DELTA_CODE: u32 = 19;
    if lit_length > 63 {
        highbit32(lit_length) + LL_DELTA_CODE
    } else {
        u32::from(LL_CODE[lit_length as usize])
    }
}

/// `ZSTD_MLcode`: the code of a match length less `MINMATCH`.
pub(crate) fn ml_code(ml_base: u32) -> u32 {
    #[rustfmt::skip]
    const ML_CODE: [u8; 128] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
        38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
        41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    const ML_DELTA_CODE: u32 = 36;
    if ml_base > 127 {
        highbit32(ml_base) + ML_DELTA_CODE
    } else {
        u32::from(ML_CODE[ml_base as usize])
    }
}

/// `SeqDef`: a sequence as the block compressors leave it.
#[derive(Clone, Copy)]
pub(crate) struct SeqDef {
    /// The offset plus `ZSTD_REP_NUM`, or 1 to 3 for a repeat offset.
    pub(crate) off_base: u32,
    pub(crate) lit_length: u16,
    /// The match length less `MINMATCH`.
    pub(crate) ml_base: u16,
}

/// `ZSTD_longLengthType_e`: which of the two lengths of one sequence does not fit 16 bits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LongLengthType {
    None,
    LiteralLength,
    MatchLength,
}

/// `SeqStore_t`: the sequences and the literals of one block.
pub(crate) struct SeqStore {
    sequences: Vec<SeqDef>,
    lit: Vec<u8>,
    ll_code: Vec<u8>,
    ml_code: Vec<u8>,
    of_code: Vec<u8>,
    long_length_type: LongLengthType,
    /// The index of the sequence to apply the long length to.
    long_length_pos: u32,
}

impl SeqStore {
    fn new() -> SeqStore {
        SeqStore {
            sequences: Vec::new(),
            lit: Vec::new(),
            ll_code: Vec::new(),
            ml_code: Vec::new(),
            of_code: Vec::new(),
            long_length_type: LongLengthType::None,
            long_length_pos: 0,
        }
    }

    /// How many sequences there are.
    pub(crate) fn nb_sequences(&self) -> usize {
        self.sequences.len()
    }

    /// `ZSTD_resetSeqStore`.
    pub(crate) fn reset(&mut self) {
        self.lit.clear();
        self.sequences.clear();
        self.long_length_type = LongLengthType::None;
    }

    /// `ZSTD_storeSeq`: one sequence, with its `lit_length` literals from `src[literals..]`.
    #[inline]
    pub(crate) fn store_seq(
        &mut self,
        src: &[u8],
        literals: usize,
        lit_length: usize,
        off_base: u32,
        match_length: usize,
    ) {
        // Copy the literals.
        self.lit
            .extend_from_slice(&src[literals..literals + lit_length]);

        // `ZSTD_storeSeqOnly`.
        // Literal length.
        if lit_length > 0xFFFF {
            self.long_length_type = LongLengthType::LiteralLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        // Match length.
        let ml_base = match_length - MINMATCH;
        if ml_base > 0xFFFF {
            self.long_length_type = LongLengthType::MatchLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        self.sequences.push(SeqDef {
            off_base,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
    }

    /// The whole of the store, as a chunk.
    fn whole(&self) -> SeqChunk {
        SeqChunk {
            seq_start: 0,
            seq_end: self.sequences.len(),
            lit_start: 0,
            lit_end: self.lit.len(),
            long_length_type: self.long_length_type,
            long_length_pos: self.long_length_pos,
        }
    }

    /// `ZSTD_seqToCodes`: the codes of the lengths and offsets of the sequences of a chunk,
    /// in the store's tables of codes at the chunk's place.
    fn seq_to_codes(&mut self, chunk: &SeqChunk) {
        // (Room for one more: a chunk can have its long length just past its end.)
        let room = self.sequences.len() + 1;
        for table in [&mut self.ll_code, &mut self.of_code, &mut self.ml_code] {
            if table.len() < room {
                table.resize(room, 0);
            }
        }
        for (i, seq) in self.sequences[chunk.seq_start..chunk.seq_end]
            .iter()
            .enumerate()
        {
            self.ll_code[chunk.seq_start + i] = ll_code(u32::from(seq.lit_length)) as u8;
            self.of_code[chunk.seq_start + i] = highbit32(seq.off_base) as u8;
            self.ml_code[chunk.seq_start + i] = ml_code(u32::from(seq.ml_base)) as u8;
        }
        if chunk.long_length_type == LongLengthType::LiteralLength {
            self.ll_code[chunk.seq_start + chunk.long_length_pos as usize] = MAX_LL as u8;
        }
        if chunk.long_length_type == LongLengthType::MatchLength {
            self.ml_code[chunk.seq_start + chunk.long_length_pos as usize] = MAX_ML as u8;
        }
    }
}

/// A part of a sequence store, as the block splitter makes one (`ZSTD_deriveSeqStoreChunk`):
/// a range of its sequences and of its literals, and where its long length is.
#[derive(Clone, Copy)]
struct SeqChunk {
    seq_start: usize,
    seq_end: usize,
    lit_start: usize,
    lit_end: usize,
    long_length_type: LongLengthType,
    /// From the start of the chunk.
    long_length_pos: u32,
}

impl SeqChunk {
    fn nb_seq(&self) -> usize {
        self.seq_end - self.seq_start
    }
}

/// `ZSTD_window_t`. The source is one piece and there is no dictionary, so what the
/// original keeps as pointers comes to this: a byte of the source at `pos` has the index
/// `pos + base`. (`base` is `ZSTD_WINDOW_START_INDEX`, but for `ZSTD_btultra2`, which after a
/// first pass over the first block moves it on by the size of the block.)
pub(crate) struct Window {
    /// The index of the first byte of the source.
    pub(crate) base: u32,
    /// Below this index is the dictionary; there is none, and this only moves up with
    /// `low_limit`.
    pub(crate) dict_limit: u32,
    /// Below this index no match is valid.
    pub(crate) low_limit: u32,
}

/// `ZSTD_MatchState_t`.
pub(crate) struct MatchState {
    pub(crate) window: Window,
    /// The index of the end of a dictionary: 0, there is none.
    pub(crate) loaded_dict_end: u32,
    /// The index from which to continue the table update.
    pub(crate) next_to_update: u32,
    pub(crate) hash_table: Vec<u32>,
    /// For `ZSTD_dfast`, the table of short matches; for the strategies that search a hash
    /// chain, the chain; for those that search a binary tree, the tree.
    pub(crate) chain_table: Vec<u32>,
    /// For the optimal parser with matches of three bytes, a table of their hashes.
    pub(crate) hash_table3: Vec<u32>,
    pub(crate) hash_log3: u32,
    /// For the strategies that search by rows: a byte of each hash ("tag") for each entry of
    /// the hash table, the first of each row being the row's head.
    pub(crate) tag_table: Vec<u8>,
    pub(crate) row_hash_log: u32,
    pub(crate) hash_salt: u64,
    pub(crate) hash_cache: [u32; ZSTD_ROW_HASH_CACHE_SIZE],
    /// Whether the lazy strategies have stopped inserting every position.
    pub(crate) lazy_skipping: bool,
    /// What the optimal parser keeps from block to block.
    pub(crate) opt: OptState,
    pub(crate) cparams: CompressionParameters,
}

/// `rawSeq`: a match the long-distance matcher found, with the literals before it.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct RawSeq {
    /// The offset of the match.
    pub(crate) offset: u32,
    /// The literals before it.
    pub(crate) lit_length: u32,
    /// The length of the match: 0 for the literals at the end of a block.
    pub(crate) match_length: u32,
}

/// `RawSeqStore_t`: the matches of the long-distance matcher, and how far they are used.
#[derive(Clone, Copy, Default)]
pub(crate) struct RawSeqPos {
    /// The sequence that is being used.
    pub(crate) pos: usize,
    /// How far into it: its literals, then its match.
    pub(crate) pos_in_sequence: usize,
}

/// `ZSTD_ROW_HASH_CACHE_SIZE`.
pub(crate) const ZSTD_ROW_HASH_CACHE_SIZE: usize = 8;

/// `ZSTD_OPT_NUM`.
pub(crate) const ZSTD_OPT_NUM: u32 = 1 << 12;

/// `ZSTD_match_t`: a match the optimal parser found.
#[derive(Clone, Copy, Default)]
pub(crate) struct OptMatch {
    /// The offset as `ZSTD_storeSeq` takes it.
    pub(crate) off: u32,
    pub(crate) len: u32,
}

/// `ZSTD_optimal_t`: a position of the optimal parser's forward pass.
#[derive(Clone, Copy, Default)]
pub(crate) struct Optimal {
    /// The price from the start of the run.
    pub(crate) price: i32,
    pub(crate) off: u32,
    pub(crate) mlen: u32,
    pub(crate) litlen: u32,
    pub(crate) rep: [u32; 3],
}

/// `ZSTD_OptPrice_e`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PriceType {
    Dynamic,
    Predef,
}

/// `optState_t`: the statistics of the optimal parser.
pub(crate) struct OptState {
    pub(crate) lit_freq: [u32; 256],
    pub(crate) lit_length_freq: [u32; MAX_LL as usize + 1],
    pub(crate) match_length_freq: [u32; MAX_ML as usize + 1],
    pub(crate) off_code_freq: [u32; MAX_OFF as usize + 1],
    pub(crate) match_table: Vec<OptMatch>,
    pub(crate) price_table: Vec<Optimal>,
    pub(crate) lit_sum: u32,
    pub(crate) lit_length_sum: u32,
    pub(crate) match_length_sum: u32,
    pub(crate) off_code_sum: u32,
    pub(crate) lit_sum_base_price: u32,
    pub(crate) lit_length_sum_base_price: u32,
    pub(crate) match_length_sum_base_price: u32,
    pub(crate) off_code_sum_base_price: u32,
    pub(crate) price_type: PriceType,
}

impl OptState {
    fn new(used: bool) -> OptState {
        // `ZSTD_OPT_SIZE`.
        let size = if used { ZSTD_OPT_NUM as usize + 3 } else { 0 };
        OptState {
            lit_freq: [0; 256],
            lit_length_freq: [0; MAX_LL as usize + 1],
            match_length_freq: [0; MAX_ML as usize + 1],
            off_code_freq: [0; MAX_OFF as usize + 1],
            match_table: vec![OptMatch::default(); size],
            price_table: vec![Optimal::default(); size],
            lit_sum: 0,
            lit_length_sum: 0,
            match_length_sum: 0,
            off_code_sum: 0,
            lit_sum_base_price: 0,
            lit_length_sum_base_price: 0,
            match_length_sum_base_price: 0,
            off_code_sum_base_price: 0,
            price_type: PriceType::Dynamic,
        }
    }

    fn reset(&mut self, used: bool) {
        let size = if used { ZSTD_OPT_NUM as usize + 3 } else { 0 };
        self.lit_freq = [0; 256];
        self.lit_length_freq = [0; MAX_LL as usize + 1];
        self.match_length_freq = [0; MAX_ML as usize + 1];
        self.off_code_freq = [0; MAX_OFF as usize + 1];
        self.match_table.clear();
        self.match_table.resize(size, OptMatch::default());
        self.price_table.clear();
        self.price_table.resize(size, Optimal::default());
        self.lit_sum = 0;
        self.lit_length_sum = 0;
        self.match_length_sum = 0;
        self.off_code_sum = 0;
        self.lit_sum_base_price = 0;
        self.lit_length_sum_base_price = 0;
        self.match_length_sum_base_price = 0;
        self.off_code_sum_base_price = 0;
        self.price_type = PriceType::Dynamic;
    }
}

/// `ZSTD_getLowestMatchIndex`: the lowest index a match may have from `curr`.
pub(crate) fn get_lowest_match_index(ms: &MatchState, curr: u32, window_log: u32) -> u32 {
    let max_distance = 1u32 << window_log;
    let lowest_valid = ms.window.low_limit;
    let within_window = if curr.wrapping_sub(lowest_valid) > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let is_dictionary = ms.loaded_dict_end != 0;
    // When using a dictionary the entire dictionary is valid if a single byte of the
    // dictionary is within the window. It is invalidated as soon as the first byte of the
    // dictionary is out of the window.
    if is_dictionary {
        lowest_valid
    } else {
        within_window
    }
}

/// `ZSTD_getLowestPrefixIndex`: the lowest index a match may have for a block that ends at
/// `curr`.
pub(crate) fn get_lowest_prefix_index(ms: &MatchState, curr: u32, window_log: u32) -> u32 {
    let max_distance = 1u32 << window_log;
    let lowest_valid = ms.window.dict_limit;
    let within_window = if curr.wrapping_sub(lowest_valid) > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let is_dictionary = ms.loaded_dict_end != 0;
    // When using a dictionary the entire dictionary is valid if a single byte of the
    // dictionary is within the window. It is invalidated as soon as the first byte of the
    // dictionary is out of the window.
    if is_dictionary {
        lowest_valid
    } else {
        within_window
    }
}

/// `ZSTD_count`: how many bytes at `p_in` are the same as at `p_match`, up to `p_in_limit`.
#[inline]
pub(crate) fn count(src: &[u8], mut p_in: usize, mut p_match: usize, p_in_limit: usize) -> usize {
    let p_start = p_in;
    // `pInLoopLimit` is `pInLimit - 7`.
    if p_in + 7 < p_in_limit {
        {
            let diff = read64(src, p_match) ^ read64(src, p_in);
            if diff != 0 {
                return (diff.trailing_zeros() >> 3) as usize;
            }
        }
        p_in += 8;
        p_match += 8;
        while p_in + 7 < p_in_limit {
            let diff = read64(src, p_match) ^ read64(src, p_in);
            if diff == 0 {
                p_in += 8;
                p_match += 8;
                continue;
            }
            p_in += (diff.trailing_zeros() >> 3) as usize;
            return p_in - p_start;
        }
    }
    if p_in + 3 < p_in_limit && read32(src, p_match) == read32(src, p_in) {
        p_in += 4;
        p_match += 4;
    }
    if p_in + 1 < p_in_limit && read16(src, p_match) == read16(src, p_in) {
        p_in += 2;
        p_match += 2;
    }
    if p_in < p_in_limit && src[p_match] == src[p_in] {
        p_in += 1;
    }
    p_in - p_start
}

const PRIME_4_BYTES: u32 = 2_654_435_761;
const PRIME_5_BYTES: u64 = 889_523_592_379;
const PRIME_6_BYTES: u64 = 227_718_039_650_203;
const PRIME_7_BYTES: u64 = 58_295_818_150_454_627;
const PRIME_8_BYTES: u64 = 0xCF1B_BCDC_B7A5_6463;

/// `ZSTD_hashPtr`: the hash, of `h_bits` bits, of the `mls` bytes at `pos`.
#[inline]
pub(crate) fn hash_ptr(src: &[u8], pos: usize, h_bits: u32, mls: u32) -> usize {
    match mls {
        5 => {
            ((read64(src, pos) << (64 - 40)).wrapping_mul(PRIME_5_BYTES) >> (64 - h_bits)) as usize
        }
        6 => {
            ((read64(src, pos) << (64 - 48)).wrapping_mul(PRIME_6_BYTES) >> (64 - h_bits)) as usize
        }
        7 => {
            ((read64(src, pos) << (64 - 56)).wrapping_mul(PRIME_7_BYTES) >> (64 - h_bits)) as usize
        }
        8 => (read64(src, pos).wrapping_mul(PRIME_8_BYTES) >> (64 - h_bits)) as usize,
        _ => (read32(src, pos).wrapping_mul(PRIME_4_BYTES) >> (32 - h_bits)) as usize,
    }
}

/// `ZSTD_hashPtrSalted`: as [`hash_ptr`], with the salt mixed in.
#[inline]
pub(crate) fn hash_ptr_salted(src: &[u8], pos: usize, h_bits: u32, mls: u32, salt: u64) -> u32 {
    (match mls {
        5 => {
            (((read64(src, pos) << (64 - 40)).wrapping_mul(PRIME_5_BYTES) ^ salt) >> (64 - h_bits))
                as usize
        }
        6 => {
            (((read64(src, pos) << (64 - 48)).wrapping_mul(PRIME_6_BYTES) ^ salt) >> (64 - h_bits))
                as usize
        }
        7 => {
            (((read64(src, pos) << (64 - 56)).wrapping_mul(PRIME_7_BYTES) ^ salt) >> (64 - h_bits))
                as usize
        }
        8 => ((read64(src, pos).wrapping_mul(PRIME_8_BYTES) ^ salt) >> (64 - h_bits)) as usize,
        _ => {
            ((read32(src, pos).wrapping_mul(PRIME_4_BYTES) ^ salt as u32) >> (32 - h_bits)) as usize
        }
    }) as u32
}

/// `ZSTD_hash3Ptr`: the hash, of `h_bits` bits, of the three bytes at `pos`.
#[inline]
pub(crate) fn hash3_ptr(src: &[u8], pos: usize, h_bits: u32) -> usize {
    const PRIME_3_BYTES: u32 = 506_832_829;
    ((read32(src, pos) << (32 - 24)).wrapping_mul(PRIME_3_BYTES) >> (32 - h_bits)) as usize
}

/// `ZSTD_bitmix`: the bits of a value mixed, as XXH3's `rrmxmx` mixes them.
fn bitmix(mut val: u64, len: u64) -> u64 {
    val ^= val.rotate_right(49) ^ val.rotate_right(24);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^= (val >> 35).wrapping_add(len);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^ (val >> 28)
}

/// `ZSTD_rowMatchFinderUsed` with the mode `ZSTD_resolveRowMatchFinderMode` gives: the
/// greedy and lazy strategies search by rows when the window is larger than 16 KB.
pub(crate) fn row_match_finder_used(cparams: &CompressionParameters) -> bool {
    matches!(
        cparams.strategy,
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2
    ) && cparams.window_log > 14
}

/// `ZSTD_blockSplitterEnabled` with the mode `ZSTD_resolveBlockSplitterMode` gives: the
/// optimal strategies split a block in two where that compresses better, when the window is
/// 128 KB or more.
pub(crate) fn block_splitter_enabled(cparams: &CompressionParameters) -> bool {
    cparams.strategy as u32 >= Strategy::Btopt as u32 && cparams.window_log >= 17
}

/// `ZSTD_resolveEnableLdm`: the optimal strategies match over long distances too when the
/// window is 128 MB or more.
pub(crate) fn ldm_enabled(cparams: &CompressionParameters) -> bool {
    cparams.strategy as u32 >= Strategy::Btopt as u32 && cparams.window_log >= 27
}

/// `ZSTD_fseCTables_t`.
#[derive(Clone)]
struct FseCTables {
    offcode_ctable: FseCTable,
    matchlength_ctable: FseCTable,
    litlength_ctable: FseCTable,
    offcode_repeat_mode: FseRepeat,
    matchlength_repeat_mode: FseRepeat,
    litlength_repeat_mode: FseRepeat,
}

/// `ZSTD_entropyCTables_t`.
#[derive(Clone)]
struct EntropyCTables {
    huf: HufCTables,
    fse: FseCTables,
}

/// `ZSTD_compressedBlockState_t`: what one block leaves for the next.
struct CompressedBlockState {
    entropy: EntropyCTables,
    rep: [u32; 3],
}

impl CompressedBlockState {
    /// A state as `ZSTD_reset_compressedBlockState` leaves it. (The original leaves the
    /// tables as they are, which are not read before they are written.)
    fn new() -> CompressedBlockState {
        CompressedBlockState {
            entropy: EntropyCTables {
                huf: HufCTables {
                    ctable: [0; 257],
                    repeat_mode: HufRepeat::None,
                },
                fse: FseCTables {
                    offcode_ctable: FseCTable::new(OFF_FSE_LOG, MAX_OFF),
                    matchlength_ctable: FseCTable::new(ML_FSE_LOG, MAX_ML),
                    litlength_ctable: FseCTable::new(LL_FSE_LOG, MAX_LL),
                    offcode_repeat_mode: FseRepeat::None,
                    matchlength_repeat_mode: FseRepeat::None,
                    litlength_repeat_mode: FseRepeat::None,
                },
            },
            rep: REP_START_VALUE,
        }
    }

    fn reset(&mut self) {
        self.entropy.huf.ctable.fill(0);
        self.entropy.huf.repeat_mode = HufRepeat::None;
        self.entropy.fse.offcode_repeat_mode = FseRepeat::None;
        self.entropy.fse.matchlength_repeat_mode = FseRepeat::None;
        self.entropy.fse.litlength_repeat_mode = FseRepeat::None;
        self.rep = REP_START_VALUE;
    }
}

/// What `ZSTD_buildSequencesStatistics` answers with (`ZSTD_symbolEncodingTypeStats_t`).
struct SymbolEncodingTypeStats {
    ll_type: u32,
    off_type: u32,
    ml_type: u32,
    /// The size of the descriptions of the three tables.
    size: usize,
    /// The size of the last description of a table of its own.
    last_count_size: usize,
}

/// One of the three codes of the sequences.
#[derive(Clone, Copy)]
enum Code {
    LiteralLengths,
    Offsets,
    MatchLengths,
}

impl Code {
    fn symbol_type(self) -> &'static SymbolType {
        match self {
            Code::LiteralLengths => &LITERAL_LENGTHS,
            Code::Offsets => &OFFSETS,
            Code::MatchLengths => &MATCH_LENGTHS,
        }
    }

    /// The code's table in `prev`, and the one to make in `next`.
    fn tables<'a>(self, prev: &'a FseCTables, next: &'a mut FseCTables) -> TableState<'a> {
        match self {
            Code::LiteralLengths => TableState {
                prev: &prev.litlength_ctable,
                prev_repeat: prev.litlength_repeat_mode,
                next: &mut next.litlength_ctable,
                next_repeat: &mut next.litlength_repeat_mode,
            },
            Code::Offsets => TableState {
                prev: &prev.offcode_ctable,
                prev_repeat: prev.offcode_repeat_mode,
                next: &mut next.offcode_ctable,
                next_repeat: &mut next.offcode_repeat_mode,
            },
            Code::MatchLengths => TableState {
                prev: &prev.matchlength_ctable,
                prev_repeat: prev.matchlength_repeat_mode,
                next: &mut next.matchlength_ctable,
                next_repeat: &mut next.matchlength_repeat_mode,
            },
        }
    }
}

/// `ZSTD_buildSequencesStatistics`: the kinds of the three tables of the sequences, the
/// tables themselves in `next_entropy`, and what describes them in `dst`.
fn build_sequences_statistics(
    seq_store: &mut SeqStore,
    chunk: &SeqChunk,
    prev_entropy: &FseCTables,
    next_entropy: &mut FseCTables,
    dst: &mut [u8],
    strategy: Strategy,
    count_workspace: &mut [u32; MAX_SEQ + 1],
) -> CResult<SymbolEncodingTypeStats> {
    let mut op = 0usize;
    let mut stats = SymbolEncodingTypeStats {
        ll_type: 0,
        off_type: 0,
        ml_type: 0,
        size: 0,
        last_count_size: 0,
    };
    let nb_seq = chunk.nb_seq();

    // Convert the lengths and distances into codes.
    seq_store.seq_to_codes(chunk);
    let of_code_table = &seq_store.of_code[chunk.seq_start..chunk.seq_end];
    let ll_code_table = &seq_store.ll_code[chunk.seq_start..chunk.seq_end];
    let ml_code_table = &seq_store.ml_code[chunk.seq_start..chunk.seq_end];

    // The tables of the literal lengths, the offsets and the match lengths, in that order.
    for (code, codes) in [
        (Code::LiteralLengths, ll_code_table),
        (Code::Offsets, of_code_table),
        (Code::MatchLengths, ml_code_table),
    ] {
        let (encoding_type, count_size) = sequences::encode_symbol_table(
            code.symbol_type(),
            &codes[..nb_seq],
            code.tables(prev_entropy, next_entropy),
            count_workspace,
            strategy,
            &mut dst[op..],
        )?;
        match code {
            Code::LiteralLengths => stats.ll_type = encoding_type,
            Code::Offsets => stats.off_type = encoding_type,
            Code::MatchLengths => stats.ml_type = encoding_type,
        }
        if encoding_type == SET_COMPRESSED {
            stats.last_count_size = count_size;
        }
        op += count_size;
    }
    stats.size = op;
    Ok(stats)
}

/// `ZSTD_updateRep`: the repeat offsets after a sequence of offset `off_base` (as
/// `ZSTD_storeSeq` takes it), whose literals' length is 0 or not.
pub(crate) fn update_rep(rep: &mut [u32; 3], off_base: u32, ll0: bool) {
    if off_base > ZSTD_REP_NUM {
        // full offset
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - ZSTD_REP_NUM;
    } else {
        // repcode
        let rep_code = off_base - 1 + u32::from(ll0);
        if rep_code > 0 {
            // note : if repCode==0, no change
            let current_offset = if rep_code == ZSTD_REP_NUM {
                rep[0].wrapping_sub(1)
            } else {
                rep[rep_code as usize]
            };
            rep[2] = if rep_code >= 2 { rep[1] } else { rep[2] };
            rep[1] = rep[0];
            rep[0] = current_offset;
        }
    }
}

/// `ZSTD_noCompressBlock`: the block as it is, behind its header.
fn no_compress_block(dst: &mut [u8], src: &[u8], last_block: u32) -> CResult<usize> {
    let c_block_header24 = last_block + (BT_RAW << 1) + ((src.len() as u32) << 3);
    if src.len() + ZSTD_BLOCK_HEADER_SIZE > dst.len() {
        return Err(CError::DstSizeTooSmall); // dst buf too small for uncompressed block
    }
    write_le24(dst, 0, c_block_header24);
    dst[ZSTD_BLOCK_HEADER_SIZE..ZSTD_BLOCK_HEADER_SIZE + src.len()].copy_from_slice(src);
    Ok(ZSTD_BLOCK_HEADER_SIZE + src.len())
}

/// `ZSTD_rleCompressBlock`: one byte for the block, behind its header.
fn rle_compress_block(
    dst: &mut [u8],
    byte: u8,
    src_size: usize,
    last_block: u32,
) -> CResult<usize> {
    let c_block_header = last_block + (BT_RLE << 1) + ((src_size as u32) << 3);
    if dst.len() < 4 {
        return Err(CError::DstSizeTooSmall);
    }
    write_le24(dst, 0, c_block_header);
    dst[3] = byte;
    Ok(4)
}

/// `ZSTD_fseCTablesMetadata_t`: the kinds of the tables of the sequences the block splitter
/// estimates with.
struct FseMetadata {
    ll_type: u32,
    of_type: u32,
    ml_type: u32,
    fse_tables_size: usize,
}

/// `ZSTD_estimateBlockSize_symbolType`: the size of the codes of one kind (and their extra
/// bits) with a table of the kind `encoding_type`.
fn estimate_block_size_symbol_type(
    kind: &SymbolType,
    encoding_type: u32,
    code_table: &[u8],
    fse_ctable: &FseCTable,
    count: &mut [u32; MAX_SEQ + 1],
) -> usize {
    let nb_seq = code_table.len();
    let mut max = kind.max;
    let (default_norm, default_norm_log) = (kind.default_norm, kind.default_norm_log);
    let additional_bits = kind.extra_bits;
    let mut c_symbol_type_size_estimate_in_bits = 0usize;

    hist::count_simple(count, &mut max, code_table); // can't fail
    if encoding_type == SET_BASIC {
        // We selected this encoding type, so it must be valid.
        c_symbol_type_size_estimate_in_bits =
            sequences::cross_entropy_cost(default_norm, default_norm_log, count, max);
    } else if encoding_type == SET_RLE {
        c_symbol_type_size_estimate_in_bits = 0;
    } else if encoding_type == SET_COMPRESSED || encoding_type == SET_REPEAT {
        c_symbol_type_size_estimate_in_bits = sequences::fse_bit_cost(fse_ctable, count, max);
    }
    if c_symbol_type_size_estimate_in_bits == sequences::COST_ERROR {
        return nb_seq * 10;
    }
    for &code in code_table {
        c_symbol_type_size_estimate_in_bits += match additional_bits {
            Some(bits) => bits[code as usize] as usize,
            None => code as usize, // for offset, offset code is also the number of additional bits
        };
    }
    c_symbol_type_size_estimate_in_bits >> 3
}

/// `ZSTD_CCtx`, as far as one call of `ZSTD_compress` uses it.
pub(crate) struct CCtx {
    /// `appliedParams.cParams`.
    cparams: CompressionParameters,
    block_size_max: usize,
    is_first_block: bool,
    /// `stage == ZSTDcs_ending`: the last block is written.
    stage_ending: bool,
    consumed_src_size: u64,
    produced_c_size: u64,
    prev_cblock: Box<CompressedBlockState>,
    next_cblock: Box<CompressedBlockState>,
    match_state: MatchState,
    seq_store: SeqStore,
    /// For long-distance matching: its state, and its matches for the block.
    ldm: Option<Box<LdmState>>,
    ldm_sequences: Vec<RawSeq>,
    /// The work area of the entropy stage: the counts of the sequences' codes, then what
    /// the Huffman compressor keeps.
    count: [u32; MAX_SEQ + 1],
    huf_workspace: Box<HufCompressTables>,
}

impl CCtx {
    /// A context as `ZSTD_compressBegin_internal` leaves it (`ZSTD_resetCCtx_internal`,
    /// `ZSTD_reset_matchState`, `ZSTD_reset_compressedBlockState`), for a source of
    /// `pledged_src_size` bytes.
    fn new(cparams: CompressionParameters, pledged_src_size: u64) -> CCtx {
        let window_size = 1usize.max((1u64 << cparams.window_log).min(pledged_src_size) as usize);
        let block_size = ZSTD_BLOCKSIZE_MAX.min(window_size);
        // `ZSTD_allocateChainTable`: every strategy but the fast one and those that search by
        // rows has one.
        let use_row = row_match_finder_used(&cparams);
        let chain_size = if cparams.strategy != Strategy::Fast && !use_row {
            1usize << cparams.chain_log
        } else {
            0
        };
        let h_size = 1usize << cparams.hash_log;
        let hash_log3 = if cparams.min_match == 3 {
            ZSTD_HASHLOG3_MAX.min(cparams.window_log)
        } else {
            0
        };
        let h3_size = if hash_log3 != 0 {
            1usize << hash_log3
        } else {
            0
        };
        CCtx {
            cparams,
            block_size_max: block_size,
            is_first_block: true,
            stage_ending: false,
            consumed_src_size: 0,
            produced_c_size: 0,
            prev_cblock: Box::new(CompressedBlockState::new()),
            next_cblock: Box::new(CompressedBlockState::new()),
            match_state: MatchState {
                // `ZSTD_window_init`.
                window: Window {
                    base: ZSTD_WINDOW_START_INDEX,
                    dict_limit: ZSTD_WINDOW_START_INDEX,
                    low_limit: ZSTD_WINDOW_START_INDEX,
                },
                loaded_dict_end: 0,
                next_to_update: ZSTD_WINDOW_START_INDEX,
                hash_table: vec![0; h_size],
                chain_table: vec![0; chain_size],
                hash_table3: vec![0; h3_size],
                hash_log3,
                // (A new context's tags are all zeros, and its salt comes of a salt and a
                // count of 0: `ZSTD_advanceHashSalt`.)
                tag_table: if use_row { vec![0; h_size] } else { Vec::new() },
                row_hash_log: if use_row {
                    cparams.hash_log - cparams.search_log.clamp(4, 6)
                } else {
                    0
                },
                hash_salt: if use_row {
                    bitmix(0, 8) ^ bitmix(0, 4)
                } else {
                    0
                },
                hash_cache: [0; ZSTD_ROW_HASH_CACHE_SIZE],
                lazy_skipping: false,
                opt: OptState::new(cparams.strategy as u32 >= Strategy::Btopt as u32),
                cparams,
            },
            seq_store: SeqStore::new(),
            ldm: if ldm_enabled(&cparams) {
                Some(Box::new(LdmState::new(&cparams, block_size)))
            } else {
                None
            },
            ldm_sequences: Vec::new(),
            count: [0; MAX_SEQ + 1],
            huf_workspace: Box::new(HufCompressTables::new()),
        }
    }

    /// Resets this context for a new frame of `pledged_src_size` bytes without dropping its
    /// heap tables when their capacities already suffice.
    fn reset_for_frame(&mut self, cparams: CompressionParameters, pledged_src_size: u64) {
        let window_size = 1usize.max((1u64 << cparams.window_log).min(pledged_src_size) as usize);
        let block_size = ZSTD_BLOCKSIZE_MAX.min(window_size);
        let use_row = row_match_finder_used(&cparams);
        let chain_size = if cparams.strategy != Strategy::Fast && !use_row {
            1usize << cparams.chain_log
        } else {
            0
        };
        let h_size = 1usize << cparams.hash_log;
        let hash_log3 = if cparams.min_match == 3 {
            ZSTD_HASHLOG3_MAX.min(cparams.window_log)
        } else {
            0
        };
        let h3_size = if hash_log3 != 0 {
            1usize << hash_log3
        } else {
            0
        };
        let tag_size = if use_row { h_size } else { 0 };

        self.cparams = cparams;
        self.block_size_max = block_size;
        self.is_first_block = true;
        self.stage_ending = false;
        self.consumed_src_size = 0;
        self.produced_c_size = 0;
        self.prev_cblock.reset();
        self.next_cblock.reset();

        self.match_state.window = Window {
            base: ZSTD_WINDOW_START_INDEX,
            dict_limit: ZSTD_WINDOW_START_INDEX,
            low_limit: ZSTD_WINDOW_START_INDEX,
        };
        self.match_state.loaded_dict_end = 0;
        self.match_state.next_to_update = ZSTD_WINDOW_START_INDEX;
        self.match_state.hash_table.clear();
        self.match_state.hash_table.resize(h_size, 0);
        self.match_state.chain_table.clear();
        self.match_state.chain_table.resize(chain_size, 0);
        self.match_state.hash_table3.clear();
        self.match_state.hash_table3.resize(h3_size, 0);
        self.match_state.hash_log3 = hash_log3;
        self.match_state.tag_table.clear();
        self.match_state.tag_table.resize(tag_size, 0);
        self.match_state.row_hash_log = if use_row {
            cparams.hash_log - cparams.search_log.clamp(4, 6)
        } else {
            0
        };
        self.match_state.hash_salt = if use_row {
            bitmix(0, 8) ^ bitmix(0, 4)
        } else {
            0
        };
        self.match_state.hash_cache = [0; ZSTD_ROW_HASH_CACHE_SIZE];
        self.match_state.lazy_skipping = false;
        self.match_state
            .opt
            .reset(cparams.strategy as u32 >= Strategy::Btopt as u32);
        self.match_state.cparams = cparams;

        self.seq_store.reset();
        if ldm_enabled(&cparams) {
            self.ldm = Some(Box::new(LdmState::new(&cparams, block_size)));
        } else {
            self.ldm = None;
        }
        self.ldm_sequences.clear();
        self.count = [0; MAX_SEQ + 1];
    }

    /// Resets match-finding window and tables for a new streaming chunk while keeping block
    /// entropy tables and repeat offsets from previous blocks of the same frame.
    #[cfg(feature = "std")]
    pub(crate) fn reset_match_state_for_chunk(&mut self) {
        let cparams = self.cparams;
        let use_row = row_match_finder_used(&cparams);
        let chain_size = if cparams.strategy != Strategy::Fast && !use_row {
            1usize << cparams.chain_log
        } else {
            0
        };
        let h_size = 1usize << cparams.hash_log;
        let h3_size = if self.match_state.hash_log3 != 0 {
            1usize << self.match_state.hash_log3
        } else {
            0
        };
        let tag_size = if use_row { h_size } else { 0 };

        self.match_state.window = Window {
            base: ZSTD_WINDOW_START_INDEX,
            dict_limit: ZSTD_WINDOW_START_INDEX,
            low_limit: ZSTD_WINDOW_START_INDEX,
        };
        self.match_state.loaded_dict_end = 0;
        self.match_state.next_to_update = ZSTD_WINDOW_START_INDEX;
        self.match_state.hash_table.clear();
        self.match_state.hash_table.resize(h_size, 0);
        self.match_state.chain_table.clear();
        self.match_state.chain_table.resize(chain_size, 0);
        self.match_state.hash_table3.clear();
        self.match_state.hash_table3.resize(h3_size, 0);
        self.match_state.tag_table.clear();
        self.match_state.tag_table.resize(tag_size, 0);
        self.match_state.hash_cache = [0; ZSTD_ROW_HASH_CACHE_SIZE];
        self.match_state.lazy_skipping = false;
        if let Some(ldm) = &mut self.ldm {
            **ldm = LdmState::new(&cparams, self.block_size_max);
        }
        self.ldm_sequences.clear();
    }

    /// `ZSTD_literalsCompressionIsDisabled`: the fast strategy with an acceleration leaves
    /// the literals as they are.
    fn literals_compression_is_disabled(&self) -> bool {
        self.cparams.strategy == Strategy::Fast && self.cparams.target_length > 0
    }

    /// `ZSTD_entropyCompressSeqStore_internal`: the literals and the sequences of the block
    /// in the sequence store, as the two sections of a compressed block.
    fn entropy_compress_seq_store_internal(
        &mut self,
        dst: &mut [u8],
        chunk: &SeqChunk,
    ) -> CResult<usize> {
        let strategy = self.cparams.strategy;
        let disable_literal_compression = self.literals_compression_is_disabled();
        let seq_store = &mut self.seq_store;
        let prev_entropy = &self.prev_cblock.entropy;
        let next_entropy = &mut self.next_cblock.entropy;
        let nb_seq = chunk.nb_seq();
        let literals = &seq_store.lit[chunk.lit_start..chunk.lit_end];
        let oend = dst.len();
        let mut op = 0usize;
        let last_count_size;

        // Compress the literals.
        {
            let lit_size = literals.len();
            let num_sequences = nb_seq;
            // Base suspicion of uncompressibility on ratio of literals to sequences.
            let suspect_uncompressible = (num_sequences == 0)
                || (lit_size / num_sequences >= SUSPECT_UNCOMPRESSIBLE_LITERAL_RATIO);

            let options = LiteralOptions {
                strategy,
                disable_compression: disable_literal_compression,
                suspect_uncompressible,
            };
            let c_size = compress_literals(
                dst,
                literals,
                &mut self.huf_workspace,
                &prev_entropy.huf,
                &mut next_entropy.huf,
                options,
            )?;
            op += c_size;
        }

        // Sequences header.
        if (oend - op) < 3 /* max nbSeq Size */ + 1
        /* seqHead */
        {
            return Err(CError::DstSizeTooSmall); // can't fit the sequences header in the output
        }
        if nb_seq < 128 {
            dst[op] = nb_seq as u8;
            op += 1;
        } else if nb_seq < LONGNBSEQ {
            dst[op] = ((nb_seq >> 8) + 0x80) as u8;
            dst[op + 1] = nb_seq as u8;
            op += 2;
        } else {
            dst[op] = 0xFF;
            dst[op + 1..op + 3].copy_from_slice(&((nb_seq - LONGNBSEQ) as u16).to_le_bytes());
            op += 3;
        }
        if nb_seq == 0 {
            // Copy the entropy tables.
            next_entropy.fse = prev_entropy.fse.clone();
            return Ok(op);
        }
        {
            let seq_head = op;
            op += 1;
            // Build the stats for the sequences.
            let stats = build_sequences_statistics(
                seq_store,
                chunk,
                &prev_entropy.fse,
                &mut next_entropy.fse,
                &mut dst[op..],
                strategy,
                &mut self.count,
            )?;
            dst[seq_head] =
                ((stats.ll_type << 6) + (stats.off_type << 4) + (stats.ml_type << 2)) as u8;
            last_count_size = stats.last_count_size;
            op += stats.size;
        }

        {
            let range = chunk.seq_start..chunk.seq_end;
            let fse = &next_entropy.fse;
            let coded = |ctable, codes| CodedSymbols { ctable, codes };
            let bitstream_size = sequences::encode_sequences(
                &mut dst[op..],
                &coded(&fse.matchlength_ctable, &seq_store.ml_code[range.clone()]),
                &coded(&fse.offcode_ctable, &seq_store.of_code[range.clone()]),
                &coded(&fse.litlength_ctable, &seq_store.ll_code[range.clone()]),
                &seq_store.sequences[range],
            )?;
            op += bitstream_size;
            // zstd versions <= 1.3.4 mistakenly report corruption when FSE_readNCount()
            // receives a buffer < 4 bytes. This can happen when the last set_compressed
            // table present is 2 bytes and the bitstream is only one byte. In this
            // exceedingly rare case, the block is given up and sent uncompressed.
            if last_count_size != 0 && (last_count_size + bitstream_size) < 4 {
                // lastCountSize >= 2 && bitstreamSize > 0 ==> lastCountSize == 3
                return Ok(0);
            }
        }

        Ok(op)
    }

    /// `ZSTD_entropyCompressSeqStore`: as above, or 0 when the block is better left as it
    /// is. `block_size` is the size of the block's source.
    fn entropy_compress_seq_store(
        &mut self,
        dst: &mut [u8],
        block_size: usize,
        chunk: &SeqChunk,
    ) -> CResult<usize> {
        let dst_capacity = dst.len();
        let c_size = self.entropy_compress_seq_store_internal(dst, chunk);
        match c_size {
            Ok(0) => Ok(0),
            // When the block is not compressible, the room can run out before the end; the
            // block is then sent as it is, for which there is room.
            Err(CError::DstSizeTooSmall) if block_size <= dst_capacity => Ok(0),
            Err(error) => Err(error),
            Ok(c_size) => {
                // Check compressibility.
                let max_c_size = block_size - min_gain(block_size, self.cparams.strategy);
                if c_size >= max_c_size {
                    return Ok(0); // block not compressed
                }
                Ok(c_size)
            }
        }
    }

    /// `ZSTD_buildSeqStore`: the sequences of the block `src[ip..ip + src_size]`. `false`
    /// (`ZSTDbss_noCompress`) for a block too small to be worth it.
    // (Follows zstd's function step for step.)
    #[allow(clippy::too_many_lines)]
    fn build_seq_store(&mut self, src: &[u8], ip: usize, src_size: usize) -> CResult<bool> {
        let ms = &mut self.match_state;
        // Assert that we have correctly flushed the ctx params into the ms's copy.
        if src_size < MIN_CBLOCK_SIZE + ZSTD_BLOCK_HEADER_SIZE + 1 + 1 {
            return Ok(false); // don't even attempt compression below a certain srcSize
        }
        self.seq_store.reset();

        // Limited update after a very long match.
        {
            let curr = (ip + ms.window.base as usize) as u32;
            if curr > ms.next_to_update + 384 {
                ms.next_to_update = curr - 192u32.min(curr - ms.next_to_update - 384);
            }
        }

        // Select and store sequences.
        {
            self.next_cblock.rep = self.prev_cblock.rep;
            // `ZSTD_selectBlockCompressor`.
            let rep = &mut self.next_cblock.rep;
            let seq_store = &mut self.seq_store;
            let row = if row_match_finder_used(&ms.cparams) {
                SearchMethod::RowHash
            } else {
                SearchMethod::HashChain
            };
            let last_ll_size = if let Some(ldm) = &mut self.ldm {
                // Long-distance matching: its matches for the block (`ZSTD_ldm_generateSequences`),
                // as candidates for the optimal parser (`ZSTD_ldm_blockCompress`, which the
                // original takes for no other strategies of its own).
                self.ldm_sequences.clear();
                if ldm
                    .generate_sequences(&mut self.ldm_sequences, src, ip, src_size)
                    .is_err()
                {
                    return Err(CError::DstSizeTooSmall);
                }
                let ldm_seq_store = (&self.ldm_sequences[..], RawSeqPos::default());
                match ms.cparams.strategy {
                    Strategy::Btopt => {
                        compress_block_opt(ms, seq_store, rep, src, ip, src_size, 0, ldm_seq_store)
                    }
                    Strategy::Btultra => {
                        compress_block_opt(ms, seq_store, rep, src, ip, src_size, 2, ldm_seq_store)
                    }
                    _ => compress_block_btultra2(
                        ms,
                        seq_store,
                        rep,
                        src,
                        ip,
                        src_size,
                        ldm_seq_store,
                    ),
                }
            } else {
                match ms.cparams.strategy {
                    Strategy::Fast => compress_block_fast(ms, seq_store, rep, src, ip, src_size),
                    Strategy::Dfast => {
                        compress_block_double_fast(ms, seq_store, rep, src, ip, src_size)
                    }
                    Strategy::Greedy => {
                        compress_block_lazy(ms, seq_store, rep, src, ip, src_size, row, 0)
                    }
                    Strategy::Lazy => {
                        compress_block_lazy(ms, seq_store, rep, src, ip, src_size, row, 1)
                    }
                    Strategy::Lazy2 => {
                        compress_block_lazy(ms, seq_store, rep, src, ip, src_size, row, 2)
                    }
                    Strategy::Btlazy2 => compress_block_lazy(
                        ms,
                        seq_store,
                        rep,
                        src,
                        ip,
                        src_size,
                        SearchMethod::BinaryTree,
                        2,
                    ),
                    Strategy::Btopt => compress_block_opt(
                        ms,
                        seq_store,
                        rep,
                        src,
                        ip,
                        src_size,
                        0,
                        (&[], RawSeqPos::default()),
                    ),
                    Strategy::Btultra => compress_block_opt(
                        ms,
                        seq_store,
                        rep,
                        src,
                        ip,
                        src_size,
                        2,
                        (&[], RawSeqPos::default()),
                    ),
                    Strategy::Btultra2 => compress_block_btultra2(
                        ms,
                        seq_store,
                        rep,
                        src,
                        ip,
                        src_size,
                        (&[], RawSeqPos::default()),
                    ),
                }
            };
            // `ZSTD_storeLastLiterals`.
            let last_literals = ip + src_size - last_ll_size;
            self.seq_store
                .lit
                .extend_from_slice(&src[last_literals..last_literals + last_ll_size]);
        }
        Ok(true)
    }

    /// `ZSTD_compressBlock_internal`: the block `src[ip..ip + src_size]`, compressed, with
    /// no header. 0 if it is better left as it is; 1 if it is one byte over and over, which
    /// is then in `dst[0]`.
    fn compress_block_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        ip: usize,
        src_size: usize,
        frame: bool,
    ) -> CResult<usize> {
        // This is the upper bound for the length of an rle block. This isn't the actual
        // upper bound; finding the real threshold needs further investigation.
        const RLE_MAX_LENGTH: usize = 25;
        let c_size = if self.build_seq_store(src, ip, src_size)? {
            // Encode the sequences into the block.
            let whole = self.seq_store.whole();
            let mut result = self.entropy_compress_seq_store(dst, src_size, &whole);

            // We don't want to emit our first block as a RLE even if it qualifies because doing
            // so will cause the decoder (cli only) to throw a "should consume all input" error.
            // This is only an issue for zstd <= v1.4.3.
            let small = matches!(result, Ok(size) if size < RLE_MAX_LENGTH);
            if frame && !self.is_first_block && small && is_rle(&src[ip..ip + src_size]) {
                result = Ok(1);
                dst[0] = src[ip];
            }
            result
        } else {
            Ok(0)
        };

        // out:
        if matches!(c_size, Ok(size) if size > 1) {
            // `ZSTD_blockState_confirmRepcodesAndEntropyTables`.
            core::mem::swap(&mut self.prev_cblock, &mut self.next_cblock);
        }
        // We check that dictionaries have offset codes available for the first block. After
        // the first block, the offcode table might not have large enough codes to represent
        // the offsets in the data.
        if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
            self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
        }

        c_size
    }

    /// `ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize`: the size a chunk of the block's
    /// sequences would come to as a block of its own, with tables for it.
    fn estimate_sub_block_size(&mut self, chunk: &SeqChunk) -> CResult<usize> {
        let strategy = self.cparams.strategy;
        let literals_compression_is_disabled = self.literals_compression_is_disabled();
        let seq_store = &mut self.seq_store;
        let prev_entropy = &self.prev_cblock.entropy;
        let next_entropy = &mut self.next_cblock.entropy;
        let literals = chunk.lit_start..chunk.lit_end;

        // `ZSTD_buildBlockEntropyStats`.
        let (h_type, huf_des_size) = build_block_entropy_stats_literals(
            &seq_store.lit[literals.clone()],
            &prev_entropy.huf,
            &mut next_entropy.huf,
            literals_compression_is_disabled,
            &mut self.huf_workspace,
            strategy as u32 >= Strategy::Btultra as u32,
        )?;
        // `ZSTD_buildBlockEntropyStats_sequences`.
        let fse_metadata = if chunk.nb_seq() != 0 {
            let mut fse_tables_buffer = [0u8; 133]; // ZSTD_MAX_FSE_HEADERS_SIZE
            let stats = build_sequences_statistics(
                seq_store,
                chunk,
                &prev_entropy.fse,
                &mut next_entropy.fse,
                &mut fse_tables_buffer,
                strategy,
                &mut self.count,
            )?;
            FseMetadata {
                ll_type: stats.ll_type,
                of_type: stats.off_type,
                ml_type: stats.ml_type,
                fse_tables_size: stats.size,
            }
        } else {
            // `ZSTD_buildDummySequencesStatistics`.
            next_entropy.fse.litlength_repeat_mode = FseRepeat::None;
            next_entropy.fse.offcode_repeat_mode = FseRepeat::None;
            next_entropy.fse.matchlength_repeat_mode = FseRepeat::None;
            FseMetadata {
                ll_type: SET_BASIC,
                of_type: SET_BASIC,
                ml_type: SET_BASIC,
                fse_tables_size: 0,
            }
        };

        // `ZSTD_estimateBlockSize`.
        let literals_size = estimate_block_size_literal(
            &seq_store.lit[literals],
            &next_entropy.huf,
            h_type,
            huf_des_size,
            &mut self.huf_workspace,
            h_type == SET_COMPRESSED,
        );
        let seq_size = {
            // `ZSTD_estimateBlockSize_sequences`, with the tables' descriptions.
            let nb_seq = chunk.nb_seq();
            // seqHead, the smallest size of the number of sequences, and its longer forms.
            let sequences_section_header_size =
                1 + 1 + usize::from(nb_seq >= 128) + usize::from(nb_seq >= LONGNBSEQ);
            let codes = chunk.seq_start..chunk.seq_end;
            let fse = &next_entropy.fse;
            let mut c_seq_size_estimate = 0;
            c_seq_size_estimate += estimate_block_size_symbol_type(
                &OFFSETS,
                fse_metadata.of_type,
                &seq_store.of_code[codes.clone()],
                &fse.offcode_ctable,
                &mut self.count,
            );
            c_seq_size_estimate += estimate_block_size_symbol_type(
                &LITERAL_LENGTHS,
                fse_metadata.ll_type,
                &seq_store.ll_code[codes.clone()],
                &fse.litlength_ctable,
                &mut self.count,
            );
            c_seq_size_estimate += estimate_block_size_symbol_type(
                &MATCH_LENGTHS,
                fse_metadata.ml_type,
                &seq_store.ml_code[codes],
                &fse.matchlength_ctable,
                &mut self.count,
            );
            c_seq_size_estimate += fse_metadata.fse_tables_size;
            c_seq_size_estimate + sequences_section_header_size
        };
        Ok(seq_size + literals_size + ZSTD_BLOCK_HEADER_SIZE)
    }

    /// `ZSTD_countSeqStoreLiteralsBytes`: the literals of the sequences of a chunk.
    fn count_seq_store_literals_bytes(&self, chunk: &SeqChunk) -> usize {
        let mut literals_bytes = 0usize;
        for (i, seq) in self.seq_store.sequences[chunk.seq_start..chunk.seq_end]
            .iter()
            .enumerate()
        {
            literals_bytes += seq.lit_length as usize;
            if i == chunk.long_length_pos as usize
                && chunk.long_length_type == LongLengthType::LiteralLength
            {
                literals_bytes += 0x10000;
            }
        }
        literals_bytes
    }

    /// `ZSTD_countSeqStoreMatchBytes`: the bytes of the matches of the sequences of a chunk.
    fn count_seq_store_match_bytes(&self, chunk: &SeqChunk) -> usize {
        let mut match_bytes = 0usize;
        for (i, seq) in self.seq_store.sequences[chunk.seq_start..chunk.seq_end]
            .iter()
            .enumerate()
        {
            match_bytes += seq.ml_base as usize + MINMATCH;
            if i == chunk.long_length_pos as usize
                && chunk.long_length_type == LongLengthType::MatchLength
            {
                match_bytes += 0x10000;
            }
        }
        match_bytes
    }

    /// `ZSTD_deriveSeqStoreChunk`: the chunk of the sequences `[start_idx, end_idx)` of the
    /// whole store.
    fn derive_seq_store_chunk(&self, start_idx: usize, end_idx: usize) -> SeqChunk {
        let original = self.seq_store.whole();
        let mut result = original;
        if start_idx > 0 {
            result.seq_end = start_idx;
            result.lit_start += self.count_seq_store_literals_bytes(&result);
        }

        // Move longLengthPos into the correct position if necessary.
        if original.long_length_type != LongLengthType::None {
            if (original.long_length_pos as usize) < start_idx
                || original.long_length_pos as usize > end_idx
            {
                result.long_length_type = LongLengthType::None;
            } else {
                result.long_length_pos -= start_idx as u32;
            }
        }
        result.seq_start = start_idx;
        result.seq_end = end_idx;
        if end_idx == original.seq_end {
            // This accounts for possible last literals if the derived chunk reaches the end of
            // the block.
            result.lit_end = original.lit_end;
        } else {
            let literals_bytes = self.count_seq_store_literals_bytes(&result);
            result.lit_end = result.lit_start + literals_bytes;
        }
        result
    }

    /// `ZSTD_seqStore_resolveOffCodes`: reconciles any divergence in the offset history that
    /// the blocks before left raw or as one byte over and over may cause, and replaces the
    /// repeat offsets of the chunk that have come to mean another offset. `d_rep` follows the
    /// history as the decoder will have it; `c_rep` as the sequences have it.
    fn seq_store_resolve_off_codes(
        &mut self,
        d_rep: &mut [u32; 3],
        c_rep: &mut [u32; 3],
        chunk: &SeqChunk,
    ) {
        // `ZSTD_resolveRepcodeToRawOffset`.
        fn raw_offset(rep: &[u32; 3], off_base: u32, ll0: bool) -> u32 {
            let adjusted_rep_code = off_base - 1 + u32::from(ll0); // [ 0 - 3 ]
            if adjusted_rep_code == ZSTD_REP_NUM {
                // litlength == 0 and offCode == 2 implies selection of first repcode - 1. This
                // is only valid if it results in a valid offset value, aka > 0.
                return rep[0].wrapping_sub(1);
            }
            rep[adjusted_rep_code as usize]
        }
        let nb_seq = chunk.nb_seq();
        let long_lit_len_idx = if chunk.long_length_type == LongLengthType::LiteralLength {
            chunk.long_length_pos as usize
        } else {
            nb_seq
        };
        for idx in 0..nb_seq {
            let seq = &mut self.seq_store.sequences[chunk.seq_start + idx];
            let ll0 = seq.lit_length == 0 && idx != long_lit_len_idx;
            let off_base = seq.off_base;
            if off_base <= ZSTD_REP_NUM {
                let d_raw_offset = raw_offset(d_rep, off_base, ll0);
                let c_raw_offset = raw_offset(c_rep, off_base, ll0);
                // Adjust simulated decompression repcode history if we come across a
                // mismatch. Replace the repcode with the offset it actually references,
                // determined by the compression repcode history.
                if d_raw_offset != c_raw_offset {
                    seq.off_base = offset_to_offbase(c_raw_offset);
                }
            }
            // Compression repcode history is always updated with values directly from the
            // unmodified seqStore. Decompression repcode history may use modified
            // seq->offset value taken from compression repcode history.
            update_rep(d_rep, seq.off_base, ll0);
            update_rep(c_rep, off_base, ll0);
        }
    }

    /// `ZSTD_compressSeqStore_singleBlock`: a chunk of the sequences as a block with its
    /// header, for the source `src[ip..ip + src_size]`.
    // (Zstd's parameters for a block.)
    #[allow(clippy::too_many_arguments)]
    fn compress_seq_store_single_block(
        &mut self,
        chunk: &SeqChunk,
        d_rep: &mut [u32; 3],
        c_rep: &mut [u32; 3],
        dst: &mut [u8],
        src: &[u8],
        ip: usize,
        src_size: usize,
        last_block: u32,
        is_partition: bool,
    ) -> CResult<usize> {
        const RLE_MAX_LENGTH: usize = 25;

        // In case of an RLE or raw block, the simulated decompression repcode history must
        // be reset.
        let d_rep_original = *d_rep;
        if is_partition {
            self.seq_store_resolve_off_codes(d_rep, c_rep, chunk);
        }

        if dst.len() < ZSTD_BLOCK_HEADER_SIZE {
            return Err(CError::DstSizeTooSmall); // Block header doesn't fit
        }
        let mut c_seqs_size =
            self.entropy_compress_seq_store(&mut dst[ZSTD_BLOCK_HEADER_SIZE..], src_size, chunk)?;

        if !self.is_first_block && c_seqs_size < RLE_MAX_LENGTH && is_rle(&src[ip..ip + src_size]) {
            // We don't want to emit our first block as a RLE even if it qualifies because
            // doing so will cause the decoder (cli only) to throw a "should consume all
            // input" error. This is only an issue for zstd <= v1.4.3.
            c_seqs_size = 1;
        }

        let c_size;
        if c_seqs_size == 0 {
            c_size = no_compress_block(dst, &src[ip..ip + src_size], last_block)?;
            *d_rep = d_rep_original; // reset simulated decompression repcode history
        } else if c_seqs_size == 1 {
            c_size = rle_compress_block(dst, src[ip], src_size, last_block)?;
            *d_rep = d_rep_original; // reset simulated decompression repcode history
        } else {
            // `ZSTD_blockState_confirmRepcodesAndEntropyTables`.
            core::mem::swap(&mut self.prev_cblock, &mut self.next_cblock);
            // `writeBlockHeader`.
            write_le24(
                dst,
                0,
                last_block + (BT_COMPRESSED << 1) + ((c_seqs_size as u32) << 3),
            );
            c_size = ZSTD_BLOCK_HEADER_SIZE + c_seqs_size;
        }

        if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
            self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
        }

        Ok(c_size)
    }

    /// `ZSTD_deriveBlockSplitsHelper`: where the sequences `[start_idx, end_idx)` are better
    /// split in two, the splits of each half, and the place between them, into `splits`.
    fn derive_block_splits_helper(
        &mut self,
        splits: &mut Vec<u32>,
        start_idx: usize,
        end_idx: usize,
    ) {
        const MIN_SEQUENCES_BLOCK_SPLITTING: usize = 300;
        const ZSTD_MAX_NB_BLOCK_SPLITS: usize = 196;
        let mid_idx = start_idx.midpoint(end_idx);

        if end_idx - start_idx < MIN_SEQUENCES_BLOCK_SPLITTING
            || splits.len() >= ZSTD_MAX_NB_BLOCK_SPLITS
        {
            return;
        }
        let full_seq_store_chunk = self.derive_seq_store_chunk(start_idx, end_idx);
        let first_half_seq_store = self.derive_seq_store_chunk(start_idx, mid_idx);
        let second_half_seq_store = self.derive_seq_store_chunk(mid_idx, end_idx);
        let estimated_original_size = self.estimate_sub_block_size(&full_seq_store_chunk);
        let estimated_first_half_size = self.estimate_sub_block_size(&first_half_seq_store);
        let estimated_second_half_size = self.estimate_sub_block_size(&second_half_seq_store);
        let (
            Ok(estimated_original_size),
            Ok(estimated_first_half_size),
            Ok(estimated_second_half_size),
        ) = (
            estimated_original_size,
            estimated_first_half_size,
            estimated_second_half_size,
        )
        else {
            return;
        };
        if estimated_first_half_size + estimated_second_half_size < estimated_original_size {
            self.derive_block_splits_helper(splits, start_idx, mid_idx);
            splits.push(mid_idx as u32);
            self.derive_block_splits_helper(splits, mid_idx, end_idx);
        }
    }

    /// `ZSTD_compressBlock_splitBlock_internal`: the block's sequences as one block, or as
    /// several where the estimates say that comes out smaller.
    fn compress_block_split_block_internal(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        ip: usize,
        block_size: usize,
        last_block: u32,
        nb_seq: usize,
    ) -> CResult<usize> {
        let mut c_size = 0usize;
        let mut ip = ip;
        let mut op = 0usize;
        let mut src_bytes_total = 0usize;

        // `ZSTD_deriveBlockSplits`.
        let mut partitions = Vec::new();
        if nb_seq > 4 {
            // (Refuse to try and split anything with less than 4 sequences.)
            self.derive_block_splits_helper(&mut partitions, 0, nb_seq);
        }
        let num_splits = partitions.len();
        partitions.push(nb_seq as u32);

        // If a block is split and some partitions are emitted as RLE/uncompressed, then
        // repcode history may become invalid. In order to reconcile potentially invalid
        // repcodes, we keep track of two separate repcode histories that simulate repcode
        // history on compression and decompression side, and use the histories to determine
        // whether we must replace a particular repcode with its raw offset.
        let mut d_rep = self.prev_cblock.rep;
        let mut c_rep = self.prev_cblock.rep;

        if num_splits == 0 {
            let whole = self.seq_store.whole();
            return self.compress_seq_store_single_block(
                &whole, &mut d_rep, &mut c_rep, dst, src, ip, block_size, last_block, false,
            );
        }

        let mut curr_seq_store = self.derive_seq_store_chunk(0, partitions[0] as usize);
        for i in 0..=num_splits {
            let last_partition = i == num_splits;
            let mut last_block_entire_src = 0;

            let mut src_bytes = self.count_seq_store_literals_bytes(&curr_seq_store)
                + self.count_seq_store_match_bytes(&curr_seq_store);
            src_bytes_total += src_bytes;
            let next_seq_store = if last_partition {
                // This is the final partition, need to account for possible last literals.
                src_bytes += block_size - src_bytes_total;
                last_block_entire_src = last_block;
                None
            } else {
                Some(
                    self.derive_seq_store_chunk(partitions[i] as usize, partitions[i + 1] as usize),
                )
            };

            let c_size_chunk = self.compress_seq_store_single_block(
                &curr_seq_store,
                &mut d_rep,
                &mut c_rep,
                &mut dst[op..],
                src,
                ip,
                src_bytes,
                last_block_entire_src,
                true,
            )?;

            ip += src_bytes;
            op += c_size_chunk;
            c_size += c_size_chunk;
            if let Some(next) = next_seq_store {
                curr_seq_store = next;
            }
        }
        // cRep and dRep may have diverged during the compression. If so, we use the dRep
        // repcodes for the next block.
        self.prev_cblock.rep = d_rep;
        Ok(c_size)
    }

    /// `ZSTD_compressBlock_splitBlock`: the block `src[ip..ip + src_size]` as one or more
    /// blocks, headers and all.
    fn compress_block_split_block(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        ip: usize,
        src_size: usize,
        last_block: u32,
    ) -> CResult<usize> {
        if !self.build_seq_store(src, ip, src_size)? {
            if self.prev_cblock.entropy.fse.offcode_repeat_mode == FseRepeat::Valid {
                self.prev_cblock.entropy.fse.offcode_repeat_mode = FseRepeat::Check;
            }
            return no_compress_block(dst, &src[ip..ip + src_size], last_block);
        }
        let nb_seq = self.seq_store.nb_sequences();
        self.compress_block_split_block_internal(dst, src, ip, src_size, last_block, nb_seq)
    }

    /// `ZSTD_optimalBlockSize`: how much of the rest of the source the next block takes.
    fn optimal_block_size(&self, src: &[u8], block_size_max: usize, savings: i64) -> usize {
        // Split level based on compression strategy, from `fast` to `btultra2`.
        const SPLIT_LEVELS: [i32; 10] = [0, 0, 1, 2, 2, 3, 3, 4, 4, 4];
        let src_size = src.len();
        // Note: conservatively only split full blocks (128 KB) currently.
        if src_size < 128 * 1024 || block_size_max < 128 * 1024 {
            return src_size.min(block_size_max);
        }
        // Do not split incompressible data though: require verified savings to allow
        // pre-splitting. Note: as a consequence, the first full block is not split.
        if savings < 3 {
            return 128 * 1024;
        }
        // (The level of the splitter is left for the strategy to say, `ZSTD_c_splitAfterSequences`
        // not being set.)
        let split_level = SPLIT_LEVELS[self.cparams.strategy as usize];
        split_block(&src[..block_size_max], split_level)
    }

    /// `ZSTD_compress_frameChunk`: the source as blocks.
    pub(crate) fn compress_frame_chunk(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        is_final_chunk: bool,
    ) -> CResult<usize> {
        let block_size_max = self.block_size_max;
        let mut remaining = src.len();
        let mut ip = 0usize;
        let mut op = 0usize;
        let mut dst_capacity = dst.len();
        let max_dist = 1u32 << self.cparams.window_log;
        let mut savings = self.consumed_src_size as i64 - self.produced_c_size as i64;

        while remaining != 0 {
            let block_size = self.optimal_block_size(&src[ip..], block_size_max, savings);
            let last_block = u32::from(is_final_chunk && block_size == remaining);

            if dst_capacity < ZSTD_BLOCK_HEADER_SIZE + MIN_CBLOCK_SIZE + 1 {
                return Err(CError::DstSizeTooSmall); // not enough space to store compressed block
            }

            // (`ZSTD_overflowCorrectIfNeeded`: the indices of a source this port takes
            // stay far from where they would need to be brought down.
            // `ZSTD_checkDictValidity`: there is no dictionary.)
            // `ZSTD_window_enforceMaxDist`.
            {
                let window = &mut self.match_state.window;
                let block_end_idx = (ip + window.base as usize) as u32;
                if block_end_idx > max_dist {
                    let new_low_limit = block_end_idx - max_dist;
                    if window.low_limit < new_low_limit {
                        window.low_limit = new_low_limit;
                    }
                    if window.dict_limit < window.low_limit {
                        window.dict_limit = window.low_limit;
                    }
                }
            }

            // Ensure hash/chain table insertion resumes no sooner than lowlimit.
            if self.match_state.next_to_update < self.match_state.window.low_limit {
                self.match_state.next_to_update = self.match_state.window.low_limit;
            }

            {
                let block_dst = &mut dst[op..op + dst_capacity];
                let c_size = if block_splitter_enabled(&self.cparams) {
                    self.compress_block_split_block(block_dst, src, ip, block_size, last_block)?
                } else {
                    let c_size = self.compress_block_internal(
                        &mut block_dst[ZSTD_BLOCK_HEADER_SIZE..],
                        src,
                        ip,
                        block_size,
                        true,
                    )?;
                    if c_size == 0 {
                        // Block is not compressible.
                        no_compress_block(block_dst, &src[ip..ip + block_size], last_block)?
                    } else {
                        let c_block_header = if c_size == 1 {
                            last_block + (BT_RLE << 1) + ((block_size as u32) << 3)
                        } else {
                            last_block + (BT_COMPRESSED << 1) + ((c_size as u32) << 3)
                        };
                        write_le24(block_dst, 0, c_block_header);
                        c_size + ZSTD_BLOCK_HEADER_SIZE
                    }
                };

                // note: do not merge block reductions (for
                // example the size of the header) into `savings`
                savings += block_size as i64 - c_size as i64;

                ip += block_size;
                remaining -= block_size;
                op += c_size;
                dst_capacity -= c_size;
                self.is_first_block = false;
            }
        }

        if is_final_chunk && op > 0 {
            self.stage_ending = true;
        }
        Ok(op)
    }

    /// `ZSTD_writeFrameHeader`, with optional `Frame_Content_Size`, optional `Content_Checksum`,
    /// and no dictionary.
    pub(crate) fn write_frame_header(
        &self,
        dst: &mut [u8],
        pledged_src_size: Option<u64>,
        checksum: bool,
    ) -> CResult<usize> {
        let window_size = 1u32 << self.cparams.window_log;
        let (single_segment, fcs_code) = match pledged_src_size {
            Some(size) => {
                let single_segment = u64::from(window_size) >= size;
                let fcs_code = u32::from(size >= 256)
                    + u32::from(size >= 65536 + 256)
                    + u32::from(size >= 0xFFFF_FFFF);
                (single_segment, fcs_code)
            }
            None => (false, 0),
        };
        let window_log_byte = ((self.cparams.window_log - ZSTD_WINDOWLOG_ABSOLUTEMIN) << 3) as u8;
        let frame_header_description_byte =
            ((u32::from(checksum) << 2) + (u32::from(single_segment) << 5) + (fcs_code << 6)) as u8;
        let mut pos = 0usize;

        if dst.len() < ZSTD_FRAMEHEADERSIZE_MAX {
            // dst buf is too small to fit worst-case frame header size
            return Err(CError::DstSizeTooSmall);
        }
        write_le32(dst, 0, ZSTD_MAGICNUMBER);
        pos += 4;
        dst[pos] = frame_header_description_byte;
        pos += 1;
        if !single_segment {
            dst[pos] = window_log_byte;
            pos += 1;
        }
        if let Some(pledged_src_size) = pledged_src_size {
            match fcs_code {
                0 => {
                    if single_segment {
                        dst[pos] = pledged_src_size as u8;
                        pos += 1;
                    }
                }
                1 => {
                    dst[pos..pos + 2]
                        .copy_from_slice(&((pledged_src_size - 256) as u16).to_le_bytes());
                    pos += 2;
                }
                2 => {
                    write_le32(dst, pos, pledged_src_size as u32);
                    pos += 4;
                }
                _ => {
                    dst[pos..pos + 8].copy_from_slice(&pledged_src_size.to_le_bytes());
                    pos += 8;
                }
            }
        }
        Ok(pos)
    }

    /// `ZSTD_compressEnd_public` after `ZSTD_compressBegin_internal`: the whole frame.
    fn compress_end(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        options: CompressOptions,
    ) -> CResult<usize> {
        let pledged = options.include_content_size.then_some(src.len() as u64);
        // `ZSTD_compressContinue_internal`, for a frame and its last chunk.
        let fh_size = self.write_frame_header(dst, pledged, options.checksum)?;
        let mut c_size = fh_size;
        if !src.is_empty() {
            // `ZSTD_window_update`: the source starts at index `ZSTD_WINDOW_START_INDEX`,
            // and is not what came before, there being nothing before.
            self.match_state.next_to_update = self.match_state.window.dict_limit;

            let chunk_size = self.compress_frame_chunk(&mut dst[fh_size..], src, true)?;
            self.consumed_src_size += src.len() as u64;
            self.produced_c_size += (chunk_size + fh_size) as u64;
            c_size += chunk_size;
        }

        // `ZSTD_writeEpilogue`.
        if !self.stage_ending {
            // Write one last empty block, make it the "last" block.
            let c_block_header24 = 1 /* last block */ + (BT_RAW << 1);
            if dst.len() - c_size < 3 {
                return Err(CError::DstSizeTooSmall); // no room for epilogue
            }
            write_le24(dst, c_size, c_block_header24);
            c_size += ZSTD_BLOCK_HEADER_SIZE;
        }
        if options.checksum {
            if dst.len() - c_size < 4 {
                return Err(CError::DstSizeTooSmall);
            }
            let digest = super::zstd_ldm::xxh64(src, 0) as u32;
            write_le32(dst, c_size, digest);
            c_size += 4;
        }
        Ok(c_size)
    }

    #[cfg(feature = "std")]
    pub(crate) fn new_streaming(level: Level) -> CCtx {
        let mut cparams = get_cparams_internal(level.get(), 4 << 20);
        if cparams.window_log > 21 {
            cparams.window_log = 21;
            cparams = adjust_cparams_internal(cparams, 2 << 20);
        }
        CCtx::new(cparams, 2 << 20)
    }

    #[cfg(feature = "std")]
    pub(crate) fn record_chunk(&mut self, src_len: usize, c_size: usize) {
        self.consumed_src_size += src_len as u64;
        self.produced_c_size += c_size as u64;
    }
}

/// Reusable Zstandard compressor context that retains its working tables and buffers across
/// calls, avoiding repeated heap allocations.
pub struct Compressor {
    cctx: Option<CCtx>,
}

impl fmt::Debug for Compressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compressor")
            .field("initialized", &self.cctx.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor {
    /// Creates a new reusable [`Compressor`]. Internal tables are allocated lazily on first
    /// use and reused by subsequent calls.
    #[must_use]
    pub const fn new() -> Self {
        Compressor { cctx: None }
    }

    fn prepare(&mut self, level: Level, src_size: u64) -> &mut CCtx {
        let cparams = get_cparams_internal(level.get(), src_size);
        if let Some(cctx) = &mut self.cctx {
            cctx.reset_for_frame(cparams, src_size);
        } else {
            self.cctx = Some(CCtx::new(cparams, src_size));
        }
        self.cctx.as_mut().expect("initialized above")
    }

    /// Compresses `data` to one Zstandard frame at `level`, producing output byte-for-byte
    /// identical to [`compress`].
    ///
    /// # Errors
    ///
    /// Returns [`CompressError::SourceTooLarge`] if `data` is 2 GiB or larger.
    pub fn compress(&mut self, data: &[u8], level: Level) -> Result<Vec<u8>, CompressError> {
        self.compress_with_options(data, CompressOptions::new(level))
    }

    /// Compresses `data` to one Zstandard frame with custom [`CompressOptions`].
    ///
    /// # Errors
    ///
    /// Returns [`CompressError::SourceTooLarge`] if `data` is 2 GiB or larger.
    pub fn compress_with_options(
        &mut self,
        data: &[u8],
        options: CompressOptions,
    ) -> Result<Vec<u8>, CompressError> {
        if data.len() >= 1usize << 31 {
            return Err(CompressError::SourceTooLarge);
        }
        let mut dst = vec![0u8; compress_bound(data.len())];
        let cctx = self.prepare(options.level, data.len() as u64);
        let size = cctx
            .compress_end(&mut dst, data, options)
            .map_err(|_| CompressError::Internal)?;
        dst.truncate(size);
        Ok(dst)
    }

    /// Compresses `data` at `level` directly into `dst`, returning the number of bytes
    /// written.
    ///
    /// When `dst.len() >= compress_bound(data.len())`, the output is byte-for-byte identical
    /// to [`compress`].
    ///
    /// # Errors
    ///
    /// Returns [`CompressError::SourceTooLarge`] if `data` is 2 GiB or larger, or
    /// [`CompressError::OutputTooSmall`] if `dst` cannot hold the compressed frame.
    pub fn compress_into(
        &mut self,
        data: &[u8],
        dst: &mut [u8],
        level: Level,
    ) -> Result<usize, CompressError> {
        self.compress_into_with_options(data, dst, CompressOptions::new(level))
    }

    /// Compresses `data` with `options` directly into `dst`, returning the number of bytes
    /// written.
    ///
    /// # Errors
    ///
    /// Returns [`CompressError::SourceTooLarge`] if `data` is 2 GiB or larger, or
    /// [`CompressError::OutputTooSmall`] if `dst` cannot hold the compressed frame.
    pub fn compress_into_with_options(
        &mut self,
        data: &[u8],
        dst: &mut [u8],
        options: CompressOptions,
    ) -> Result<usize, CompressError> {
        if data.len() >= 1usize << 31 {
            return Err(CompressError::SourceTooLarge);
        }
        let bound = compress_bound(data.len());
        let has_bound = dst.len() >= bound;
        let work_dst = if has_bound { &mut dst[..bound] } else { dst };
        let cctx = self.prepare(options.level, data.len() as u64);
        cctx.compress_end(work_dst, data, options)
            .map_err(|err| match err {
                CError::DstSizeTooSmall if !has_bound => CompressError::OutputTooSmall,
                _ => CompressError::Internal,
            })
    }
}

/// Compresses `data` to one Zstandard frame at `level` (`ZSTD_compress`).
///
/// The frame is byte for byte the one libzstd v1.5.7 gives for
/// `ZSTD_compress(dst, ZSTD_compressBound(n), data, n, level)`.
///
/// # Errors
///
/// [`CompressError::SourceTooLarge`] for data of 2 GiB or more, which this port does not
/// compress.
pub fn compress(data: &[u8], level: Level) -> Result<Vec<u8>, CompressError> {
    compress_with_options(data, CompressOptions::new(level))
}

/// Compresses `data` to one Zstandard frame with custom [`CompressOptions`] (such as an
/// `XXH64` content checksum or omitting `Frame_Content_Size`).
///
/// With [`CompressOptions::new(level)`](CompressOptions::new), the output is byte for byte
/// identical to [`compress`].
///
/// # Errors
///
/// Returns [`CompressError::SourceTooLarge`] for data of 2 GiB or more.
pub fn compress_with_options(
    data: &[u8],
    options: CompressOptions,
) -> Result<Vec<u8>, CompressError> {
    if data.len() >= 1usize << 31 {
        return Err(CompressError::SourceTooLarge);
    }
    let cparams = get_cparams_internal(options.level.get(), data.len() as u64);
    let mut dst = vec![0u8; compress_bound(data.len())];
    let mut cctx = CCtx::new(cparams, data.len() as u64);
    let size = cctx
        .compress_end(&mut dst, data, options)
        .map_err(|_| CompressError::Internal)?;
    dst.truncate(size);
    Ok(dst)
}

/// Compresses `data` to one Zstandard frame at `level` directly into `dst`, returning the
/// number of bytes written.
///
/// Size `dst` to at least [`compress_bound(data.len())`](compress_bound) bytes to guarantee
/// room for any input and byte-for-byte parity with [`compress`].
///
/// # Errors
///
/// Returns [`CompressError::SourceTooLarge`] for data of 2 GiB or more, or
/// [`CompressError::OutputTooSmall`] if `dst` is too small to hold the frame.
pub fn compress_into(data: &[u8], dst: &mut [u8], level: Level) -> Result<usize, CompressError> {
    compress_into_with_options(data, dst, CompressOptions::new(level))
}

/// Compresses `data` with custom [`CompressOptions`] directly into `dst`, returning the
/// number of bytes written.
///
/// # Errors
///
/// Returns [`CompressError::SourceTooLarge`] for data of 2 GiB or more, or
/// [`CompressError::OutputTooSmall`] if `dst` is too small to hold the frame.
pub fn compress_into_with_options(
    data: &[u8],
    dst: &mut [u8],
    options: CompressOptions,
) -> Result<usize, CompressError> {
    if data.len() >= 1usize << 31 {
        return Err(CompressError::SourceTooLarge);
    }
    let bound = compress_bound(data.len());
    let has_bound = dst.len() >= bound;
    let work_dst = if has_bound { &mut dst[..bound] } else { dst };
    let cparams = get_cparams_internal(options.level.get(), data.len() as u64);
    let mut cctx = CCtx::new(cparams, data.len() as u64);
    cctx.compress_end(work_dst, data, options)
        .map_err(|err| match err {
            CError::DstSizeTooSmall if !has_bound => CompressError::OutputTooSmall,
            _ => CompressError::Internal,
        })
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::super::zstd_decompress::decompress;
    use super::*;
    use crate::Level;

    fn noise(len: usize, mut state: u64, mask: u8) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 56) as u8 & mask
            })
            .collect()
    }

    #[test]
    fn nothing_is_a_frame_of_nine_bytes() {
        // The magic number, a header that says "one segment, of no bytes", and one last,
        // empty block.
        assert_eq!(
            compress(&[], Level::new(3).unwrap()).unwrap(),
            [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(compress_bound(0), 64);
        assert_eq!(compress_bound(1 << 20), (1 << 20) + (1 << 12));
    }

    #[test]
    fn frames_decode_to_their_sources() {
        let mut text = Vec::new();
        while text.len() < 300_000 {
            let n = text.len();
            text.extend_from_slice(
                format!(
                    "line {n} of a text that says much the same again and again, {}\n",
                    n % 7
                )
                .as_bytes(),
            );
        }
        let sources = [
            vec![7u8],
            vec![0u8; 5000],
            noise(70_000, 1, 0xFF),
            noise(200_000, 2, 0x0F),
            text.clone(),
            [noise(150_000, 3, 0xFF), text].concat(),
        ];
        for source in &sources {
            for level in [-100, -1, 0, 1, 2, 3] {
                let frame = compress(source, Level::new(level).unwrap()).unwrap();
                assert!(frame.len() <= compress_bound(source.len()));
                assert_eq!(
                    decompress(&frame, source.len()).as_deref(),
                    Ok(&source[..]),
                    "{} bytes at level {level}",
                    source.len()
                );
            }
        }
        // What compresses does.
        assert!(compress(&sources[1], Level::new(1).unwrap()).unwrap().len() < 30);
        assert!(
            compress(&sources[4], Level::new(3).unwrap()).unwrap().len() < sources[4].len() / 5
        );
    }

    #[test]
    fn every_level_compresses_and_comes_back() {
        let mut text = Vec::new();
        while text.len() < 300_000 {
            let n = text.len();
            text.extend_from_slice(
                format!(
                    "line {n} of a text that says much the same again and again, {}\n",
                    n % 7
                )
                .as_bytes(),
            );
        }
        for level in 4..=22 {
            for source in [&text[..1000], &text[..40_000], &text[..]] {
                let frame = compress(source, Level::new(level).unwrap()).unwrap();
                assert_eq!(
                    decompress(&frame, source.len()).as_deref(),
                    Ok(source),
                    "{} bytes at level {level}",
                    source.len()
                );
            }
        }
    }

    #[test]
    fn the_parameters_of_a_level_follow_the_size_of_the_source() {
        // Level 3 for a large source, as the table has it.
        let p = get_cparams_internal(3, 10 << 20);
        assert_eq!(
            (
                p.window_log,
                p.chain_log,
                p.hash_log,
                p.min_match,
                p.target_length,
                p.strategy
            ),
            (21, 16, 17, 5, 0, Strategy::Dfast)
        );
        // For a hundred bytes: the tables shrink with the window, which is then set to the
        // least a frame can say.
        let p = get_cparams_internal(3, 100);
        assert_eq!(
            (
                p.window_log,
                p.chain_log,
                p.hash_log,
                p.min_match,
                p.strategy
            ),
            (10, 7, 8, 4, Strategy::Dfast)
        );
        // A negative level is the fast strategy with the level as its acceleration.
        let p = get_cparams_internal(-7, 1 << 20);
        assert_eq!(
            (
                p.window_log,
                p.hash_log,
                p.min_match,
                p.target_length,
                p.strategy
            ),
            (19, 13, 6, 7, Strategy::Fast)
        );
        assert_eq!(
            get_cparams_internal(-1 << 20, 1 << 20).target_length,
            1 << 17
        );
    }

    /// No source the comparison makes gives a block of 0x7F00 sequences or more, whose number
    /// is written the long way: here the sequences are made by hand, and the block is
    /// decoded by the port of the reference decoder.
    #[test]
    fn a_block_of_very_many_sequences_decodes() {
        const SEQUENCES: usize = 32700;
        let mut expected = Vec::new();
        let cparams = get_cparams_internal(3, SEQUENCES as u64 * 4);
        let mut cctx = CCtx::new(cparams, SEQUENCES as u64 * 4);
        for i in 0..SEQUENCES {
            // One literal, then three more of it: a match at a distance of one.
            let byte = [(i % 251) as u8];
            cctx.seq_store
                .store_seq(&byte, 0, 1, offset_to_offbase(1), 3);
            expected.extend_from_slice(&[byte[0]; 4]);
        }
        const { assert!(SEQUENCES >= LONGNBSEQ) };
        let mut frame = vec![0u8; compress_bound(expected.len())];
        let header = cctx
            .write_frame_header(&mut frame, Some(expected.len() as u64), false)
            .unwrap();
        let whole = cctx.seq_store.whole();
        let size = cctx
            .entropy_compress_seq_store(&mut frame[header + 3..], expected.len(), &whole)
            .unwrap();
        assert!(size > 1);
        write_le24(
            &mut frame,
            header,
            1 + (BT_COMPRESSED << 1) + ((size as u32) << 3),
        );
        frame.truncate(header + 3 + size);
        assert_eq!(
            decompress(&frame, expected.len()).as_deref(),
            Ok(&expected[..])
        );
    }
}
