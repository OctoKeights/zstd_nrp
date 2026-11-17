//! Doors into the compressor's entropy coders, for `compare/` and the tests: they check the
//! coders against the originals one function at a time, with what a whole frame seldom or
//! never asks of them. Not part of the crate's interface, and free to change.
//!
//! An answer is a size, or the number of the original's error code (`lib/zstd_errors.h`).

use super::common::CError;
use super::fse_compress::{self, FseCTable};
use super::huf_compress::{self, HufCTable, HufCompressTables, HufNbStreams, HufRepeat};
use super::zstd_compress::Strategy;
use super::zstd_compress_literals::{HufCTables, compress_literals};

fn code(error: CError) -> u32 {
    match error {
        CError::Generic => 1,
        CError::TableLogTooLarge => 44,
        CError::MaxSymbolValueTooLarge => 46,
        CError::DstSizeTooSmall => 70,
        CError::SrcSizeWrong => 72,
    }
}

/// The number of the strategy (`ZSTD_strategy`) that `level` takes for a source of
/// `src_size` bytes: 1 for `ZSTD_fast` to 9 for `ZSTD_btultra2`.
pub fn strategy_of(level: i32, src_size: usize) -> u32 {
    super::zstd_compress::get_cparams_internal(level, src_size as u64).strategy as u32
}

/// `FSE_optimalTableLog`.
pub fn fse_optimal_table_log(max_table_log: u32, src_size: usize, max_symbol_value: u32) -> u32 {
    fse_compress::optimal_table_log(max_table_log, src_size, max_symbol_value)
}

/// `FSE_normalizeCount`.
pub fn fse_normalize_count(
    norm: &mut [i16],
    table_log: u32,
    count: &[u32],
    total: usize,
    max_symbol_value: u32,
    use_low_prob_count: bool,
) -> Result<u32, u32> {
    fse_compress::normalize_count(
        norm,
        table_log,
        count,
        total,
        max_symbol_value,
        use_low_prob_count,
    )
    .map_err(code)
}

/// `FSE_writeNCount`.
pub fn fse_write_ncount(
    buffer: &mut [u8],
    norm: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> Result<usize, u32> {
    fse_compress::write_ncount(buffer, norm, max_symbol_value, table_log).map_err(code)
}

/// `FSE_buildCTable_wksp`, then `FSE_compress_usingCTable`.
pub fn fse_compress(
    dst: &mut [u8],
    src: &[u8],
    norm: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> usize {
    let mut ct = FseCTable::new(12, 255);
    fse_compress::build_ctable(&mut ct, norm, max_symbol_value, table_log);
    fse_compress::compress_using_ctable(dst, src, &ct)
}

fn repeat_from(number: u32) -> HufRepeat {
    match number {
        0 => HufRepeat::None,
        1 => HufRepeat::Check,
        _ => HufRepeat::Valid,
    }
}

/// What `HUF_compress1X_repeat` and `HUF_compress4X_repeat` keep between calls.
pub struct Huf {
    tables: Box<HufCompressTables>,
    old: HufCTable,
}

impl Default for Huf {
    fn default() -> Huf {
        Huf {
            tables: Box::new(HufCompressTables::new()),
            old: [0; 257],
        }
    }
}

impl Huf {
    /// `HUF_compress4X_repeat` or `HUF_compress1X_repeat`, for every byte value and a table
    /// log of 11. `repeat` is the original's `HUF_repeat`: 0, 1 or 2.
    pub fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        four: bool,
        repeat: &mut u32,
        prefer_repeat: bool,
        suspect_uncompressible: bool,
    ) -> Result<usize, u32> {
        let mut mode = repeat_from(*repeat);
        let nb_streams = if four {
            HufNbStreams::Four
        } else {
            HufNbStreams::Single
        };
        let answer = huf_compress::compress_repeat(
            dst,
            src,
            255,
            11,
            nb_streams,
            &mut self.tables,
            &mut self.old,
            &mut mode,
            prefer_repeat,
            suspect_uncompressible,
            false,
        );
        *repeat = mode as u32;
        answer.map_err(code)
    }
}

/// What `ZSTD_compressLiterals` is handed from one block to the next.
pub struct Literals {
    tables: Box<HufCompressTables>,
    prev: HufCTables,
    next: HufCTables,
}

impl Default for Literals {
    fn default() -> Literals {
        Literals {
            tables: Box::new(HufCompressTables::new()),
            prev: HufCTables {
                ctable: [0; 257],
                repeat_mode: HufRepeat::None,
            },
            next: HufCTables {
                ctable: [0; 257],
                repeat_mode: HufRepeat::None,
            },
        }
    }
}

impl Literals {
    /// `ZSTD_compressLiterals`, for the strategy 1 (`ZSTD_fast`) or 2 (`ZSTD_dfast`).
    pub fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        strategy: u32,
        disable_literal_compression: bool,
        suspect_uncompressible: bool,
    ) -> Result<usize, u32> {
        let strategy = if strategy == 1 {
            Strategy::Fast
        } else {
            Strategy::Dfast
        };
        compress_literals(
            dst,
            src,
            &mut self.tables,
            &self.prev,
            &mut self.next,
            strategy,
            disable_literal_compression,
            suspect_uncompressible,
        )
        .map_err(code)
    }

    /// The `repeatMode` of the tables for the next block.
    pub fn next_repeat_mode(&self) -> u32 {
        self.next.repeat_mode as u32
    }

    /// The tables for the next block become the ones of the block before.
    pub fn keep(&mut self) {
        std::mem::swap(&mut self.prev, &mut self.next);
    }
}
