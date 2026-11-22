//! Doors into the compressor's entropy coders, for `compare/` and the tests: they check the
//! coders against the originals one function at a time, with what a whole frame seldom or
//! never asks of them. Not part of the crate's interface, and free to change.
//!
//! An answer is a size, or the number of the original's error code (`lib/zstd_errors.h`).

use alloc::boxed::Box;
use core::fmt;

use super::common::CError;
use super::fse_compress::{self, FSE_MAX_TABLELOG, FSE_MIN_TABLELOG, FseCTable};
use super::huf_compress::{
    self, HUF_BLOCKSIZE_MAX, HUF_SYMBOLVALUE_MAX, HufCTable, HufCompressTables, HufNbStreams,
    HufRepeat,
};
use super::zstd_compress::Strategy;
use super::zstd_compress_literals::{HufCTables, LiteralOptions, compress_literals};

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
#[must_use]
pub fn strategy_of(level: i32, src_size: usize) -> u32 {
    super::zstd_compress::get_cparams_internal(level, src_size as u64).strategy as u32
}

/// `FSE_optimalTableLog`.
#[must_use]
pub fn fse_optimal_table_log(max_table_log: u32, src_size: usize, max_symbol_value: u32) -> u32 {
    fse_compress::optimal_table_log(
        max_table_log,
        src_size,
        max_symbol_value.min(HUF_SYMBOLVALUE_MAX),
    )
}

/// `FSE_normalizeCount`.
///
/// # Errors
///
/// Returns the numeric `ZSTD_ErrorCode` if `table_log`, `max_symbol_value`, `total`, or the
/// slices / count distribution are out of range or cannot be normalized.
pub fn fse_normalize_count(
    norm: &mut [i16],
    table_log: u32,
    count: &[u32],
    total: usize,
    max_symbol_value: u32,
    use_low_prob_count: bool,
) -> Result<u32, u32> {
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return Err(code(CError::MaxSymbolValueTooLarge));
    }
    if table_log > FSE_MAX_TABLELOG {
        return Err(code(CError::TableLogTooLarge));
    }
    if table_log != 0 && table_log < FSE_MIN_TABLELOG {
        return Err(code(CError::Generic));
    }
    if total == 0 || total > u32::MAX as usize {
        return Err(code(CError::Generic));
    }
    let symbols = max_symbol_value as usize + 1;
    if norm.len() < symbols || count.len() < symbols {
        return Err(code(CError::Generic));
    }
    let sum: u64 = count[..symbols].iter().map(|&c| u64::from(c)).sum();
    if sum != total as u64 {
        return Err(code(CError::Generic));
    }
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
///
/// # Errors
///
/// Returns the numeric `ZSTD_ErrorCode` if `table_log` or `max_symbol_value` is out of
/// range, `norm` is not a valid normalized distribution, or `buffer` is too small.
pub fn fse_write_ncount(
    buffer: &mut [u8],
    norm: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> Result<usize, u32> {
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return Err(code(CError::MaxSymbolValueTooLarge));
    }
    if table_log > FSE_MAX_TABLELOG {
        return Err(code(CError::TableLogTooLarge));
    }
    if table_log < FSE_MIN_TABLELOG {
        return Err(code(CError::Generic));
    }
    let symbols = max_symbol_value as usize + 1;
    if norm.len() < symbols {
        return Err(code(CError::Generic));
    }
    fse_compress::write_ncount(buffer, norm, max_symbol_value, table_log).map_err(code)
}

/// Validates that `norm[..=max_symbol_value]` is a well-formed normalized FSE distribution
/// summing to `1 << table_log`.
fn valid_norm_distribution(norm: &[i16], max_symbol_value: u32, table_log: u32) -> bool {
    if max_symbol_value > HUF_SYMBOLVALUE_MAX
        || !(FSE_MIN_TABLELOG..=FSE_MAX_TABLELOG).contains(&table_log)
    {
        return false;
    }
    let symbols = max_symbol_value as usize + 1;
    if norm.len() < symbols {
        return false;
    }
    let table_size = 1u32 << table_log;
    let mut sum = 0u32;
    for &n in &norm[..symbols] {
        if n < -1 {
            return false;
        }
        let weight = if n == -1 { 1 } else { n as u32 };
        sum = sum.saturating_add(weight);
    }
    sum == table_size
}

/// `FSE_buildCTable_wksp`, then `FSE_compress_usingCTable`.
pub fn fse_compress(
    dst: &mut [u8],
    src: &[u8],
    norm: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> usize {
    if !valid_norm_distribution(norm, max_symbol_value, table_log) {
        return 0;
    }
    if src.len() > 2
        && src
            .iter()
            .any(|&b| u32::from(b) > max_symbol_value || norm[b as usize] == 0)
    {
        return 0;
    }
    let mut ct = FseCTable::new(FSE_MAX_TABLELOG, HUF_SYMBOLVALUE_MAX);
    fse_compress::build_ctable(&mut ct, norm, max_symbol_value, table_log);
    fse_compress::compress_using_ctable(dst, src, &ct)
}

fn repeat_from(number: u32) -> Option<HufRepeat> {
    match number {
        0 => Some(HufRepeat::None),
        1 => Some(HufRepeat::Check),
        2 => Some(HufRepeat::Valid),
        _ => None,
    }
}

/// What `HUF_compress1X_repeat` and `HUF_compress4X_repeat` keep between calls.
pub struct Huf {
    tables: Box<HufCompressTables>,
    old: HufCTable,
}

impl fmt::Debug for Huf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Huf")
            .field("table_log", &(self.old[0] & 0xFF))
            .field("max_symbol_value", &((self.old[0] >> 8) & 0xFF))
            .finish_non_exhaustive()
    }
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
    ///
    /// # Errors
    ///
    /// Returns the numeric `ZSTD_ErrorCode` if `src` exceeds `HUF_BLOCKSIZE_MAX`, `repeat` is
    /// invalid, or writing the table fails.
    pub fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        four: bool,
        repeat: &mut u32,
        prefer_repeat: bool,
        suspect_uncompressible: bool,
    ) -> Result<usize, u32> {
        let Some(mut mode) = repeat_from(*repeat) else {
            return Err(code(CError::Generic));
        };
        if mode == HufRepeat::Valid {
            let table_log = (self.old[0] & 0xFF) as u32;
            let header_max = ((self.old[0] >> 8) & 0xFF) as u32;
            if !(1..=12).contains(&table_log)
                || src.iter().any(|&b| {
                    u32::from(b) > header_max || self.old[1 + b as usize].trailing_zeros() >= 8
                })
            {
                return Err(code(CError::Generic));
            }
        }
        let nb_streams = if four {
            HufNbStreams::Four
        } else {
            HufNbStreams::Single
        };
        let params = huf_compress::HufParams {
            max_symbol_value: HUF_SYMBOLVALUE_MAX,
            max_log: 11,
            nb_streams,
            prefer_repeat,
            suspect_uncompressible,
            optimal_depth: false,
        };
        let answer = huf_compress::compress_repeat(
            dst,
            src,
            params,
            &mut self.tables,
            &mut self.old,
            &mut mode,
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

impl fmt::Debug for Literals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Literals")
            .field("prev_repeat_mode", &self.prev.repeat_mode)
            .field("next_repeat_mode", &self.next.repeat_mode)
            .finish_non_exhaustive()
    }
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
    /// `ZSTD_compressLiterals`, for strategies `1..=9` (`ZSTD_fast` to `ZSTD_btultra2`).
    ///
    /// # Errors
    ///
    /// Returns the numeric `ZSTD_ErrorCode` if `src` exceeds `128 KiB`, `strategy` is outside
    /// `1..=9`, or `dst` is too small.
    pub fn compress(
        &mut self,
        dst: &mut [u8],
        src: &[u8],
        strategy: u32,
        disable_literal_compression: bool,
        suspect_uncompressible: bool,
    ) -> Result<usize, u32> {
        if src.len() > HUF_BLOCKSIZE_MAX {
            return Err(code(CError::SrcSizeWrong));
        }
        let strategy = match strategy {
            1 => Strategy::Fast,
            2 => Strategy::Dfast,
            3 => Strategy::Greedy,
            4 => Strategy::Lazy,
            5 => Strategy::Lazy2,
            6 => Strategy::Btlazy2,
            7 => Strategy::Btopt,
            8 => Strategy::Btultra,
            9 => Strategy::Btultra2,
            _ => return Err(code(CError::Generic)),
        };
        let options = LiteralOptions {
            strategy,
            disable_compression: disable_literal_compression,
            suspect_uncompressible,
        };
        compress_literals(
            dst,
            src,
            &mut self.tables,
            &self.prev,
            &mut self.next,
            options,
        )
        .map_err(code)
    }

    /// The `repeatMode` of the tables for the next block.
    #[must_use]
    pub fn next_repeat_mode(&self) -> u32 {
        self.next.repeat_mode as u32
    }

    /// The tables for the next block become the ones of the block before.
    pub fn keep(&mut self) {
        core::mem::swap(&mut self.prev, &mut self.next);
    }
}
