//! The literals section of a block: a port of `lib/compress/zstd_compress_literals.c` of
//! zstd v1.5.7.

use super::common::{CError, CResult, write_le16, write_le24, write_le32};
use super::huf_compress::{
    self, HUF_SYMBOLVALUE_MAX, HufCTable, HufCompressTables, HufNbStreams, HufRepeat,
};
use super::zstd_compress::{SET_BASIC, SET_COMPRESSED, SET_REPEAT, SET_RLE, Strategy, min_gain};

/// `LitHufLog`.
const LIT_HUF_LOG: u32 = 11;

/// `ZSTD_hufCTables_t`.
#[derive(Clone)]
pub(crate) struct HufCTables {
    pub(crate) ctable: HufCTable,
    pub(crate) repeat_mode: HufRepeat,
}

/// `ZSTD_buildBlockEntropyStats_literals`: for the block splitter's estimates, the kind of
/// literals section the literals `src` would have (`hType`), with its table in `next_huf`;
/// and the size of the table's description (`hufDesSize`).
pub(crate) fn build_block_entropy_stats_literals(
    src: &[u8],
    prev_huf: &HufCTables,
    next_huf: &mut HufCTables,
    literals_compression_is_disabled: bool,
    workspace: &mut HufCompressTables,
    optimal_depth: bool,
) -> CResult<(u32, usize)> {
    let src_size = src.len();
    let mut huff_log = LIT_HUF_LOG;
    let mut repeat = prev_huf.repeat_mode;

    // Prepare nextEntropy assuming reusing the existing table.
    next_huf.clone_from(prev_huf);

    if literals_compression_is_disabled {
        return Ok((SET_BASIC, 0));
    }

    // small ? don't even attempt compression (speed opt)
    {
        const COMPRESS_LITERALS_SIZE_MIN: usize = 63; // heuristic
        let min_lit_size = if prev_huf.repeat_mode == HufRepeat::Valid {
            6
        } else {
            COMPRESS_LITERALS_SIZE_MIN
        };
        if src_size <= min_lit_size {
            return Ok((SET_BASIC, 0));
        }
    }

    // Scan input and build symbol stats.
    let (largest, max_symbol_value) = huf_compress::count_literals(workspace, src);
    if largest == src_size {
        // only one literal symbol
        return Ok((SET_RLE, 0));
    }
    if largest <= (src_size >> 7) + 4 {
        // heuristic: likely not compressible
        return Ok((SET_BASIC, 0));
    }

    // Validate the previous Huffman table.
    if repeat == HufRepeat::Check
        && !huf_compress::counted_fit(workspace, &prev_huf.ctable, max_symbol_value)
    {
        repeat = HufRepeat::None;
    }

    // Build Huffman Tree.
    next_huf.ctable.fill(0);
    huff_log = huf_compress::build_table_for_counts(
        workspace,
        &mut next_huf.ctable,
        src_size,
        max_symbol_value,
        huff_log,
        optimal_depth,
    )?;

    // Build and write the CTable.
    let new_c_size = huf_compress::estimate_counted(workspace, &next_huf.ctable, max_symbol_value);
    let mut huf_des_buffer = [0u8; 128]; // ZSTD_MAX_HUF_HEADER_SIZE
    let h_size = huf_compress::write_table(
        &mut huf_des_buffer,
        &next_huf.ctable,
        max_symbol_value,
        huff_log,
    )?;
    // Check against repeating the previous CTable.
    if repeat != HufRepeat::None {
        let old_c_size =
            huf_compress::estimate_counted(workspace, &prev_huf.ctable, max_symbol_value);
        if old_c_size < src_size && (old_c_size <= h_size + new_c_size || h_size + 12 >= src_size) {
            next_huf.clone_from(prev_huf);
            return Ok((SET_REPEAT, 0));
        }
    }
    if new_c_size + h_size >= src_size {
        next_huf.clone_from(prev_huf);
        return Ok((SET_BASIC, 0));
    }
    next_huf.repeat_mode = HufRepeat::Check;
    Ok((SET_COMPRESSED, h_size))
}

/// `ZSTD_estimateBlockSize_literal`: the size the block splitter estimates for the literals
/// section (header and content) of a block.
pub(crate) fn estimate_block_size_literal(
    literals: &[u8],
    huf: &HufCTables,
    h_type: u32,
    huf_des_size: usize,
    workspace: &mut HufCompressTables,
    write_entropy: bool,
) -> usize {
    let lit_size = literals.len();
    let literal_section_header_size =
        3 + usize::from(lit_size >= 1024) + usize::from(lit_size >= 16 * 1024);
    let single_stream = lit_size < 256;

    match h_type {
        SET_BASIC => lit_size,
        SET_RLE => 1,
        _ => {
            let (_, max_symbol_value) = huf_compress::count_literals(workspace, literals);
            let mut c_lit_size_estimate =
                huf_compress::estimate_counted(workspace, &huf.ctable, max_symbol_value);
            if write_entropy {
                c_lit_size_estimate += huf_des_size;
            }
            if !single_stream {
                c_lit_size_estimate += 6; // multi-stream huffman uses 6-byte jump table
            }
            c_lit_size_estimate + literal_section_header_size
        }
    }
}

/// `ZSTD_noCompressLiterals`: the literals as they are, behind their size.
pub(crate) fn no_compress_literals(dst: &mut [u8], src: &[u8]) -> CResult<usize> {
    let src_size = src.len();
    let fl_size = 1 + usize::from(src_size > 31) + usize::from(src_size > 4095);

    if src_size + fl_size > dst.len() {
        return Err(CError::DstSizeTooSmall);
    }

    match fl_size {
        1 => dst[0] = (SET_BASIC + ((src_size as u32) << 3)) as u8, // 2 - 1 - 5
        2 => write_le16(
            dst,
            0,
            (SET_BASIC + (1 << 2) + ((src_size as u32) << 4)) as u16,
        ), // 2 - 2 - 12
        _ => write_le32(dst, 0, SET_BASIC + (3 << 2) + ((src_size as u32) << 4)), // 2 - 2 - 20
    }

    dst[fl_size..fl_size + src_size].copy_from_slice(src);
    Ok(src_size + fl_size)
}

/// `allBytesIdentical`.
fn all_bytes_identical(src: &[u8]) -> bool {
    let b = src[0];
    src[1..].iter().all(|&x| x == b)
}

/// `ZSTD_compressRleLiteralsBlock`: one byte and how many times it comes.
pub(crate) fn compress_rle_literals_block(dst: &mut [u8], src: &[u8]) -> usize {
    let src_size = src.len();
    let fl_size = 1 + usize::from(src_size > 31) + usize::from(src_size > 4095);

    match fl_size {
        1 => dst[0] = (SET_RLE + ((src_size as u32) << 3)) as u8, // 2 - 1 - 5
        2 => write_le16(
            dst,
            0,
            (SET_RLE + (1 << 2) + ((src_size as u32) << 4)) as u16,
        ), // 2 - 2 - 12
        _ => write_le32(dst, 0, SET_RLE + (3 << 2) + ((src_size as u32) << 4)), // 2 - 2 - 20
    }

    dst[fl_size] = src[0];
    fl_size + 1
}

/// `ZSTD_minLiteralsToCompress`: the fewest literals that are worth a try at compression,
/// which depends on the strategy and on whether there is a table from before.
fn min_literals_to_compress(strategy: Strategy, huf_repeat: HufRepeat) -> usize {
    // btultra2: min 8 bytes; then 2x larger for each successive compression strategy;
    // max threshold 64 bytes.
    let shift = (9 - strategy as i32).min(3);
    if huf_repeat == HufRepeat::Valid {
        6
    } else {
        8usize << shift
    }
}

/// `ZSTD_compressLiterals`: the literals section, Huffman coded where that is smaller.
/// `next_huf` becomes the table to carry to the next block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_literals(
    dst: &mut [u8],
    src: &[u8],
    entropy_workspace: &mut HufCompressTables,
    prev_huf: &HufCTables,
    next_huf: &mut HufCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    suspect_uncompressible: bool,
) -> CResult<usize> {
    let src_size = src.len();
    let dst_capacity = dst.len();
    let lh_size = 3 + usize::from(src_size >= 1024) + usize::from(src_size >= 16 * 1024);
    let mut single_stream = src_size < 256;
    let mut h_type = SET_COMPRESSED;
    let c_lit_size;

    // Prepare nextEntropy assuming reusing the existing table.
    *next_huf = prev_huf.clone();

    if disable_literal_compression {
        return no_compress_literals(dst, src);
    }

    // If too small, don't even attempt compression (speed opt).
    if src_size < min_literals_to_compress(strategy, prev_huf.repeat_mode) {
        return no_compress_literals(dst, src);
    }

    if dst_capacity < lh_size + 1 {
        return Err(CError::DstSizeTooSmall); // not enough space for compression
    }
    {
        let mut repeat = prev_huf.repeat_mode;
        let prefer_repeat = (strategy as u32) < (Strategy::Lazy as u32) && src_size <= 1024;
        if repeat == HufRepeat::Valid && lh_size == 3 {
            single_stream = true;
        }
        let nb_streams = if single_stream {
            HufNbStreams::Single
        } else {
            HufNbStreams::Four
        };
        let result = huf_compress::compress_repeat(
            &mut dst[lh_size..],
            src,
            HUF_SYMBOLVALUE_MAX,
            LIT_HUF_LOG,
            nb_streams,
            entropy_workspace,
            &mut next_huf.ctable,
            &mut repeat,
            prefer_repeat,
            suspect_uncompressible,
            strategy as u32 >= Strategy::Btultra as u32,
        );
        if repeat != HufRepeat::None {
            // Reused the existing table.
            h_type = SET_REPEAT;
        }
        let min_gain = min_gain(src_size, strategy);
        match result {
            Ok(size) if size != 0 && size < src_size - min_gain => c_lit_size = size,
            _ => {
                *next_huf = prev_huf.clone();
                return no_compress_literals(dst, src);
            }
        }
    }
    if c_lit_size == 1 {
        // A return value of 1 signals that the alphabet consists of a single symbol.
        // However, in some rare circumstances, it could be the compressed size (a single
        // byte). For that outcome to have a chance to happen, it's necessary that
        // srcSize < 8 (note that it's also necessary to avoid generating statistics).
        // Therefore, in such a case, actively check that all bytes are identical.
        if src_size >= 8 || all_bytes_identical(src) {
            *next_huf = prev_huf.clone();
            return Ok(compress_rle_literals_block(dst, src));
        }
    }

    if h_type == SET_COMPRESSED {
        // Using a newly constructed table.
        next_huf.repeat_mode = HufRepeat::Check;
    }

    // Build the header.
    match lh_size {
        3 => {
            // 2 - 2 - 10 - 10
            let lhc = h_type
                + (u32::from(!single_stream) << 2)
                + ((src_size as u32) << 4)
                + ((c_lit_size as u32) << 14);
            write_le24(dst, 0, lhc);
        }
        4 => {
            // 2 - 2 - 14 - 14
            let lhc = h_type + (2 << 2) + ((src_size as u32) << 4) + ((c_lit_size as u32) << 18);
            write_le32(dst, 0, lhc);
        }
        _ => {
            // 2 - 2 - 18 - 18
            let lhc = h_type + (3 << 2) + ((src_size as u32) << 4) + ((c_lit_size as u32) << 22);
            write_le32(dst, 0, lhc);
            dst[4] = (c_lit_size >> 10) as u8;
        }
    }
    Ok(lh_size + c_lit_size)
}
