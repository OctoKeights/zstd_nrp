//! FSE (finite state entropy) coding: a port of `lib/compress/fse_compress.c` of zstd
//! v1.5.7 and of the encoder in `lib/common/fse.h`, as a 64-bit build has them.
//!
//! The original keeps a coding table in one array of 32-bit words: the table's log and its
//! highest symbol, then the state table, then one transform per symbol. Here the three parts
//! are the three fields of [`FseCTable`]. The work areas that the original is handed are
//! local to each function.

use super::bitstream::BitCStream;
use super::common::{CError, CResult, highbit32};

pub(crate) const FSE_MAX_TABLELOG: u32 = 12;
pub(crate) const FSE_MIN_TABLELOG: u32 = 5;
pub(crate) const FSE_DEFAULT_TABLELOG: u32 = 11;
pub(crate) const FSE_NCOUNTBOUND: usize = 512;

/// `FSE_TABLESTEP`.
#[inline]
fn fse_tablestep(table_size: u32) -> u32 {
    (table_size >> 1) + (table_size >> 3) + 3
}

/// `FSE_BLOCKBOUND`.
#[inline]
fn fse_blockbound(size: usize) -> usize {
    size + (size >> 7) + 4 + 8
}

/// `FSE_symbolCompressionTransform`.
#[derive(Clone, Copy, Default)]
pub(crate) struct SymbolTT {
    pub(crate) delta_find_state: i32,
    pub(crate) delta_nb_bits: u32,
}

/// `FSE_CTable`.
#[derive(Clone)]
pub(crate) struct FseCTable {
    pub(crate) table_log: u32,
    pub(crate) max_symbol_value: u32,
    pub(crate) state_table: Vec<u16>,
    pub(crate) symbol_tt: Vec<SymbolTT>,
}

impl FseCTable {
    /// Room for a table of up to `max_table_log` and symbols up to `max_symbol_value`
    /// (`FSE_CTABLE_SIZE_U32`).
    pub(crate) fn new(max_table_log: u32, max_symbol_value: u32) -> FseCTable {
        FseCTable {
            table_log: 0,
            max_symbol_value: 0,
            state_table: vec![0; 1usize << max_table_log],
            symbol_tt: vec![SymbolTT::default(); max_symbol_value as usize + 1],
        }
    }
}

/// `FSE_buildCTable_wksp`.
pub(crate) fn build_ctable(
    ct: &mut FseCTable,
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) {
    let table_size = 1u32 << table_log;
    let table_mask = table_size - 1;
    let step = fse_tablestep(table_size);
    let max_sv1 = max_symbol_value + 1;
    let mut cumul = [0u16; 258];
    let mut table_symbol = vec![0u8; table_size as usize];
    let mut high_threshold = table_size - 1;

    ct.table_log = table_log;
    ct.max_symbol_value = max_symbol_value;

    // Symbol start positions.
    cumul[0] = 0;
    for u in 1..=max_sv1 as usize {
        if normalized_counter[u - 1] == -1 {
            // A low probability symbol.
            cumul[u] = cumul[u - 1].wrapping_add(1);
            table_symbol[high_threshold as usize] = (u - 1) as u8;
            high_threshold = high_threshold.wrapping_sub(1);
        } else {
            cumul[u] = cumul[u - 1].wrapping_add(normalized_counter[u - 1] as u16);
        }
    }
    cumul[max_sv1 as usize] = (table_size + 1) as u16;

    // Spread the symbols.
    if high_threshold == table_size - 1 {
        // No low probability symbol: lay the symbols down in order, then spread them. (The
        // original lays them down eight bytes at a time, writing past each run and over it
        // with the next; what is left is the same.)
        let mut spread = vec![0u8; table_size as usize];
        let mut pos = 0usize;
        for s in 0..max_sv1 as usize {
            let n = normalized_counter[s] as i32;
            if n > 0 {
                spread[pos..pos + n as usize].fill(s as u8);
                pos += n as usize;
            }
        }
        let mut position = 0usize;
        let unroll = 2usize;
        let mut s = 0usize;
        while s < table_size as usize {
            for u in 0..unroll {
                let u_position = (position + (u * step as usize)) & table_mask as usize;
                table_symbol[u_position] = spread[s + u];
            }
            position = (position + (unroll * step as usize)) & table_mask as usize;
            s += unroll;
        }
    } else {
        let mut position = 0u32;
        for symbol in 0..max_sv1 {
            let freq = normalized_counter[symbol as usize] as i32;
            let mut nb_occurrences = 0;
            while nb_occurrences < freq {
                table_symbol[position as usize] = symbol as u8;
                position = (position + step) & table_mask;
                while position > high_threshold {
                    // The low probability area.
                    position = (position + step) & table_mask;
                }
                nb_occurrences += 1;
            }
        }
    }

    // Build the state table.
    for u in 0..table_size {
        let s = table_symbol[u as usize] as usize;
        ct.state_table[cumul[s] as usize] = (table_size + u) as u16;
        cumul[s] = cumul[s].wrapping_add(1);
    }

    // Build the symbol transforms.
    let mut total = 0u32;
    for s in 0..=max_symbol_value as usize {
        match normalized_counter[s] {
            0 => {
                // Filled all the same, for the sake of FSE_getMaxNbBits().
                ct.symbol_tt[s].delta_nb_bits =
                    ((table_log + 1) << 16).wrapping_sub(1 << table_log);
            }
            -1 | 1 => {
                ct.symbol_tt[s].delta_nb_bits = (table_log << 16).wrapping_sub(1 << table_log);
                ct.symbol_tt[s].delta_find_state = total.wrapping_sub(1) as i32;
                total += 1;
            }
            n => {
                let n = n as u32;
                let max_bits_out = table_log - highbit32(n - 1);
                let min_state_plus = n << max_bits_out;
                ct.symbol_tt[s].delta_nb_bits = (max_bits_out << 16).wrapping_sub(min_state_plus);
                ct.symbol_tt[s].delta_find_state = total.wrapping_sub(n) as i32;
                total += n;
            }
        }
    }
}

/// `FSE_NCountWriteBound`.
fn ncount_write_bound(max_symbol_value: u32, table_log: u32) -> usize {
    let max_header_size =
        (((max_symbol_value as usize + 1) * table_log as usize + 4 + 2) / 8) + 1 + 2;
    if max_symbol_value != 0 {
        max_header_size
    } else {
        FSE_NCOUNTBOUND
    }
}

/// `FSE_writeNCount_generic`. `header` is the whole of the room there is.
fn write_ncount_generic(
    header: &mut [u8],
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
    write_is_safe: bool,
) -> CResult<usize> {
    let oend = header.len();
    let mut out = 0usize;
    let table_size = 1i32 << table_log;
    let mut bit_stream = 0u32;
    let mut bit_count = 0i32;
    let mut symbol = 0u32;
    let alphabet_size = max_symbol_value + 1;
    let mut previous_is_0 = false;

    // Table size.
    bit_stream = bit_stream.wrapping_add((table_log - FSE_MIN_TABLELOG) << bit_count);
    bit_count += 4;

    // Init.
    let mut remaining = table_size + 1; // +1 for extra accuracy
    let mut threshold = table_size;
    let mut nb_bits = table_log as i32 + 1;

    while symbol < alphabet_size && remaining > 1 {
        // Stops at 1.
        if previous_is_0 {
            let mut start = symbol;
            while symbol < alphabet_size && normalized_counter[symbol as usize] == 0 {
                symbol += 1;
            }
            if symbol == alphabet_size {
                break; // incorrect distribution
            }
            while symbol >= start + 24 {
                start += 24;
                bit_stream = bit_stream.wrapping_add(0xFFFFu32 << bit_count);
                if !write_is_safe && out + 2 > oend {
                    return Err(CError::DstSizeTooSmall);
                }
                header[out] = bit_stream as u8;
                header[out + 1] = (bit_stream >> 8) as u8;
                out += 2;
                bit_stream >>= 16;
            }
            while symbol >= start + 3 {
                start += 3;
                bit_stream = bit_stream.wrapping_add(3u32 << bit_count);
                bit_count += 2;
            }
            bit_stream = bit_stream.wrapping_add((symbol - start) << bit_count);
            bit_count += 2;
            if bit_count > 16 {
                if !write_is_safe && out + 2 > oend {
                    return Err(CError::DstSizeTooSmall);
                }
                header[out] = bit_stream as u8;
                header[out + 1] = (bit_stream >> 8) as u8;
                out += 2;
                bit_stream >>= 16;
                bit_count -= 16;
            }
        }
        {
            let mut count = normalized_counter[symbol as usize] as i32;
            symbol += 1;
            let max = (2 * threshold - 1) - remaining;
            remaining -= if count < 0 { -count } else { count };
            count += 1; // +1 for extra accuracy
            if count >= threshold {
                count += max; // [0..max[ [max..threshold[ (...) [threshold+max 2*threshold[
            }
            bit_stream = bit_stream.wrapping_add((count as u32) << bit_count);
            bit_count += nb_bits;
            bit_count -= i32::from(count < max);
            previous_is_0 = count == 1;
            if remaining < 1 {
                return Err(CError::Generic);
            }
            while remaining < threshold {
                nb_bits -= 1;
                threshold >>= 1;
            }
        }
        if bit_count > 16 {
            if !write_is_safe && out + 2 > oend {
                return Err(CError::DstSizeTooSmall);
            }
            header[out] = bit_stream as u8;
            header[out + 1] = (bit_stream >> 8) as u8;
            out += 2;
            bit_stream >>= 16;
            bit_count -= 16;
        }
    }

    if remaining != 1 {
        return Err(CError::Generic); // incorrect normalized distribution
    }

    // Flush the remaining bit stream.
    if !write_is_safe && out + 2 > oend {
        return Err(CError::DstSizeTooSmall);
    }
    header[out] = bit_stream as u8;
    header[out + 1] = (bit_stream >> 8) as u8;
    out += ((bit_count + 7) / 8) as usize;

    Ok(out)
}

/// `FSE_writeNCount`: the normalized counts, written the compact way the format has them.
pub(crate) fn write_ncount(
    buffer: &mut [u8],
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> CResult<usize> {
    if table_log > FSE_MAX_TABLELOG {
        return Err(CError::TableLogTooLarge);
    }
    if table_log < FSE_MIN_TABLELOG {
        return Err(CError::Generic);
    }
    if buffer.len() < ncount_write_bound(max_symbol_value, table_log) {
        return write_ncount_generic(
            buffer,
            normalized_counter,
            max_symbol_value,
            table_log,
            false,
        );
    }
    write_ncount_generic(
        buffer,
        normalized_counter,
        max_symbol_value,
        table_log,
        true,
    )
}

/// `FSE_minTableLog`.
fn min_table_log(src_size: usize, max_symbol_value: u32) -> u32 {
    let min_bits_src = highbit32(src_size as u32) + 1;
    let min_bits_symbols = highbit32(max_symbol_value) + 2;
    min_bits_src.min(min_bits_symbols)
}

/// `FSE_optimalTableLog_internal`.
pub(crate) fn optimal_table_log_internal(
    max_table_log: u32,
    src_size: usize,
    max_symbol_value: u32,
    minus: u32,
) -> u32 {
    let max_bits_src = highbit32((src_size - 1) as u32).wrapping_sub(minus);
    let mut table_log = max_table_log;
    let min_bits = min_table_log(src_size, max_symbol_value);
    if table_log == 0 {
        table_log = FSE_DEFAULT_TABLELOG;
    }
    if max_bits_src < table_log {
        table_log = max_bits_src; // accuracy can be reduced
    }
    if min_bits > table_log {
        table_log = min_bits; // need a minimum to safely represent all symbol values
    }
    table_log.clamp(FSE_MIN_TABLELOG, FSE_MAX_TABLELOG)
}

/// `FSE_optimalTableLog`.
pub(crate) fn optimal_table_log(max_table_log: u32, src_size: usize, max_symbol_value: u32) -> u32 {
    optimal_table_log_internal(max_table_log, src_size, max_symbol_value, 2)
}

/// `FSE_normalizeM2`: the second way to normalize, used when the first is too far off.
fn normalize_m2(
    norm: &mut [i16],
    table_log: u32,
    count: &[u32],
    mut total: usize,
    max_symbol_value: u32,
    low_prob_count: i16,
) -> CResult<()> {
    const NOT_YET_ASSIGNED: i16 = -2;
    let mut distributed = 0u32;

    // Init.
    let low_threshold = (total >> table_log) as u32;
    let mut low_one = ((total * 3) >> (table_log + 1)) as u32;

    for s in 0..=max_symbol_value as usize {
        if count[s] == 0 {
            norm[s] = 0;
            continue;
        }
        if count[s] <= low_threshold {
            norm[s] = low_prob_count;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        if count[s] <= low_one {
            norm[s] = 1;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        norm[s] = NOT_YET_ASSIGNED;
    }
    let mut to_distribute = (1u32 << table_log).wrapping_sub(distributed);

    if to_distribute == 0 {
        return Ok(());
    }

    if (total / to_distribute as usize) > low_one as usize {
        // Risk of rounding to zero.
        low_one = ((total * 3) / (to_distribute as usize * 2)) as u32;
        for s in 0..=max_symbol_value as usize {
            if norm[s] == NOT_YET_ASSIGNED && count[s] <= low_one {
                norm[s] = 1;
                distributed += 1;
                total -= count[s] as usize;
            }
        }
        to_distribute = (1u32 << table_log).wrapping_sub(distributed);
    }

    if distributed == max_symbol_value + 1 {
        // All values are pretty poor: all of the rest goes to the largest.
        let mut max_v = 0usize;
        let mut max_c = 0u32;
        for s in 0..=max_symbol_value as usize {
            if count[s] > max_c {
                max_v = s;
                max_c = count[s];
            }
        }
        norm[max_v] = norm[max_v].wrapping_add(to_distribute as i16);
        return Ok(());
    }

    if total == 0 {
        // All of the symbols were low enough for the lowOne or lowThreshold.
        let mut s = 0usize;
        while to_distribute > 0 {
            if norm[s] > 0 {
                to_distribute -= 1;
                norm[s] += 1;
            }
            s = (s + 1) % (max_symbol_value as usize + 1);
        }
        return Ok(());
    }

    {
        let v_step_log = 62 - table_log as u64;
        let mid = (1u64 << (v_step_log - 1)) - 1;
        let r_step = ((1u64 << v_step_log)
            .wrapping_mul(to_distribute as u64)
            .wrapping_add(mid))
            / (total as u32 as u64); // scale on remaining
        let mut tmp_total = mid;
        for s in 0..=max_symbol_value as usize {
            if norm[s] == NOT_YET_ASSIGNED {
                let end = tmp_total.wrapping_add((count[s] as u64).wrapping_mul(r_step));
                let s_start = (tmp_total >> v_step_log) as u32;
                let s_end = (end >> v_step_log) as u32;
                let weight = s_end.wrapping_sub(s_start);
                if weight < 1 {
                    return Err(CError::Generic);
                }
                norm[s] = weight as i16;
                tmp_total = end;
            }
        }
    }

    Ok(())
}

/// `FSE_normalizeCount`: counts brought to a total of `1 << table_log`. The answer is the
/// table log, or 0 when one symbol is all there is (which calls for RLE instead).
pub(crate) fn normalize_count(
    normalized_counter: &mut [i16],
    mut table_log: u32,
    count: &[u32],
    total: usize,
    max_symbol_value: u32,
    use_low_prob_count: bool,
) -> CResult<u32> {
    // Sanity checks.
    if table_log == 0 {
        table_log = FSE_DEFAULT_TABLELOG;
    }
    if table_log < FSE_MIN_TABLELOG {
        return Err(CError::Generic); // unsupported size
    }
    if table_log > FSE_MAX_TABLELOG {
        return Err(CError::TableLogTooLarge); // unsupported size
    }
    if table_log < min_table_log(total, max_symbol_value) {
        return Err(CError::Generic); // too small a table log, the compression may be poor
    }

    {
        const RTB_TABLE: [u32; 8] = [0, 473195, 504333, 520860, 550000, 700000, 750000, 830000];
        let low_prob_count: i16 = if use_low_prob_count { -1 } else { 1 };
        let scale = 62 - table_log as u64;
        let step = (1u64 << 62) / (total as u32 as u64); // <== here, one division!
        let v_step = 1u64 << (scale - 20);
        let mut still_to_distribute = 1i32 << table_log;
        let mut largest = 0usize;
        let mut largest_p: i16 = 0;
        let low_threshold = (total >> table_log) as u32;

        for s in 0..=max_symbol_value as usize {
            if count[s] as usize == total {
                return Ok(0); // rle special case
            }
            if count[s] == 0 {
                normalized_counter[s] = 0;
                continue;
            }
            if count[s] <= low_threshold {
                normalized_counter[s] = low_prob_count;
                still_to_distribute -= 1;
            } else {
                let scaled = (count[s] as u64).wrapping_mul(step);
                let mut proba = (scaled >> scale) as i16;
                if proba < 8 {
                    let rest_to_beat = v_step * RTB_TABLE[proba as usize] as u64;
                    proba += i16::from(scaled.wrapping_sub((proba as u64) << scale) > rest_to_beat);
                }
                if proba > largest_p {
                    largest_p = proba;
                    largest = s;
                }
                normalized_counter[s] = proba;
                still_to_distribute -= proba as i32;
            }
        }
        if -still_to_distribute >= (normalized_counter[largest] as i32 >> 1) {
            // The corner case: another normalization method is needed.
            normalize_m2(
                normalized_counter,
                table_log,
                count,
                total,
                max_symbol_value,
                low_prob_count,
            )?;
        } else {
            normalized_counter[largest] =
                normalized_counter[largest].wrapping_add(still_to_distribute as i16);
        }
    }

    Ok(table_log)
}

/// `FSE_buildCTable_rle`: the table of a single symbol.
pub(crate) fn build_ctable_rle(ct: &mut FseCTable, symbol_value: u8) {
    ct.table_log = 0;
    ct.max_symbol_value = symbol_value as u32;
    ct.state_table[0] = 0;
    ct.state_table[1] = 0; // just in case
    ct.symbol_tt[symbol_value as usize].delta_nb_bits = 0;
    ct.symbol_tt[symbol_value as usize].delta_find_state = 0;
}

/// `FSE_CState_t`.
pub(crate) struct FseCState<'a> {
    value: i64,
    ct: &'a FseCTable,
    state_log: u32,
}

impl<'a> FseCState<'a> {
    /// `FSE_initCState`.
    pub(crate) fn init(ct: &'a FseCTable) -> FseCState<'a> {
        FseCState {
            value: 1i64 << ct.table_log,
            ct,
            state_log: ct.table_log,
        }
    }

    /// `FSE_initCState2`: the state that costs the least to start from, for a first symbol.
    pub(crate) fn init2(ct: &'a FseCTable, symbol: u32) -> FseCState<'a> {
        let mut state = FseCState::init(ct);
        let symbol_tt = ct.symbol_tt[symbol as usize];
        let nb_bits_out = symbol_tt.delta_nb_bits.wrapping_add(1 << 15) >> 16;
        state.value = (nb_bits_out << 16).wrapping_sub(symbol_tt.delta_nb_bits) as i64;
        state.value = ct.state_table
            [((state.value >> nb_bits_out) + symbol_tt.delta_find_state as i64) as usize]
            as i64;
        state
    }

    /// `FSE_encodeSymbol`.
    #[inline]
    pub(crate) fn encode_symbol(&mut self, bit_c: &mut BitCStream, symbol: u32) {
        let symbol_tt = self.ct.symbol_tt[symbol as usize];
        let nb_bits_out = ((self.value + symbol_tt.delta_nb_bits as i64) >> 16) as u32;
        bit_c.add_bits(self.value as u64, nb_bits_out);
        self.value = self.ct.state_table
            [((self.value >> nb_bits_out) + symbol_tt.delta_find_state as i64) as usize]
            as i64;
    }

    /// `FSE_flushCState`.
    pub(crate) fn flush(&self, bit_c: &mut BitCStream) {
        bit_c.add_bits(self.value as u64, self.state_log);
        bit_c.flush_bits();
    }
}

/// `FSE_compress_usingCTable`: 0 if `src` does not come out smaller, or the output is too
/// small.
pub(crate) fn compress_using_ctable(dst: &mut [u8], src: &[u8], ct: &FseCTable) -> usize {
    let fast = dst.len() >= fse_blockbound(src.len());
    let mut src_size = src.len();
    let mut ip = src.len();

    // Init.
    if src_size <= 2 {
        return 0;
    }
    let mut bit_c = match BitCStream::init(dst) {
        Some(bit_c) => bit_c,
        None => return 0, // not enough space available to write a bitstream
    };
    let flush = |bit_c: &mut BitCStream| {
        if fast {
            bit_c.flush_bits_fast()
        } else {
            bit_c.flush_bits()
        }
    };
    let next = |ip: &mut usize| -> u32 {
        *ip -= 1;
        src[*ip] as u32
    };

    let mut c_state1;
    let mut c_state2;
    if src_size & 1 != 0 {
        c_state1 = FseCState::init2(ct, next(&mut ip));
        c_state2 = FseCState::init2(ct, next(&mut ip));
        c_state1.encode_symbol(&mut bit_c, next(&mut ip));
        flush(&mut bit_c);
    } else {
        c_state2 = FseCState::init2(ct, next(&mut ip));
        c_state1 = FseCState::init2(ct, next(&mut ip));
    }

    // Join to a multiple of four.
    src_size -= 2;
    if src_size & 2 != 0 {
        // (A 64-bit container holds four symbols of FSE_MAX_TABLELOG bits.)
        c_state2.encode_symbol(&mut bit_c, next(&mut ip));
        c_state1.encode_symbol(&mut bit_c, next(&mut ip));
        flush(&mut bit_c);
    }

    // Two or four symbols a loop.
    while ip > 0 {
        c_state2.encode_symbol(&mut bit_c, next(&mut ip));
        c_state1.encode_symbol(&mut bit_c, next(&mut ip));
        c_state2.encode_symbol(&mut bit_c, next(&mut ip));
        c_state1.encode_symbol(&mut bit_c, next(&mut ip));
        flush(&mut bit_c);
    }

    c_state2.flush(&mut bit_c);
    c_state1.flush(&mut bit_c);
    bit_c.close()
}
