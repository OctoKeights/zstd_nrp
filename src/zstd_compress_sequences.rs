//! The sequences section of a block: a port of `lib/compress/zstd_compress_sequences.c` of
//! zstd v1.5.7, as a 64-bit build has it.
//!
//! Below `ZSTD_lazy` a table is chosen by rules of thumb; from `ZSTD_lazy` up, by weighing
//! the cost of each kind of table against the others.

use super::bitstream::BitCStream;
use super::common::{CError, CResult};
use super::fse_compress::{self, FseCState, FseCTable, SymbolTT};
use super::hist;
use super::zstd_compress::{SET_BASIC, SET_COMPRESSED, SET_REPEAT, SET_RLE, SeqDef, Strategy};

pub(crate) const MAX_ML: u32 = 52;
pub(crate) const MAX_LL: u32 = 35;
pub(crate) const DEFAULT_MAX_OFF: u32 = 28;
pub(crate) const MAX_OFF: u32 = 31;
/// `MaxSeq`: the most symbols a sequence table has.
pub(crate) const MAX_SEQ: usize = 52;
pub(crate) const ML_FSE_LOG: u32 = 9;
pub(crate) const LL_FSE_LOG: u32 = 9;
pub(crate) const OFF_FSE_LOG: u32 = 8;

pub(crate) const LL_BITS: [u8; MAX_LL as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
pub(crate) const LL_DEFAULT_NORM: [i16; MAX_LL as usize + 1] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
pub(crate) const LL_DEFAULT_NORM_LOG: u32 = 6;

#[rustfmt::skip]
pub(crate) const ML_BITS: [u8; MAX_ML as usize + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
#[rustfmt::skip]
pub(crate) const ML_DEFAULT_NORM: [i16; MAX_ML as usize + 1] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
pub(crate) const ML_DEFAULT_NORM_LOG: u32 = 6;

pub(crate) const OF_DEFAULT_NORM: [i16; DEFAULT_MAX_OFF as usize + 1] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
pub(crate) const OF_DEFAULT_NORM_LOG: u32 = 5;

/// `FSE_repeat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FseRepeat {
    /// Cannot use the previous table.
    None,
    /// Can use the previous table, but it must be checked.
    Check,
    /// Can use the previous table and it is assumed to be valid.
    Valid,
}

/// `ZSTD_useLowProbCount`: whether to use counts of -1, "less than one". They help with
/// many sequences, and hurt with few.
fn use_low_prob_count(nb_seq: usize) -> bool {
    // Heuristic: this should cover most blocks <= 16K and start to fade out after 16K to
    // about 32K depending on compressibility.
    nb_seq >= 2048
}

/// `kInverseProbabilityLog256`: `-log2(x / 256) * 256`, rounded down, for `x` in
/// `[0, 256)` (and 0 for 0).
#[rustfmt::skip]
const K_INVERSE_PROBABILITY_LOG256: [u32; 256] = [
    0,    2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162,
    1130, 1100, 1073, 1047, 1024, 1001, 980,  960,  941,  923,  906,  889,
    874,  859,  844,  830,  817,  804,  791,  779,  768,  756,  745,  734,
    724,  714,  704,  694,  685,  676,  667,  658,  650,  642,  633,  626,
    618,  610,  603,  595,  588,  581,  574,  567,  561,  554,  548,  542,
    535,  529,  523,  517,  512,  506,  500,  495,  489,  484,  478,  473,
    468,  463,  458,  453,  448,  443,  438,  434,  429,  424,  420,  415,
    411,  407,  402,  398,  394,  390,  386,  382,  377,  373,  370,  366,
    362,  358,  354,  350,  347,  343,  339,  336,  332,  329,  325,  322,
    318,  315,  311,  308,  305,  302,  298,  295,  292,  289,  286,  282,
    279,  276,  273,  270,  267,  264,  261,  258,  256,  253,  250,  247,
    244,  241,  239,  236,  233,  230,  228,  225,  222,  220,  217,  215,
    212,  209,  207,  204,  202,  199,  197,  194,  192,  190,  187,  185,
    182,  180,  178,  175,  173,  171,  168,  166,  164,  162,  159,  157,
    155,  153,  151,  149,  146,  144,  142,  140,  138,  136,  134,  132,
    130,  128,  126,  123,  121,  119,  117,  115,  114,  112,  110,  108,
    106,  104,  102,  100,  98,   96,   94,   93,   91,   89,   87,   85,
    83,   82,   80,   78,   76,   74,   73,   71,   69,   67,   66,   64,
    62,   61,   59,   57,   55,   54,   52,   50,   49,   47,   46,   44,
    42,   41,   39,   37,   36,   34,   33,   31,   30,   28,   26,   25,
    23,   22,   20,   19,   17,   16,   14,   13,   11,   10,   8,    7,
    5,    4,    2,    1,
];

/// A cost the original cannot work out: its `ERROR(GENERIC)`, larger than any cost.
pub(crate) const COST_ERROR: usize = usize::MAX;

/// `ZSTD_NCountCost`: the cost in bytes of the description of the table of `count`.
fn ncount_cost(count: &[u32], max: u32, nb_seq: usize, fse_log: u32) -> usize {
    let mut norm = [0i16; MAX_SEQ + 1];
    let mut wksp = [0u8; 512]; // FSE_NCOUNTBOUND
    let table_log = fse_compress::optimal_table_log(fse_log, nb_seq, max);
    if fse_compress::normalize_count(
        &mut norm,
        table_log,
        count,
        nb_seq,
        max,
        use_low_prob_count(nb_seq),
    )
    .is_err()
    {
        return COST_ERROR;
    }
    fse_compress::write_ncount(&mut wksp, &norm, max, table_log).unwrap_or(COST_ERROR)
}

/// `ZSTD_entropyCost`: the cost in bits of the symbols of `count` at the bound of entropy.
pub(crate) fn entropy_cost(count: &[u32], max: u32, total: usize) -> usize {
    let mut cost = 0u32;
    for &c in &count[..=max as usize] {
        let mut norm = ((256 * c as usize) / total) as u32;
        if c != 0 && norm == 0 {
            norm = 1;
        }
        cost = cost.wrapping_add(c.wrapping_mul(K_INVERSE_PROBABILITY_LOG256[norm as usize]));
    }
    (cost >> 8) as usize
}

/// `ZSTD_fseBitCost`: the cost in bits of the symbols of `count` with `ctable`, or
/// [`COST_ERROR`] where it cannot code one of them.
pub(crate) fn fse_bit_cost(ctable: &FseCTable, count: &[u32], max: u32) -> usize {
    const K_ACCURACY_LOG: u32 = 8;
    let mut cost = 0usize;
    // `FSE_initCState`.
    let table_log = ctable.table_log;
    if ctable.max_symbol_value < max {
        return COST_ERROR;
    }
    let symbols = max as usize + 1;
    for (tt, &count) in ctable.symbol_tt[..symbols].iter().zip(&count[..symbols]) {
        let bad_cost = (table_log + 1) << K_ACCURACY_LOG;
        // `FSE_bitCost`.
        let bit_cost = {
            let delta_nb_bits = tt.delta_nb_bits;
            let min_nb_bits = delta_nb_bits >> 16;
            let threshold = (min_nb_bits + 1) << 16;
            let table_size = 1u32 << table_log;
            let delta_from_threshold =
                threshold.wrapping_sub(delta_nb_bits.wrapping_add(table_size));
            // linear interpolation (very approximate)
            let normalized_delta_from_threshold =
                (delta_from_threshold << K_ACCURACY_LOG) >> table_log;
            let bit_multiplier = 1u32 << K_ACCURACY_LOG;
            ((min_nb_bits + 1) * bit_multiplier).wrapping_sub(normalized_delta_from_threshold)
        };
        if count == 0 {
            continue;
        }
        if bit_cost >= bad_cost {
            return COST_ERROR;
        }
        cost += count as usize * bit_cost as usize;
    }
    cost >> K_ACCURACY_LOG
}

/// `ZSTD_crossEntropyCost`: the cost in bits of the symbols of `count` with the table of
/// `norm`.
pub(crate) fn cross_entropy_cost(
    norm: &[i16],
    accuracy_log: u32,
    count: &[u32],
    max: u32,
) -> usize {
    let shift = 8 - accuracy_log;
    let mut cost = 0usize;
    for s in 0..=max as usize {
        let norm_acc = if norm[s] == -1 { 1 } else { norm[s] as u32 };
        let norm256 = norm_acc << shift;
        cost += count[s] as usize * K_INVERSE_PROBABILITY_LOG256[norm256 as usize] as usize;
    }
    cost >> 8
}

const DEFAULT_LL_CTABLE: (
    [u16; 1 << LL_DEFAULT_NORM_LOG],
    [SymbolTT; MAX_LL as usize + 1],
) = fse_compress::build_static_ctable(&LL_DEFAULT_NORM, LL_DEFAULT_NORM_LOG);
const DEFAULT_OF_CTABLE: (
    [u16; 1 << OF_DEFAULT_NORM_LOG],
    [SymbolTT; DEFAULT_MAX_OFF as usize + 1],
) = fse_compress::build_static_ctable(&OF_DEFAULT_NORM, OF_DEFAULT_NORM_LOG);
const DEFAULT_ML_CTABLE: (
    [u16; 1 << ML_DEFAULT_NORM_LOG],
    [SymbolTT; MAX_ML as usize + 1],
) = fse_compress::build_static_ctable(&ML_DEFAULT_NORM, ML_DEFAULT_NORM_LOG);

/// What zstd fixes for one of the three codes of the sequences: literal lengths, offsets or
/// match lengths.
pub(crate) struct SymbolType {
    /// The largest code.
    pub(crate) max: u32,
    /// The largest log a table of them may have.
    pub(crate) fse_log: u32,
    /// The predefined distribution, its log and its largest code.
    pub(crate) default_norm: &'static [i16],
    pub(crate) default_norm_log: u32,
    pub(crate) default_max: u32,
    /// Precomputed `FseCTable` arrays for `SET_BASIC`.
    pub(crate) default_state_table: &'static [u16],
    pub(crate) default_symbol_tt: &'static [SymbolTT],
    /// The extra bits after each code; none for offsets, whose code is their number.
    pub(crate) extra_bits: Option<&'static [u8]>,
}

/// Literal lengths.
pub(crate) const LITERAL_LENGTHS: SymbolType = SymbolType {
    max: MAX_LL,
    fse_log: LL_FSE_LOG,
    default_norm: &LL_DEFAULT_NORM,
    default_norm_log: LL_DEFAULT_NORM_LOG,
    default_max: MAX_LL,
    default_state_table: &DEFAULT_LL_CTABLE.0,
    default_symbol_tt: &DEFAULT_LL_CTABLE.1,
    extra_bits: Some(&LL_BITS),
};

/// Offsets.
pub(crate) const OFFSETS: SymbolType = SymbolType {
    max: MAX_OFF,
    fse_log: OFF_FSE_LOG,
    default_norm: &OF_DEFAULT_NORM,
    default_norm_log: OF_DEFAULT_NORM_LOG,
    default_max: DEFAULT_MAX_OFF,
    default_state_table: &DEFAULT_OF_CTABLE.0,
    default_symbol_tt: &DEFAULT_OF_CTABLE.1,
    extra_bits: None,
};

/// Match lengths.
pub(crate) const MATCH_LENGTHS: SymbolType = SymbolType {
    max: MAX_ML,
    fse_log: ML_FSE_LOG,
    default_norm: &ML_DEFAULT_NORM,
    default_norm_log: ML_DEFAULT_NORM_LOG,
    default_max: MAX_ML,
    default_state_table: &DEFAULT_ML_CTABLE.0,
    default_symbol_tt: &DEFAULT_ML_CTABLE.1,
    extra_bits: Some(&ML_BITS),
};

/// The codes of one kind in a block, counted: `count` up to `max`, the largest code there.
pub(crate) struct Histogram<'a> {
    pub(crate) count: &'a mut [u32],
    pub(crate) max: u32,
    /// The count of the most frequent code.
    pub(crate) most_frequent: usize,
    /// How many codes were counted.
    pub(crate) nb_seq: usize,
}

/// The table of one code: the previous block's, with its repeat mode, and the next block's,
/// being made.
pub(crate) struct TableState<'a> {
    pub(crate) prev: &'a FseCTable,
    pub(crate) prev_repeat: FseRepeat,
    pub(crate) next: &'a mut FseCTable,
    pub(crate) next_repeat: &'a mut FseRepeat,
}

/// `ZSTD_selectEncodingType`: the kind of table for one of the three codes of the
/// sequences, counted in `histogram`.
pub(crate) fn select_encoding_type(
    kind: &SymbolType,
    repeat_mode: &mut FseRepeat,
    prev_ctable: &FseCTable,
    histogram: &Histogram<'_>,
    is_default_allowed: bool,
    strategy: Strategy,
) -> u32 {
    let (count, max) = (&*histogram.count, histogram.max);
    let (most_frequent, nb_seq) = (histogram.most_frequent, histogram.nb_seq);
    let (default_norm, default_norm_log) = (kind.default_norm, kind.default_norm_log);
    if most_frequent == nb_seq {
        *repeat_mode = FseRepeat::None;
        if is_default_allowed && nb_seq <= 2 {
            // Prefer set_basic over set_rle when there are 2 or fewer symbols, since RLE
            // uses 1 byte, but it is possible to do it in fewer bits with set_basic.
            return SET_BASIC;
        }
        return SET_RLE;
    }
    if (strategy as u32) < (Strategy::Lazy as u32) {
        if is_default_allowed {
            let static_fse_nb_seq_max = 1000usize;
            let mult = 10 - strategy as usize;
            let base_log = 3usize;
            // 28-36 for offset, 56-72 for lengths
            let dynamic_fse_nb_seq_min = ((1usize << default_norm_log) * mult) >> base_log;
            if *repeat_mode == FseRepeat::Valid && nb_seq < static_fse_nb_seq_max {
                return SET_REPEAT;
            }
            if nb_seq < dynamic_fse_nb_seq_min || most_frequent < (nb_seq >> (default_norm_log - 1))
            {
                // The format allows default tables to be repeated, but it isn't useful. When
                // using simple heuristics to select the encoding type, default tables are never
                // repeated; a new block always starts from them afresh.
                *repeat_mode = FseRepeat::None;
                return SET_BASIC;
            }
        }
    } else {
        let basic_cost = if is_default_allowed {
            cross_entropy_cost(default_norm, default_norm_log, count, max)
        } else {
            COST_ERROR
        };
        let repeat_cost = if *repeat_mode == FseRepeat::None {
            COST_ERROR
        } else {
            fse_bit_cost(prev_ctable, count, max)
        };
        let ncount_cost = ncount_cost(count, max, nb_seq, kind.fse_log);
        let compressed_cost = (ncount_cost << 3).wrapping_add(entropy_cost(count, max, nb_seq));

        if basic_cost <= repeat_cost && basic_cost <= compressed_cost {
            *repeat_mode = FseRepeat::None;
            return SET_BASIC;
        }
        if repeat_cost <= compressed_cost {
            return SET_REPEAT;
        }
    }
    *repeat_mode = FseRepeat::Check;
    SET_COMPRESSED
}

/// `ZSTD_buildCTable`: the table of the chosen kind in `next_ctable`, and what describes it
/// in `dst`. `code_table` holds the codes counted in `histogram`. The answer is the size of
/// the description.
pub(crate) fn build_ctable(
    dst: &mut [u8],
    next_ctable: &mut FseCTable,
    prev_ctable: &FseCTable,
    kind: &SymbolType,
    encoding_type: u32,
    histogram: &mut Histogram<'_>,
    code_table: &[u8],
) -> CResult<usize> {
    let (max, nb_seq) = (histogram.max, histogram.nb_seq);
    let count = &mut *histogram.count;
    match encoding_type {
        SET_RLE => {
            fse_compress::build_ctable_rle(next_ctable, max as u8);
            if dst.is_empty() {
                return Err(CError::DstSizeTooSmall); // not enough space
            }
            dst[0] = code_table[0];
            Ok(1)
        }
        SET_REPEAT => {
            next_ctable.clone_from(prev_ctable);
            Ok(0)
        }
        SET_BASIC => {
            next_ctable.table_log = kind.default_norm_log;
            next_ctable.max_symbol_value = kind.default_max;
            next_ctable.state_table[..kind.default_state_table.len()]
                .copy_from_slice(kind.default_state_table);
            next_ctable.symbol_tt[..kind.default_symbol_tt.len()]
                .copy_from_slice(kind.default_symbol_tt);
            Ok(0)
        }
        _ => {
            let mut norm = [0i16; MAX_SEQ + 1];
            let mut nb_seq_1 = nb_seq;
            let table_log = fse_compress::optimal_table_log(kind.fse_log, nb_seq, max);
            if count[code_table[nb_seq - 1] as usize] > 1 {
                count[code_table[nb_seq - 1] as usize] -= 1;
                nb_seq_1 -= 1;
            }
            fse_compress::normalize_count(
                &mut norm,
                table_log,
                count,
                nb_seq_1,
                max,
                use_low_prob_count(nb_seq_1),
            )?;
            {
                // overflow protected
                let n_count_size = fse_compress::write_ncount(dst, &norm, max, table_log)?;
                fse_compress::build_ctable(next_ctable, &norm, max, table_log);
                Ok(n_count_size)
            }
        }
    }
}

/// One code's table for a block: counts `codes` (in `count`), chooses the kind of table,
/// builds it in `tables.next` and writes what describes it to `dst`. Returns the kind and
/// the size of the description.
pub(crate) fn encode_symbol_table(
    kind: &SymbolType,
    codes: &[u8],
    TableState {
        prev,
        prev_repeat,
        next,
        next_repeat,
    }: TableState<'_>,
    count: &mut [u32],
    strategy: Strategy,
    dst: &mut [u8],
) -> CResult<(u32, usize)> {
    let mut max = kind.max;
    let most_frequent = hist::count_simple(count, &mut max, codes) as usize;
    let mut histogram = Histogram {
        count,
        max,
        most_frequent,
        nb_seq: codes.len(),
    };
    // The predefined table holds only codes up to its own largest (which matters for
    // offsets alone).
    let is_default_allowed = max <= kind.default_max;
    *next_repeat = prev_repeat;
    let encoding_type = select_encoding_type(
        kind,
        next_repeat,
        prev,
        &histogram,
        is_default_allowed,
        strategy,
    );
    let size = build_ctable(dst, next, prev, kind, encoding_type, &mut histogram, codes)?;
    Ok((encoding_type, size))
}

/// The table of one code and the codes that use it.
pub(crate) struct CodedSymbols<'a> {
    pub(crate) ctable: &'a FseCTable,
    pub(crate) codes: &'a [u8],
}

/// `ZSTD_encodeSequences`: the sequences as one bit stream, last sequence first, with the
/// three codes of each and their tables; `sequences` holds their values.
pub(crate) fn encode_sequences(
    dst: &mut [u8],
    match_lengths: &CodedSymbols<'_>,
    offsets: &CodedSymbols<'_>,
    literal_lengths: &CodedSymbols<'_>,
    sequences: &[SeqDef],
) -> CResult<usize> {
    let (ctable_match_length, ml_code_table) = (match_lengths.ctable, match_lengths.codes);
    let (ctable_offset_bits, of_code_table) = (offsets.ctable, offsets.codes);
    let (ctable_lit_length, ll_code_table) = (literal_lengths.ctable, literal_lengths.codes);
    let nb_seq = sequences.len();
    let Some(mut block_stream) = BitCStream::init(dst) else {
        return Err(CError::DstSizeTooSmall);
    };

    // First symbols.
    let mut state_match_length =
        FseCState::init2(ctable_match_length, u32::from(ml_code_table[nb_seq - 1]));
    let mut state_offset_bits =
        FseCState::init2(ctable_offset_bits, u32::from(of_code_table[nb_seq - 1]));
    let mut state_lit_length =
        FseCState::init2(ctable_lit_length, u32::from(ll_code_table[nb_seq - 1]));
    block_stream.add_bits(
        u64::from(sequences[nb_seq - 1].lit_length),
        u32::from(LL_BITS[ll_code_table[nb_seq - 1] as usize]),
    );
    block_stream.add_bits(
        u64::from(sequences[nb_seq - 1].ml_base),
        u32::from(ML_BITS[ml_code_table[nb_seq - 1] as usize]),
    );
    // (A 64-bit build never has offsets too long for one go: the window stops at 2^31.)
    add_offset_bits(
        &mut block_stream,
        sequences[nb_seq - 1].off_base,
        u32::from(of_code_table[nb_seq - 1]),
    );
    block_stream.flush_bits();

    for n in (0..nb_seq - 1).rev() {
        let ll_code = ll_code_table[n];
        let of_code = of_code_table[n];
        let ml_code = ml_code_table[n];
        let ll_bits = u32::from(LL_BITS[ll_code as usize]);
        let of_bits = u32::from(of_code);
        let ml_bits = u32::from(ML_BITS[ml_code as usize]);
        // 32b*/64b*
        // (7)*/(7)*
        state_offset_bits.encode_symbol(&mut block_stream, u32::from(of_code)); // 15*/15*
        state_match_length.encode_symbol(&mut block_stream, u32::from(ml_code)); // 24*/24*
        state_lit_length.encode_symbol(&mut block_stream, u32::from(ll_code)); // 16*/33*
        if of_bits + ml_bits + ll_bits >= 64 - 7 - (LL_FSE_LOG + ML_FSE_LOG + OFF_FSE_LOG) {
            block_stream.flush_bits(); // (7)
        }
        block_stream.add_bits(u64::from(sequences[n].lit_length), ll_bits);
        block_stream.add_bits(u64::from(sequences[n].ml_base), ml_bits);
        if of_bits + ml_bits + ll_bits > 56 {
            block_stream.flush_bits();
        }
        add_offset_bits(&mut block_stream, sequences[n].off_base, of_bits); // 31
        block_stream.flush_bits(); // (7)
    }

    state_match_length.flush(&mut block_stream);
    state_offset_bits.flush(&mut block_stream);
    state_lit_length.flush(&mut block_stream);

    {
        let stream_size = block_stream.close();
        if stream_size == 0 {
            return Err(CError::DstSizeTooSmall); // not enough space
        }
        Ok(stream_size)
    }
}

/// The offset's bits. `BIT_addBits` takes fewer than 32 bits at a time, and an offset code
/// is 31 at most.
#[inline]
fn add_offset_bits(block_stream: &mut BitCStream, off_base: u32, of_bits: u32) {
    block_stream.add_bits(u64::from(off_base), of_bits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precomputed_set_basic_tables_match_runtime_build_ctable() {
        for kind in [&LITERAL_LENGTHS, &OFFSETS, &MATCH_LENGTHS] {
            let mut runtime = FseCTable::new(kind.fse_log, kind.max);
            fse_compress::build_ctable(
                &mut runtime,
                kind.default_norm,
                kind.default_max,
                kind.default_norm_log,
            );
            let table_size = 1usize << kind.default_norm_log;
            let symbols = kind.default_max as usize + 1;
            assert_eq!(&runtime.state_table[..table_size], kind.default_state_table);
            assert_eq!(&runtime.symbol_tt[..symbols], kind.default_symbol_tt);
        }
    }
}
