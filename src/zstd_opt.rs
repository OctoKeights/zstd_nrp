//! The optimal block compressors: a port of `lib/compress/zstd_opt.c` of zstd v1.5.7, for a
//! block with no dictionary (`ZSTD_compressBlock_btopt`, `_btultra` and `_btultra2`).
//!
//! They find every match from each place with a binary tree (and, for matches of three
//! bytes, a hash table of their own), price each way of covering the next bytes with
//! matches and literals from statistics of the sequences so far, and take the cheapest way
//! over a stretch before they go on. `btultra2` makes a first pass over the first block to
//! seed its statistics, then forgets it.
//!
//! The original works with pointers; here a place is an offset into the whole input, and a
//! byte at `pos` has the index `pos + base`.

// (The arithmetic is written as the original has it.)
#![allow(clippy::implicit_saturating_sub, clippy::manual_is_multiple_of)]

use super::common::{highbit32, read32};
use super::hist;
use super::zstd_compress::{
    MatchState, OptMatch, OptState, Optimal, PriceType, RawSeq, RawSeqPos, SeqStore, ZSTD_OPT_NUM,
    count, get_lowest_match_index, hash_ptr, hash3_ptr, ll_code, ml_code, offset_to_offbase,
    update_rep,
};
use super::zstd_compress_sequences::{LL_BITS, MAX_LL, MAX_ML, MAX_OFF, ML_BITS};

/// `ZSTD_LITFREQ_ADD`: scaling factor for litFreq, so that frequencies adapt faster to new
/// stats.
const ZSTD_LITFREQ_ADD: u32 = 2;
const ZSTD_MAX_PRICE: i32 = 1 << 30;

/// `ZSTD_PREDEF_THRESHOLD`: if srcSize < ZSTD_PREDEF_THRESHOLD, symbols' cost is assumed
/// static, directly determined by pre-defined distributions.
const ZSTD_PREDEF_THRESHOLD: usize = 8;

const BITCOST_ACCURACY: u32 = 8;
const BITCOST_MULTIPLIER: u32 = 1 << BITCOST_ACCURACY;

const ZSTD_BLOCKSIZE_MAX: u32 = 1 << 17;
const MINMATCH: u32 = 3;
const ZSTD_REP_NUM: u32 = 3;

/// `ZSTD_bitWeight`: estimated "cost" of a stat in full bits only.
#[inline]
fn bit_weight(stat: u32) -> u32 {
    highbit32(stat + 1) * BITCOST_MULTIPLIER
}

/// `ZSTD_fracWeight`: fractional-bit "cost" of a stat, using linear interpolation
/// approximation.
#[inline]
fn frac_weight(raw_stat: u32) -> u32 {
    let stat = raw_stat + 1;
    let hb = highbit32(stat);
    let b_weight = hb * BITCOST_MULTIPLIER;
    // Fweight was meant for "Fractional weight" but it's effectively a value between 1 and 2
    // using fixed point arithmetic.
    let f_weight = (stat << BITCOST_ACCURACY) >> hb;
    b_weight + f_weight
}

/// `WEIGHT`: opt==approx, ultra==accurate.
#[inline]
fn weight(stat: u32, opt_level: i32) -> u32 {
    if opt_level != 0 {
        frac_weight(stat)
    } else {
        bit_weight(stat)
    }
}

// (`ZSTD_compressedLiterals`: the literals are compressed, there being no setting that says
// otherwise.)

/// `ZSTD_setBasePrices`.
fn set_base_prices(opt: &mut OptState, opt_level: i32) {
    opt.lit_sum_base_price = weight(opt.lit_sum, opt_level);
    opt.lit_length_sum_base_price = weight(opt.lit_length_sum, opt_level);
    opt.match_length_sum_base_price = weight(opt.match_length_sum, opt_level);
    opt.off_code_sum_base_price = weight(opt.off_code_sum, opt_level);
}

/// `ZSTD_downscaleStats`, with `base_1guaranteed` or not.
fn downscale_stats(table: &mut [u32], last_elt_index: u32, shift: u32, base1: bool) -> u32 {
    let mut sum = 0u32;
    for stat in &mut table[..=last_elt_index as usize] {
        let base = if base1 { 1 } else { u32::from(*stat > 0) };
        let new_stat = base + (*stat >> shift);
        sum += new_stat;
        *stat = new_stat;
    }
    sum
}

/// `ZSTD_scaleStats`: reduce all elt frequencies in table if sum too large; return the
/// resulting sum of elements.
fn scale_stats(table: &mut [u32], last_elt_index: u32, log_target: u32) -> u32 {
    let prevsum: u32 = table[..=last_elt_index as usize].iter().sum();
    let factor = prevsum >> log_target;
    if factor <= 1 {
        return prevsum;
    }
    downscale_stats(table, last_elt_index, highbit32(factor), true)
}

/// `ZSTD_rescaleFreqs`: on the first block (`lit_length_sum == 0`), the statistics to start
/// from, the literals' from the block itself; on the others, the statistics so far scaled
/// down, to seed the next block's.
fn rescale_freqs(opt: &mut OptState, block: &[u8], opt_level: i32) {
    opt.price_type = PriceType::Dynamic;

    if opt.lit_length_sum == 0 {
        // no literals stats collected -> first block assumed -> init

        // heuristic: use pre-defined stats for too small inputs
        if block.len() <= ZSTD_PREDEF_THRESHOLD {
            opt.price_type = PriceType::Predef;
        }

        // (The tables of a dictionary, a previous block's Huffman table being valid, are not
        // there to take hints from: a first block has no previous block.)

        // first block, no dictionary
        {
            // base initial cost of literals on direct frequency within src
            let mut lit = 255u32;
            // use raw first block to init statistics
            hist::count_simple(&mut opt.lit_freq, &mut lit, block);
            opt.lit_sum = downscale_stats(&mut opt.lit_freq, 255, 8, false);
        }

        {
            #[rustfmt::skip]
            const BASE_LL_FREQS: [u32; MAX_LL as usize + 1] = [
                4, 2, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ];
            opt.lit_length_freq = BASE_LL_FREQS;
            opt.lit_length_sum = BASE_LL_FREQS.iter().sum();
        }

        opt.match_length_freq = [1; MAX_ML as usize + 1];
        opt.match_length_sum = MAX_ML + 1;

        {
            #[rustfmt::skip]
            const BASE_OFC_FREQS: [u32; MAX_OFF as usize + 1] = [
                6, 2, 1, 1, 2, 3, 4, 4,
                4, 3, 2, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
            ];
            opt.off_code_freq = BASE_OFC_FREQS;
            opt.off_code_sum = BASE_OFC_FREQS.iter().sum();
        }
    } else {
        // new block : scale down accumulated statistics
        opt.lit_sum = scale_stats(&mut opt.lit_freq, 255, 12);
        opt.lit_length_sum = scale_stats(&mut opt.lit_length_freq, MAX_LL, 11);
        opt.match_length_sum = scale_stats(&mut opt.match_length_freq, MAX_ML, 11);
        opt.off_code_sum = scale_stats(&mut opt.off_code_freq, MAX_OFF, 11);
    }

    set_base_prices(opt, opt_level);
}

/// `ZSTD_rawLiteralsCost`: price of literals (only) in specified segment (which length can
/// be 0). Does not include price of literalLength symbol.
fn raw_literals_cost(literals: &[u8], opt: &OptState, opt_level: i32) -> u32 {
    let lit_length = literals.len() as u32;
    if lit_length == 0 {
        return 0;
    }

    if opt.price_type == PriceType::Predef {
        return (lit_length * 6) * BITCOST_MULTIPLIER; // 6 bit per literal - no statistic used
    }

    // dynamic statistics
    let mut price = opt.lit_sum_base_price.wrapping_mul(lit_length);
    let lit_price_max = opt.lit_sum_base_price - BITCOST_MULTIPLIER;
    for &lit in literals {
        let mut lit_price = weight(opt.lit_freq[lit as usize], opt_level);
        if lit_price > lit_price_max {
            lit_price = lit_price_max;
        }
        price = price.wrapping_sub(lit_price);
    }
    price
}

/// `ZSTD_litLengthPrice`: cost of literalLength symbol.
fn lit_length_price(lit_length: u32, opt: &OptState, opt_level: i32) -> u32 {
    if opt.price_type == PriceType::Predef {
        return weight(lit_length, opt_level);
    }

    // ZSTD_LLcode() can't compute litLength price for sizes >= ZSTD_BLOCKSIZE_MAX because it
    // isn't representable in the zstd format. So instead just pretend it would cost 1 bit
    // more than ZSTD_BLOCKSIZE_MAX - 1. In such a case, the block would be all literals.
    if lit_length == ZSTD_BLOCKSIZE_MAX {
        return BITCOST_MULTIPLIER + lit_length_price(ZSTD_BLOCKSIZE_MAX - 1, opt, opt_level);
    }

    // dynamic statistics
    let ll_code = ll_code(lit_length);
    (u32::from(LL_BITS[ll_code as usize]) * BITCOST_MULTIPLIER)
        .wrapping_add(opt.lit_length_sum_base_price)
        .wrapping_sub(weight(opt.lit_length_freq[ll_code as usize], opt_level))
}

/// `ZSTD_getMatchPrice`: the cost of the match part (offset + matchLength) of a sequence.
/// `opt_level` below 2 favors small offsets for decompression speed.
#[inline]
fn get_match_price(off_base: u32, match_length: u32, opt: &OptState, opt_level: i32) -> u32 {
    let off_code = highbit32(off_base);
    let ml_base = match_length - MINMATCH;

    if opt.price_type == PriceType::Predef {
        // fixed scheme, does not use statistics
        return weight(ml_base, opt_level) + ((16 + off_code) * BITCOST_MULTIPLIER);
        // emulated offset cost
    }

    // dynamic statistics
    let mut price = (off_code * BITCOST_MULTIPLIER).wrapping_add(
        opt.off_code_sum_base_price
            .wrapping_sub(weight(opt.off_code_freq[off_code as usize], opt_level)),
    );
    if opt_level < 2 && off_code >= 20 {
        // handicap for long distance offsets, favor decompression speed
        price = price.wrapping_add((off_code - 19) * 2 * BITCOST_MULTIPLIER);
    }

    // match Length
    {
        let ml_code = ml_code(ml_base);
        price = price.wrapping_add(
            (u32::from(ML_BITS[ml_code as usize]) * BITCOST_MULTIPLIER).wrapping_add(
                opt.match_length_sum_base_price
                    .wrapping_sub(weight(opt.match_length_freq[ml_code as usize], opt_level)),
            ),
        );
    }

    // heuristic : make matches a bit more costly to
    // favor less sequences -> faster decompression speed
    price.wrapping_add(BITCOST_MULTIPLIER / 5)
}

/// `ZSTD_updateStats`.
fn update_stats(opt: &mut OptState, literals: &[u8], off_base: u32, match_length: u32) {
    let lit_length = literals.len() as u32;
    // literals
    for &lit in literals {
        opt.lit_freq[lit as usize] += ZSTD_LITFREQ_ADD;
    }
    opt.lit_sum += lit_length * ZSTD_LITFREQ_ADD;

    // literal Length
    {
        let ll_code = ll_code(lit_length);
        opt.lit_length_freq[ll_code as usize] += 1;
        opt.lit_length_sum += 1;
    }

    // offset code : follows storeSeq() numeric representation
    {
        let off_code = highbit32(off_base);
        opt.off_code_freq[off_code as usize] += 1;
        opt.off_code_sum += 1;
    }

    // match Length
    {
        let ml_base = match_length - MINMATCH;
        let ml_code = ml_code(ml_base);
        opt.match_length_freq[ml_code as usize] += 1;
        opt.match_length_sum += 1;
    }
}

/// `ZSTD_readMINMATCH`: for comparisons only.
#[inline]
fn read_minmatch(src: &[u8], pos: usize, length: u32) -> u32 {
    if length == 3 {
        read32(src, pos) << 8
    } else {
        read32(src, pos)
    }
}

/// `ZSTD_newRep`: the repeat offsets after a sequence.
#[inline]
fn new_rep(mut rep: [u32; 3], off_base: u32, ll0: bool) -> [u32; 3] {
    update_rep(&mut rep, off_base, ll0);
    rep
}

/// `ZSTD_insertAndFindFirstIndexHash3`: update hashTable3 up to ip (excluded).
fn insert_and_find_first_index_hash3(
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    ip: usize,
) -> u32 {
    let hash_log3 = ms.hash_log3;
    let base = ms.window.base as usize;
    let mut idx = *next_to_update3;
    let target = (ip + base) as u32;
    let hash3 = hash3_ptr(src, ip, hash_log3);

    while idx < target {
        ms.hash_table3[hash3_ptr(src, idx as usize - base, hash_log3)] = idx;
        idx += 1;
    }

    *next_to_update3 = target;
    ms.hash_table3[hash3]
}

/// A place in the binary tree that is written to, or none (`dummy32`).
const NOWHERE: usize = usize::MAX;

/// `ZSTD_insertBt1`: add one or multiple positions to the tree; `ip` is assumed to be no
/// further than `iend - 8`, and `target` is where the update goes to. The answer is the
/// number of positions added.
fn insert_bt1(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    iend: usize,
    target: u32,
    mls: u32,
) -> u32 {
    let hash_log = ms.cparams.hash_log;
    let h = hash_ptr(src, ip, hash_log, mls);
    let bt_log = ms.cparams.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut match_index = ms.hash_table[h];
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let base = ms.window.base as usize;
    let curr = (ip + base) as u32;
    let bt_low = if bt_mask >= curr { 0 } else { curr - bt_mask };
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // windowLow is based on target because we only need positions that will be in the
    // window at the end of the tree update.
    let window_low = get_lowest_match_index(ms, target, ms.cparams.window_log);
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 8usize;
    let mut nb_compares = 1u32 << ms.cparams.search_log;

    ms.hash_table[h] = curr; // Update Hash Table
    let bt = &mut ms.chain_table;

    while nb_compares != 0 && match_index >= window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // guaranteed minimum nb of common bytes
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize - base;
        match_length += count(src, ip + match_length, m + match_length, iend);

        if match_length > best_length {
            best_length = match_length;
            if match_length as u32 > match_end_idx - match_index {
                match_end_idx = match_index + match_length as u32;
            }
        }

        if ip + match_length == iend {
            // equal : no way to know if inf or sup
            // drop, to guarantee consistency; miss a bit of
            // compression, but other solutions can corrupt tree
            break;
        }

        if src[m + match_length] < src[ip + match_length] {
            // necessarily within buffer
            // match is smaller than current
            // update smaller idx
            bt[smaller_ptr] = match_index;
            // all smaller will now have at least this guaranteed common length
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_ptr = NOWHERE;
                break; // beyond tree size, stop searching
            }
            // new "candidate" => larger than match, which was smaller than target
            smaller_ptr = next_ptr + 1;
            // new matchIndex, larger than previous and closer to current
            match_index = bt[next_ptr + 1];
        } else {
            // match is larger than current
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_ptr = NOWHERE;
                break; // beyond tree size, stop searching
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    if smaller_ptr != NOWHERE {
        bt[smaller_ptr] = 0;
    }
    if larger_ptr != NOWHERE {
        bt[larger_ptr] = 0;
    }
    let mut positions = 0u32;
    if best_length > 384 {
        positions = 192u32.min((best_length - 384) as u32); // speed optimization
    }
    positions.max(match_end_idx - (curr + 8))
}

/// `ZSTD_updateTree_internal`: every place up to `ip` into the tree.
fn update_tree_internal(ms: &mut MatchState, src: &[u8], ip: usize, iend: usize, mls: u32) {
    let base = ms.window.base as usize;
    let target = (ip + base) as u32;
    let mut idx = ms.next_to_update;

    while idx < target {
        let forward = insert_bt1(ms, src, idx as usize - base, iend, target, mls);
        idx += forward;
    }
    ms.next_to_update = target;
}

/// `ZSTD_insertBtAndGetAllMatches`: the matches from `ip`, from the repeat offsets and the
/// tree, each longer than the one before; with `ip` put into the tree. The answer is how
/// many there are, in `matches`.
#[allow(clippy::too_many_arguments)]
fn insert_bt_and_get_all_matches(
    matches: &mut [OptMatch],
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    ip: usize,
    i_limit: usize,
    rep: &[u32; 3],
    ll0: bool,
    length_to_beat: u32,
    mls: u32,
) -> u32 {
    let sufficient_len = ms.cparams.target_length.min(ZSTD_OPT_NUM - 1);
    let base = ms.window.base as usize;
    let curr = (ip + base) as u32;
    let hash_log = ms.cparams.hash_log;
    let min_match = if mls == 3 { 3 } else { 4 };
    let h = hash_ptr(src, ip, hash_log, mls);
    let mut match_index = ms.hash_table[h];
    let bt_log = ms.cparams.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let dict_limit = ms.window.dict_limit;
    let bt_low = if bt_mask >= curr { 0 } else { curr - bt_mask };
    let window_low = get_lowest_match_index(ms, curr, ms.cparams.window_log);
    let match_low = if window_low != 0 { window_low } else { 1 };
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // farthest referenced position of any match => detects repetitive patterns
    let mut match_end_idx = curr + 8 + 1;
    let mut mnum = 0u32;
    let mut nb_compares = 1u32 << ms.cparams.search_log;
    let mut best_length = (length_to_beat - 1) as usize;

    // check repCode
    {
        let ll0 = u32::from(ll0);
        let last_r = ZSTD_REP_NUM + ll0;
        for rep_code in ll0..last_r {
            let rep_offset = if rep_code == ZSTD_REP_NUM {
                rep[0].wrapping_sub(1)
            } else {
                rep[rep_code as usize]
            };
            let rep_index = curr.wrapping_sub(rep_offset);
            let mut rep_len = 0u32;
            if rep_offset.wrapping_sub(1) /* intentional overflow, discards 0 and -1 */ < curr - dict_limit
            {
                // equivalent to `curr > repIndex >= dictLimit`
                if rep_index >= window_low
                    && read_minmatch(src, ip, min_match)
                        == read_minmatch(src, ip - rep_offset as usize, min_match)
                {
                    rep_len = count(
                        src,
                        ip + min_match as usize,
                        ip + min_match as usize - rep_offset as usize,
                        i_limit,
                    ) as u32
                        + min_match;
                }
            }
            // (Else repIndex < dictLimit || repIndex >= curr: there is no dictionary.)
            // save longer solution
            if rep_len as usize > best_length {
                best_length = rep_len as usize;
                matches[mnum as usize] = OptMatch {
                    off: rep_code - ll0 + 1,
                    len: rep_len,
                }; // expect value between 1 and 3
                mnum += 1;
                if rep_len > sufficient_len || ip + rep_len as usize == i_limit {
                    // best possible
                    return mnum;
                }
            }
        }
    }

    // HC3 match finder
    if mls == 3 && best_length < mls as usize {
        let match_index3 = insert_and_find_first_index_hash3(ms, next_to_update3, src, ip);
        if match_index3 >= match_low && curr - match_index3 < (1 << 18) {
            // heuristic : longer distance likely too expensive
            let mlen = count(src, ip, match_index3 as usize - base, i_limit);

            // save best solution
            if mlen >= mls as usize {
                // == 3 > bestLength
                best_length = mlen;
                matches[0] = OptMatch {
                    off: offset_to_offbase(curr - match_index3),
                    len: mlen as u32,
                };
                mnum = 1;
                if mlen > sufficient_len as usize || ip + mlen == i_limit {
                    // best possible length
                    ms.next_to_update = curr + 1; // skip insertion
                    return 1;
                }
            }
        }
        // no dictMatchState lookup: dicts don't have a populated HC3 table
    }

    ms.hash_table[h] = curr; // Update Hash Table
    let bt = &mut ms.chain_table;

    while nb_compares != 0 && match_index >= match_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // guaranteed minimum nb of common bytes
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize - base;
        match_length += count(src, ip + match_length, m + match_length, i_limit);

        if match_length > best_length {
            if match_length as u32 > match_end_idx - match_index {
                match_end_idx = match_index + match_length as u32;
            }
            best_length = match_length;
            matches[mnum as usize] = OptMatch {
                off: offset_to_offbase(curr - match_index),
                len: match_length as u32,
            };
            mnum += 1;
            if match_length > ZSTD_OPT_NUM as usize || ip + match_length == i_limit {
                // equal : no way to know if inf or sup
                break; // drop, to preserve bt consistency (miss a little bit of compression)
            }
        }

        if src[m + match_length] < src[ip + match_length] {
            // match smaller than current
            // update smaller idx
            bt[smaller_ptr] = match_index;
            // all smaller will now have at least this guaranteed common length
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_ptr = NOWHERE;
                break; // beyond tree size, stop the search
            }
            // new candidate => larger than match, which was smaller than current
            smaller_ptr = next_ptr + 1;
            // new matchIndex, larger than previous, closer to current
            match_index = bt[next_ptr + 1];
        } else {
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_ptr = NOWHERE;
                break; // beyond tree size, stop the search
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    if smaller_ptr != NOWHERE {
        bt[smaller_ptr] = 0;
    }
    if larger_ptr != NOWHERE {
        bt[larger_ptr] = 0;
    }

    ms.next_to_update = match_end_idx - 8; // skip repetitive patterns
    mnum
}

/// `ZSTD_btGetAllMatches_internal`, with no dictionary.
#[allow(clippy::too_many_arguments)]
#[inline]
fn bt_get_all_matches(
    matches: &mut [OptMatch],
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    ip: usize,
    i_high_limit: usize,
    rep: &[u32; 3],
    ll0: bool,
    length_to_beat: u32,
    mls: u32,
) -> u32 {
    if ip + (ms.window.base as usize) < ms.next_to_update as usize {
        return 0; // skipped area
    }
    update_tree_internal(ms, src, ip, i_high_limit, mls);
    insert_bt_and_get_all_matches(
        matches,
        ms,
        next_to_update3,
        src,
        ip,
        i_high_limit,
        rep,
        ll0,
        length_to_beat,
        mls,
    )
}

// ---------- LDM helper functions ----------

/// `ZSTD_optLdm_t`: what is needed to make the decision about a long-distance match.
struct OptLdm<'a> {
    /// External match candidates store for this block.
    seq: &'a [RawSeq],
    at: RawSeqPos,
    /// Start position of the current match candidate.
    start_pos_in_block: u32,
    /// End position of the current match candidate.
    end_pos_in_block: u32,
    /// Offset of the match candidate.
    offset: u32,
}

impl OptLdm<'_> {
    /// `ZSTD_optLdm_skipRawSeqStoreBytes`: moves forward in the store by `nb_bytes`.
    fn skip_raw_seq_store_bytes(&mut self, nb_bytes: usize) {
        let mut curr_pos = (self.at.pos_in_sequence + nb_bytes) as u32;
        while curr_pos != 0 && self.at.pos < self.seq.len() {
            let curr_seq = self.seq[self.at.pos];
            if curr_pos >= curr_seq.lit_length + curr_seq.match_length {
                curr_pos -= curr_seq.lit_length + curr_seq.match_length;
                self.at.pos += 1;
            } else {
                self.at.pos_in_sequence = curr_pos as usize;
                break;
            }
        }
        if curr_pos == 0 || self.at.pos == self.seq.len() {
            self.at.pos_in_sequence = 0;
        }
    }

    /// `ZSTD_opt_getNextMatchAndUpdateSeqStore`: the beginning and end of the next match in
    /// the current block.
    fn get_next_match_and_update_seq_store(
        &mut self,
        curr_pos_in_block: u32,
        block_bytes_remaining: u32,
    ) {
        // Setting match end position to MAX to ensure we never use an LDM during this block.
        if self.seq.is_empty() || self.at.pos >= self.seq.len() {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            return;
        }
        // Calculate appropriate bytes left in matchLength and litLength after adjusting
        // based on ldmSeqStore->posInSequence.
        let curr_seq = self.seq[self.at.pos];
        let curr_block_end_pos = curr_pos_in_block + block_bytes_remaining;
        let pos_in_sequence = self.at.pos_in_sequence as u32;
        let literals_bytes_remaining = if pos_in_sequence < curr_seq.lit_length {
            curr_seq.lit_length - pos_in_sequence
        } else {
            0
        };
        let match_bytes_remaining = if literals_bytes_remaining == 0 {
            curr_seq.match_length - (pos_in_sequence - curr_seq.lit_length)
        } else {
            curr_seq.match_length
        };

        // If there are more literal bytes than bytes remaining in block, no ldm is possible.
        if literals_bytes_remaining >= block_bytes_remaining {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            self.skip_raw_seq_store_bytes(block_bytes_remaining as usize);
            return;
        }

        // Matches may be < minMatch by this process. In that case, we will reject them when
        // we are deciding whether or not to add the ldm.
        self.start_pos_in_block = curr_pos_in_block + literals_bytes_remaining;
        self.end_pos_in_block = self.start_pos_in_block + match_bytes_remaining;
        self.offset = curr_seq.offset;

        if self.end_pos_in_block > curr_block_end_pos {
            // Match ends after the block ends, we can't use the whole match.
            self.end_pos_in_block = curr_block_end_pos;
            self.skip_raw_seq_store_bytes((curr_block_end_pos - curr_pos_in_block) as usize);
        } else {
            // Consume nb of bytes equal to size of sequence left.
            self.skip_raw_seq_store_bytes(
                (literals_bytes_remaining + match_bytes_remaining) as usize,
            );
        }
    }

    /// `ZSTD_optLdm_maybeAddMatch`: adds a match if it's long enough, keeping the order of
    /// `matches`.
    fn maybe_add_match(
        &self,
        matches: &mut [OptMatch],
        nb_matches: &mut u32,
        curr_pos_in_block: u32,
        min_match: u32,
    ) {
        let pos_diff = curr_pos_in_block.wrapping_sub(self.start_pos_in_block);
        // Note: ZSTD_match_t actually contains offBase
        // and matchLength (before subtracting MINMATCH).
        let candidate_match_length = self
            .end_pos_in_block
            .wrapping_sub(self.start_pos_in_block)
            .wrapping_sub(pos_diff);

        // Ensure that current block position is not outside of the match.
        if curr_pos_in_block < self.start_pos_in_block
            || curr_pos_in_block >= self.end_pos_in_block
            || candidate_match_length < min_match
        {
            return;
        }

        if *nb_matches == 0
            || (candidate_match_length > matches[*nb_matches as usize - 1].len
                && *nb_matches < ZSTD_OPT_NUM)
        {
            let candidate_off_base = offset_to_offbase(self.offset);
            matches[*nb_matches as usize] = OptMatch {
                off: candidate_off_base,
                len: candidate_match_length,
            };
            *nb_matches += 1;
        }
    }

    /// `ZSTD_optLdm_processMatchCandidate`: the store updated and the match added as needed.
    fn process_match_candidate(
        &mut self,
        matches: &mut [OptMatch],
        nb_matches: &mut u32,
        curr_pos_in_block: u32,
        remaining_bytes: u32,
        min_match: u32,
    ) {
        if self.seq.is_empty() || self.at.pos >= self.seq.len() {
            return;
        }

        if curr_pos_in_block >= self.end_pos_in_block {
            if curr_pos_in_block > self.end_pos_in_block {
                // The position at which ZSTD_optLdm_processMatchCandidate() is called is not
                // necessarily at the end of a match from the ldm seq store, and will often be
                // some bytes over beyond matchEndPosInBlock. As such, we need to correct for
                // these "overshoots".
                let pos_overshoot = curr_pos_in_block - self.end_pos_in_block;
                self.skip_raw_seq_store_bytes(pos_overshoot as usize);
            }
            self.get_next_match_and_update_seq_store(curr_pos_in_block, remaining_bytes);
        }
        self.maybe_add_match(matches, nb_matches, curr_pos_in_block, min_match);
    }
}

// ---------- Optimal parser ----------

/// `ZSTD_compressBlock_opt_generic`, with no dictionary: the sequences of the block
/// `src[istart..istart + src_size]` go to `seq_store`. `opt_level` is 0 for `btopt` and 2
/// for `btultra`; `ldm` the long-distance matches for the block, if there are any. The
/// answer is how many bytes at the end of the block no sequence covers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_block_opt(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
    opt_level: i32,
    ldm: (&[RawSeq], RawSeqPos),
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    let iend = istart + src_size;
    let ilimit = iend as isize - 8;
    let base = ms.window.base as usize;
    let prefix_start = ms.window.dict_limit as usize - base;

    let sufficient_len = ms.cparams.target_length.min(ZSTD_OPT_NUM - 1);
    let min_match = if ms.cparams.min_match == 3 { 3 } else { 4 };
    let mls = ms.cparams.min_match.clamp(3, 6);
    let mut next_to_update3 = ms.next_to_update;

    // (The two tables, taken out of the state while the parser uses it.)
    let mut opt = std::mem::take(&mut ms.opt.price_table);
    let mut matches = std::mem::take(&mut ms.opt.match_table);
    let mut last_stretch = Optimal::default();
    let mut opt_ldm = OptLdm {
        seq: ldm.0,
        at: ldm.1,
        start_pos_in_block: 0,
        end_pos_in_block: 0,
        offset: 0,
    };

    opt_ldm.get_next_match_and_update_seq_store((ip - istart) as u32, (iend - ip) as u32);

    // init
    rescale_freqs(&mut ms.opt, &src[istart..iend], opt_level);
    ip += usize::from(ip == prefix_start);

    let lit_price = |opt_state: &OptState, pos: usize| {
        raw_literals_cost(&src[pos..pos + 1], opt_state, opt_level) as i32
    };
    let ll_price = |opt_state: &OptState, lit_length: u32| {
        lit_length_price(lit_length, opt_state, opt_level) as i32
    };
    let ll_incprice = |opt_state: &OptState, lit_length: u32| {
        ll_price(opt_state, lit_length) - ll_price(opt_state, lit_length - 1)
    };

    // Match Loop
    'outer: while (ip as isize) < ilimit {
        let mut cur: u32;
        let mut last_pos: u32;

        'forward: {
            // find first match
            {
                let litlen = (ip - anchor) as u32;
                let ll0 = litlen == 0;
                let mut nb_matches = bt_get_all_matches(
                    &mut matches,
                    ms,
                    &mut next_to_update3,
                    src,
                    ip,
                    iend,
                    rep,
                    ll0,
                    min_match,
                    mls,
                );
                opt_ldm.process_match_candidate(
                    &mut matches,
                    &mut nb_matches,
                    (ip - istart) as u32,
                    (iend - ip) as u32,
                    min_match,
                );
                if nb_matches == 0 {
                    ip += 1;
                    continue 'outer;
                }

                // Match found: let's store this solution, and eventually find more
                // candidates. During this forward pass, @opt is used to store stretches,
                // defined as "a match followed by N literals". Note how this is different
                // from a Sequence, which is "N literals followed by a match". Storing
                // stretches allows us to store different match predecessors for each
                // literal position part of a literals run.

                // initialize opt[0]
                opt[0].mlen = 0; // there are only literals so far
                opt[0].litlen = litlen;
                // No need to include the actual price of the literals before the first match
                // because it is static for the duration of the forward pass, and is included
                // in every subsequent price. But, we include the literal length because the
                // cost variation of litlen depends on the value of litlen.
                opt[0].price = ll_price(&ms.opt, litlen);
                opt[0].rep = *rep;

                // large match -> immediate encoding
                {
                    let max_ml = matches[nb_matches as usize - 1].len;
                    let max_off_base = matches[nb_matches as usize - 1].off;

                    if max_ml > sufficient_len {
                        last_stretch.litlen = 0;
                        last_stretch.mlen = max_ml;
                        last_stretch.off = max_off_base;
                        cur = 0;
                        last_pos = max_ml;
                        break 'forward;
                    }
                }

                // set prices for first matches starting position == 0
                {
                    let mut pos = 1u32;
                    while pos < min_match {
                        opt[pos as usize].price = ZSTD_MAX_PRICE;
                        opt[pos as usize].mlen = 0;
                        opt[pos as usize].litlen = litlen + pos;
                        pos += 1;
                    }
                    for match_nb in 0..nb_matches as usize {
                        let off_base = matches[match_nb].off;
                        let end = matches[match_nb].len;
                        while pos <= end {
                            let match_price =
                                get_match_price(off_base, pos, &ms.opt, opt_level) as i32;
                            let sequence_price = opt[0].price + match_price;
                            let o = &mut opt[pos as usize];
                            o.mlen = pos;
                            o.off = off_base;
                            o.litlen = 0; // end of match
                            o.price = sequence_price + ll_price(&ms.opt, 0);
                            pos += 1;
                        }
                    }
                    last_pos = pos - 1;
                    opt[pos as usize].price = ZSTD_MAX_PRICE;
                }
            }

            // check further positions
            cur = 1;
            while cur <= last_pos {
                let c = cur as usize;
                let inr = ip + c;

                // Fix current position with one literal if cheaper
                {
                    let litlen = opt[c - 1].litlen + 1;
                    let price = opt[c - 1].price
                        + lit_price(&ms.opt, ip + c - 1)
                        + ll_incprice(&ms.opt, litlen);
                    if price <= opt[c].price {
                        let prev_match = opt[c];
                        opt[c] = opt[c - 1];
                        opt[c].litlen = litlen;
                        opt[c].price = price;
                        if opt_level >= 1 // additional check only for higher modes
                            && prev_match.litlen == 0 // replace a match
                            && ll_incprice(&ms.opt, 1) < 0 // ll1 is cheaper than ll0
                            && ip + c < iend
                        {
                            // check next position, in case it would be cheaper
                            let with1literal = prev_match.price
                                + lit_price(&ms.opt, ip + c)
                                + ll_incprice(&ms.opt, 1);
                            let with_more_literals = price
                                + lit_price(&ms.opt, ip + c)
                                + ll_incprice(&ms.opt, litlen + 1);
                            if with1literal < with_more_literals && with1literal < opt[c + 1].price
                            {
                                // update offset history - before it disappears
                                let prev = (cur - prev_match.mlen) as usize;
                                let new_reps =
                                    new_rep(opt[prev].rep, prev_match.off, opt[prev].litlen == 0);
                                opt[c + 1] = prev_match; // mlen & offbase
                                opt[c + 1].rep = new_reps;
                                opt[c + 1].litlen = 1;
                                opt[c + 1].price = with1literal;
                                if last_pos < cur + 1 {
                                    last_pos = cur + 1;
                                }
                            }
                        }
                    }
                }

                // Offset history is not updated during match comparison. Do it here, now that
                // the match is selected and confirmed.
                if opt[c].litlen == 0 {
                    // just finished a match => alter offset history
                    let prev = (cur - opt[c].mlen) as usize;
                    let new_reps = new_rep(opt[prev].rep, opt[c].off, opt[prev].litlen == 0);
                    opt[c].rep = new_reps;
                }

                // last match must start at a minimum distance of 8 from oend
                if inr as isize > ilimit {
                    cur += 1;
                    continue;
                }

                if cur == last_pos {
                    break;
                }

                if opt_level == 0
                    && opt[c + 1].price <= opt[c].price + (BITCOST_MULTIPLIER / 2) as i32
                {
                    cur += 1;
                    continue; // skip unpromising positions; about ~+6% speed, -0.01 ratio
                }

                {
                    let ll0 = opt[c].litlen == 0;
                    let previous_price = opt[c].price;
                    let base_price = previous_price + ll_price(&ms.opt, 0);
                    let reps = opt[c].rep;
                    let mut nb_matches = bt_get_all_matches(
                        &mut matches,
                        ms,
                        &mut next_to_update3,
                        src,
                        inr,
                        iend,
                        &reps,
                        ll0,
                        min_match,
                        mls,
                    );

                    opt_ldm.process_match_candidate(
                        &mut matches,
                        &mut nb_matches,
                        (inr - istart) as u32,
                        (iend - inr) as u32,
                        min_match,
                    );

                    if nb_matches == 0 {
                        cur += 1;
                        continue;
                    }

                    {
                        let longest_ml = matches[nb_matches as usize - 1].len;
                        if longest_ml > sufficient_len
                            || cur + longest_ml >= ZSTD_OPT_NUM
                            || ip + (cur + longest_ml) as usize >= iend
                        {
                            last_stretch.mlen = longest_ml;
                            last_stretch.off = matches[nb_matches as usize - 1].off;
                            last_stretch.litlen = 0;
                            last_pos = cur + longest_ml;
                            break 'forward;
                        }
                    }

                    // set prices using matches found at position == cur
                    for match_nb in 0..nb_matches as usize {
                        let offset = matches[match_nb].off;
                        let last_ml = matches[match_nb].len;
                        let start_ml = if match_nb > 0 {
                            matches[match_nb - 1].len + 1
                        } else {
                            min_match
                        };
                        let mut mlen = last_ml;
                        while mlen >= start_ml {
                            // scan downward
                            let pos = cur + mlen;
                            let price = base_price
                                + get_match_price(offset, mlen, &ms.opt, opt_level) as i32;

                            if pos > last_pos || price < opt[pos as usize].price {
                                while last_pos < pos {
                                    // fill empty positions, for future comparisons
                                    last_pos += 1;
                                    opt[last_pos as usize].price = ZSTD_MAX_PRICE;
                                    // just needs to be != 0, to mean "not an end of match"
                                    opt[last_pos as usize].litlen = 1;
                                }
                                let o = &mut opt[pos as usize];
                                o.mlen = mlen;
                                o.off = offset;
                                o.litlen = 0;
                                o.price = price;
                            } else if opt_level == 0 {
                                // early update abort; gets ~+10% speed for about -0.01 ratio loss
                                break;
                            }
                            mlen -= 1;
                        }
                    }
                }
                opt[last_pos as usize + 1].price = ZSTD_MAX_PRICE;
                cur += 1;
            } // for (cur = 1; cur <= last_pos; cur++)

            last_stretch = opt[last_pos as usize];
            cur = last_pos - last_stretch.mlen;
        }

        // _shortestPath: cur, last_pos, best_mlen, best_off have to be set
        if last_stretch.mlen == 0 {
            // no solution : all matches have been converted into literals
            ip += last_pos as usize;
            continue;
        }

        // Update offset history
        if last_stretch.litlen == 0 {
            // finishing on a match : update offset history
            *rep = new_rep(
                opt[cur as usize].rep,
                last_stretch.off,
                opt[cur as usize].litlen == 0,
            );
        } else {
            *rep = last_stretch.rep;
            cur -= last_stretch.litlen;
        }

        // Let's write the shortest path solution. It is stored in @opt in reverse order,
        // starting from @storeEnd (==cur+2), effectively partially @opt overwriting.
        // Content is changed too:
        // - So far, @opt stored stretches, aka a match followed by literals
        // - Now, it will store sequences, aka literals followed by a match
        {
            let store_end = cur as usize + 2;
            let mut store_start;
            let mut stretch_pos = cur as usize;

            if last_stretch.litlen > 0 {
                // last "sequence" is unfinished: just a bunch of literals
                opt[store_end].litlen = last_stretch.litlen;
                opt[store_end].mlen = 0;
                store_start = store_end - 1;
                opt[store_start] = last_stretch;
            }
            {
                opt[store_end] = last_stretch; // note: litlen will be fixed
                store_start = store_end;
            }
            loop {
                let next_stretch = opt[stretch_pos];
                opt[store_start].litlen = next_stretch.litlen;
                if next_stretch.mlen == 0 {
                    // reaching beginning of segment
                    break;
                }
                store_start -= 1;
                opt[store_start] = next_stretch; // note: litlen will be fixed
                stretch_pos -= (next_stretch.litlen + next_stretch.mlen) as usize;
            }

            // save sequences
            for store_pos in store_start..=store_end {
                let llen = opt[store_pos].litlen as usize;
                let mlen = opt[store_pos].mlen;
                let off_base = opt[store_pos].off;
                let advance = llen + mlen as usize;
                if mlen == 0 {
                    // only literals => must be last "sequence", actually starting a new
                    // stream of sequences
                    // last "sequence" is a bunch of literals => don't progress anchor
                    ip = anchor + llen;
                    continue; // will finish
                }

                update_stats(&mut ms.opt, &src[anchor..anchor + llen], off_base, mlen);
                seq_store.store_seq(src, anchor, llen, off_base, mlen as usize);
                anchor += advance;
                ip = anchor;
            }

            // update all costs
            set_base_prices(&mut ms.opt, opt_level);
        }
    } // while (ip < ilimit)

    ms.opt.price_table = opt;
    ms.opt.match_table = matches;

    // Return the last literals size
    iend - anchor
}

/// `ZSTD_initStats_ultra`: a first compression pass, just to seed stats with more accurate
/// starting values. Only works on first block, with no dictionary. (The long-distance
/// matches, where there are any, are taken in it too.)
fn init_stats_ultra(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &[u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
    ldm: (&[RawSeq], RawSeqPos),
) {
    let mut tmp_rep = *rep; // updated rep codes will sink here

    // generate stats into ms->opt
    compress_block_opt(ms, seq_store, &mut tmp_rep, src, istart, src_size, 2, ldm);

    // invalidate first scan from history, only keep entropy stats
    seq_store.reset();
    ms.window.base += src_size as u32;
    ms.window.dict_limit += src_size as u32;
    ms.window.low_limit = ms.window.dict_limit;
    ms.next_to_update = ms.window.dict_limit;
}

/// `ZSTD_compressBlock_btultra2`: as `btultra`, with a first pass over the first block of
/// the frame to collect statistics, which seed the second. `ldm` the long-distance matches
/// for the block, if there are any.
pub(crate) fn compress_block_btultra2(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
    ldm: (&[RawSeq], RawSeqPos),
) -> usize {
    let curr = (istart + ms.window.base as usize) as u32;

    // 2-passes strategy: this strategy makes a first pass over first block to collect
    // statistics in order to seed next round's statistics with it. After 1st pass,
    // function forgets history, and starts a new block. Consequently, this can only work if
    // no data has been previously loaded in tables, aka, no dictionary, no prefix, no ldm
    // preprocessing. The compression ratio gain is generally small (~0.5% on first block),
    // the cost is 2x cpu time on first block.
    if ms.opt.lit_length_sum == 0 // first block
        && seq_store.nb_sequences() == 0 // no ldm
        && ms.window.dict_limit == ms.window.low_limit // no dictionary
        && curr == ms.window.dict_limit // start of frame, nothing already loaded nor skipped
        && src_size > ZSTD_PREDEF_THRESHOLD
    // input large enough to not employ default stats
    {
        init_stats_ultra(ms, seq_store, rep, src, istart, src_size, ldm);
    }

    compress_block_opt(ms, seq_store, rep, src, istart, src_size, 2, ldm)
}
