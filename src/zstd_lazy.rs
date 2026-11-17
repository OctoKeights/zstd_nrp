//! The greedy and lazy block compressors: a port of `lib/compress/zstd_lazy.c` of zstd
//! v1.5.7, for a block with no dictionary (`ZSTD_compressBlock_greedy`, `_lazy`, `_lazy2`
//! and `_btlazy2`, and their `_row` forms).
//!
//! They look for the longest match at each place with one of three match finders: a hash
//! chain, rows of a hash table searched by a byte of each hash (which the original compares
//! sixteen or more at a time with SIMD instructions, and here one at a time, to the same
//! mask), or a binary tree sorted as it is searched. Then the lazy ones look one or two
//! places further for a better match before they take it.
//!
//! The original works with pointers; here a place is an offset into the whole input, and a
//! byte at `pos` has the index `pos + base`.

// (The arithmetic is written as the original has it.)
#![allow(clippy::implicit_saturating_sub, clippy::manual_is_multiple_of)]

use super::common::{highbit32, read32};
use super::zstd_compress::{
    K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore, ZSTD_ROW_HASH_CACHE_SIZE, count,
    get_lowest_match_index, get_lowest_prefix_index, hash_ptr, hash_ptr_salted, offset_to_offbase,
};

const K_LAZY_SKIPPING_STEP: usize = 8;

/// `ZSTD_DUBT_UNSORTED_MARK`: in the binary tree, the mark of a place not sorted yet.
const ZSTD_DUBT_UNSORTED_MARK: u32 = 1;

/// `ZSTD_ROW_HASH_TAG_BITS`: the bits of a hash kept in the table of tags.
const ZSTD_ROW_HASH_TAG_BITS: u32 = 8;
const ZSTD_ROW_HASH_TAG_MASK: u32 = (1 << ZSTD_ROW_HASH_TAG_BITS) - 1;
const ZSTD_ROW_HASH_MAX_ENTRIES: usize = 64;
const ZSTD_ROW_HASH_CACHE_MASK: u32 = ZSTD_ROW_HASH_CACHE_SIZE as u32 - 1;

/// A place in the binary tree that is written to, or none (`dummy32`).
const NOWHERE: usize = usize::MAX;

/// `searchMethod_e`: how the block compressor looks for matches.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchMethod {
    HashChain,
    BinaryTree,
    RowHash,
}

// ---------- Binary tree ----------

/// `ZSTD_updateDUBT`: every place up to `ip` into the hash table, and into the tree as a
/// chain of places not sorted yet.
fn update_dubt(ms: &mut MatchState, src: &[u8], ip: usize, mls: u32) {
    let hash_log = ms.cparams.hash_log;
    let bt_log = ms.cparams.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let base = ms.window.base as usize;
    let target = (ip + base) as u32;
    let mut idx = ms.next_to_update;

    while idx < target {
        let h = hash_ptr(src, idx as usize - base, hash_log, mls); // assumption : ip + 8 <= iend
        let match_index = ms.hash_table[h];
        let next_candidate = 2 * (idx & bt_mask) as usize;

        ms.hash_table[h] = idx; // Update Hash Table
        ms.chain_table[next_candidate] = match_index; // update BT like a chain
        ms.chain_table[next_candidate + 1] = ZSTD_DUBT_UNSORTED_MARK;
        idx += 1;
    }
    ms.next_to_update = target;
}

/// `ZSTD_insertDUBT1`: sort one already inserted but unsorted position. Assumption:
/// `curr >= btlow == (curr - btmask)`.
fn insert_dubt1(
    ms: &mut MatchState,
    src: &[u8],
    curr: u32,
    input_end: usize,
    mut nb_compares: u32,
    bt_low: u32,
) {
    let bt_log = ms.cparams.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let base = ms.window.base as usize;
    let ip = curr as usize - base;
    let iend = input_end;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // This candidate is unsorted: the next sorted candidate is reached through
    // `*smaller_ptr`, while `*larger_ptr` contains the previous unsorted candidate (which is
    // already saved and can be overwritten).
    let mut match_index = ms.chain_table[smaller_ptr];
    let window_valid = ms.window.low_limit;
    let max_distance = 1u32 << ms.cparams.window_log;
    let window_low = if curr - window_valid > max_distance {
        curr - max_distance
    } else {
        window_valid
    };
    let bt = &mut ms.chain_table;

    while nb_compares != 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // guaranteed minimum nb of common bytes
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize - base;
        match_length += count(src, ip + match_length, m + match_length, iend);

        if ip + match_length == iend {
            // equal : no way to know if inf or sup
            // drop, to guarantee consistency; miss a bit of
            // compression, but other solutions can corrupt tree
            break;
        }

        if src[m + match_length] < src[ip + match_length] {
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
}

/// `ZSTD_DUBT_findBestMatch`: the places of the chain that are not sorted yet sorted into
/// the tree, then the longest match found in it, with `ip` put into it.
fn dubt_find_best_match(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u32,
    mls: u32,
) -> usize {
    let hash_log = ms.cparams.hash_log;
    let h = hash_ptr(src, ip, hash_log, mls);
    let mut match_index = ms.hash_table[h];

    let base = ms.window.base as usize;
    let curr = (ip + base) as u32;
    let window_low = get_lowest_match_index(ms, curr, ms.cparams.window_log);

    let bt_log = ms.cparams.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let bt_low = if bt_mask >= curr { 0 } else { curr - bt_mask };
    let unsort_limit = bt_low.max(window_low);

    let mut next_candidate = 2 * (match_index & bt_mask) as usize;
    let mut unsorted_mark = next_candidate + 1;
    let mut nb_compares = 1u32 << ms.cparams.search_log;
    let mut nb_candidates = nb_compares;
    let mut previous_candidate = 0u32;

    // reach end of unsorted candidates list
    while match_index > unsort_limit
        && ms.chain_table[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK
        && nb_candidates > 1
    {
        // the unsortedMark becomes a reversed chain, to move up back to original position
        ms.chain_table[unsorted_mark] = previous_candidate;
        previous_candidate = match_index;
        match_index = ms.chain_table[next_candidate];
        next_candidate = 2 * (match_index & bt_mask) as usize;
        unsorted_mark = next_candidate + 1;
        nb_candidates -= 1;
    }

    // nullify last candidate if it's still unsorted: simplification, detrimental to
    // compression ratio, beneficial for speed
    if match_index > unsort_limit && ms.chain_table[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK {
        ms.chain_table[next_candidate] = 0;
        ms.chain_table[unsorted_mark] = 0;
    }

    // batch sort stacked candidates
    match_index = previous_candidate;
    while match_index != 0 {
        // will end on matchIndex == 0
        let next_candidate_idx = ms.chain_table[2 * (match_index & bt_mask) as usize + 1];
        insert_dubt1(ms, src, match_index, iend, nb_candidates, unsort_limit);
        match_index = next_candidate_idx;
        nb_candidates += 1;
    }

    // find longest match
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 0usize;

    match_index = ms.hash_table[h];
    ms.hash_table[h] = curr; // Update Hash Table
    let bt = &mut ms.chain_table;

    while nb_compares != 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // guaranteed minimum nb of common bytes
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize - base;
        match_length += count(src, ip + match_length, m + match_length, iend);

        if match_length > best_length {
            if match_length as u32 > match_end_idx - match_index {
                match_end_idx = match_index + match_length as u32;
            }
            if 4 * (match_length - best_length) as i32
                > highbit32(curr - match_index + 1) as i32 - highbit32(*off_base) as i32
            {
                best_length = match_length;
                *off_base = offset_to_offbase(curr - match_index);
            }
            if ip + match_length == iend {
                // equal : no way to know if inf or sup
                break; // drop, to guarantee consistency (miss a little bit of compression)
            }
        }

        if src[m + match_length] < src[ip + match_length] {
            // match is smaller than current
            // update smaller idx
            bt[smaller_ptr] = match_index;
            // all smaller will now have at least this guaranteed common length
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_ptr = NOWHERE;
                break; // beyond tree size, stop the search
            }
            // new "smaller" => larger of match
            smaller_ptr = next_ptr + 1;
            // new matchIndex larger than previous (closer to current)
            match_index = bt[next_ptr + 1];
        } else {
            // match is larger than current
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
    best_length
}

/// `ZSTD_BtFindBestMatch`: tree updater, providing best match.
fn bt_find_best_match(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    i_limit: usize,
    off_base: &mut u32,
    mls: u32,
) -> usize {
    if ip + (ms.window.base as usize) < ms.next_to_update as usize {
        return 0; // skipped area
    }
    update_dubt(ms, src, ip, mls);
    dubt_find_best_match(ms, src, ip, i_limit, off_base, mls)
}

// ---------- Hash chain ----------

/// `ZSTD_insertAndFindFirstIndex_internal`: the chains updated up to `ip` (excluded), and
/// the first place in the chain of `ip`.
fn insert_and_find_first_index(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    mls: u32,
    lazy_skipping: bool,
) -> u32 {
    let hash_log = ms.cparams.hash_log;
    let chain_mask = (1u32 << ms.cparams.chain_log) - 1;
    let base = ms.window.base as usize;
    let target = (ip + base) as u32;
    let mut idx = ms.next_to_update;

    while idx < target {
        // catch up
        let h = hash_ptr(src, idx as usize - base, hash_log, mls);
        ms.chain_table[(idx & chain_mask) as usize] = ms.hash_table[h];
        ms.hash_table[h] = idx;
        idx += 1;
        // Stop inserting every position when in the lazy skipping mode.
        if lazy_skipping {
            break;
        }
    }

    ms.next_to_update = target;
    ms.hash_table[hash_ptr(src, ip, hash_log, mls)]
}

/// `ZSTD_HcFindBestMatch`: the longest match along the chain of `ip`.
fn hc_find_best_match(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    i_limit: usize,
    offset: &mut u32,
    mls: u32,
) -> usize {
    let chain_size = 1u32 << ms.cparams.chain_log;
    let chain_mask = chain_size - 1;
    let base = ms.window.base as usize;
    let curr = (ip + base) as u32;
    let max_distance = 1u32 << ms.cparams.window_log;
    let lowest_valid = ms.window.low_limit;
    let within_max_distance = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let is_dictionary = ms.loaded_dict_end != 0;
    let low_limit = if is_dictionary {
        lowest_valid
    } else {
        within_max_distance
    };
    let min_chain = if curr > chain_size {
        curr - chain_size
    } else {
        0
    };
    let mut nb_attempts = 1u32 << ms.cparams.search_log;
    let mut ml = 4 - 1;

    // HC4 match finder
    let lazy_skipping = ms.lazy_skipping;
    let mut match_index = insert_and_find_first_index(ms, src, ip, mls, lazy_skipping);

    while match_index >= low_limit && nb_attempts > 0 {
        let mut current_ml = 0;
        let m = match_index as usize - base;
        // read 4B starting from (match + ml + 1 - sizeof(U32))
        if read32(src, m + ml - 3) == read32(src, ip + ml - 3) {
            // potentially better
            current_ml = count(src, ip, m, i_limit);
        }

        // save best solution
        if current_ml > ml {
            ml = current_ml;
            *offset = offset_to_offbase(curr - match_index);
            if ip + current_ml == i_limit {
                break; // best possible, avoids read overflow on next attempt
            }
        }

        if match_index <= min_chain {
            break;
        }
        match_index = ms.chain_table[(match_index & chain_mask) as usize];
        nb_attempts -= 1;
    }
    ml
}

// ---------- Rows ----------

/// `ZSTD_row_nextIndex`: the next place to insert at in a row, whose head is at `head`, and
/// the head moved on to it: backwards from the end, around `[1, entries)`.
#[inline]
fn row_next_index(head: &mut u8, row_mask: u32) -> u32 {
    let mut next = u32::from(*head).wrapping_sub(1) & row_mask;
    next += if next == 0 { row_mask } else { 0 }; // skip first position
    *head = next as u8;
    next
}

/// `ZSTD_row_fillHashCache`: the hash cache filled from `idx`, with up to
/// `ZSTD_ROW_HASH_CACHE_SIZE` entries, but not beyond `i_limit`.
fn row_fill_hash_cache(ms: &mut MatchState, src: &[u8], mls: u32, idx: u32, i_limit: isize) {
    let hash_log = ms.row_hash_log;
    let base = ms.window.base as isize;
    let pos = idx as isize - base;
    let max_elems_to_prefetch = if pos > i_limit {
        0
    } else {
        (i_limit - pos + 1) as u32
    };
    let lim = idx + (ZSTD_ROW_HASH_CACHE_SIZE as u32).min(max_elems_to_prefetch);

    for idx in idx..lim {
        let hash = hash_ptr_salted(
            src,
            (idx as isize - base) as usize,
            hash_log + ZSTD_ROW_HASH_TAG_BITS,
            mls,
            ms.hash_salt,
        );
        ms.hash_cache[(idx & ZSTD_ROW_HASH_CACHE_MASK) as usize] = hash;
    }
}

/// `ZSTD_row_nextCachedHash`: the hash of the place `idx`, from the cache, which takes the
/// hash of the place `ZSTD_ROW_HASH_CACHE_SIZE` further in its stead.
#[inline]
fn row_next_cached_hash(ms: &mut MatchState, src: &[u8], idx: u32, mls: u32) -> u32 {
    let pos = idx as usize - ms.window.base as usize;
    let new_hash = hash_ptr_salted(
        src,
        pos + ZSTD_ROW_HASH_CACHE_SIZE,
        ms.row_hash_log + ZSTD_ROW_HASH_TAG_BITS,
        mls,
        ms.hash_salt,
    );
    let slot = (idx & ZSTD_ROW_HASH_CACHE_MASK) as usize;
    let hash = ms.hash_cache[slot];
    ms.hash_cache[slot] = new_hash;
    hash
}

/// `ZSTD_row_update_internalImpl`: the places from `update_start_idx` to `update_end_idx`
/// into the hash table.
fn row_update_internal_impl(
    ms: &mut MatchState,
    src: &[u8],
    update_start_idx: u32,
    update_end_idx: u32,
    mls: u32,
    row_log: u32,
    row_mask: u32,
    use_cache: bool,
) {
    let base = ms.window.base as usize;
    for idx in update_start_idx..update_end_idx {
        let hash = if use_cache {
            row_next_cached_hash(ms, src, idx, mls)
        } else {
            hash_ptr_salted(
                src,
                idx as usize - base,
                ms.row_hash_log + ZSTD_ROW_HASH_TAG_BITS,
                mls,
                ms.hash_salt,
            )
        };
        let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << row_log) as usize;
        let pos = row_next_index(&mut ms.tag_table[rel_row], row_mask) as usize;
        ms.tag_table[rel_row + pos] = (hash & ZSTD_ROW_HASH_TAG_MASK) as u8;
        ms.hash_table[rel_row + pos] = idx;
    }
}

/// `ZSTD_row_update_internal`: the places up to `ip` into the hash table, but for the
/// middle of a long match.
fn row_update_internal(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    mls: u32,
    row_log: u32,
    row_mask: u32,
) {
    let mut idx = ms.next_to_update;
    let target = (ip + ms.window.base as usize) as u32;
    const K_SKIP_THRESHOLD: u32 = 384;
    const K_MAX_MATCH_START_POSITIONS_TO_UPDATE: u32 = 96;
    const K_MAX_MATCH_END_POSITIONS_TO_UPDATE: u32 = 32;

    // (With the hash cache.) If we decide to skip, then we only update a set number of
    // positions at the beginning and end of the match.
    if target - idx > K_SKIP_THRESHOLD {
        let bound = idx + K_MAX_MATCH_START_POSITIONS_TO_UPDATE;
        row_update_internal_impl(ms, src, idx, bound, mls, row_log, row_mask, true);
        idx = target - K_MAX_MATCH_END_POSITIONS_TO_UPDATE;
        row_fill_hash_cache(ms, src, mls, idx, ip as isize + 1);
    }
    row_update_internal_impl(ms, src, idx, target, mls, row_log, row_mask, true);
    ms.next_to_update = target;
}

/// `ZSTD_row_getMatchMask`: a bit for each entry of a row whose tag is `tag`, rotated so
/// that the head's is the lowest.
#[inline]
fn row_get_match_mask(tag_row: &[u8], tag: u8, head: u32, row_entries: usize) -> u64 {
    let mut matches = 0u64;
    for (i, &t) in tag_row[..row_entries].iter().enumerate() {
        matches |= u64::from(t == tag) << i;
    }
    match row_entries {
        16 => u64::from((matches as u16).rotate_right(head)),
        32 => u64::from((matches as u32).rotate_right(head)),
        _ => matches.rotate_right(head),
    }
}

/// `ZSTD_RowFindBestMatch`: the longest match among the entries of the row of `ip` whose
/// tag is its tag, with `ip` put into the row.
fn row_find_best_match(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    i_limit: usize,
    offset: &mut u32,
    mls: u32,
    row_log: u32,
) -> usize {
    let base = ms.window.base as usize;
    let curr = (ip + base) as u32;
    let max_distance = 1u32 << ms.cparams.window_log;
    let lowest_valid = ms.window.low_limit;
    let within_max_distance = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let is_dictionary = ms.loaded_dict_end != 0;
    let low_limit = if is_dictionary {
        lowest_valid
    } else {
        within_max_distance
    };
    let row_entries = 1usize << row_log;
    let row_mask = row_entries as u32 - 1;
    // nb of searches is capped at nb entries per row
    let capped_search_log = ms.cparams.search_log.min(row_log);
    let mut nb_attempts = 1u32 << capped_search_log;
    let mut ml = 4 - 1;

    // Update the hashTable and tagTable up to (but not including) ip.
    let hash = if !ms.lazy_skipping {
        row_update_internal(ms, src, ip, mls, row_log, row_mask);
        row_next_cached_hash(ms, src, curr, mls)
    } else {
        // Stop inserting every position when in the lazy skipping mode. The hash cache is
        // also not kept up to date in this mode.
        ms.next_to_update = curr;
        hash_ptr_salted(
            src,
            ip,
            ms.row_hash_log + ZSTD_ROW_HASH_TAG_BITS,
            mls,
            ms.hash_salt,
        )
    };

    // Get the hash for ip, compute the appropriate row.
    let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << row_log) as usize;
    let tag = hash & ZSTD_ROW_HASH_TAG_MASK;
    let head = u32::from(ms.tag_table[rel_row]) & row_mask;
    let mut match_buffer = [0u32; ZSTD_ROW_HASH_MAX_ENTRIES];
    let mut num_matches = 0;
    let mut matches = row_get_match_mask(&ms.tag_table[rel_row..], tag as u8, head, row_entries);

    // Cycle through the matches.
    while matches > 0 && nb_attempts > 0 {
        let match_pos = (head + matches.trailing_zeros()) & row_mask;
        let match_index = ms.hash_table[rel_row + match_pos as usize];
        matches &= matches - 1;
        if match_pos == 0 {
            continue;
        }
        if match_index < low_limit {
            break;
        }
        match_buffer[num_matches] = match_index;
        num_matches += 1;
        nb_attempts -= 1;
    }

    // Speed opt: insert current byte into hashtable too. This allows us to avoid one
    // iteration of the loop in ZSTD_row_update_internal() at the next search.
    {
        let pos = row_next_index(&mut ms.tag_table[rel_row], row_mask) as usize;
        ms.tag_table[rel_row + pos] = tag as u8;
        ms.hash_table[rel_row + pos] = ms.next_to_update;
        ms.next_to_update += 1;
    }

    // Return the longest match.
    for &match_index in &match_buffer[..num_matches] {
        let mut current_ml = 0;
        let m = match_index as usize - base;
        // read 4B starting from (match + ml + 1 - sizeof(U32))
        if read32(src, m + ml - 3) == read32(src, ip + ml - 3) {
            // potentially better
            current_ml = count(src, ip, m, i_limit);
        }

        // Save best solution.
        if current_ml > ml {
            ml = current_ml;
            *offset = offset_to_offbase(curr - match_index);
            if ip + current_ml == i_limit {
                break; // best possible, avoids read overflow on next attempt
            }
        }
    }
    ml
}

/// `ZSTD_searchMax`: the length of the longest match from `ip`, and its offset, by the
/// search method.
#[inline]
fn search_max(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
    iend: usize,
    offset: &mut u32,
    mls: u32,
    row_log: u32,
    search_method: SearchMethod,
) -> usize {
    match search_method {
        SearchMethod::BinaryTree => bt_find_best_match(ms, src, ip, iend, offset, mls),
        SearchMethod::HashChain => hc_find_best_match(ms, src, ip, iend, offset, mls),
        SearchMethod::RowHash => row_find_best_match(ms, src, ip, iend, offset, mls, row_log),
    }
}

/// `(int)(a - b + c)` of the original, for lengths and bits: the arithmetic of `size_t`,
/// cast to `int`.
#[inline]
fn gain(a: usize, b: u32, c: i64) -> i32 {
    (a as i64 - i64::from(b) + c) as i32
}

/// `ZSTD_compressBlock_lazy_generic`, with no dictionary: the sequences of the block
/// `src[istart..istart + src_size]` go to `seq_store`. `depth` is 0 for the greedy
/// strategy, 1 for the lazy one, 2 for the second lazy one. The answer is how many bytes at
/// the end of the block no sequence covers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_block_lazy(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
    search_method: SearchMethod,
    depth: u32,
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    let iend = istart + src_size;
    // (Before the block, for a block too short for it: a place, not an offset.)
    let ilimit = iend as isize
        - 8
        - if search_method == SearchMethod::RowHash {
            ZSTD_ROW_HASH_CACHE_SIZE as isize
        } else {
            0
        };
    let base = ms.window.base as usize;
    let prefix_lowest_index = ms.window.dict_limit;
    let prefix_lowest = prefix_lowest_index as usize - base;
    let mls = ms.cparams.min_match.clamp(4, 6);
    let row_log = ms.cparams.search_log.clamp(4, 6);

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    let dict_and_prefix_length = (ip - prefix_lowest) as u32;
    ip += usize::from(dict_and_prefix_length == 0);
    {
        let curr = (ip + base) as u32;
        let window_low = get_lowest_prefix_index(ms, curr, ms.cparams.window_log);
        let max_rep = curr - window_low;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    // Reset the lazy skipping state.
    ms.lazy_skipping = false;

    if search_method == SearchMethod::RowHash {
        let next_to_update = ms.next_to_update;
        row_fill_hash_cache(ms, src, mls, next_to_update, ilimit);
    }

    // Match Loop
    while (ip as isize) < ilimit {
        let mut match_length = 0usize;
        let mut off_base = REPCODE1_TO_OFFBASE;
        let mut start = ip + 1;
        let mut found_repeat = false;

        // check repCode
        if offset_1 > 0 && read32(src, ip + 1 - offset_1 as usize) == read32(src, ip + 1) {
            match_length = count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize, iend) + 4;
            found_repeat = depth == 0;
        }

        // (`goto _storeSequence` for the repeat offset of the greedy strategy.)
        if !found_repeat {
            // first search (depth 0)
            {
                let mut offbase_found = 999999999u32;
                let ml2 = search_max(
                    ms,
                    src,
                    ip,
                    iend,
                    &mut offbase_found,
                    mls,
                    row_log,
                    search_method,
                );
                if ml2 > match_length {
                    match_length = ml2;
                    start = ip;
                    off_base = offbase_found;
                }
            }

            if match_length < 4 {
                // jump faster over incompressible sections
                let step = ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
                ip += step;
                // Enter the lazy skipping mode once we are skipping more than 8 bytes at a
                // time. In this mode we stop inserting every position into our tables, and
                // only insert positions that we search, which is one in step positions.
                ms.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
                continue;
            }

            // let's try to find a better solution
            if depth >= 1 {
                while (ip as isize) < ilimit {
                    ip += 1;
                    if off_base != 0
                        && offset_1 > 0
                        && read32(src, ip) == read32(src, ip - offset_1 as usize)
                    {
                        let ml_rep = count(src, ip + 4, ip + 4 - offset_1 as usize, iend) + 4;
                        let gain2 = (ml_rep * 3) as i32;
                        let gain1 = gain(match_length * 3, highbit32(off_base), 1);
                        if ml_rep >= 4 && gain2 > gain1 {
                            match_length = ml_rep;
                            off_base = REPCODE1_TO_OFFBASE;
                            start = ip;
                        }
                    }
                    {
                        let mut ofb_candidate = 999999999u32;
                        let ml2 = search_max(
                            ms,
                            src,
                            ip,
                            iend,
                            &mut ofb_candidate,
                            mls,
                            row_log,
                            search_method,
                        );
                        let gain2 = gain(ml2 * 4, highbit32(ofb_candidate), 0); // raw approx
                        let gain1 = gain(match_length * 4, highbit32(off_base), 4);
                        if ml2 >= 4 && gain2 > gain1 {
                            match_length = ml2;
                            off_base = ofb_candidate;
                            start = ip;
                            continue; // search a better one
                        }
                    }

                    // let's find an even better one
                    if depth == 2 && (ip as isize) < ilimit {
                        ip += 1;
                        if off_base != 0
                            && offset_1 > 0
                            && read32(src, ip) == read32(src, ip - offset_1 as usize)
                        {
                            let ml_rep = count(src, ip + 4, ip + 4 - offset_1 as usize, iend) + 4;
                            let gain2 = (ml_rep * 4) as i32;
                            let gain1 = gain(match_length * 4, highbit32(off_base), 1);
                            if ml_rep >= 4 && gain2 > gain1 {
                                match_length = ml_rep;
                                off_base = REPCODE1_TO_OFFBASE;
                                start = ip;
                            }
                        }
                        {
                            let mut ofb_candidate = 999999999u32;
                            let ml2 = search_max(
                                ms,
                                src,
                                ip,
                                iend,
                                &mut ofb_candidate,
                                mls,
                                row_log,
                                search_method,
                            );
                            let gain2 = gain(ml2 * 4, highbit32(ofb_candidate), 0); // raw approx
                            let gain1 = gain(match_length * 4, highbit32(off_base), 7);
                            if ml2 >= 4 && gain2 > gain1 {
                                match_length = ml2;
                                off_base = ofb_candidate;
                                start = ip;
                                continue;
                            }
                        }
                    }
                    break; // nothing found : store previous solution
                }
            }

            // catch up
            if off_base > 3 {
                // `OFFBASE_IS_OFFSET`
                let offset = (off_base - 3) as usize;
                // only search for offset within prefix
                while start > anchor
                    && start as isize - offset as isize > prefix_lowest as isize
                    && src[start - 1] == src[start - offset - 1]
                {
                    start -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset as u32;
            }
        }

        // store sequence
        // _storeSequence:
        {
            let lit_length = start - anchor;
            seq_store.store_seq(src, anchor, lit_length, off_base, match_length);
            ip = start + match_length;
            anchor = ip;
        }
        if ms.lazy_skipping {
            // We've found a match, disable lazy skipping mode, and refill the hash cache.
            if search_method == SearchMethod::RowHash {
                let next_to_update = ms.next_to_update;
                row_fill_hash_cache(ms, src, mls, next_to_update, ilimit);
            }
            ms.lazy_skipping = false;
        }

        // check immediate repcode
        while (ip as isize) <= ilimit
            && offset_2 > 0
            && read32(src, ip) == read32(src, ip - offset_2 as usize)
        {
            // store sequence
            match_length = count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
            std::mem::swap(&mut offset_1, &mut offset_2); // swap repcodes
            seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, match_length);
            ip += match_length;
            anchor = ip;
        }
    }

    // If offset_1 started invalid (offsetSaved1 != 0) and became valid (offset_1 != 0),
    // rotate saved offsets. See comment in ZSTD_compressBlock_fast_noDict for more context.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // save reps for next block
    rep[0] = if offset_1 != 0 {
        offset_1
    } else {
        offset_saved1
    };
    rep[1] = if offset_2 != 0 {
        offset_2
    } else {
        offset_saved2
    };

    // Return the last literals size
    iend - anchor
}
