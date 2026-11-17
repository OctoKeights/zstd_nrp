//! The double-fast block compressor: a port of `ZSTD_compressBlock_doubleFast` in
//! `lib/compress/zstd_double_fast.c` of zstd v1.5.7, for a block with no dictionary.
//!
//! It keeps two tables: one of the hashes of eight bytes, for long matches, and one of the
//! hashes of a few bytes, for short ones. The original works with pointers and jumps
//! between labels; here the places are offsets into the whole input, and the labels are the
//! arms of a loop.

use super::common::{read32, read64};
use super::zstd_compress::{
    HASH_READ_SIZE, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    ZSTD_WINDOW_START_INDEX, count, get_lowest_prefix_index, hash_ptr, offset_to_offbase,
};

/// What ends the search for a match from one place.
enum Found {
    /// `_cleanup`: the end of the block.
    Nothing,
    /// `_match_stored`: a match with the first repeat offset, already stored.
    Repeat,
    /// `_match_found`: a long match.
    Long,
    /// `_search_next_long`: a short match, and maybe a long one a byte further.
    Short,
}

/// `ZSTD_compressBlock_doubleFast`: the sequences of the block
/// `src[istart..istart + src_size]` go to `seq_store`. The answer is how many bytes at the
/// end of the block no sequence covers.
pub(crate) fn compress_block_double_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
) -> usize {
    // (The original has one copy of the function per minimum match.)
    let mls = match ms.cparams.min_match {
        m @ 5..=7 => m,
        _ => 4,
    };
    let h_bits_l = ms.cparams.hash_log;
    let h_bits_s = ms.cparams.chain_log;
    let window_log = ms.cparams.window_log;
    // `base + index` is `index - BASE` here, and `ptr - base` is `ptr + BASE`.
    const BASE: usize = ZSTD_WINDOW_START_INDEX as usize;
    let mut anchor = istart;
    let end_index = (istart + BASE + src_size) as u32;
    // presumes that, if there is a dictionary, it must be using Attach mode
    let prefix_lowest_index = get_lowest_prefix_index(ms, end_index, window_log);
    let prefix_lowest = prefix_lowest_index as usize - BASE;
    let iend = istart + src_size;
    // `ilimit` is `iend - HASH_READ_SIZE`, which can be before the block: the comparisons
    // with it have the eight bytes on the other side.
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    const K_STEP_INCR: usize = 1 << K_SEARCH_STRENGTH;

    let mut ip = istart; // the position at which we are currently searching

    // init
    ip += usize::from(ip == prefix_lowest);
    {
        let current = (ip + BASE) as u32;
        let window_low = get_lowest_prefix_index(ms, current, window_log);
        let max_rep = current - window_low;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    let hash_long = &mut ms.hash_table;
    let hash_small = &mut ms.chain_table;

    // Outer loop: one iteration per match found and stored.
    loop {
        let mut step = 1usize;
        let mut next_step = ip + K_STEP_INCR;
        let mut ip1 = ip + step; // the position after the current position

        if ip1 + HASH_READ_SIZE > iend {
            break; // cleanup
        }

        let mut hl0 = hash_ptr(src, ip, h_bits_l, 8); // the long hash at ip
        let mut idxl0 = hash_long[hl0]; // the long match index for ip
        let mut matchl0 = (idxl0 as usize).wrapping_sub(BASE); // the long match for ip
        let mut hl1 = 0usize; // the long hash at ip1
        let mut idxl1 = 0u32; // the long match index for ip1
        let mut matchl1 = 0usize; // the long match for ip1
        let mut matchs0; // the short match for ip
        let mut m_length = 0usize;
        let mut offset = 0u32;
        let mut curr;

        // Inner loop: one iteration per search / position.
        let found = loop {
            let hs0 = hash_ptr(src, ip, h_bits_s, mls);
            let idxs0 = hash_small[hs0];
            curr = (ip + BASE) as u32;
            matchs0 = (idxs0 as usize).wrapping_sub(BASE);

            hash_long[hl0] = curr; // update the hash tables
            hash_small[hs0] = curr;

            // Check the no-dictionary repeat code.
            if (offset_1 > 0) & (read32(src, ip + 1 - offset_1 as usize) == read32(src, ip + 1)) {
                m_length = count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize, iend) + 4;
                ip += 1;
                seq_store.store_seq(src, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                break Found::Repeat;
            }

            hl1 = hash_ptr(src, ip1, h_bits_l, 8);

            // idxl0 > prefixLowestIndex is a (somewhat) unpredictable branch. However the
            // expression below compiles into a conditional move in the original.
            if idxl0 >= prefix_lowest_index && read64(src, matchl0) == read64(src, ip) {
                m_length = count(src, ip + 8, matchl0 + 8, iend) + 8;
                offset = (ip - matchl0) as u32;
                while ((ip > anchor) & (matchl0 > prefix_lowest))
                    && (src[ip - 1] == src[matchl0 - 1])
                {
                    // catch up
                    ip -= 1;
                    matchl0 -= 1;
                    m_length += 1;
                }
                break Found::Long;
            }

            idxl1 = hash_long[hl1];
            matchl1 = (idxl1 as usize).wrapping_sub(BASE);

            // Same optimization as matchl0 above.
            if idxs0 >= prefix_lowest_index && read32(src, matchs0) == read32(src, ip) {
                break Found::Short;
            }

            if ip1 >= next_step {
                step += 1;
                next_step += K_STEP_INCR;
            }
            ip = ip1;
            ip1 += step;

            hl0 = hl1;
            idxl0 = idxl1;
            matchl0 = matchl1;

            if ip1 + HASH_READ_SIZE > iend {
                break Found::Nothing;
            }
        };

        match found {
            Found::Nothing => break, // cleanup
            Found::Repeat => {}
            Found::Long | Found::Short => {
                if let Found::Short = found {
                    // search_next_long.
                    // Short match found.
                    m_length = count(src, ip + 4, matchs0 + 4, iend) + 4;
                    offset = (ip - matchs0) as u32;

                    // Check the prefix long +1 match.
                    if (idxl1 > prefix_lowest_index) && (read64(src, matchl1) == read64(src, ip1)) {
                        let l1len = count(src, ip1 + 8, matchl1 + 8, iend) + 8;
                        if l1len > m_length {
                            // Use the long match instead.
                            ip = ip1;
                            m_length = l1len;
                            offset = (ip - matchl1) as u32;
                            matchs0 = matchl1;
                        }
                    }

                    while ((ip > anchor) & (matchs0 > prefix_lowest))
                        && (src[ip - 1] == src[matchs0 - 1])
                    {
                        // Complete backward.
                        ip -= 1;
                        matchs0 -= 1;
                        m_length += 1;
                    }
                }

                // match_found: requires ip, offset, mLength.
                offset_2 = offset_1;
                offset_1 = offset;

                if step < 4 {
                    // It is safe to write this value back to the hashtable, because the
                    // match is at least 4 bytes long, so the next search starts after ip1.
                    hash_long[hl1] = (ip1 + BASE) as u32;
                }

                seq_store.store_seq(
                    src,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    m_length,
                );
            }
        }

        // match_stored.
        // Match found.
        ip += m_length;
        anchor = ip;

        if ip + HASH_READ_SIZE <= iend {
            // Complementary insertion.
            // Done after iLimit test, as candidates could be > iend-8.
            {
                let index_to_insert = curr + 2;
                let pos = index_to_insert as usize - BASE;
                hash_long[hash_ptr(src, pos, h_bits_l, 8)] = index_to_insert;
                hash_long[hash_ptr(src, ip - 2, h_bits_l, 8)] = (ip - 2 + BASE) as u32;
                hash_small[hash_ptr(src, pos, h_bits_s, mls)] = index_to_insert;
                hash_small[hash_ptr(src, ip - 1, h_bits_s, mls)] = (ip - 1 + BASE) as u32;
            }

            // Check immediate repeat codes.
            while (ip + HASH_READ_SIZE <= iend)
                && ((offset_2 > 0) & (read32(src, ip) == read32(src, ip - offset_2 as usize)))
            {
                // Store the sequence.
                let r_length = count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
                std::mem::swap(&mut offset_1, &mut offset_2); // swap offset_2 <=> offset_1
                hash_small[hash_ptr(src, ip, h_bits_s, mls)] = (ip + BASE) as u32;
                hash_long[hash_ptr(src, ip, h_bits_l, 8)] = (ip + BASE) as u32;
                seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                ip += r_length;
                anchor = ip;
                // faster when present ... (?)
            }
        }
    }

    // cleanup.
    // If offset_1 started invalid (offsetSaved1 != 0) and became valid (offset_1 != 0),
    // rotate saved offsets.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // Save the repeat offsets for the next block.
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

    // Return the last literals size.
    iend - anchor
}
