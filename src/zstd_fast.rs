//! The fast block compressor: a port of `ZSTD_compressBlock_fast` in
//! `lib/compress/zstd_fast.c` of zstd v1.5.7, for a block with no dictionary.
//!
//! It keeps one table of the last place each hash of a few bytes was seen. The original
//! works with pointers and jumps between labels; here the places are offsets into the
//! whole input, and the labels are the arms of a loop.

use super::common::read32;
use super::zstd_compress::{
    HASH_READ_SIZE, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    ZSTD_WINDOW_START_INDEX, count, get_lowest_prefix_index, hash_ptr, offset_to_offbase,
};

/// What ends the search for a match from one place.
enum Found {
    /// `_cleanup`: the end of the block.
    Nothing,
    /// `_offset`: a match with what the table pointed at.
    Offset,
    /// `_match`: a match with the first repeat offset.
    Repeat,
}

/// `ZSTD_compressBlock_fast`: the sequences of the block `src[istart..istart + src_size]`
/// go to `seq_store`. The answer is how many bytes at the end of the block no sequence
/// covers.
pub(crate) fn compress_block_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; 3],
    src: &[u8],
    istart: usize,
    src_size: usize,
) -> usize {
    // (The original has one copy of the function per minimum match, and two ways to read a
    // candidate, with a branch or without; they give the same matches.)
    let mls = match ms.cparams.min_match {
        m @ 5..=7 => m,
        _ => 4,
    };
    let hlog = ms.cparams.hash_log;
    let window_log = ms.cparams.window_log;
    // min 2
    let step_size =
        (ms.cparams.target_length + u32::from(ms.cparams.target_length == 0) + 1) as usize;
    // `base + index` is `index - BASE` here, and `ptr - base` is `ptr + BASE`.
    const BASE: usize = ZSTD_WINDOW_START_INDEX as usize;
    let end_index = (istart + BASE + src_size) as u32;
    let prefix_start_index = get_lowest_prefix_index(ms, end_index, window_log);
    let prefix_start = prefix_start_index as usize - BASE;
    let iend = istart + src_size;
    // `ilimit` is `iend - HASH_READ_SIZE`, which can be before the block: the comparisons
    // with it have the eight bytes on the other side.

    let mut anchor = istart;
    let mut ip0 = istart;

    let mut rep_offset1 = rep[0];
    let mut rep_offset2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    const K_STEP_INCR: usize = 1 << (K_SEARCH_STRENGTH - 1);

    ip0 += usize::from(ip0 == prefix_start);
    {
        let curr = (ip0 + BASE) as u32;
        let window_low = get_lowest_prefix_index(ms, curr, window_log);
        let max_rep = curr - window_low;
        if rep_offset2 > max_rep {
            offset_saved2 = rep_offset2;
            rep_offset2 = 0;
        }
        if rep_offset1 > max_rep {
            offset_saved1 = rep_offset1;
            rep_offset1 = 0;
        }
    }

    let hash_table = &mut ms.hash_table;
    // `ZSTD_match4Found_branch`.
    let match_found = |current_ptr: usize, match_idx: u32| -> bool {
        match_idx >= prefix_start_index
            && read32(src, current_ptr) == read32(src, match_idx as usize - BASE)
    };

    // start. Outer search loop.
    loop {
        let mut step = step_size;
        let mut next_step = ip0 + K_STEP_INCR;

        // Calculate positions; they stay in this order: ip0 < ip1 < ip2 <= ip3.
        let mut ip1 = ip0 + 1;
        let mut ip2 = ip0 + step;
        let mut ip3 = ip2 + 1;

        if ip3 + HASH_READ_SIZE >= iend {
            break; // cleanup
        }

        let mut hash0 = hash_ptr(src, ip0, hlog, mls);
        let mut hash1 = hash_ptr(src, ip1, hlog, mls);

        let mut match_idx = hash_table[hash0];
        let mut current0;
        let mut match0 = 0usize;
        let mut m_length = 0usize;
        let mut offcode = 0u32;

        let found = loop {
            // Load the repeat offset match for ip[2].
            let rval = read32(src, ip2 - rep_offset1 as usize);

            // Write back the table entry.
            current0 = (ip0 + BASE) as u32;
            hash_table[hash0] = current0;

            // Check the repeat offset at ip[2].
            if (read32(src, ip2) == rval) & (rep_offset1 > 0) {
                ip0 = ip2;
                match0 = ip0 - rep_offset1 as usize;
                m_length = usize::from(src[ip0 - 1] == src[match0 - 1]);
                ip0 -= m_length;
                match0 -= m_length;
                offcode = REPCODE1_TO_OFFBASE;
                m_length += 4;

                // Write the next hash table entry: it's already calculated. This write is
                // known to be safe because ip1 is before the repeat offset match.
                hash_table[hash1] = (ip1 + BASE) as u32;

                break Found::Repeat;
            }

            if match_found(ip0, match_idx) {
                // Write the next hash table entry (it's already calculated). This write is
                // known to be safe because ip1 == ip0 + 1, so searching backwards is known
                // to succeed.
                hash_table[hash1] = (ip1 + BASE) as u32;

                break Found::Offset;
            }

            // Look up ip[1].
            match_idx = hash_table[hash1];

            // Hash ip[2].
            hash0 = hash1;
            hash1 = hash_ptr(src, ip2, hlog, mls);

            // Advance to the next positions.
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            // Write back the table entry.
            current0 = (ip0 + BASE) as u32;
            hash_table[hash0] = current0;

            if match_found(ip0, match_idx) {
                // Write the next hash table entry, since it's already calculated.
                if step <= 4 {
                    // Avoid writing an index if it's >= position where the search will
                    // resume. The minimum possible match has length 4, so the search can
                    // resume at ip0 + 4.
                    hash_table[hash1] = (ip1 + BASE) as u32;
                }
                break Found::Offset;
            }

            // Look up ip[1].
            match_idx = hash_table[hash1];

            // Hash ip[2].
            hash0 = hash1;
            hash1 = hash_ptr(src, ip2, hlog, mls);

            // Advance to the next positions.
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;

            // Calculate the step.
            if ip2 >= next_step {
                step += 1;
                next_step += K_STEP_INCR;
            }

            if ip3 + HASH_READ_SIZE >= iend {
                break Found::Nothing;
            }
        };

        match found {
            Found::Nothing => break, // cleanup
            Found::Offset => {
                // offset. Requires: ip0, idx.
                // Compute the offset code.
                match0 = match_idx as usize - BASE;
                rep_offset2 = rep_offset1;
                rep_offset1 = (ip0 - match0) as u32;
                offcode = offset_to_offbase(rep_offset1);
                m_length = 4;

                // Count the backwards match length.
                while ((ip0 > anchor) & (match0 > prefix_start))
                    && (src[ip0 - 1] == src[match0 - 1])
                {
                    ip0 -= 1;
                    match0 -= 1;
                    m_length += 1;
                }
            }
            Found::Repeat => {}
        }

        // match. Requires: ip0, match0, offcode.
        // Count the forward length.
        m_length += count(src, ip0 + m_length, match0 + m_length, iend);

        seq_store.store_seq(src, anchor, ip0 - anchor, offcode, m_length);

        ip0 += m_length;
        anchor = ip0;

        // Fill the table and check for an immediate repeat code.
        if ip0 + HASH_READ_SIZE <= iend {
            // Fill the table.
            let pos = current0 as usize - BASE + 2;
            // here because current+2 could be > iend-8
            hash_table[hash_ptr(src, pos, hlog, mls)] = current0 + 2;
            hash_table[hash_ptr(src, ip0 - 2, hlog, mls)] = (ip0 - 2 + BASE) as u32;

            if rep_offset2 > 0 {
                while (ip0 + HASH_READ_SIZE <= iend)
                    && (read32(src, ip0) == read32(src, ip0 - rep_offset2 as usize))
                {
                    // Store the sequence.
                    let r_length = count(src, ip0 + 4, ip0 + 4 - rep_offset2 as usize, iend) + 4;
                    // swap rep_offset2 <=> rep_offset1
                    std::mem::swap(&mut rep_offset1, &mut rep_offset2);
                    hash_table[hash_ptr(src, ip0, hlog, mls)] = (ip0 + BASE) as u32;
                    ip0 += r_length;
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                    anchor = ip0;
                    // faster when present (confirmed on gcc-8) ... (?)
                }
            }
        }
    }

    // cleanup.
    // Note that there are probably still a couple of positions that could be searched;
    // however, it seems to be a meaningful performance hit to try to search them. So let's
    // not.

    // When the repeat offsets overflow, they are saved as 0 at the start, and restored here:
    // if offset_1 started invalid (offsetSaved1 != 0) and became valid (rep_offset1 != 0),
    // rotate saved offsets.
    offset_saved2 = if offset_saved1 != 0 && rep_offset1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // Save the repeat offsets for the next block.
    rep[0] = if rep_offset1 != 0 {
        rep_offset1
    } else {
        offset_saved1
    };
    rep[1] = if rep_offset2 != 0 {
        rep_offset2
    } else {
        offset_saved2
    };

    // Return the last literals size.
    iend - anchor
}
