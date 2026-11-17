//! Huffman coding of literals: a port of `lib/compress/huf_compress.c` of zstd v1.5.7, as a
//! 64-bit build has it.
//!
//! From `ZSTD_btultra` up the depth of the table is the one that comes out smallest
//! (`HUF_flags_optimalDepth`); below, a quicker estimate.

// (The arithmetic is written as the original has it.)
#![allow(clippy::manual_div_ceil, clippy::needless_range_loop)]

use super::common::{CError, CResult, highbit32, write_le16};
use super::fse_compress::{self, FseCTable};
use super::hist;

pub(crate) const HUF_BLOCKSIZE_MAX: usize = 128 * 1024;
pub(crate) const HUF_TABLELOG_MAX: u32 = 12;
pub(crate) const HUF_TABLELOG_DEFAULT: u32 = 11;
pub(crate) const HUF_SYMBOLVALUE_MAX: u32 = 255;

/// `HUF_CElt`: the number of bits in the low byte, the code in the top bits.
pub(crate) type HufCElt = u64;

/// `HUF_CElt[HUF_CTABLE_SIZE_ST(255)]`: a header (`HUF_CTableHeader`: the table log in the
/// low byte, the highest symbol in the next), then one element per symbol.
pub(crate) type HufCTable = [HufCElt; 257];

/// `HUF_repeat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HufRepeat {
    /// Cannot use the previous table.
    None,
    /// Can use the previous table, but it must be checked.
    Check,
    /// Can use the previous table and it is assumed to be valid.
    Valid,
}

/// `nodeElt`.
#[derive(Clone, Copy, Default)]
struct NodeElt {
    count: u32,
    parent: u16,
    byte: u8,
    nb_bits: u8,
}

/// `rankPos`.
#[derive(Clone, Copy, Default)]
struct RankPos {
    base: u16,
    curr: u16,
}

const RANK_POSITION_TABLE_SIZE: usize = 192;
const RANK_POSITION_MAX_COUNT_LOG: u32 = 32;
const RANK_POSITION_LOG_BUCKETS_BEGIN: u32 =
    (RANK_POSITION_TABLE_SIZE as u32 - 1) - RANK_POSITION_MAX_COUNT_LOG - 1;
/// `RANK_POSITION_LOG_BUCKETS_BEGIN + ZSTD_highbit32(RANK_POSITION_LOG_BUCKETS_BEGIN)`.
const RANK_POSITION_DISTINCT_COUNT_CUTOFF: u32 = RANK_POSITION_LOG_BUCKETS_BEGIN + 7;

const STARTNODE: i32 = HUF_SYMBOLVALUE_MAX as i32 + 1;

/// `HUF_compress_tables_t`: what the original keeps in the entropy work area from one block
/// to the next.
pub(crate) struct HufCompressTables {
    count: [u32; 256],
    ctable: HufCTable,
    /// `huffNodeTbl`. The original's `huffNode` starts at its second element.
    huff_node_tbl: [NodeElt; 512],
    rank_position: [RankPos; RANK_POSITION_TABLE_SIZE],
}

impl HufCompressTables {
    pub(crate) fn new() -> HufCompressTables {
        HufCompressTables {
            count: [0; 256],
            ctable: [0; 257],
            huff_node_tbl: [NodeElt::default(); 512],
            rank_position: [RankPos::default(); RANK_POSITION_TABLE_SIZE],
        }
    }
}

const MAX_FSE_TABLELOG_FOR_HUFF_HEADER: u32 = 6;

/// `HUF_compressWeights`: the weights of a table, FSE coded.
fn compress_weights(dst: &mut [u8], weight_table: &[u8]) -> CResult<usize> {
    let wt_size = weight_table.len();
    let mut op = 0usize;
    let mut max_symbol_value = HUF_TABLELOG_MAX;
    let mut table_log = MAX_FSE_TABLELOG_FOR_HUFF_HEADER;
    let mut count = [0u32; HUF_TABLELOG_MAX as usize + 1];
    let mut norm = [0i16; HUF_TABLELOG_MAX as usize + 1];

    // Init conditions.
    if wt_size <= 1 {
        return Ok(0); // not compressible
    }

    // Scan the input and build the symbol stats.
    {
        let max_count = hist::count_simple(&mut count, &mut max_symbol_value, weight_table);
        if max_count as usize == wt_size {
            return Ok(1); // only a single symbol in src: rle
        }
        if max_count == 1 {
            return Ok(0); // each symbol present at most once: not compressible
        }
    }

    table_log = fse_compress::optimal_table_log(table_log, wt_size, max_symbol_value);
    fse_compress::normalize_count(
        &mut norm,
        table_log,
        &count,
        wt_size,
        max_symbol_value,
        false,
    )?;

    // Write the table description header.
    {
        let h_size =
            fse_compress::write_ncount(&mut dst[op..], &norm, max_symbol_value, table_log)?;
        op += h_size;
    }

    // Compress.
    let mut ctable = FseCTable::new(MAX_FSE_TABLELOG_FOR_HUFF_HEADER, HUF_TABLELOG_MAX);
    fse_compress::build_ctable(&mut ctable, &norm, max_symbol_value, table_log);
    {
        let c_size = fse_compress::compress_using_ctable(&mut dst[op..], weight_table, &ctable);
        if c_size == 0 {
            return Ok(0); // not enough space for compressed data
        }
        op += c_size;
    }

    Ok(op)
}

#[inline]
fn get_nb_bits(elt: HufCElt) -> u64 {
    elt & 0xFF
}

#[inline]
fn set_value(elt: &mut HufCElt, value: u64) {
    let nb_bits = get_nb_bits(*elt);
    if nb_bits > 0 {
        *elt |= value << (64 - nb_bits);
    }
}

/// `HUF_readCTableHeader`: the table log and the highest symbol.
#[inline]
fn read_ctable_header(ctable: &HufCTable) -> (u32, u32) {
    ((ctable[0] & 0xFF) as u32, ((ctable[0] >> 8) & 0xFF) as u32)
}

/// `HUF_writeCTableHeader`.
#[inline]
fn write_ctable_header(ctable: &mut HufCTable, table_log: u32, max_symbol_value: u32) {
    ctable[0] = (table_log as u8) as u64 | (((max_symbol_value as u8) as u64) << 8);
}

/// `HUF_writeCTable_wksp`: the description of a table, as a block's literals section has it.
fn write_ctable(
    dst: &mut [u8],
    ctable: &HufCTable,
    max_symbol_value: u32,
    huff_log: u32,
) -> CResult<usize> {
    let ct = &ctable[1..];
    let mut bits_to_weight = [0u8; HUF_TABLELOG_MAX as usize + 1];
    let mut huff_weight = [0u8; HUF_SYMBOLVALUE_MAX as usize];
    let max_dst_size = dst.len();
    let max_symbol_value = max_symbol_value as usize;

    // Check conditions.
    if max_symbol_value > HUF_SYMBOLVALUE_MAX as usize {
        return Err(CError::MaxSymbolValueTooLarge);
    }

    // Convert to weights.
    bits_to_weight[0] = 0;
    for n in 1..huff_log as usize + 1 {
        bits_to_weight[n] = (huff_log as usize + 1 - n) as u8;
    }
    for n in 0..max_symbol_value {
        huff_weight[n] = bits_to_weight[get_nb_bits(ct[n]) as usize];
    }

    // Attempt the weights compression by FSE.
    if max_dst_size < 1 {
        return Err(CError::DstSizeTooSmall);
    }
    {
        let h_size = compress_weights(&mut dst[1..], &huff_weight[..max_symbol_value])?;
        if (h_size > 1) & (h_size < max_symbol_value / 2) {
            // FSE compressed.
            dst[0] = h_size as u8;
            return Ok(h_size + 1);
        }
    }

    // Write the raw values as 4-bit fields (max: 15).
    if max_symbol_value > (256 - 128) {
        // should not happen: likely means the source cannot be compressed
        return Err(CError::Generic);
    }
    if ((max_symbol_value + 1) / 2) + 1 > max_dst_size {
        return Err(CError::DstSizeTooSmall); // not enough space within the dst buffer
    }
    dst[0] = (128 /* special case */ + (max_symbol_value - 1)) as u8;
    // to be sure it doesn't cause an msan issue in the final combination
    huff_weight[max_symbol_value] = 0;
    let mut n = 0;
    while n < max_symbol_value {
        dst[(n / 2) + 1] = (huff_weight[n] << 4).wrapping_add(huff_weight[n + 1]);
        n += 2;
    }
    Ok(((max_symbol_value + 1) / 2) + 1)
}

/// The original's `huffNode`: a view of the node table that starts at its second element,
/// so that the element before the first can be asked for.
struct Nodes<'a>(&'a mut [NodeElt]);

impl Nodes<'_> {
    #[inline]
    fn at(&mut self, n: i32) -> &mut NodeElt {
        &mut self.0[(n + 1) as usize]
    }
}

/// `HUF_setMaxHeight`: enforces `target_nb_bits` on the tree described in `huff_node`. The
/// answer is the highest number of bits there is afterwards.
fn set_max_height(huff_node: &mut Nodes, last_non_null: u32, target_nb_bits: u32) -> u32 {
    let largest_bits = huff_node.at(last_non_null as i32).nb_bits as u32;
    // Early exit: no elt > targetNbBits, so the tree is already valid.
    if largest_bits <= target_nb_bits {
        return largest_bits;
    }

    // There are several too large elements (at least >= 2).
    {
        let mut total_cost = 0i32;
        let base_cost = 1u32 << (largest_bits - target_nb_bits);
        let mut n = last_non_null as i32;

        // Adjust any ranks > targetNbBits to targetNbBits.
        while huff_node.at(n).nb_bits as u32 > target_nb_bits {
            total_cost = total_cost.wrapping_add(
                (base_cost - (1u32 << (largest_bits - huff_node.at(n).nb_bits as u32))) as i32,
            );
            huff_node.at(n).nb_bits = target_nb_bits as u8;
            n -= 1;
        }
        // n stops at huffNode[n].nbBits <= targetNbBits.
        // Find n so that huffNode[n].nbBits < targetNbBits.
        while huff_node.at(n).nb_bits as u32 == target_nb_bits {
            n -= 1;
        }

        // Renorm totalCost from 2^largestBits to 2^targetNbBits; it is certain to be a
        // multiple of baseCost.
        total_cost >>= largest_bits - target_nb_bits;

        // Repay normalized cost.
        {
            const NO_SYMBOL: u32 = 0xF0F0F0F0;
            let mut rank_last = [NO_SYMBOL; HUF_TABLELOG_MAX as usize + 2];

            // Get pos of last (smallest = lowest cum. count) symbol per rank.
            {
                let mut current_nb_bits = target_nb_bits;
                let mut pos = n;
                while pos >= 0 {
                    if huff_node.at(pos).nb_bits as u32 >= current_nb_bits {
                        pos -= 1;
                        continue;
                    }
                    current_nb_bits = huff_node.at(pos).nb_bits as u32; // < targetNbBits
                    rank_last[(target_nb_bits - current_nb_bits) as usize] = pos as u32;
                    pos -= 1;
                }
            }

            while total_cost > 0 {
                // Try to reduce the next power of 2 above totalCost because we gain back
                // half the rank.
                let mut n_bits_to_decrease = highbit32(total_cost as u32) + 1;
                while n_bits_to_decrease > 1 {
                    let high_pos = rank_last[n_bits_to_decrease as usize];
                    let low_pos = rank_last[n_bits_to_decrease as usize - 1];
                    if high_pos == NO_SYMBOL {
                        n_bits_to_decrease -= 1;
                        continue;
                    }
                    // Decrease highPos if no symbols of lowPos or if it is not cheaper to
                    // remove 2 lowPos than highPos.
                    if low_pos == NO_SYMBOL {
                        break;
                    }
                    {
                        let high_total = huff_node.at(high_pos as i32).count;
                        let low_total = 2u32.wrapping_mul(huff_node.at(low_pos as i32).count);
                        if high_total <= low_total {
                            break;
                        }
                    }
                    n_bits_to_decrease -= 1;
                }
                // Only triggered when there is no rank 1 symbol left => find the closest
                // one (note: there is necessarily at least one!).
                while n_bits_to_decrease <= HUF_TABLELOG_MAX
                    && rank_last[n_bits_to_decrease as usize] == NO_SYMBOL
                {
                    n_bits_to_decrease += 1;
                }
                // Increase the number of bits to gain back half the rank cost.
                total_cost -= 1 << (n_bits_to_decrease - 1);
                huff_node
                    .at(rank_last[n_bits_to_decrease as usize] as i32)
                    .nb_bits += 1;

                // Fix up the new rank. If the new rank was empty, this symbol is now its
                // smallest; otherwise it is the largest symbol of the new rank, so nothing
                // is needed.
                if rank_last[n_bits_to_decrease as usize - 1] == NO_SYMBOL {
                    rank_last[n_bits_to_decrease as usize - 1] =
                        rank_last[n_bits_to_decrease as usize];
                }
                // Fix up the old rank. If the symbol was at position 0, it was the highest
                // weight symbol in the tree, so the rank must now be empty; otherwise the
                // next element is either in this rank, or the rank is empty.
                if rank_last[n_bits_to_decrease as usize] == 0 {
                    // Special case: reached the largest symbol.
                    rank_last[n_bits_to_decrease as usize] = NO_SYMBOL;
                } else {
                    rank_last[n_bits_to_decrease as usize] -= 1;
                    if huff_node
                        .at(rank_last[n_bits_to_decrease as usize] as i32)
                        .nb_bits as u32
                        != target_nb_bits - n_bits_to_decrease
                    {
                        // this rank is now empty
                        rank_last[n_bits_to_decrease as usize] = NO_SYMBOL;
                    }
                }
            }

            // Sometimes the cost correction overshoots: give the extra back to the
            // lowest probability symbols.
            while total_cost < 0 {
                // If no rank 1 symbol exists (using up all of rank 0 is not wanted),
                // create a rank 1 symbol from the lowest probability symbol of rank 0.
                if rank_last[1] == NO_SYMBOL {
                    while huff_node.at(n).nb_bits as u32 == target_nb_bits {
                        n -= 1;
                    }
                    huff_node.at(n + 1).nb_bits -= 1;
                    rank_last[1] = (n + 1) as u32;
                    total_cost += 1;
                    continue;
                }
                huff_node.at(rank_last[1] as i32 + 1).nb_bits -= 1;
                rank_last[1] += 1;
                total_cost += 1;
            }
        }
    }

    target_nb_bits
}

/// `HUF_getIndex`: the bucket of a count. Low counts have a bucket each; from the cutoff up
/// a bucket holds the counts of one power of two.
#[inline]
fn get_index(count: u32) -> u32 {
    if count < RANK_POSITION_DISTINCT_COUNT_CUTOFF {
        count
    } else {
        highbit32(count) + RANK_POSITION_LOG_BUCKETS_BEGIN
    }
}

/// `HUF_insertionSort`, from `low` to `high`, by count, descending.
fn insertion_sort(huff_node: &mut [NodeElt], low: i32, high: i32) {
    let size = high - low + 1;
    let huff_node = &mut huff_node[low as usize..];
    for i in 1..size {
        let key = huff_node[i as usize];
        let mut j = i - 1;
        while j >= 0 && huff_node[j as usize].count < key.count {
            huff_node[j as usize + 1] = huff_node[j as usize];
            j -= 1;
        }
        huff_node[(j + 1) as usize] = key;
    }
}

/// `HUF_quickSortPartition`: pivot helper for the quicksort.
fn quick_sort_partition(arr: &mut [NodeElt], low: i32, high: i32) -> i32 {
    // Simply select the rightmost element as pivot. "Better" selectors like median-of-three
    // don't experimentally appear to have any benefit.
    let pivot = arr[high as usize].count;
    let mut i = low - 1;
    let mut j = low;
    while j < high {
        if arr[j as usize].count > pivot {
            i += 1;
            arr.swap(i as usize, j as usize);
        }
        j += 1;
    }
    arr.swap((i + 1) as usize, high as usize);
    i + 1
}

/// `HUF_simpleQuickSort`: a classic quicksort by descending "count", using an insertion
/// sort for small arrays.
fn simple_quick_sort(arr: &mut [NodeElt], mut low: i32, mut high: i32) {
    const K_INSERTION_SORT_THRESHOLD: i32 = 8;
    if high - low < K_INSERTION_SORT_THRESHOLD {
        insertion_sort(arr, low, high);
        return;
    }
    while low < high {
        let idx = quick_sort_partition(arr, low, high);
        if idx - low < high - idx {
            simple_quick_sort(arr, low, idx - 1);
            low = idx + 1;
        } else {
            simple_quick_sort(arr, idx + 1, high);
            high = idx - 1;
        }
    }
}

/// `HUF_sort`: the symbols by descending count, by bucket, with a quicksort inside the
/// buckets that hold more than one count. `huff_node` is the original's `huffNode`: the
/// node table from its second element.
fn sort(
    huff_node: &mut [NodeElt],
    count: &[u32],
    max_symbol_value: u32,
    rank_position: &mut [RankPos; RANK_POSITION_TABLE_SIZE],
) {
    let max_symbol_value1 = max_symbol_value as usize + 1;

    // Compute base and set curr to base. For symbol s let lowerRank = HUF_getIndex(count[n])
    // and rank = lowerRank + 1. Then 2^lowerRank <= count[n] < 2^rank. The start position of
    // each bucket is tracked by putting the number of symbols in that bucket in
    // rankPosition[lowerRank].base, then taking the cumulative sum.
    rank_position.fill(RankPos::default());
    for n in 0..max_symbol_value1 {
        let lower_rank = get_index(count[n]) as usize;
        rank_position[lower_rank].base += 1;
    }

    // Set base and curr to position of first element in the bucket.
    for n in (1..RANK_POSITION_TABLE_SIZE).rev() {
        rank_position[n - 1].base = rank_position[n - 1]
            .base
            .wrapping_add(rank_position[n].base);
        rank_position[n - 1].curr = rank_position[n - 1].base;
    }

    // Insert each symbol into its appropriate bucket, building up huffNode.
    for n in 0..max_symbol_value1 {
        let c = count[n];
        let r = get_index(c) as usize + 1;
        let pos = rank_position[r].curr as usize;
        rank_position[r].curr += 1;
        huff_node[pos].count = c;
        huff_node[pos].byte = n as u8;
    }

    // Sort each bucket.
    for n in RANK_POSITION_DISTINCT_COUNT_CUTOFF as usize..RANK_POSITION_TABLE_SIZE - 1 {
        let bucket_size = rank_position[n].curr as i32 - rank_position[n].base as i32;
        let bucket_start_idx = rank_position[n].base as usize;
        if bucket_size > 1 {
            simple_quick_sort(&mut huff_node[bucket_start_idx..], 0, bucket_size - 1);
        }
    }
}

/// `HUF_buildTree`: the tree, as parents and numbers of bits, of the sorted nodes. The
/// answer is the place of the last node with a count.
fn build_tree(huff_node: &mut Nodes, max_symbol_value: u32) -> i32 {
    let mut node_nb = STARTNODE;

    // Init for parents.
    let mut non_null_rank = max_symbol_value as i32;
    while huff_node.at(non_null_rank).count == 0 {
        non_null_rank -= 1;
    }
    let mut low_s = non_null_rank;
    let node_root = node_nb + low_s - 1;
    let mut low_n = node_nb;
    huff_node.at(node_nb).count = huff_node
        .at(low_s)
        .count
        .wrapping_add(huff_node.at(low_s - 1).count);
    huff_node.at(low_s).parent = node_nb as u16;
    huff_node.at(low_s - 1).parent = node_nb as u16;
    node_nb += 1;
    low_s -= 2;
    for n in node_nb..=node_root {
        huff_node.at(n).count = 1u32 << 30;
    }
    huff_node.at(-1).count = 1u32 << 31; // fake entry, strong barrier

    // Create parents.
    while node_nb <= node_root {
        let n1 = if huff_node.at(low_s).count < huff_node.at(low_n).count {
            low_s -= 1;
            low_s + 1
        } else {
            low_n += 1;
            low_n - 1
        };
        let n2 = if huff_node.at(low_s).count < huff_node.at(low_n).count {
            low_s -= 1;
            low_s + 1
        } else {
            low_n += 1;
            low_n - 1
        };
        huff_node.at(node_nb).count = huff_node.at(n1).count.wrapping_add(huff_node.at(n2).count);
        huff_node.at(n1).parent = node_nb as u16;
        huff_node.at(n2).parent = node_nb as u16;
        node_nb += 1;
    }

    // Distribute weights (unlimited tree height).
    huff_node.at(node_root).nb_bits = 0;
    let mut n = node_root - 1;
    while n >= STARTNODE {
        let parent = huff_node.at(n).parent as i32;
        huff_node.at(n).nb_bits = huff_node.at(parent).nb_bits + 1;
        n -= 1;
    }
    for n in 0..=non_null_rank {
        let parent = huff_node.at(n).parent as i32;
        huff_node.at(n).nb_bits = huff_node.at(parent).nb_bits + 1;
    }

    non_null_rank
}

/// `HUF_buildCTableFromTree`: the codes of the symbols, from the numbers of bits.
fn build_ctable_from_tree(
    ctable: &mut HufCTable,
    huff_node: &mut Nodes,
    non_null_rank: i32,
    max_symbol_value: u32,
    max_nb_bits: u32,
) {
    // Fill the result into the ctable (val, nbBits).
    let mut nb_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 1];
    let mut val_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 1];
    let alphabet_size = max_symbol_value as i32 + 1;
    for n in 0..=non_null_rank {
        nb_per_rank[huff_node.at(n).nb_bits as usize] += 1;
    }
    // Determine the starting value per rank.
    {
        let mut min = 0u16;
        for n in (1..=max_nb_bits as usize).rev() {
            val_per_rank[n] = min; // get starting value within each rank
            min = min.wrapping_add(nb_per_rank[n]);
            min >>= 1;
        }
    }
    for n in 0..alphabet_size {
        let node = *huff_node.at(n);
        // push nbBits per symbol, symbol order
        ctable[1 + node.byte as usize] = node.nb_bits as u64;
    }
    for n in 0..alphabet_size as usize {
        // Assign value within rank, symbol order.
        let rank = get_nb_bits(ctable[1 + n]) as usize;
        let value = val_per_rank[rank];
        val_per_rank[rank] = val_per_rank[rank].wrapping_add(1);
        set_value(&mut ctable[1 + n], value as u64);
    }

    write_ctable_header(ctable, max_nb_bits, max_symbol_value);
}

/// `HUF_buildCTable_wksp`: a table for the counts, with codes of no more than `max_nb_bits`
/// bits. The answer is the highest number of bits used.
fn build_ctable(
    ctable: &mut HufCTable,
    count: &[u32],
    max_symbol_value: u32,
    mut max_nb_bits: u32,
    huff_node_tbl: &mut [NodeElt; 512],
    rank_position: &mut [RankPos; RANK_POSITION_TABLE_SIZE],
) -> CResult<u32> {
    // Safety checks.
    if max_nb_bits == 0 {
        max_nb_bits = HUF_TABLELOG_DEFAULT;
    }
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return Err(CError::MaxSymbolValueTooLarge);
    }
    huff_node_tbl.fill(NodeElt::default());

    // Sort, decreasing order.
    sort(
        &mut huff_node_tbl[1..],
        count,
        max_symbol_value,
        rank_position,
    );

    // Build the tree.
    let mut huff_node = Nodes(&mut huff_node_tbl[..]);
    let non_null_rank = build_tree(&mut huff_node, max_symbol_value);

    // Determine and enforce maxTableLog.
    max_nb_bits = set_max_height(&mut huff_node, non_null_rank as u32, max_nb_bits);
    if max_nb_bits > HUF_TABLELOG_MAX {
        return Err(CError::Generic); // check fit into table
    }

    build_ctable_from_tree(
        ctable,
        &mut huff_node,
        non_null_rank,
        max_symbol_value,
        max_nb_bits,
    );

    Ok(max_nb_bits)
}

/// `HUF_estimateCompressedSize`.
fn estimate_compressed_size(ctable: &HufCTable, count: &[u32], max_symbol_value: u32) -> usize {
    let ct = &ctable[1..];
    let mut nb_bits = 0usize;
    for s in 0..=max_symbol_value as usize {
        nb_bits += get_nb_bits(ct[s]) as usize * count[s] as usize;
    }
    nb_bits >> 3
}

/// `HUF_optimalTableLog` with `HUF_flags_optimalDepth`: of the depths from the least the
/// symbols need, the one that comes out smallest, table and all (as far as the sizes come
/// down).
fn optimal_table_log_by_depth(
    max_table_log: u32,
    max_symbol_value: u32,
    table: &mut HufCompressTables,
) -> u32 {
    // (The room the original's workspace leaves for the description.)
    let mut dst = [0u8; 4096];
    // `HUF_cardinality`, `HUF_minTableLog`.
    let symbol_cardinality = table.count[..=max_symbol_value as usize]
        .iter()
        .filter(|&&c| c != 0)
        .count() as u32;
    let min_table_log = highbit32(symbol_cardinality) + 1;
    let mut opt_size = usize::MAX - 1;
    let mut opt_log = max_table_log;

    // Search until size increases.
    for opt_log_guess in min_table_log..=max_table_log {
        let Ok(max_bits) = build_ctable(
            &mut table.ctable,
            &table.count,
            max_symbol_value,
            opt_log_guess,
            &mut table.huff_node_tbl,
            &mut table.rank_position,
        ) else {
            continue;
        };
        if max_bits < opt_log_guess && opt_log_guess > min_table_log {
            break;
        }
        let Ok(h_size) = write_ctable(&mut dst, &table.ctable, max_symbol_value, max_bits) else {
            continue;
        };

        let new_size =
            estimate_compressed_size(&table.ctable, &table.count, max_symbol_value) + h_size;
        if new_size > opt_size + 1 {
            break;
        }
        if new_size < opt_size {
            opt_size = new_size;
            opt_log = opt_log_guess;
        }
    }
    opt_log
}

/// What `ZSTD_buildBlockEntropyStats_literals` asks of the Huffman coder, for the block
/// splitter's estimates: the literals of `src` counted in `table.count` (`HIST_count_wksp`),
/// the largest count, and the highest symbol.
pub(crate) fn count_literals(table: &mut HufCompressTables, src: &[u8]) -> (usize, u32) {
    let mut max_symbol_value = HUF_SYMBOLVALUE_MAX;
    let largest = hist::count_simple(&mut table.count, &mut max_symbol_value, src) as usize;
    (largest, max_symbol_value)
}

/// With the counts of [`count_literals`]: whether `ctable` codes every symbol counted
/// (`HUF_validateCTable`).
pub(crate) fn counted_fit(
    table: &HufCompressTables,
    ctable: &HufCTable,
    max_symbol_value: u32,
) -> bool {
    validate_ctable(ctable, &table.count, max_symbol_value)
}

/// With the counts of [`count_literals`]: a new table for them in `ctable`, of the depth
/// `HUF_optimalTableLog` takes, and its depth.
pub(crate) fn build_table_for_counts(
    table: &mut HufCompressTables,
    ctable: &mut HufCTable,
    src_size: usize,
    max_symbol_value: u32,
    huff_log: u32,
    optimal_depth: bool,
) -> CResult<u32> {
    let huff_log = if optimal_depth {
        optimal_table_log_by_depth(huff_log, max_symbol_value, table)
    } else {
        fse_compress::optimal_table_log_internal(huff_log, src_size, max_symbol_value, 1)
    };
    build_ctable(
        ctable,
        &table.count,
        max_symbol_value,
        huff_log,
        &mut table.huff_node_tbl,
        &mut table.rank_position,
    )
}

/// With the counts of [`count_literals`]: what the literals come to with `ctable`, in bytes
/// (`HUF_estimateCompressedSize`).
pub(crate) fn estimate_counted(
    table: &HufCompressTables,
    ctable: &HufCTable,
    max_symbol_value: u32,
) -> usize {
    estimate_compressed_size(ctable, &table.count, max_symbol_value)
}

/// The description of `ctable` (`HUF_writeCTable_wksp`).
pub(crate) fn write_table(
    dst: &mut [u8],
    ctable: &HufCTable,
    max_symbol_value: u32,
    huff_log: u32,
) -> CResult<usize> {
    write_ctable(dst, ctable, max_symbol_value, huff_log)
}

/// `HUF_validateCTable`: whether the table has a code for every symbol that is counted.
fn validate_ctable(ctable: &HufCTable, count: &[u32], max_symbol_value: u32) -> bool {
    let (_, header_max_symbol_value) = read_ctable_header(ctable);
    let ct = &ctable[1..];
    let mut bad = false;

    if header_max_symbol_value < max_symbol_value {
        return false;
    }

    for s in 0..=max_symbol_value as usize {
        bad |= (count[s] != 0) & (get_nb_bits(ct[s]) == 0);
    }
    !bad
}

/// `HUF_CStream_t`: a bit stream with two containers. Codes go in from the top of a
/// container, so that a code's bits need not be masked.
struct HufCStream<'a> {
    bit_container: [u64; 2],
    bit_pos: [u64; 2],
    dst: &'a mut [u8],
    ptr: usize,
    end_ptr: usize,
}

impl<'a> HufCStream<'a> {
    /// `HUF_initCStream`. `None` where the original answers `dstSize_tooSmall`.
    fn init(dst: &'a mut [u8]) -> Option<HufCStream<'a>> {
        if dst.len() <= 8 {
            return None;
        }
        let end_ptr = dst.len() - 8;
        Some(HufCStream {
            bit_container: [0; 2],
            bit_pos: [0; 2],
            dst,
            ptr: 0,
            end_ptr,
        })
    }

    /// `HUF_addBits`. With `k_fast` the low bits of the element are left in the container:
    /// they are shifted out of it by what comes after.
    #[inline]
    fn add_bits(&mut self, elt: HufCElt, idx: usize, k_fast: bool) {
        // This is efficient on x86-64 with BMI2 because shrx only reads the low 6 bits of
        // the register. The compiler should get this right, but in case it doesn't, the low
        // 8 bits are the number of bits and nothing else.
        self.bit_container[idx] >>= get_nb_bits(elt);
        self.bit_container[idx] |= if k_fast { elt } else { elt & !0xFFu64 };
        // The low byte of bitPos is the count; the rest of it is dirty.
        self.bit_pos[idx] = self.bit_pos[idx].wrapping_add(elt);
    }

    /// `HUF_zeroIndex1`.
    #[inline]
    fn zero_index1(&mut self) {
        self.bit_container[1] = 0;
        self.bit_pos[1] = 0;
    }

    /// `HUF_mergeIndex1`: the second container goes into the first.
    #[inline]
    fn merge_index1(&mut self) {
        self.bit_container[0] >>= self.bit_pos[1] & 0xFF;
        self.bit_container[0] |= self.bit_container[1];
        self.bit_pos[0] = self.bit_pos[0].wrapping_add(self.bit_pos[1]);
    }

    /// `HUF_flushBits`: the whole bytes of the first container go to the output. Without
    /// `k_fast` the stream stops at the end of the output.
    #[inline]
    fn flush_bits(&mut self, k_fast: bool) {
        // The upper bits of bitPos are noisy, so they must be masked out.
        let nb_bits = self.bit_pos[0] & 0xFF;
        let nb_bytes = (nb_bits >> 3) as usize;
        // The top nbBits bits of bitContainer are the ones that need to be flushed.
        let bit_container = self.bit_container[0]
            .checked_shr(64 - nb_bits as u32)
            .unwrap_or(0);
        // Mask bitPos to account for the bytes consumed.
        self.bit_pos[0] &= 7;
        self.dst[self.ptr..self.ptr + 8].copy_from_slice(&bit_container.to_le_bytes());
        self.ptr += nb_bytes;
        if !k_fast && self.ptr > self.end_ptr {
            self.ptr = self.end_ptr;
        }
        // bitContainer doesn't need to be modified because the leftover bits are already
        // the top bitPos bits, and the bottom bits are not used.
    }

    /// `HUF_closeCStream`: the size of the stream in bytes, or 0 if it did not fit.
    fn close(mut self) -> usize {
        // `HUF_endMark`: one bit, set.
        let mut end_mark: HufCElt = 1;
        set_value(&mut end_mark, 1);
        self.add_bits(end_mark, 0, false);
        self.flush_bits(false);
        {
            let nb_bits = self.bit_pos[0] & 0xFF;
            if self.ptr >= self.end_ptr {
                return 0; // overflow detected
            }
            self.ptr + usize::from(nb_bits > 0)
        }
    }
}

/// `HUF_compress1X_usingCTable_internal_body_loop`.
#[inline]
fn compress1x_body_loop(
    bit_c: &mut HufCStream,
    ip: &[u8],
    ct: &[HufCElt],
    k_unroll: i32,
    k_fast_flush: bool,
    k_last_fast: bool,
) {
    // Join to kUnroll.
    let mut n = ip.len() as i32;
    let mut rem = n % k_unroll;
    if rem > 0 {
        while rem > 0 {
            n -= 1;
            bit_c.add_bits(ct[ip[n as usize] as usize], 0, false);
            rem -= 1;
        }
        bit_c.flush_bits(k_fast_flush);
    }

    // Join to 2 * kUnroll.
    if n % (2 * k_unroll) != 0 {
        for u in 1..k_unroll {
            bit_c.add_bits(ct[ip[(n - u) as usize] as usize], 0, true);
        }
        bit_c.add_bits(ct[ip[(n - k_unroll) as usize] as usize], 0, k_last_fast);
        bit_c.flush_bits(k_fast_flush);
        n -= k_unroll;
    }

    while n > 0 {
        // Encode kUnroll symbols into the bitstream @ index 0.
        for u in 1..k_unroll {
            bit_c.add_bits(ct[ip[(n - u) as usize] as usize], 0, true);
        }
        bit_c.add_bits(ct[ip[(n - k_unroll) as usize] as usize], 0, k_last_fast);
        bit_c.flush_bits(k_fast_flush);
        // Encode kUnroll symbols into the bitstream @ index 1. This allows us to start
        // filling the bit container without any data dependencies.
        bit_c.zero_index1();
        for u in 1..k_unroll {
            bit_c.add_bits(ct[ip[(n - k_unroll - u) as usize] as usize], 1, true);
        }
        bit_c.add_bits(
            ct[ip[(n - k_unroll - k_unroll) as usize] as usize],
            1,
            k_last_fast,
        );
        // Merge bitstream @ index 1 into the bitstream @ index 0.
        bit_c.merge_index1();
        bit_c.flush_bits(k_fast_flush);
        n -= 2 * k_unroll;
    }
}

/// `HUF_tightCompressBound`: the upper bound for the length of the bit stream there can be
/// for this table log, eight bytes of slack included.
#[inline]
fn tight_compress_bound(src_size: usize, table_log: usize) -> usize {
    ((src_size * table_log) >> 3) + 8
}

/// `HUF_compress1X_usingCTable_internal`: one stream of codes. 0 if it does not fit.
fn compress1x_using_ctable(dst: &mut [u8], src: &[u8], ctable: &HufCTable) -> usize {
    let (table_log, _) = read_ctable_header(ctable);
    let ct = &ctable[1..];
    let dst_size = dst.len();

    // Init.
    if dst_size < 8 {
        return 0; // not enough space to compress
    }
    let mut bit_c = match HufCStream::init(dst) {
        Some(bit_c) => bit_c,
        None => return 0,
    };

    if dst_size < tight_compress_bound(src.len(), table_log as usize) || table_log > 11 {
        compress1x_body_loop(
            &mut bit_c, src, ct, /* kUnroll */ 4, /* kFast */ false,
            /* kLastFast */ false,
        );
    } else {
        match table_log {
            // The loops written out by table log, as the original has them for 64 bits.
            11 => compress1x_body_loop(&mut bit_c, src, ct, 5, true, false),
            10 => compress1x_body_loop(&mut bit_c, src, ct, 5, true, true),
            9 => compress1x_body_loop(&mut bit_c, src, ct, 6, true, false),
            8 => compress1x_body_loop(&mut bit_c, src, ct, 7, true, false),
            7 => compress1x_body_loop(&mut bit_c, src, ct, 8, true, false),
            _ => compress1x_body_loop(&mut bit_c, src, ct, 9, true, true),
        }
    }

    bit_c.close()
}

/// `HUF_compress4X_usingCTable_internal`: four streams of codes behind their three sizes.
fn compress4x_using_ctable(dst: &mut [u8], src: &[u8], ctable: &HufCTable) -> usize {
    let src_size = src.len();
    let segment_size = (src_size + 3) / 4; // first 3 segments
    let mut ip = 0usize;
    let mut op = 0usize;

    if dst.len() < 6 + 1 + 1 + 1 + 8 {
        return 0; // minimum space to compress successfully
    }
    if src_size < 12 {
        return 0; // no saving possible: too small input
    }
    op += 6; // jumpTable

    for stream in 0..3 {
        let c_size = compress1x_using_ctable(&mut dst[op..], &src[ip..ip + segment_size], ctable);
        if c_size == 0 || c_size > 65535 {
            return 0;
        }
        write_le16(dst, stream * 2, c_size as u16);
        op += c_size;
        ip += segment_size;
    }

    {
        let c_size = compress1x_using_ctable(&mut dst[op..], &src[ip..], ctable);
        if c_size == 0 || c_size > 65535 {
            return 0;
        }
        op += c_size;
    }

    op
}

/// `HUF_nbStreams_e`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HufNbStreams {
    Single,
    Four,
}

/// `HUF_compressCTable_internal`. `op` is where the streams start in `dst`; the answer
/// counts from the start of `dst`.
fn compress_ctable_internal(
    dst: &mut [u8],
    mut op: usize,
    src: &[u8],
    nb_streams: HufNbStreams,
    ctable: &HufCTable,
) -> usize {
    let c_size = if nb_streams == HufNbStreams::Single {
        compress1x_using_ctable(&mut dst[op..], src, ctable)
    } else {
        compress4x_using_ctable(&mut dst[op..], src, ctable)
    };
    if c_size == 0 {
        return 0; // uncompressible
    }
    op += c_size;
    // Check compressibility.
    if op >= src.len() - 1 {
        return 0;
    }
    op
}

const SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE: usize = 4096;
const SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO: usize = 10; // must be >= 2

/// What `HUF_compress1X_repeat` and `HUF_compress4X_repeat` share (`HUF_compress_internal`):
/// `src` as a Huffman table and its streams, or as streams of the table of the block before
/// (`old_huf_table`, where `repeat` allows it; `repeat` is `None` afterwards if the table
/// is new). 0 if `src` is not worth it, 1 if it is one byte over and over.
///
/// `prefer_repeat`, `suspect_uncompressible` and `optimal_depth` are the original's
/// `HUF_flags_preferRepeat`, `HUF_flags_suspectUncompressible` and `HUF_flags_optimalDepth`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_repeat(
    dst: &mut [u8],
    src: &[u8],
    mut max_symbol_value: u32,
    mut huff_log: u32,
    nb_streams: HufNbStreams,
    table: &mut HufCompressTables,
    old_huf_table: &mut HufCTable,
    repeat: &mut HufRepeat,
    prefer_repeat: bool,
    suspect_uncompressible: bool,
    optimal_depth: bool,
) -> CResult<usize> {
    let src_size = src.len();
    let dst_size = dst.len();
    let mut op = 0usize;

    // Checks and inits.
    if src_size == 0 {
        return Ok(0); // uncompressed
    }
    if dst_size == 0 {
        return Ok(0); // cannot fit anything within dst budget
    }
    if src_size > HUF_BLOCKSIZE_MAX {
        return Err(CError::SrcSizeWrong); // current block size limit
    }
    if huff_log > HUF_TABLELOG_MAX {
        return Err(CError::TableLogTooLarge);
    }
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return Err(CError::MaxSymbolValueTooLarge);
    }
    if max_symbol_value == 0 {
        max_symbol_value = HUF_SYMBOLVALUE_MAX;
    }
    if huff_log == 0 {
        huff_log = HUF_TABLELOG_DEFAULT;
    }

    // Heuristic: if the old table is valid, use it for small inputs.
    if prefer_repeat && *repeat == HufRepeat::Valid {
        return Ok(compress_ctable_internal(
            dst,
            op,
            src,
            nb_streams,
            old_huf_table,
        ));
    }

    // If uncompressible data is suspected, try sampling to check.
    if suspect_uncompressible
        && src_size >= (SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE * SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO)
    {
        let mut largest_total = 0usize;
        {
            let mut max_symbol_value_begin = max_symbol_value;
            let largest_begin = hist::count_simple(
                &mut table.count,
                &mut max_symbol_value_begin,
                &src[..SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE],
            );
            largest_total += largest_begin as usize;
        }
        {
            let mut max_symbol_value_end = max_symbol_value;
            let largest_end = hist::count_simple(
                &mut table.count,
                &mut max_symbol_value_end,
                &src[src_size - SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE..],
            );
            largest_total += largest_end as usize;
        }
        if largest_total <= ((2 * SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE) >> 7) + 4 {
            return Ok(0); // heuristic: probably not compressible enough
        }
    }

    // Scan the input and build the symbol stats.
    {
        let largest = hist::count_simple(&mut table.count, &mut max_symbol_value, src) as usize;
        if largest == src_size {
            dst[0] = src[0];
            return Ok(1); // single symbol, rle
        }
        if largest <= (src_size >> 7) + 4 {
            return Ok(0); // heuristic: probably not compressible enough
        }
    }

    // Check the validity of the previous table.
    if *repeat == HufRepeat::Check
        && !validate_ctable(old_huf_table, &table.count, max_symbol_value)
    {
        *repeat = HufRepeat::None;
    }
    // Heuristic: use the existing table for small inputs.
    if prefer_repeat && *repeat != HufRepeat::None {
        return Ok(compress_ctable_internal(
            dst,
            op,
            src,
            nb_streams,
            old_huf_table,
        ));
    }

    // Build the Huffman tree.
    huff_log = if optimal_depth {
        optimal_table_log_by_depth(huff_log, max_symbol_value, table)
    } else {
        fse_compress::optimal_table_log_internal(huff_log, src_size, max_symbol_value, 1)
    };
    {
        let max_bits = build_ctable(
            &mut table.ctable,
            &table.count,
            max_symbol_value,
            huff_log,
            &mut table.huff_node_tbl,
            &mut table.rank_position,
        )?;
        huff_log = max_bits;
    }

    // Write the table description header.
    {
        let h_size = write_ctable(dst, &table.ctable, max_symbol_value, huff_log)?;
        // Check if reusing the previous table gives a smaller result.
        if *repeat != HufRepeat::None {
            let old_size = estimate_compressed_size(old_huf_table, &table.count, max_symbol_value);
            let new_size = estimate_compressed_size(&table.ctable, &table.count, max_symbol_value);
            if old_size <= h_size + new_size || h_size + 12 >= src_size {
                return Ok(compress_ctable_internal(
                    dst,
                    op,
                    src,
                    nb_streams,
                    old_huf_table,
                ));
            }
        }

        // Use the new Huffman table.
        if h_size + 12 >= src_size {
            return Ok(0);
        }
        op += h_size;
        *repeat = HufRepeat::None;
        *old_huf_table = table.ctable; // save the new table
    }
    Ok(compress_ctable_internal(
        dst,
        op,
        src,
        nb_streams,
        &table.ctable,
    ))
}
