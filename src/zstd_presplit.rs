//! Where to end a block early: a port of `lib/compress/zstd_preSplit.c` of zstd v1.5.7.
//!
//! A block of the full size is looked at before it is compressed; if its content changes
//! along the way, it is split where it changes, so that each part gets tables of its own.

use super::common::read16;
use super::hist;

const THRESHOLD_PENALTY_RATE: u64 = 16;
const THRESHOLD_BASE: u64 = THRESHOLD_PENALTY_RATE - 2;
const THRESHOLD_PENALTY: i32 = 3;

const HASHLENGTH: usize = 2;
const HASHLOG_MAX: u32 = 10;
const HASHTABLESIZE: usize = 1 << HASHLOG_MAX;
const KNUTH: u32 = 0x9e3779b9;

/// `hash2`. hashLog == 8: just take the byte, no hashing.
#[inline]
fn hash2(p: &[u8], pos: usize, hash_log: u32) -> usize {
    if hash_log == 8 {
        return p[pos] as usize;
    }
    ((read16(p, pos) as u32).wrapping_mul(KNUTH) >> (32 - hash_log)) as usize
}

/// `Fingerprint`.
struct Fingerprint {
    events: [u32; HASHTABLESIZE],
    nb_events: usize,
}

impl Fingerprint {
    fn new() -> Fingerprint {
        Fingerprint {
            events: [0; HASHTABLESIZE],
            nb_events: 0,
        }
    }
}

/// `addEvents_generic`.
fn add_events(fp: &mut Fingerprint, src: &[u8], sampling_rate: usize, hash_log: u32) {
    let limit = src.len() - HASHLENGTH + 1;
    let mut n = 0;
    while n < limit {
        fp.events[hash2(src, n, hash_log)] += 1;
        n += sampling_rate;
    }
    fp.nb_events += limit / sampling_rate;
}

/// `recordFingerprint_generic`.
fn record_fingerprint(fp: &mut Fingerprint, src: &[u8], sampling_rate: usize, hash_log: u32) {
    fp.events[..1usize << hash_log].fill(0);
    fp.nb_events = 0;
    add_events(fp, src, sampling_rate, hash_log);
}

fn abs64(s64: i64) -> u64 {
    (if s64 < 0 { s64.wrapping_neg() } else { s64 }) as u64
}

/// `fpDistance`.
fn fp_distance(fp1: &Fingerprint, fp2: &Fingerprint, hash_log: u32) -> u64 {
    let mut distance = 0u64;
    for n in 0..1usize << hash_log {
        distance = distance.wrapping_add(abs64(
            (fp1.events[n] as i64)
                .wrapping_mul(fp2.nb_events as i64)
                .wrapping_sub((fp2.events[n] as i64).wrapping_mul(fp1.nb_events as i64)),
        ));
    }
    distance
}

/// `compareFingerprints`: whether the two are sufficiently different.
fn compare_fingerprints(
    reference: &Fingerprint,
    newfp: &Fingerprint,
    penalty: i32,
    hash_log: u32,
) -> bool {
    let p50 = (reference.nb_events as u64).wrapping_mul(newfp.nb_events as u64);
    let deviation = fp_distance(reference, newfp, hash_log);
    let threshold =
        p50.wrapping_mul(THRESHOLD_BASE.wrapping_add(penalty as u64)) / THRESHOLD_PENALTY_RATE;
    deviation >= threshold
}

/// `mergeEvents`.
fn merge_events(acc: &mut Fingerprint, newfp: &Fingerprint) {
    for n in 0..HASHTABLESIZE {
        acc.events[n] = acc.events[n].wrapping_add(newfp.events[n]);
    }
    acc.nb_events += newfp.nb_events;
}

const CHUNKSIZE: usize = 8 << 10;

/// `ZSTD_splitBlock_byChunks`: the block is looked at eight kilobytes at a time; it ends
/// before the first chunk that differs enough from what came before.
fn split_block_by_chunks(block: &[u8], level: usize) -> usize {
    // The sampling rate and the hash log of the four levels.
    const RECORDS: [(usize, u32); 4] = [(43, 8), (11, 9), (5, 10), (1, 10)];
    let (rate, hash_log) = RECORDS[level];
    let block_size = block.len();
    let mut penalty = THRESHOLD_PENALTY;
    let mut past_events = Fingerprint::new();
    let mut new_events = Fingerprint::new();

    record_fingerprint(&mut past_events, &block[..CHUNKSIZE], rate, hash_log);
    let mut pos = CHUNKSIZE;
    while pos <= block_size - CHUNKSIZE {
        record_fingerprint(
            &mut new_events,
            &block[pos..pos + CHUNKSIZE],
            rate,
            hash_log,
        );
        if compare_fingerprints(&past_events, &new_events, penalty, hash_log) {
            return pos;
        } else {
            merge_events(&mut past_events, &new_events);
            if penalty > 0 {
                penalty -= 1;
            }
        }
        pos += CHUNKSIZE;
    }
    block_size
}

/// `ZSTD_splitBlock_fromBorders`: a very fast strategy that only looks at the two ends of
/// the block, and at its middle if they differ. The block is then cut at 32, 64 or 96
/// kilobytes.
fn split_block_from_borders(block: &[u8]) -> usize {
    const SEGMENT_SIZE: usize = 512;
    let block_size = block.len();
    let mut past_events = Fingerprint::new();
    let mut new_events = Fingerprint::new();
    // (The original keeps this one in the unused half of the first.)
    let mut middle_events = Fingerprint::new();

    hist::add(&mut past_events.events, &block[..SEGMENT_SIZE]);
    hist::add(&mut new_events.events, &block[block_size - SEGMENT_SIZE..]);
    past_events.nb_events = SEGMENT_SIZE;
    new_events.nb_events = SEGMENT_SIZE;
    if !compare_fingerprints(&past_events, &new_events, 0, 8) {
        return block_size;
    }

    let middle = block_size / 2 - SEGMENT_SIZE / 2;
    hist::add(
        &mut middle_events.events,
        &block[middle..middle + SEGMENT_SIZE],
    );
    middle_events.nb_events = SEGMENT_SIZE;
    {
        let dist_from_begin = fp_distance(&past_events, &middle_events, 8);
        let dist_from_end = fp_distance(&new_events, &middle_events, 8);
        let min_distance = (SEGMENT_SIZE * SEGMENT_SIZE / 3) as u64;
        if abs64((dist_from_begin as i64).wrapping_sub(dist_from_end as i64)) < min_distance {
            return 64 * 1024;
        }
        if dist_from_begin > dist_from_end {
            32 * 1024
        } else {
            96 * 1024
        }
    }
}

/// `ZSTD_splitBlock`: how much of `block`, which is a full 128 kilobytes, to make one block
/// of. Level 0 looks at the borders only; levels 1 to 4 look at all of it, from the least
/// to the most closely.
pub(crate) fn split_block(block: &[u8], level: i32) -> usize {
    if level == 0 {
        return split_block_from_borders(block);
    }
    // byChunks, levels 0 to 3.
    split_block_by_chunks(block, (level - 1) as usize)
}
