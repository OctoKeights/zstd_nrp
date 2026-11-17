//! Byte histograms: a port of `lib/compress/hist.c` of zstd v1.5.7.
//!
//! The original has a plain loop and a faster one that counts in four tables at once. Both
//! give the same counts, the same highest symbol and the same answer, so one loop stands for
//! both here.

/// `HIST_add`.
pub(crate) fn add(count: &mut [u32], src: &[u8]) {
    for &b in src {
        count[b as usize] += 1;
    }
}

/// `HIST_count_simple`, and what `HIST_countFast_wksp` and `HIST_count_wksp` come to when
/// no byte of `src` is above `*max_symbol_value`: `count[0..=*max_symbol_value]` is filled,
/// `*max_symbol_value` becomes the highest byte present, and the answer is the largest
/// count.
pub(crate) fn count_simple(count: &mut [u32], max_symbol_value: &mut u32, src: &[u8]) -> u32 {
    let mut max = *max_symbol_value;
    let mut largest_count = 0;
    count[..=max as usize].fill(0);
    if src.is_empty() {
        *max_symbol_value = 0;
        return 0;
    }
    for &b in src {
        count[b as usize] += 1;
    }
    while count[max as usize] == 0 {
        max -= 1;
    }
    *max_symbol_value = max;
    for &c in &count[..=max as usize] {
        if c > largest_count {
            largest_count = c;
        }
    }
    largest_count
}
