//! The port of zstd's compressor against results recorded from the original, so that a change
//! shows without a C compiler at hand.
//!
//! `tests/data/zstd_compress_expected.txt` is what `compare/dump_zstd_compress.c` printed for
//! `zstd_compress_small 7 200` (see `compare/compare.sh`): hashes of the frames libzstd's
//! `ZSTD_compress` makes of made-up data of thirteen kinds, at the levels that are ported.
//! `tests/data/zstd_compress_more_expected.txt` is what it printed for
//! `zstd_compress_more_small 7 160`: the same at the levels from 4 to 22, of the strategies
//! from greedy to the second ultra one.
//! `tests/data/zstd_entropy_expected.txt` is what `compare/dump_zstd_entropy.c` printed for
//! `zstd_entropy 9 4000`: hashes of what the original's entropy coders answer when asked one
//! function at a time, with too little room and with counts that are hard to normalize.

mod made_up;

fn same(printed: &str, expected: &str) {
    for (line, (ours, theirs)) in printed.lines().zip(expected.lines()).enumerate() {
        assert_eq!(ours, theirs, "line {}", line + 1);
    }
    assert_eq!(printed.lines().count(), expected.lines().count());
}

/// The frames are the original's, and the port of the reference decoder gives their data
/// back.
#[test]
fn compresses_as_zstd_does() {
    same(
        &made_up::zstd_compress("zstd_compress_small", 7, 200, true),
        include_str!("data/zstd_compress_expected.txt"),
    );
}

/// The same at every level from 4 up.
#[test]
fn compresses_at_the_higher_levels_as_zstd_does() {
    same(
        &made_up::zstd_compress_up_to("zstd_compress_more_small", 7, 160, true, 9),
        include_str!("data/zstd_compress_more_expected.txt"),
    );
}

#[test]
fn the_entropy_coders_answer_as_the_originals_do() {
    same(
        &made_up::zstd_entropy(9, 4000),
        include_str!("data/zstd_entropy_expected.txt"),
    );
}
