# Recorded results

`zstd_frames.bin` holds Zstandard frames that the zstd library made of made-up data, as
`compare/dump_zstd.c` wrote them, and `zstd_decode_expected.txt` what zstd's reference decoder
makes of each, as the same program prints it; `tests/decode_golden.rs` checks that the port
prints the same from the same frames.

`zstd_compress_expected.txt` is what `compare/dump_zstd_compress.c` prints of the frames the
zstd library's `ZSTD_compress` makes of made-up data (`zstd_compress_more_expected.txt` the
same at the levels from 4 up), and `zstd_entropy_expected.txt` what
`compare/dump_zstd_entropy.c` prints of the answers of the entropy coders inside that
library, asked one function at a time; `tests/compress_golden.rs` checks that the port prints
the same.

To make them again, run the comparison once (it builds the original's side), then that by
itself:

    compare/compare.sh <checkout of zstd> 3000 1 "zstd_decode zstd_compress zstd_entropy"
    tmp="${TMPDIR:-/tmp}/zstd_nrp-compare"
    "$tmp/dump-zstd" zstd_decode_small 6 120 tests/data/zstd_frames.bin > tests/data/zstd_decode_expected.txt
    "$tmp/dump-zstd-compress" zstd_compress_small 7 200 > tests/data/zstd_compress_expected.txt
    "$tmp/dump-zstd-compress" zstd_compress_more_small 7 160 > tests/data/zstd_compress_more_expected.txt
    "$tmp/dump-zstd-entropy" zstd_entropy 9 4000 > tests/data/zstd_entropy_expected.txt

No picture or file from anywhere is in this repository: every file and stream the tests and
the comparison use is made up from a seed.
