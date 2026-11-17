#!/bin/sh
# Compares zstd_nrp with zstd (https://github.com/facebook/zstd).
#
#   compare/compare.sh <checkout of zstd> [count] [seeds] [dumps]
#
# zstd's library is built from the checkout (without assembly and without threads), and the C
# programs here against it; examples/dump.rs is built from the port. Both run the same made-up
# data for each seed, and what they print is compared byte for byte.
#
# The decoder: compare/dump_zstd.c has the library make frames of every kind, which it writes to
# a file for the Rust side, and compare/dump_zstd_edu.c wraps zstd's reference decoder
# (doc/educational_decoder) so that a damaged frame gives its message back in place of stopping
# the program. Dump: zstd_decode, with a tenth of [count] (200,000 by default) as the number of
# frames.
#
# The compressor: compare/dump_zstd_compress.c has ZSTD_compress make frames of made-up data at
# every level, and compare/dump_zstd_entropy.c asks the entropy coders inside the library one
# function at a time, for what a whole frame seldom or never asks of them. Dumps: zstd_compress
# (levels 1 to 3, 4 for some sizes, 0 and the negative ones) and zstd_compress_more (4 to 22),
# each with a hundredth of [count] as the number of sources (of up to five megabytes each);
# zstd_compress_long, one source of 64 to 80 megabytes at level 22 for each seed, which takes
# long-distance matching; and zstd_entropy, with [count] as the number of rounds.
set -u
if [ $# -lt 1 ]; then
    echo "usage: $0 <checkout of zstd> [count] [seeds] [dumps]" >&2
    exit 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
source=$1
blocks=${2:-200000}
seeds=${3:-3}
dumps=${4:-zstd_decode zstd_compress zstd_compress_more zstd_compress_long zstd_entropy}
tmp=${TMPDIR:-/tmp}/zstd_nrp-compare
mkdir -p "$tmp" || exit 2
if ! [ -f "$source/doc/educational_decoder/zstd_decompress.c" ]; then
    echo "$source does not look like checkout of zstd" >&2
    exit 2
fi

(cd "$here" && cargo build --release -q --ignore-rust-version --example dump) || exit 2
rust=$(cd "$here" && cargo metadata --format-version 1 --no-deps 2>/dev/null | sed 's/.*"target_directory":"\([^"]*\)".*/\1/')/release/examples/dump

mkdir -p "$tmp/zstd-obj" || exit 2
(cd "$tmp/zstd-obj" && ${CC:-cc} -O2 -c -DZSTD_DISABLE_ASM -I "$source/lib" -I "$source/lib/common" "$source"/lib/common/*.c "$source"/lib/compress/*.c "$source"/lib/decompress/*.c "$source"/lib/dictBuilder/*.c) || exit 2
${CC:-cc} -O2 -c -I "$source/doc/educational_decoder" "$here/compare/dump_zstd_edu.c" -o "$tmp/dump_zstd_edu.o" || exit 2
${CC:-cc} -O2 -I "$source/lib" -I "$source/lib/dictBuilder" "$here/compare/dump_zstd.c" "$tmp/dump_zstd_edu.o" "$tmp"/zstd-obj/*.o -o "$tmp/dump-zstd" || exit 2
${CC:-cc} -O2 -I "$source/lib" "$here/compare/dump_zstd_compress.c" "$tmp"/zstd-obj/*.o -o "$tmp/dump-zstd-compress" || exit 2
${CC:-cc} -O2 -I "$source/lib" "$here/compare/dump_zstd_entropy.c" "$tmp"/zstd-obj/*.o -o "$tmp/dump-zstd-entropy" || exit 2

bad=0
for what in $dumps; do
    extra=
    case $what in
    zstd_decode)
        reference=$tmp/dump-zstd
        count=$((blocks / 10))
        extra=$tmp/zstd-frames.bin
        ;;
    zstd_compress | zstd_compress_more)
        reference=$tmp/dump-zstd-compress
        count=$((blocks / 100))
        ;;
    zstd_compress_long)
        reference=$tmp/dump-zstd-compress
        count=1
        ;;
    zstd_entropy)
        reference=$tmp/dump-zstd-entropy
        count=$blocks
        ;;
    *)
        echo "unknown dump $what" >&2
        exit 2
        ;;
    esac
    seed=1
    while [ "$seed" -le "$seeds" ]; do
        # shellcheck disable=SC2086
        "$reference" "$what" "$seed" "$count" $extra > "$tmp/reference.txt" 2> /dev/null
        # shellcheck disable=SC2086
        "$rust" "$what" "$seed" "$count" $extra > "$tmp/rust.txt"
        if [ ! -s "$tmp/reference.txt" ]; then
            echo "$what, seed $seed: NOT COMPARED, the original's side printed nothing"
            bad=$((bad + 1))
        elif cmp -s "$tmp/reference.txt" "$tmp/rust.txt"; then
            echo "$what, seed $seed: the same ($(tail -1 "$tmp/rust.txt"))"
        else
            echo "$what, seed $seed: DIFFERENT"
            bad=$((bad + 1))
        fi
        seed=$((seed + 1))
    done
done
[ "$bad" -eq 0 ]
