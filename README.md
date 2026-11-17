# zstd_nrp

**Zstandard in pure, safe Rust: a native Rust port of zstd.**

zstd_nrp is a line-for-line port of [zstd](https://github.com/facebook/zstd) v1.5.7: its
compressor, which gives the frames `ZSTD_compress` gives, byte for byte, at every level from
the negative ones to 22; and its reference decoder, which reads any frame and refuses a damaged
one with the original's message.

## Highlights

- **Bit-identical frames.** Every level, all nine strategies, the splitting of blocks,
  long-distance matching and the entropy coders, as zstd has them.

- **Every frame read.** The decoder is the port of the reference decoder that comes with zstd
  (`doc/educational_decoder`), dictionaries included.

- **Zero dependencies.** Standard library only: no C compiler, no build script.

- **No `unsafe` code.** Enforced by `#![forbid(unsafe_code)]`.

## Installation

```toml
[dependencies]
zstd_nrp = "0.1"
```

## Quick start

```rust
let data: Vec<u8> = b"to be or not to be, that is the question; ".repeat(100);

// A frame at level 3 (negative levels are faster, 22 is the best).
let frame = zstd_nrp::compress(&data, 3).unwrap();
assert!(frame.len() < data.len() / 10);

// The frame says how long its data is; decompress takes the most it may make.
assert_eq!(zstd_nrp::get_decompressed_size(&frame).unwrap(), Some(data.len() as u64));
assert_eq!(zstd_nrp::decompress(&frame, data.len()).unwrap(), data);
```

## What is ported

| Module | Original | What it does |
|---|---|---|
| `zstd_compress` | `lib/compress`, `lib/common` | Bytes to a frame (`compress`): the frame and its blocks, the strategies (`zstd_fast`, `zstd_double_fast`, `zstd_lazy`, `zstd_opt`), long-distance matching (`zstd_ldm`), the splitting of blocks (`zstd_presplit`) and the entropy coders (`fse_compress`, `huf_compress`, `hist`, `bitstream`) |
| `zstd_decompress` | `doc/educational_decoder/zstd_decompress.c` | Frames to bytes (`decompress`, `decompress_with_dict`) |

Of the compressor, what one call of `ZSTD_compress` on a source that is all there does not use
is left out: dictionaries, checksums, streaming and threads.

## Differences from the original

The code is translated from C to Rust. Where the reference decoder stops the program with a
message, the port gives the message back, and its output grows as it is written. In the
compressor, places in the source stand for pointers, and the work areas the original carves out
of one block of memory are fields and local arrays. What they compute is kept: the same frame,
byte for byte, as `ZSTD_compress` gives for a source and a level; the same bytes from every
frame; and the same message for a frame the reference decoder refuses.

## Verification

`compare/compare.sh` builds zstd's library from a checkout, the C programs in `compare/`
against it, and `examples/dump.rs` against the port; it runs both over the same made-up data
and compares what they print byte for byte:

```sh
compare/compare.sh <checkout of zstd> [count] [seeds] [dumps]
```

| Dump | What it covers | Last full run |
|---|---|---|
| `zstd_decode` | Frames the zstd library made of made-up data, at every level, with and without checksums and content sizes, small windows, long-distance matching, targeted block sizes and flushes, and dictionaries; a third damaged first, for which the message is compared | 20,000 frames (200 megabytes): 14,700 decoded and 5,300 refused with the same message |
| `zstd_compress` | Made-up data of thirteen kinds, from empty to five megabytes, at levels 1 to 3, the default, 4 for some sizes, and the negative levels; each frame also decoded | 33,000 sources (3.4 gigabytes), every frame identical |
| `zstd_compress_more` | The same data at levels 4 to 22: every strategy from greedy to the second ultra one, the optimal parser and the splitting of blocks | 6,600 sources (1.6 gigabytes), every frame identical |
| `zstd_compress_long` | 64 to 80 megabytes at level 22, which uses long-distance matching | 4 sources (290 megabytes), every frame identical |
| `zstd_entropy` | The entropy coders one function at a time, for what a whole frame seldom or never asks of them | 3.3 million rounds, identical |

The C was built by gcc and clang, and the larger runs repeated with Rust's overflow checks
enabled.

`cargo test` needs no C compiler: the tests check the port against frames and hashes recorded
from zstd (`tests/data`).

## Licence

As zstd is: BSD ([LICENSE](LICENSE), which keeps zstd's copyright notice) or the GNU General
Public License, version 2 ([COPYING](COPYING)), whichever you prefer.
