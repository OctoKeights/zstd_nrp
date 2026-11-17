# zstd_nrp

**Zstandard compression in pure, safe Rust, bit-identical to zstd.**

**Overview** · [Guide](docs/guide.md) · [Verification](docs/verification.md) · [Performance](docs/performance.md)

---

zstd_nrp is a native Rust port of [zstd](https://github.com/facebook/zstd) v1.5.7: its
compressor, which produces the frames `ZSTD_compress` produces, byte for byte, at every
level from the negative ones to 22; and its reference decoder, which reads any frame and
refuses a damaged one with the original's message.

## Highlights

- **Bit-identical frames.** Every level, all nine strategies, block splitting,
  long-distance matching and the entropy coders, as zstd has them.

- **Every frame read.** The decoder is a port of the reference decoder that comes with zstd
  (`doc/educational_decoder`), dictionaries included.

- **Zero dependencies.** Standard library only: no C compiler, no build script.

- **No `unsafe` code.** Enforced by `#![forbid(unsafe_code)]`.

## Installation

```toml
[dependencies]
zstd_nrp = "0.2"
```

## Quick start

```rust
use zstd_nrp::{Level, compress, decompress, decompressed_size};

let data = b"to be or not to be, that is the question; ".repeat(100);

let frame = compress(&data, Level::DEFAULT).unwrap();
assert!(frame.len() < data.len() / 10);

// The frame records its size; decompress takes the most it may produce.
assert_eq!(decompressed_size(&frame).unwrap(), Some(data.len() as u64));
assert_eq!(decompress(&frame, data.len()).unwrap(), data);
```

## Scope

One-shot compression of data held in memory, and decompression of single frames, with or
without a dictionary. Compression with dictionaries, checksums, streaming and threads is not
ported.

## Licence

As zstd is: BSD (see [`LICENSE`](LICENSE), which keeps zstd's copyright notice) or the GNU
General Public License, version 2 ([`COPYING`](COPYING)), whichever you prefer.

Bug reports and contributions are welcome, above all any data that zstd_nrp compresses
differently from zstd, or any frame it decodes differently from the reference decoder.
