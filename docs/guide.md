# Guide

[Overview](../README.md) · **Guide** · [Verification](verification.md) · [Performance](performance.md)

---

- [Compression levels](#compression-levels)
- [Compressing](#compressing)
- [Decompressing](#decompressing)
- [Dictionaries](#dictionaries)
- [Correspondence with zstd](#correspondence-with-zstd)
- [Differences from zstd](#differences-from-zstd)

## Compression levels

| Levels | Strategy |
|---|---|
| -131,072 to -1 | `fast`, accelerated: each lower level skips more |
| 1, 2 | `fast` |
| 3 (`Level::DEFAULT`), 4 | `dfast` |
| 5 | `greedy` |
| 6, 7 | `lazy` |
| 8 to 12 | `lazy2` |
| 13 to 15 | `btlazy2` |
| 16, 17 | `btopt` |
| 18 | `btultra` |
| 19 to 22 (`Level::MAX`) | `btultra2`; from 20, with larger windows |

These are the strategies for data larger than 256 KiB; for smaller data, zstd's tables choose
by size as well as level, and the port follows them. The highest levels use long-distance
matching for very large data. `Level::new` accepts `Level::MIN` to
`Level::MAX` and returns `None` otherwise; level 0 is the default level, as zstd takes it.

## Compressing

`compress` produces one frame holding the whole of the data, with its size in the header and
no checksum, as `ZSTD_compress` does. It fails only for data of 2 GiB or more:

```rust
use zstd_nrp::{Level, compress, compress_bound};

let data = vec![7u8; 100_000];
let frame = compress(&data, Level::new(19).unwrap()).unwrap();
assert!(frame.len() <= compress_bound(data.len()));
```

## Decompressing

`decompress` reads one frame into no more than a given number of bytes. Anything after the
frame is ignored, and, like the reference decoder, it verifies no checksum. A frame that
cannot be read gives a `DecompressError` whose `message` is the reference decoder's.

`decompressed_size` reads the size a frame's header records, or `None` when the header
records none.

## Dictionaries

A frame compressed with a dictionary needs it to decompress. `Dictionary::parse` reads a
dictionary in zstd's format, or takes any other bytes as raw content:

```rust
use zstd_nrp::{Dictionary, Level, compress, decompress_with_dict};

let dictionary = Dictionary::parse(b"raw content: any bytes not in zstd's format").unwrap();
let frame = compress(b"hello", Level::DEFAULT).unwrap();
assert_eq!(decompress_with_dict(&frame, 5, &dictionary).unwrap(), b"hello");
```

## Correspondence with zstd

| zstd | zstd_nrp |
|---|---|
| `ZSTD_compress(dst, ZSTD_compressBound(n), src, n, level)` | `compress(src, level)` |
| `ZSTD_compressBound` | `compress_bound` |
| `ZSTD_minCLevel()`, `ZSTD_CLEVEL_DEFAULT`, `ZSTD_maxCLevel()` | `Level::MIN`, `Level::DEFAULT`, `Level::MAX` |
| `ZSTD_decompress` (of `doc/educational_decoder`) | `decompress` |
| `ZSTD_decompress_with_dict`, `parse_dictionary` | `decompress_with_dict`, `Dictionary::parse` |
| `ZSTD_get_decompressed_size` | `decompressed_size` |

## Differences from zstd

- **The reference decoder.** zstd's library has a fast decoder; this crate ports the simpler
  reference decoder, which reads the same frames, and gives back its message where it would
  stop the program.

- **Output grows as it is written.** The decoder allocates as it decodes, so a large limit
  costs nothing for a small frame.

- **No raw pointers.** In the compressor, positions in the data stand for pointers, and the
  work areas zstd carves out of one block of memory are fields and local arrays.
