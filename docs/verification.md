# Verification

[Overview](../README.md) · [Guide](guide.md) · **Verification** · [Performance](performance.md)

---

zstd_nrp is checked against zstd itself: both are run over the same synthetic data and
their output compared byte for byte.

## The comparison

`compare/compare.sh` builds zstd's library from a checkout of zstd v1.5.7, without assembly
and without threads, and the C programs in `compare/` against it; `examples/dump.rs` is
built against zstd_nrp. It runs both and compares what they print:

```sh
compare/compare.sh <checkout of zstd> [count] [seeds] [dumps]
```

Both programs generate the same data from each seed and print a running hash of what they
produce:

- **zstd_decode**: frames of every kind made by zstd's library (`compare/dump_zstd.c`),
  synthetic data compressed at every level and with every kind of setting, with and without
  dictionaries, a third of them damaged. Each is decoded by zstd's reference decoder
  (`doc/educational_decoder`, wrapped by `compare/dump_zstd_edu.c` so that a damaged frame
  returns its message rather than stopping the program) and by zstd_nrp.

- **zstd_compress**: synthetic data of thirteen kinds and of up to five megabytes,
  compressed with `ZSTD_compress` at levels 1 to 3, 4 for some sizes, 0 and the negative
  levels.

- **zstd_compress_more**: the same at levels 4 to 22, from the greedy strategy to the second
  ultra strategy.

- **zstd_compress_long**: a source of 64 to 80 megabytes at level 22, which enables
  long-distance matching.

- **zstd_entropy**: the library's entropy coders called one function at a time
  (`compare/dump_zstd_entropy.c`), for cases a whole frame seldom or never reaches: too
  little room for the output, and counts that are hard to normalise.

## Results

| Dump | Seeds | Input | Result |
|---|---|---|---|
| zstd_decode | 2 | 20,000 frames (195 MB) | 14,644 decoded identically, 5,356 refused with the same message |
| zstd_compress | 2 | 2,000 sources (444 MB) | Every frame identical (185 MB) |
| zstd_compress_more | 2 | 2,000 sources (461 MB) | Every frame identical (166 MB) |
| zstd_compress_long | 2 | 2 sources (147 MB) | Every frame identical |
| zstd_entropy | 2 | 200,000 rounds | 154,945 outputs identical, 45,055 refused identically |

## Tests

`cargo test` needs no C compiler. `tests/decode_golden.rs` and `tests/compress_golden.rs`
check zstd_nrp against hashes and frames recorded from zstd (`tests/data/`), unit tests
check the levels and round trips, and the examples in the README and the Guide are run as
tests. `tests/data/README.md` explains how to record the data again.
