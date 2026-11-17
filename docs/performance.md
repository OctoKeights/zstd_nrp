# Performance

[Overview](../README.md) · [Guide](guide.md) · [Verification](verification.md) · **Performance**

---

`examples/bench.rs` compresses and decompresses four megabytes of synthetic text-like data
(words from a small vocabulary) and four of binary-like data (runs, repeats and noise) at
levels -5, 1, 3, 9 and 19, reporting the best of five runs (two at level 19):

```sh
cargo run --release --example bench
```

## Throughput

Measured on one core of an Intel Xeon at 2.1 GHz, built for generic x86-64, in megabytes of
uncompressed data per second:

| Data | Level | Ratio | Compress | Decompress |
|---|---|---|---|---|
| Text-like | -5 | 24.4% | 201 | 165 |
| Text-like | 1 | 22.2% | 226 | 192 |
| Text-like | 3 | 21.3% | 253 | 242 |
| Text-like | 9 | 19.6% | 23.3 | 230 |
| Text-like | 19 | 15.1% | 1.3 | 372 |
| Binary-like | -5 | 19.4% | 410 | 399 |
| Binary-like | 1 | 16.0% | 352 | 408 |
| Binary-like | 3 | 16.2% | 220 | 351 |
| Binary-like | 9 | 14.1% | 45.9 | 503 |
| Binary-like | 19 | 13.6% | 1.9 | 474 |

## Compared with 0.1

Version 0.2 rewrote the crate as idiomatic Rust. Measured alternately with 0.1 on the same
machine:

| Data | Level | Compress | Decompress |
|---|---|---|---|
| Text-like | -5 | 12% faster | 40% faster |
| Text-like | 1 | 8% faster | 45% faster |
| Text-like | 3 | 3% faster | 67% faster |
| Text-like | 9 | 6% faster | 53% faster |
| Text-like | 19 | 8% faster | 67% faster |
| Binary-like | -5 | 4% faster | 28% faster |
| Binary-like | 1 | 4% faster | 32% faster |
| Binary-like | 3 | 6% faster | 27% faster |
| Binary-like | 9 | 4% faster | 53% faster |
| Binary-like | 19 | 6% faster | 44% faster |

Decompression gains from reading the bitstream a word at a time where it can, and from
copying matches that do not overlap their source in one operation; it executes about 27%
fewer instructions. The compressor's code executes the same number of instructions as
before, so its small gains are from code layout rather than from less work.
