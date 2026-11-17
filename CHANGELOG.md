# Changelog

## 0.2.0

- **Breaking: an idiomatic API.** `compress` takes a `Level` (with `Level::MIN`,
  `Level::DEFAULT` and `Level::MAX`, made with `Level::new` or `TryFrom<i32>`, refusing
  levels outside -131072 to 22 with an `UnsupportedLevel`) in place of an `i32`, and returns
  a `CompressError`. The decoder's errors are a `DecompressError`, whose `message()` gives
  the reference decoder's message, in place of `ZstdError`'s public string.
  `get_decompressed_size` is `decompressed_size`. The `zstd_compress` and `zstd_decompress`
  modules are no longer public; everything they offered is at the crate root.

- **Faster.** Decompression is 27% to 67% faster, and compression 3% to 12% (see
  [Performance](docs/performance.md)). Output is unchanged, checked against zstd on 4,000
  sources compressed, two of over 64 megabytes, and 20,000 frames decoded.

- **Rewritten as idiomatic Rust.** The code no longer mirrors the original's C line by line.

- **Documentation.** Every public item is documented, the README is a short overview, and
  the detail is in [Guide](docs/guide.md), [Verification](docs/verification.md) and
  [Performance](docs/performance.md).

## 0.1.0

- First release: the port of zstd's compressor and of its reference decoder, moved out of [rustbcx](https://github.com/OctoKeights/rustbcx), where
  it was `rustbcx::zstd`.
