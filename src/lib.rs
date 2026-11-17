//! Zstandard in pure, safe Rust: a native port of [zstd](https://github.com/facebook/zstd)
//! v1.5.7, its compressor and its reference decoder.
//!
//! - [`zstd_compress`]: bytes to a frame ([`compress`]), the port of the compressor of zstd
//!   itself (`lib/compress`), at every level: its nine strategies, the splitting of blocks,
//!   long-distance matching and the entropy coders. The frames are the ones `ZSTD_compress`
//!   gives, byte for byte.
//! - [`zstd_decompress`]: frames to bytes ([`decompress`]), the port of the reference decoder
//!   that comes with zstd (`doc/educational_decoder`).
//!
//! The files of the compressor follow the original's: `bitstream`, `fse_compress`, `hist`
//! and `huf_compress` are the entropy coders, `zstd_compress_literals` and
//! `zstd_compress_sequences` the two sections of a block, `zstd_fast`, `zstd_double_fast`,
//! `zstd_lazy` and `zstd_opt` the strategies, `zstd_ldm` long-distance matching,
//! `zstd_presplit` what decides where a block ends early, `clevels` the table of levels, and
//! `zstd_compress` the frame and its blocks (and where they are split).

#![forbid(unsafe_code)]
// The code follows the original's line for line, and these are its shapes.
#![allow(
    clippy::needless_range_loop,
    clippy::too_many_arguments,
    clippy::manual_range_contains
)]

mod bitstream;
mod clevels;
mod common;
#[doc(hidden)]
pub mod compare_hooks;
mod fse_compress;
mod hist;
mod huf_compress;
pub mod zstd_compress;
mod zstd_compress_literals;
mod zstd_compress_sequences;
pub mod zstd_decompress;
mod zstd_double_fast;
mod zstd_fast;
mod zstd_lazy;
mod zstd_ldm;
mod zstd_opt;
mod zstd_presplit;

pub use zstd_compress::{compress, compress_bound};

pub use zstd_decompress::{
    Dictionary, ZstdError, decompress, decompress_with_dict, get_decompressed_size,
};

/// (The README's examples, compiled and run with the tests.)
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
