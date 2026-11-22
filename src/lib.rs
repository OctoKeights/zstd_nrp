//! Zstandard compression in pure, safe Rust: a native port of
//! [zstd](https://github.com/facebook/zstd) v1.5.7, its compressor and its reference decoder.
//!
//! - [`compress`] compresses to one Zstandard frame at a [`Level`], producing the frames
//!   `ZSTD_compress` produces, byte for byte, at every level, with all nine strategies,
//!   block splitting, long-distance matching and the entropy coders. [`compress_with_options`]
//!   adds `XXH64` content checksums and optional header content sizes, [`compress_into`]
//!   writes directly into a caller slice, and [`Compressor`] reuses working tables across
//!   calls.
//!
//! - [`decompress`] decompresses a frame, and [`decompress_with_dict`] one compressed with a
//!   [`Dictionary`]: the port of the reference decoder that comes with zstd
//!   (`doc/educational_decoder`). [`decompress_with_options`], [`decompress_frame`], and
//!   [`decompress_stream`] add `XXH64` checksum verification, strict RFC 8878 validation,
//!   skippable frames, and concatenated streams, while [`Decompressor`] and
//!   [`decompress_into`] avoid repeated allocations.
//!
//! - [`decompressed_size`] and [`frame_dict_id`] inspect a frame's header, and (with the
//!   default `std` feature) `io::Encoder` and `io::Decoder` provide streaming
//!   `std::io::Write` / `std::io::Read` adapters.
//!
//! ```
//! use zstd_nrp::{Level, compress, decompress};
//!
//! let data = b"to be or not to be, that is the question; ".repeat(100);
//! let frame = compress(&data, Level::DEFAULT).unwrap();
//! assert_eq!(decompress(&frame, data.len()).unwrap(), data);
//! ```
//!
//! The compressor's modules follow the original's files: `bitstream`, `fse_compress`, `hist`
//! and `huf_compress` are the entropy coders, `zstd_compress_literals` and
//! `zstd_compress_sequences` the two sections of a block, `zstd_fast`, `zstd_double_fast`,
//! `zstd_lazy` and `zstd_opt` the strategies, `zstd_ldm` long-distance matching,
//! `zstd_presplit` what decides where a block ends early, `clevels` the table of levels, and
//! `zstd_compress` the frame and its blocks.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod bitstream;
mod clevels;
mod common;
#[doc(hidden)]
pub mod compare_hooks;
mod fse_compress;
mod hist;
mod huf_compress;
#[cfg(feature = "std")]
pub mod io;
mod zstd_compress;
mod zstd_compress_literals;
mod zstd_compress_sequences;
mod zstd_decompress;
mod zstd_double_fast;
mod zstd_fast;
mod zstd_lazy;
mod zstd_ldm;
mod zstd_opt;
mod zstd_presplit;

pub use zstd_compress::{
    CompressOptions, Compressor, checked_compress_bound, compress, compress_bound, compress_into,
    compress_into_with_options, compress_with_options,
};
pub use zstd_decompress::{
    DecompressError, DecompressErrorKind, DecompressOptions, Decompressor, Dictionary, decompress,
    decompress_frame, decompress_frame_with_options, decompress_into, decompress_into_with_options,
    decompress_stream, decompress_with_dict, decompress_with_options, decompressed_size,
    frame_dict_id,
};

use core::fmt;

/// A compression level: from [`Level::MIN`], the fastest, through 1 and the default, 3, to
/// [`Level::MAX`], 22, the smallest.
///
/// Negative levels trade compression for speed, each lower one a little further. Levels 20
/// to 22 (zstd's "ultra" levels) use larger windows, and so more memory to decompress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(i32);

impl Level {
    /// The fastest level, -131,072 (`ZSTD_minCLevel()`).
    pub const MIN: Level = Level(-131_072);

    /// zstd's default level, 3 (`ZSTD_CLEVEL_DEFAULT`).
    pub const DEFAULT: Level = Level(3);

    /// The smallest output, level 22 (`ZSTD_maxCLevel()`).
    pub const MAX: Level = Level(22);

    /// The level `level`, if it is from [`Level::MIN`] to [`Level::MAX`]. Level 0 is the
    /// default level, as zstd takes it.
    #[must_use]
    pub const fn new(level: i32) -> Option<Level> {
        match level {
            0 => Some(Level::DEFAULT),
            -131_072..=22 => Some(Level(level)),
            _ => None,
        }
    }

    /// Clamps `level` into [`Level::MIN`]..=[`Level::MAX`], mapping `0` to [`Level::DEFAULT`]
    /// just as zstd's `ZSTD_compress` does.
    #[must_use]
    pub const fn new_clamped(level: i32) -> Level {
        if level == 0 {
            Level::DEFAULT
        } else if level < Level::MIN.0 {
            Level::MIN
        } else if level > Level::MAX.0 {
            Level::MAX
        } else {
            Level(level)
        }
    }

    /// The level as a number.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

impl TryFrom<i32> for Level {
    type Error = UnsupportedLevel;

    fn try_from(level: i32) -> Result<Self, Self::Error> {
        Level::new(level).ok_or(UnsupportedLevel(level))
    }
}

/// The error for a compression level outside [`Level::MIN`] to [`Level::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnsupportedLevel(pub i32);

impl fmt::Display for UnsupportedLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "compression level {} is not supported (use -131072 to 22)",
            self.0
        )
    }
}

impl core::error::Error for UnsupportedLevel {}

/// Why data could not be compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressError {
    /// The data is 2 GiB or more, which this port does not compress in one frame.
    SourceTooLarge,
    /// The destination slice passed to [`compress_into`] or [`Compressor::compress_into`] was
    /// too small to hold the compressed frame.
    OutputTooSmall,
    /// The compressor ran out of room in an output of `ZSTD_compressBound` bytes, which no
    /// input should make it do; this would be a bug in the port.
    Internal,
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CompressError::SourceTooLarge => "the data is too large to compress (2 GiB or more)",
            CompressError::OutputTooSmall => "destination buffer is too small for compressed frame",
            CompressError::Internal => "the compressor failed (a bug in zstd_nrp)",
        })
    }
}

impl core::error::Error for CompressError {}

#[cfg(feature = "std")]
impl From<CompressError> for std::io::Error {
    fn from(err: CompressError) -> Self {
        let kind = match err {
            CompressError::SourceTooLarge | CompressError::OutputTooSmall => {
                std::io::ErrorKind::InvalidInput
            }
            CompressError::Internal => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_the_ones_zstd_takes() {
        assert_eq!(Level::new(0), Some(Level::DEFAULT));
        assert_eq!(Level::new(-131_072), Some(Level::MIN));
        assert_eq!(Level::new(-131_073), None);
        assert_eq!(Level::try_from(23), Err(UnsupportedLevel(23)));
        assert_eq!(Level::new_clamped(0), Level::DEFAULT);
        assert_eq!(Level::new_clamped(-500_000), Level::MIN);
        assert_eq!(Level::new_clamped(100), Level::MAX);
        assert_eq!(Level::new_clamped(-7), Level(-7));
        assert_eq!(Level::new_clamped(15), Level(15));
        assert!(Level::MIN < Level::DEFAULT && Level::DEFAULT < Level::MAX);
    }
}

/// The README's examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The Guide's examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../docs/guide.md")]
struct GuideDoctests;
