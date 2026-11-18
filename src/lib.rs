//! Zstandard compression in pure, safe Rust: a native port of
//! [zstd](https://github.com/facebook/zstd) v1.5.7, its compressor and its reference decoder.
//!
//! - [`compress`] compresses to one Zstandard frame at a [`Level`], producing the frames
//!   `ZSTD_compress` produces, byte for byte, at every level, with all nine strategies,
//!   block splitting, long-distance matching and the entropy coders.
//!
//! - [`decompress`] decompresses a frame, and [`decompress_with_dict`] one compressed with a
//!   [`Dictionary`]: the port of the reference decoder that comes with zstd
//!   (`doc/educational_decoder`).
//!
//! - [`decompressed_size`] reads the size a frame's header records.
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod bitstream;
mod clevels;
mod common;
#[doc(hidden)]
pub mod compare_hooks;
mod fse_compress;
mod hist;
mod huf_compress;
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

pub use zstd_compress::{compress, compress_bound};
pub use zstd_decompress::{
    DecompressError, Dictionary, decompress, decompress_with_dict, decompressed_size,
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

impl std::error::Error for UnsupportedLevel {}

/// Why data could not be compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressError {
    /// The data is 2 GiB or more, which this port does not compress in one frame.
    SourceTooLarge,
    /// The compressor ran out of room in an output of `ZSTD_compressBound` bytes, which no
    /// input should make it do; this would be a bug in the port.
    Internal,
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CompressError::SourceTooLarge => "the data is too large to compress (2 GiB or more)",
            CompressError::Internal => "the compressor failed (a bug in zstd_nrp)",
        })
    }
}

impl std::error::Error for CompressError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_the_ones_zstd_takes() {
        assert_eq!(Level::new(0), Some(Level::DEFAULT));
        assert_eq!(Level::new(-131_072), Some(Level::MIN));
        assert_eq!(Level::new(-131_073), None);
        assert_eq!(Level::try_from(23), Err(UnsupportedLevel(23)));
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
