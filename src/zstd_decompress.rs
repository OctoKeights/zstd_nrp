//! The Zstandard decoder: the port of the reference decoder that comes with zstd,
//! `doc/educational_decoder/zstd_decompress.c` (Meta Platforms, BSD licence), the "Zstandard
//! educational decoder implementation", extended with optional checksum verification, strict
//! RFC 8878 validation, skippable frames, concatenated streams, and reusable state. See
//! <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>.
//!
//! [`decompress`] and [`decompress_with_dict`] preserve the exact behavior and error messages
//! of the reference decoder: one frame, ignoring trailing bytes and skipping any checksum.
//! [`decompress_with_options`], [`decompress_frame`], and [`decompress_stream`] add `XXH64`
//! checksum verification, strict RFC 8878 checks, skippable frames, and multi-frame streams.

use alloc::vec::Vec;
use core::fmt;

/// Broad category of a [`DecompressError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecompressErrorKind {
    /// The input did not begin with a valid Zstandard frame magic number.
    InvalidFrameMagic,
    /// The input ended before the frame was complete, or a length field ran past the input.
    UnexpectedEof,
    /// The decompressed output would exceed `max_len` (or the destination slice length).
    OutputTooSmall,
    /// Compressed data, headers, entropy tables, or backreference offsets were invalid.
    CorruptedInput,
    /// The 32-bit `XXH64` content checksum at the end of the frame did not match.
    ChecksumMismatch,
    /// Under [`DecompressOptions::strict`], the decoded frame size differed from the header's
    /// `Frame_Content_Size`.
    ContentSizeMismatch,
    /// The dictionary bytes passed to [`Dictionary::parse`] were too short or malformed.
    InvalidDictionary,
    /// The frame requested a dictionary ID that did not match the provided [`Dictionary`].
    DictionaryMismatch,
}

/// Why a frame could not be decompressed: its [`DecompressErrorKind`] and the message the
/// reference decoder stops with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecompressError {
    kind: DecompressErrorKind,
    message: &'static str,
}

impl DecompressError {
    pub(crate) const fn new(kind: DecompressErrorKind, message: &'static str) -> DecompressError {
        DecompressError { kind, message }
    }

    /// Broad category of this decompression failure.
    #[must_use]
    pub const fn kind(&self) -> DecompressErrorKind {
        self.kind
    }

    /// The reference decoder's message, such as `"Input buffer smaller than it should be or
    /// input is corrupted"`.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl core::error::Error for DecompressError {}

#[cfg(feature = "std")]
impl From<DecompressError> for std::io::Error {
    fn from(err: DecompressError) -> Self {
        let io_kind = match err.kind {
            DecompressErrorKind::UnexpectedEof => std::io::ErrorKind::UnexpectedEof,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(io_kind, err)
    }
}

type R<T> = Result<T, DecompressError>;

/// Options for decompressing Zstandard frames and streams with [`decompress_with_options`],
/// [`decompress_frame_with_options`], [`Decompressor`], or `io::Decoder`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecompressOptions {
    /// Verify the 32-bit `XXH64` `Content_Checksum` trailer when present in a frame
    /// (defaults to `true`).
    pub verify_checksum: bool,
    /// Enforce strict RFC 8878 validation: pledged `Frame_Content_Size` must match the
    /// actual decoded frame length, block sizes (compressed and uncompressed) must not exceed
    /// `128 KiB`, and sequence backreference `offset` must be non-zero (defaults to `false`).
    pub strict: bool,
    /// Decode all concatenated frames until the end of the input slice rather than stopping
    /// after the first frame (defaults to `false`; [`decompress_stream`] and `io::Decoder`
    /// enable this by default).
    pub multi_frame: bool,
    /// Recognize and skip skippable frames (`0x184D2A50..=0x184D2A5F`) rather than rejecting
    /// their magic numbers (defaults to `true`).
    pub allow_skippable: bool,
}

impl Default for DecompressOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompressOptions {
    /// Default options: `verify_checksum: true`, `strict: false`, `multi_frame: false`,
    /// `allow_skippable: true`.
    #[must_use]
    pub const fn new() -> Self {
        DecompressOptions {
            verify_checksum: true,
            strict: false,
            multi_frame: false,
            allow_skippable: true,
        }
    }

    /// Strict RFC 8878 options (`verify_checksum: true`, `strict: true`,
    /// `multi_frame: false`, `allow_skippable: true`).
    #[must_use]
    pub const fn strict() -> Self {
        DecompressOptions {
            verify_checksum: true,
            strict: true,
            multi_frame: false,
            allow_skippable: true,
        }
    }

    /// Reference-decoder compatibility options used by [`decompress`] and
    /// [`decompress_with_dict`].
    const fn educational() -> Self {
        DecompressOptions {
            verify_checksum: false,
            strict: false,
            multi_frame: false,
            allow_skippable: false,
        }
    }

    /// Sets whether to verify `XXH64` frame content checksums.
    #[must_use]
    pub const fn with_verify_checksum(mut self, verify_checksum: bool) -> Self {
        self.verify_checksum = verify_checksum;
        self
    }

    /// Sets whether to enforce strict RFC 8878 checks.
    #[must_use]
    pub const fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Sets whether to decode all concatenated frames in the input.
    #[must_use]
    pub const fn with_multi_frame(mut self, multi_frame: bool) -> Self {
        self.multi_frame = multi_frame;
        self
    }

    /// Sets whether skippable frames (`0x184D2A50..=0x184D2A5F`) are skipped.
    #[must_use]
    pub const fn with_skippable(mut self, allow_skippable: bool) -> Self {
        self.allow_skippable = allow_skippable;
        self
    }
}

/******* IMPORTANT CONSTANTS *********************************************/

// Zstandard frame
// "Magic_Number
// 4 Bytes, little-endian format. Value : 0xFD2FB528"
pub(crate) const ZSTD_MAGIC_NUMBER: u32 = 0xFD2F_B528;

// Skippable frames magic range: 0x184D2A50 to 0x184D2A5F
pub(crate) const SKIPPABLE_MAGIC_LOW: u32 = 0x184D_2A50;
pub(crate) const SKIPPABLE_MAGIC_HIGH: u32 = 0x184D_2A5F;

// The size of `Block_Content` is limited by `Block_Maximum_Size`,
pub(crate) const ZSTD_BLOCK_SIZE_MAX: usize = 128 * 1024;

// literal blocks can't be larger than their block
const MAX_LITERALS_SIZE: usize = ZSTD_BLOCK_SIZE_MAX;

/******* UTILITY MACROS AND TYPES *********************************************/

fn error<T>(kind: DecompressErrorKind, s: &'static str) -> R<T> {
    Err(DecompressError::new(kind, s))
}
fn inp_size<T>() -> R<T> {
    error(
        DecompressErrorKind::UnexpectedEof,
        "Input buffer smaller than it should be or input is corrupted",
    )
}
fn out_size<T>() -> R<T> {
    error(
        DecompressErrorKind::OutputTooSmall,
        "Output buffer too small for output",
    )
}
fn corruption<T>() -> R<T> {
    error(
        DecompressErrorKind::CorruptedInput,
        "Corruption detected while decompressing",
    )
}
fn checksum_mismatch<T>() -> R<T> {
    error(
        DecompressErrorKind::ChecksumMismatch,
        "Content checksum did not match",
    )
}
fn content_size_mismatch<T>() -> R<T> {
    error(
        DecompressErrorKind::ContentSizeMismatch,
        "Decompressed size does not match frame content size",
    )
}

/*** IO STREAM OPERATIONS *************/

/// `ostream_t`: destination sink (either a growable `Vec<u8>` bounded by `remaining` or a
/// fixed `&mut [u8]` slice) written forward.
enum OStream<'o> {
    Vec {
        out: &'o mut Vec<u8>,
        remaining: usize,
    },
    Slice {
        dst: &'o mut [u8],
        pos: usize,
    },
}

/// `istream_t`: wraps the data passed into `ZSTD_decompress`, so that all IO operations are
/// safely bounds checked. They are read forward, and reads are treated as little-endian.
#[derive(Clone, Copy)]
struct IStream<'a> {
    /// (What the stream is a part of: a stream can be backed up to before where it began.)
    src: &'a [u8],
    ptr: usize,
    len: usize,

    // Input often reads a few bits at a time, so maintain an internal offset
    bit_offset: i32,
}

impl<'a> IStream<'a> {
    /// `IO_make_istream`
    fn new(src: &'a [u8]) -> IStream<'a> {
        IStream {
            src,
            ptr: 0,
            len: src.len(),
            bit_offset: 0,
        }
    }

    /// `IO_read_bits`: reads `num` bits from a bitstream, and updates the internal offset
    fn read_bits(&mut self, num_bits: i32) -> R<u64> {
        if num_bits > 64 || num_bits <= 0 {
            return error(
                DecompressErrorKind::CorruptedInput,
                "Attempt to read an invalid number of bits",
            );
        }

        let bytes = ((num_bits + self.bit_offset + 7) / 8) as usize;
        let full_bytes = ((num_bits + self.bit_offset) / 8) as usize;
        if bytes > self.len {
            return inp_size();
        }

        let result = read_bits_le(&self.src[self.ptr..], num_bits, self.bit_offset as usize)?;
        self.bit_offset = (num_bits + self.bit_offset) % 8;
        self.ptr += full_bytes;
        self.len -= full_bytes;
        Ok(result)
    }

    /// `IO_rewind_bits`: backs-up the stream by `num` bits so they can be read again.
    fn rewind_bits(&mut self, num_bits: i32) -> R<()> {
        if num_bits < 0 {
            return error(
                DecompressErrorKind::CorruptedInput,
                "Attempting to rewind stream by a negative number of bits",
            );
        }

        // move the offset back by `num_bits` bits
        let new_offset = self.bit_offset - num_bits;
        // determine the number of whole bytes we have to rewind, rounding up to an
        // integer number (e.g. if `new_offset == -5`, `bytes == 1`)
        let bytes = (-(new_offset - 7) / 8) as usize;

        if bytes > self.ptr {
            return inp_size();
        }
        self.ptr -= bytes;
        self.len += bytes;
        // make sure the resulting `bit_offset` is positive, as mod in C does not
        // convert numbers from negative to positive (e.g. -22 % 8 == -6)
        self.bit_offset = ((new_offset % 8) + 8) % 8;
        Ok(())
    }

    /// `IO_align_stream`: if the remaining bits in a byte will be unused, advance to the end
    /// of the byte
    fn align_stream(&mut self) -> R<()> {
        if self.bit_offset != 0 {
            if self.len == 0 {
                return inp_size();
            }
            self.ptr += 1;
            self.len -= 1;
            self.bit_offset = 0;
        }
        Ok(())
    }

    /// `IO_istream_len`: returns the number of bytes left to be read in this stream.
    fn istream_len(&self) -> usize {
        self.len
    }

    /// `IO_get_read_ptr`: advances the stream by `len` bytes, and returns the chunk that was
    /// skipped. The stream must be byte aligned.
    fn get_read_ptr(&mut self, len: usize) -> R<&'a [u8]> {
        if len > self.len {
            return inp_size();
        }
        if self.bit_offset != 0 {
            return error(
                DecompressErrorKind::CorruptedInput,
                "Attempting to operate on a non-byte aligned stream",
            );
        }
        let chunk = &self.src[self.ptr..self.ptr + len];
        self.ptr += len;
        self.len -= len;
        Ok(chunk)
    }

    /// `IO_advance_input`: advance the inner state by `len` bytes.
    fn advance_input(&mut self, len: usize) -> R<()> {
        self.get_read_ptr(len).map(|_| ())
    }

    /// `IO_make_sub_istream`: returns an `istream_t` with the same base as `in`, and length
    /// `len`. Then, advance `in` to account for the consumed bytes.
    fn make_sub_istream(&mut self, len: usize) -> R<IStream<'a>> {
        let ptr = self.ptr;
        self.get_read_ptr(len)?;
        Ok(IStream {
            src: self.src,
            ptr,
            len,
            bit_offset: 0,
        })
    }
}

impl<'o> OStream<'o> {
    fn from_vec(out: &'o mut Vec<u8>, remaining: usize) -> OStream<'o> {
        OStream::Vec { out, remaining }
    }

    fn from_slice(dst: &'o mut [u8]) -> OStream<'o> {
        OStream::Slice { dst, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        match self {
            OStream::Vec { remaining, .. } => *remaining,
            OStream::Slice { dst, pos } => dst.len() - *pos,
        }
    }

    #[inline]
    fn current_len(&self) -> usize {
        match self {
            OStream::Vec { out, .. } => out.len(),
            OStream::Slice { pos, .. } => *pos,
        }
    }

    #[inline]
    fn slice_from(&self, start: usize) -> &[u8] {
        match self {
            OStream::Vec { out, .. } => &out[start..],
            OStream::Slice { dst, pos } => &dst[start..*pos],
        }
    }

    #[inline]
    fn write_byte(&mut self, symb: u8) -> R<()> {
        match self {
            OStream::Vec { out, remaining } => {
                if *remaining == 0 {
                    return out_size();
                }
                out.push(symb);
                *remaining -= 1;
                Ok(())
            }
            OStream::Slice { dst, pos } => {
                if *pos >= dst.len() {
                    return out_size();
                }
                dst[*pos] = symb;
                *pos += 1;
                Ok(())
            }
        }
    }

    #[inline]
    fn extend_slice(&mut self, data: &[u8]) -> R<()> {
        match self {
            OStream::Vec { out, remaining } => {
                if data.len() > *remaining {
                    return out_size();
                }
                out.extend_from_slice(data);
                *remaining -= data.len();
                Ok(())
            }
            OStream::Slice { dst, pos } => {
                if data.len() > dst.len() - *pos {
                    return out_size();
                }
                dst[*pos..*pos + data.len()].copy_from_slice(data);
                *pos += data.len();
                Ok(())
            }
        }
    }

    #[inline]
    fn fill_bytes(&mut self, count: usize, byte: u8) -> R<()> {
        match self {
            OStream::Vec { out, remaining } => {
                if count > *remaining {
                    return out_size();
                }
                out.resize(out.len() + count, byte);
                *remaining -= count;
                Ok(())
            }
            OStream::Slice { dst, pos } => {
                if count > dst.len() - *pos {
                    return out_size();
                }
                dst[*pos..*pos + count].fill(byte);
                *pos += count;
                Ok(())
            }
        }
    }

    #[inline]
    fn reserve_check(&self, len: usize) -> R<()> {
        if len > self.remaining() {
            return out_size();
        }
        Ok(())
    }

    /// Copies a backreference match of `match_length` bytes at `offset` back, doubling the
    /// copied period on overlapping matches (`offset < match_length`).
    #[inline]
    fn copy_periodic(&mut self, offset: usize, match_length: usize) -> R<()> {
        if match_length == 0 {
            return Ok(());
        }
        if offset == 0 {
            return self.fill_bytes(match_length, 0);
        }
        if offset == 1 {
            let byte = match self {
                OStream::Vec { out, .. } => out[out.len() - 1],
                OStream::Slice { dst, pos } => dst[*pos - 1],
            };
            return self.fill_bytes(match_length, byte);
        }
        match self {
            OStream::Vec { out, remaining } => {
                if match_length > *remaining {
                    return out_size();
                }
                out.reserve(match_length);
                let mut period = offset;
                let mut left = match_length;
                while left > 0 {
                    let cur_end = out.len();
                    let copy_len = left.min(period);
                    out.extend_from_within(cur_end - period..cur_end - period + copy_len);
                    left -= copy_len;
                    period += copy_len;
                }
                *remaining -= match_length;
                Ok(())
            }
            OStream::Slice { dst, pos } => {
                if match_length > dst.len() - *pos {
                    return out_size();
                }
                let mut period = offset;
                let mut left = match_length;
                while left > 0 {
                    let cur_end = *pos;
                    let copy_len = left.min(period);
                    dst.copy_within(cur_end - period..cur_end - period + copy_len, cur_end);
                    *pos += copy_len;
                    left -= copy_len;
                    period += copy_len;
                }
                Ok(())
            }
        }
    }
}

/*** BITSTREAM OPERATIONS *************/

/// `read_bits_LE`: read `num` bits (up to 64) from `src + offset`, where `offset` is in bits,
/// and return them interpreted as a little-endian unsigned integer.
fn read_bits_le(src: &[u8], num_bits: i32, offset: usize) -> R<u64> {
    if num_bits > 64 {
        return error(
            DecompressErrorKind::CorruptedInput,
            "Attempt to read an invalid number of bits",
        );
    }

    // Skip over bytes that aren't in range
    let mut at = offset / 8;
    let mut bit_offset = offset % 8;

    // (All of them from one word, where the input has a word left and the bits fit in it.)
    if num_bits <= 0 {
        return Ok(0);
    }
    if let Some(word) = src.get(at..at + 8)
        && bit_offset + num_bits as usize <= 64
    {
        let word = u64::from_le_bytes([
            word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
        ]) >> bit_offset;
        return Ok(if num_bits == 64 {
            word
        } else {
            word & ((1 << num_bits) - 1)
        });
    }

    let mut res = 0u64;

    let mut shift = 0;
    let mut left = num_bits;
    while left > 0 {
        let mask = if left >= 8 { 0xff } else { (1u64 << left) - 1 };
        // Read the next byte, shift it to account for the offset, and then mask
        // out the top part if we don't need all the bits
        res += ((u64::from(src[at]) >> bit_offset) & mask) << shift;
        at += 1;
        shift += 8 - bit_offset;
        left -= 8 - bit_offset as i32;
        bit_offset = 0;
    }

    Ok(res)
}

/// `STREAM_read_bits`: read bits from the end of a HUF or FSE bitstream.
fn stream_read_bits(src: &[u8], bits: i32, offset: &mut i64) -> R<u64> {
    *offset -= i64::from(bits);
    let mut actual_off = *offset;
    let mut actual_bits = i64::from(bits);
    if *offset < 0 {
        actual_bits += *offset;
        actual_off = 0;
    }
    let mut res = read_bits_le(src, actual_bits as i32, actual_off as usize)?;

    if *offset < 0 {
        // Fill in the bottom "overflowed" bits with 0's
        res = if -*offset >= 64 { 0 } else { res << -*offset };
    }
    Ok(res)
}

/// Buffered backward bit reader for HUF and FSE bitstreams. Caches a 64-bit little-endian
/// window from `src` and falls back to [`stream_read_bits`] near the beginning of `src` or
/// for unusual widths, preserving 100% identical behavior on all inputs.
struct BackwardBitReader<'a> {
    src: &'a [u8],
    bit_offset: i64,
    buf: u64,
    buf_bit_start: i64,
}

impl<'a> BackwardBitReader<'a> {
    #[inline]
    fn new(src: &'a [u8], bit_offset: i64) -> Self {
        let mut reader = Self {
            src,
            bit_offset,
            buf: 0,
            buf_bit_start: i64::MAX,
        };
        reader.refill();
        reader
    }

    #[inline]
    fn refill(&mut self) {
        if self.src.len() >= 8 && self.bit_offset > 0 {
            let end_byte = (((self.bit_offset + 7) >> 3) as usize).min(self.src.len());
            let start_byte = end_byte.saturating_sub(8);
            if start_byte + 8 <= self.src.len() {
                let b = &self.src[start_byte..start_byte + 8];
                self.buf = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                self.buf_bit_start = (start_byte * 8) as i64;
            }
        }
    }

    #[inline]
    fn read_bits(&mut self, bits: i32) -> R<u64> {
        if bits == 0 {
            return Ok(0);
        }
        if bits > 0 && bits <= 57 {
            let new_offset = self.bit_offset - i64::from(bits);
            if new_offset >= self.buf_bit_start && self.bit_offset <= self.buf_bit_start + 64 {
                self.bit_offset = new_offset;
                let shift = (new_offset - self.buf_bit_start) as u32;
                return Ok((self.buf >> shift) & ((1u64 << bits) - 1));
            }
            if new_offset >= 0 && self.src.len() >= 8 {
                self.refill();
                if new_offset >= self.buf_bit_start && self.bit_offset <= self.buf_bit_start + 64 {
                    self.bit_offset = new_offset;
                    let shift = (new_offset - self.buf_bit_start) as u32;
                    return Ok((self.buf >> shift) & ((1u64 << bits) - 1));
                }
            }
        }
        stream_read_bits(self.src, bits, &mut self.bit_offset)
    }
}

/*** BIT COUNTING OPERATIONS **********/

/// `highest_set_bit`: returns the index of the highest set bit in `num`, or `-1` if
/// `num == 0`
#[inline]
fn highest_set_bit(num: u64) -> i32 {
    63 - num.leading_zeros() as i32
}

/*** HUFFMAN PRIMITIVES ***************/

const HUF_MAX_BITS: usize = 16;
const HUF_MAX_SYMBS: usize = 256;

/// `HUF_dtable`: structure containing all tables necessary for efficient Huffman decoding.
#[derive(Clone, Default)]
struct HufDtable {
    symbols: Vec<u8>,
    num_bits: Vec<u8>,
    max_bits: i32,
}

impl HufDtable {
    fn clear(&mut self) {
        self.symbols.clear();
        self.num_bits.clear();
        self.max_bits = 0;
    }

    fn copy_from_dtable(&mut self, src: &HufDtable) {
        if src.max_bits == 0 {
            self.clear();
            return;
        }
        self.symbols.clear();
        self.symbols.extend_from_slice(&src.symbols);
        self.num_bits.clear();
        self.num_bits.extend_from_slice(&src.num_bits);
        self.max_bits = src.max_bits;
    }
}

/*** FSE PRIMITIVES *******************/

// For more description of FSE see
// https://github.com/Cyan4973/FiniteStateEntropy/

const FSE_MAX_ACCURACY_LOG: i32 = 15;
const FSE_MAX_SYMBS: usize = 256;

/// `FSE_dtable`: the tables needed to decode FSE encoded streams
#[derive(Clone, Default)]
struct FseDtable {
    symbols: Vec<u8>,
    num_bits: Vec<u8>,
    new_state_base: Vec<u16>,
    accuracy_log: i32,
}

impl FseDtable {
    fn clear(&mut self) {
        self.symbols.clear();
        self.num_bits.clear();
        self.new_state_base.clear();
        self.accuracy_log = 0;
    }

    fn copy_from_dtable(&mut self, src: &FseDtable) {
        if src.accuracy_log == 0 {
            self.clear();
            return;
        }
        self.symbols.clear();
        self.symbols.extend_from_slice(&src.symbols);
        self.num_bits.clear();
        self.num_bits.extend_from_slice(&src.num_bits);
        self.new_state_base.clear();
        self.new_state_base.extend_from_slice(&src.new_state_base);
        self.accuracy_log = src.accuracy_log;
    }
}

/******* ZSTD HELPER STRUCTS AND PROTOTYPES ***********************************/

/// `frame_header_t`
#[derive(Clone, Copy, Default)]
pub(crate) struct FrameHeader {
    pub(crate) window_size: u64,
    pub(crate) frame_content_size: Option<u64>,
    pub(crate) dictionary_id: u32,
    pub(crate) content_checksum_flag: bool,
    pub(crate) single_segment_flag: bool,
}

/// `frame_context_t`: the context needed to decode blocks in a frame
#[derive(Default)]
struct FrameContext {
    header: FrameHeader,
    current_total_output: usize,
    literals_dtable: HufDtable,
    ll_dtable: FseDtable,
    ml_dtable: FseDtable,
    of_dtable: FseDtable,
    previous_offsets: [u64; 3],
}

/// Reusable scratch buffers for decoding blocks without reallocating tables and literal buffers
/// on each call.
#[derive(Default)]
struct DecompressScratch {
    ctx: FrameContext,
    literals_buf: Vec<u8>,
    weights_buf: Vec<u8>,
}

/// The parsed contents of a dictionary: `dictionary_t`. This includes Huffman and FSE tables
/// used for decoding and data on offsets. [`Dictionary::default`] is the one that is none.
#[derive(Clone, Default)]
pub struct Dictionary {
    literals_dtable: HufDtable,
    ll_dtable: FseDtable,
    ml_dtable: FseDtable,
    of_dtable: FseDtable,
    content: Vec<u8>,
    has_content: bool,
    previous_offsets: [u64; 3],
    id: u32,
}

impl fmt::Debug for Dictionary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dictionary")
            .field("id", &self.id)
            .field("content_len", &self.content.len())
            .field("has_tables", &(self.id != 0))
            .finish_non_exhaustive()
    }
}

/// `sequence_command_t`
#[derive(Clone, Copy)]
struct SequenceCommand {
    literal_length: u32,
    match_length: u32,
    offset: u32,
}

/// Reusable Zstandard decompressor that retains its entropy decoding tables and literal
/// buffers across calls, avoiding repeated heap allocations.
#[derive(Default)]
pub struct Decompressor {
    scratch: DecompressScratch,
}

impl fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decompressor")
            .field("literals_capacity", &self.scratch.literals_buf.capacity())
            .finish_non_exhaustive()
    }
}

impl Decompressor {
    /// Creates a new reusable [`Decompressor`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompresses one Zstandard frame holding no more than `max_len` bytes, matching
    /// [`decompress`].
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if the frame is invalid, truncated, or exceeds `max_len`.
    pub fn decompress(&mut self, frame: &[u8], max_len: usize) -> Result<Vec<u8>, DecompressError> {
        self.decompress_with_dict(frame, max_len, &Dictionary::default())
    }

    /// Decompresses one Zstandard frame directly into `dst`, returning the number of bytes
    /// written (matching [`decompress_into`]).
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if the frame is invalid, truncated, or decompresses to
    /// more than `dst.len()` bytes.
    pub fn decompress_into(
        &mut self,
        frame: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, DecompressError> {
        let mut input = IStream::new(frame);
        let mut out = OStream::from_slice(dst);
        decode_single_or_multi(
            &mut self.scratch,
            &mut out,
            &mut input,
            &Dictionary::default(),
            DecompressOptions::educational(),
        )?;
        Ok(out.current_len())
    }

    /// Decompresses one Zstandard frame compressed with `parsed_dict`, matching
    /// [`decompress_with_dict`].
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if the frame is invalid, truncated, exceeds `max_len`,
    /// or requires another dictionary.
    pub fn decompress_with_dict(
        &mut self,
        frame: &[u8],
        max_len: usize,
        parsed_dict: &Dictionary,
    ) -> Result<Vec<u8>, DecompressError> {
        let mut vec = Vec::new();
        let mut input = IStream::new(frame);
        let mut out = OStream::from_vec(&mut vec, max_len);
        decode_single_or_multi(
            &mut self.scratch,
            &mut out,
            &mut input,
            parsed_dict,
            DecompressOptions::educational(),
        )?;
        Ok(vec)
    }

    /// Decompresses `src` (up to `max_len` output bytes) with custom [`DecompressOptions`].
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if any frame is invalid, truncated, fails checksum or
    /// strict validation, or exceeds `max_len`.
    pub fn decompress_with_options(
        &mut self,
        src: &[u8],
        max_len: usize,
        options: DecompressOptions,
    ) -> Result<Vec<u8>, DecompressError> {
        self.decompress_with_dict_and_options(src, max_len, &Dictionary::default(), options)
    }

    /// Decompresses `src` with `parsed_dict` and custom [`DecompressOptions`].
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if any frame is invalid, truncated, fails checksum or
    /// strict validation, requires another dictionary, or exceeds `max_len`.
    pub fn decompress_with_dict_and_options(
        &mut self,
        src: &[u8],
        max_len: usize,
        parsed_dict: &Dictionary,
        options: DecompressOptions,
    ) -> Result<Vec<u8>, DecompressError> {
        let mut vec = Vec::new();
        let mut input = IStream::new(src);
        let mut out = OStream::from_vec(&mut vec, max_len);
        decode_single_or_multi(
            &mut self.scratch,
            &mut out,
            &mut input,
            parsed_dict,
            options,
        )?;
        Ok(vec)
    }

    /// Decompresses `src` directly into `dst` with custom [`DecompressOptions`], returning
    /// the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if any frame is invalid, truncated, fails checksum or
    /// strict validation, or exceeds `dst.len()`.
    pub fn decompress_into_with_options(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        options: DecompressOptions,
    ) -> Result<usize, DecompressError> {
        let mut input = IStream::new(src);
        let mut out = OStream::from_slice(dst);
        decode_single_or_multi(
            &mut self.scratch,
            &mut out,
            &mut input,
            &Dictionary::default(),
            options,
        )?;
        Ok(out.current_len())
    }

    /// Decompresses one frame (data frame or skippable frame) from the start of `src`,
    /// verifying checksums by default and returning `(decoded_bytes, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if the frame is invalid, truncated, fails checksum
    /// verification, or exceeds `max_len`.
    pub fn decompress_frame(
        &mut self,
        src: &[u8],
        max_len: usize,
    ) -> Result<(Vec<u8>, usize), DecompressError> {
        self.decompress_frame_with_options(src, max_len, DecompressOptions::new())
    }

    /// Decompresses one frame from the start of `src` with `options` (`multi_frame` is
    /// ignored), returning `(decoded_bytes, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if the frame is invalid, truncated, fails validation, or
    /// exceeds `max_len`.
    pub fn decompress_frame_with_options(
        &mut self,
        src: &[u8],
        max_len: usize,
        options: DecompressOptions,
    ) -> Result<(Vec<u8>, usize), DecompressError> {
        let mut vec = Vec::new();
        let mut input = IStream::new(src);
        let mut out = OStream::from_vec(&mut vec, max_len);
        decode_frame(
            &mut self.scratch,
            &mut out,
            &mut input,
            &Dictionary::default(),
            options.with_multi_frame(false),
        )?;
        Ok((vec, input.ptr))
    }

    /// Decompresses all concatenated Zstandard and skippable frames in `src` (verifying
    /// checksums by default) up to `max_len` total output bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DecompressError`] if any frame in `src` is invalid, truncated, fails
    /// checksum verification, or total output exceeds `max_len`.
    pub fn decompress_stream(
        &mut self,
        src: &[u8],
        max_len: usize,
    ) -> Result<Vec<u8>, DecompressError> {
        self.decompress_with_options(
            src,
            max_len,
            DecompressOptions::new().with_multi_frame(true),
        )
    }
}

/// Decompresses a Zstandard frame that holds no more than `max_len` bytes
/// (`ZSTD_decompress`). Anything after the frame is ignored.
///
/// # Errors
///
/// A [`DecompressError`], whose message is the reference decoder's, if the frame is not a
/// valid one, is cut short, or holds more than `max_len` bytes.
pub fn decompress(frame: &[u8], max_len: usize) -> Result<Vec<u8>, DecompressError> {
    decompress_with_dict(frame, max_len, &Dictionary::default())
}

/// Decompresses a Zstandard frame directly into `dst`, returning the number of bytes written.
/// Anything after the frame is ignored.
///
/// # Errors
///
/// Returns a [`DecompressError`] if the frame is invalid, truncated, or decompresses to more
/// than `dst.len()` bytes.
pub fn decompress_into(frame: &[u8], dst: &mut [u8]) -> Result<usize, DecompressError> {
    Decompressor::new().decompress_into(frame, dst)
}

/// Decompresses a Zstandard frame compressed with a dictionary, that holds no more than
/// `max_len` bytes (`ZSTD_decompress_with_dict`).
///
/// # Errors
///
/// A [`DecompressError`], whose message is the reference decoder's, if the frame is not a
/// valid one, is cut short, or holds more than `max_len` bytes, or was
/// compressed with another dictionary.
pub fn decompress_with_dict(
    frame: &[u8],
    max_len: usize,
    parsed_dict: &Dictionary,
) -> Result<Vec<u8>, DecompressError> {
    Decompressor::new().decompress_with_dict(frame, max_len, parsed_dict)
}

/// Decompresses `src` (up to `max_len` output bytes) with custom [`DecompressOptions`],
/// supporting `XXH64` checksum verification, strict RFC 8878 validation, skippable frames,
/// and concatenated multi-frame streams.
///
/// # Errors
///
/// Returns a [`DecompressError`] if any frame is invalid, truncated, fails checksum or strict
/// validation, or exceeds `max_len`.
pub fn decompress_with_options(
    src: &[u8],
    max_len: usize,
    options: DecompressOptions,
) -> Result<Vec<u8>, DecompressError> {
    Decompressor::new().decompress_with_options(src, max_len, options)
}

/// Decompresses `src` directly into `dst` with custom [`DecompressOptions`], returning the
/// number of bytes written.
///
/// # Errors
///
/// Returns a [`DecompressError`] if any frame is invalid, truncated, fails checksum or strict
/// validation, or exceeds `dst.len()`.
pub fn decompress_into_with_options(
    src: &[u8],
    dst: &mut [u8],
    options: DecompressOptions,
) -> Result<usize, DecompressError> {
    Decompressor::new().decompress_into_with_options(src, dst, options)
}

/// Decompresses one frame (data frame or skippable frame) from the start of `src`, verifying
/// `XXH64` content checksums by default, and returns `(decoded_bytes, bytes_consumed)`.
///
/// # Errors
///
/// Returns a [`DecompressError`] if the frame is invalid, truncated, fails checksum
/// verification, or exceeds `max_len`.
pub fn decompress_frame(src: &[u8], max_len: usize) -> Result<(Vec<u8>, usize), DecompressError> {
    Decompressor::new().decompress_frame(src, max_len)
}

/// Decompresses one frame from the start of `src` with custom [`DecompressOptions`]
/// (`multi_frame` is ignored), returning `(decoded_bytes, bytes_consumed)`.
///
/// # Errors
///
/// Returns a [`DecompressError`] if the frame is invalid, truncated, fails validation, or
/// exceeds `max_len`.
pub fn decompress_frame_with_options(
    src: &[u8],
    max_len: usize,
    options: DecompressOptions,
) -> Result<(Vec<u8>, usize), DecompressError> {
    Decompressor::new().decompress_frame_with_options(src, max_len, options)
}

/// Decompresses all concatenated Zstandard and skippable frames in `src` (verifying `XXH64`
/// checksums by default) up to `max_len` total output bytes.
///
/// An empty `src` produces an empty `Vec`.
///
/// # Errors
///
/// Returns a [`DecompressError`] if any frame in `src` is invalid, truncated, fails checksum
/// verification, or total output exceeds `max_len`.
pub fn decompress_stream(src: &[u8], max_len: usize) -> Result<Vec<u8>, DecompressError> {
    Decompressor::new().decompress_stream(src, max_len)
}

/******* FRAME DECODING ******************************************************/

fn decode_single_or_multi(
    scratch: &mut DecompressScratch,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    dict: &Dictionary,
    options: DecompressOptions,
) -> R<()> {
    if options.multi_frame {
        while input.istream_len() > 0 {
            decode_frame(scratch, out, input, dict, options)?;
        }
        Ok(())
    } else {
        decode_frame(scratch, out, input, dict, options)
    }
}

/// `decode_frame`
fn decode_frame(
    scratch: &mut DecompressScratch,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    dict: &Dictionary,
    options: DecompressOptions,
) -> R<()> {
    let magic_number = input.read_bits(32)? as u32;
    if magic_number == ZSTD_MAGIC_NUMBER {
        return decode_data_frame(scratch, out, input, dict, options);
    }
    if options.allow_skippable
        && (SKIPPABLE_MAGIC_LOW..=SKIPPABLE_MAGIC_HIGH).contains(&magic_number)
    {
        let skip_len = input.read_bits(32)? as usize;
        input.advance_input(skip_len)?;
        return Ok(());
    }

    error(
        DecompressErrorKind::InvalidFrameMagic,
        "Tried to decode non-ZSTD frame",
    )
}

/// `decode_data_frame`: decode a frame that contains compressed data.
fn decode_data_frame(
    scratch: &mut DecompressScratch,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    dict: &Dictionary,
    options: DecompressOptions,
) -> R<()> {
    init_frame_context(&mut scratch.ctx, input, dict)?;

    if let Some(fcs) = scratch.ctx.header.frame_content_size
        && fcs > out.remaining() as u64
    {
        return out_size();
    }

    decompress_data(scratch, out, input, dict, options)
}

/// `init_frame_context`
fn init_frame_context(ctx: &mut FrameContext, input: &mut IStream<'_>, dict: &Dictionary) -> R<()> {
    ctx.header = parse_frame_header(input)?;
    ctx.current_total_output = 0;
    ctx.literals_dtable.clear();
    ctx.ll_dtable.clear();
    ctx.ml_dtable.clear();
    ctx.of_dtable.clear();
    ctx.previous_offsets = [1, 4, 8];

    frame_context_apply_dict(ctx, dict)
}

/// `parse_frame_header`
#[cfg(feature = "std")]
pub(crate) fn parse_frame_header_from_slice(header_bytes: &[u8]) -> R<FrameHeader> {
    let mut input = IStream::new(header_bytes);
    parse_frame_header(&mut input)
}

fn parse_frame_header(input: &mut IStream<'_>) -> R<FrameHeader> {
    let mut header = FrameHeader::default();
    let descriptor = input.read_bits(8)? as u8;

    // decode frame header descriptor into flags
    let frame_content_size_flag = descriptor >> 6;
    let single_segment_flag = (descriptor >> 5) & 1;
    let reserved_bit = (descriptor >> 3) & 1;
    let content_checksum_flag = (descriptor >> 2) & 1;
    let dictionary_id_flag = descriptor & 3;

    if reserved_bit != 0 {
        return corruption();
    }

    header.single_segment_flag = single_segment_flag != 0;
    header.content_checksum_flag = content_checksum_flag != 0;

    // decode window size
    if single_segment_flag == 0 {
        let window_descriptor = input.read_bits(8)? as u8;
        let exponent = window_descriptor >> 3;
        let mantissa = window_descriptor & 7;

        let window_base = 1u64 << (10 + exponent);
        let window_add = (window_base / 8) * u64::from(mantissa);
        header.window_size = window_base + window_add;
    }

    // decode dictionary id if it exists
    if dictionary_id_flag != 0 {
        const BYTES_ARRAY: [i32; 4] = [0, 1, 2, 4];
        let bytes = BYTES_ARRAY[usize::from(dictionary_id_flag)];

        header.dictionary_id = input.read_bits(bytes * 8)? as u32;
    } else {
        header.dictionary_id = 0;
    }

    // decode frame content size if it exists
    if single_segment_flag != 0 || frame_content_size_flag != 0 {
        const BYTES_ARRAY: [i32; 4] = [1, 2, 4, 8];
        let bytes = BYTES_ARRAY[usize::from(frame_content_size_flag)];

        let mut fcs = input.read_bits(bytes * 8)?;
        if bytes == 2 {
            // "When Field_Size is 2, the offset of 256 is added."
            fcs += 256;
        }
        header.frame_content_size = Some(fcs);
    } else {
        header.frame_content_size = None;
    }

    if single_segment_flag != 0 {
        header.window_size = header.frame_content_size.unwrap_or(0);
    }

    Ok(header)
}

/// `decompress_data`: decompress the data from a frame block by block
fn decompress_data(
    scratch: &mut DecompressScratch,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    dict: &Dictionary,
    options: DecompressOptions,
) -> R<()> {
    let frame_output_start = out.current_len();
    let dict_content = if dict.has_content {
        &dict.content[..]
    } else {
        &[]
    };

    loop {
        let last_block = input.read_bits(1)? != 0;
        let block_type = input.read_bits(2)?;
        let block_len = input.read_bits(21)? as usize;

        if options.strict && block_len > ZSTD_BLOCK_SIZE_MAX {
            return corruption();
        }

        match block_type {
            0 => {
                // Raw_Block
                let read_ptr = input.get_read_ptr(block_len)?;
                out.extend_slice(read_ptr)?;
                scratch.ctx.current_total_output += block_len;
            }
            1 => {
                // RLE_Block
                let read_ptr = input.get_read_ptr(1)?;
                out.fill_bytes(block_len, read_ptr[0])?;
                scratch.ctx.current_total_output += block_len;
            }
            2 => {
                // Compressed_Block
                let mut block_stream = input.make_sub_istream(block_len)?;
                decompress_block(
                    scratch,
                    out,
                    &mut block_stream,
                    dict_content,
                    options.strict,
                )?;
            }
            _ => {
                return corruption();
            }
        }

        if options.strict
            && let Some(fcs) = scratch.ctx.header.frame_content_size
            && scratch.ctx.current_total_output as u64 > fcs
        {
            return content_size_mismatch();
        }

        if last_block {
            break;
        }
    }

    if options.strict
        && let Some(fcs) = scratch.ctx.header.frame_content_size
        && scratch.ctx.current_total_output as u64 != fcs
    {
        return content_size_mismatch();
    }

    if scratch.ctx.header.content_checksum_flag {
        let trailer = input.get_read_ptr(4)?;
        if options.verify_checksum {
            let expected = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            let actual = super::zstd_ldm::xxh64(out.slice_from(frame_output_start), 0) as u32;
            if actual != expected {
                return checksum_mismatch();
            }
        }
    }
    Ok(())
}

/// Streaming block-by-block frame decoder used by [`crate::io::Decoder`].
#[cfg(feature = "std")]
#[derive(Default)]
pub(crate) struct StreamFrameDecoder {
    scratch: DecompressScratch,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy)]
pub(crate) struct RawBlock<'a> {
    pub(crate) block_type: u8,
    pub(crate) block_len: usize,
    pub(crate) payload: &'a [u8],
}

#[cfg(feature = "std")]
impl StreamFrameDecoder {
    pub(crate) fn start_frame(&mut self, header: FrameHeader, dict: &Dictionary) -> R<()> {
        self.scratch.ctx.header = header;
        self.scratch.ctx.current_total_output = 0;
        self.scratch.ctx.literals_dtable.clear();
        self.scratch.ctx.ll_dtable.clear();
        self.scratch.ctx.ml_dtable.clear();
        self.scratch.ctx.of_dtable.clear();
        self.scratch.ctx.previous_offsets = [1, 4, 8];
        frame_context_apply_dict(&mut self.scratch.ctx, dict)
    }

    pub(crate) fn header(&self) -> FrameHeader {
        self.scratch.ctx.header
    }

    pub(crate) fn current_total_output(&self) -> usize {
        self.scratch.ctx.current_total_output
    }

    pub(crate) fn decode_block_into_vec(
        &mut self,
        block: RawBlock<'_>,
        out_vec: &mut Vec<u8>,
        remaining_limit: usize,
        dict: &Dictionary,
        strict: bool,
    ) -> R<()> {
        let RawBlock {
            block_type,
            block_len,
            payload,
        } = block;
        if strict && block_len > ZSTD_BLOCK_SIZE_MAX {
            return corruption();
        }
        let dict_content = if dict.has_content {
            &dict.content[..]
        } else {
            &[]
        };
        let mut out = OStream::from_vec(out_vec, remaining_limit);
        match block_type {
            0 => {
                out.extend_slice(payload)?;
                self.scratch.ctx.current_total_output += block_len;
            }
            1 => {
                out.fill_bytes(block_len, payload[0])?;
                self.scratch.ctx.current_total_output += block_len;
            }
            2 => {
                let mut block_stream = IStream::new(payload);
                decompress_block(
                    &mut self.scratch,
                    &mut out,
                    &mut block_stream,
                    dict_content,
                    strict,
                )?;
            }
            _ => return corruption(),
        }
        if strict
            && let Some(fcs) = self.scratch.ctx.header.frame_content_size
            && self.scratch.ctx.current_total_output as u64 > fcs
        {
            return content_size_mismatch();
        }
        Ok(())
    }

    pub(crate) fn finish_frame(&self, strict: bool) -> R<()> {
        if strict
            && let Some(fcs) = self.scratch.ctx.header.frame_content_size
            && self.scratch.ctx.current_total_output as u64 != fcs
        {
            return content_size_mismatch();
        }
        Ok(())
    }
}

/******* BLOCK DECOMPRESSION **************************************************/

/// `decompress_block`
fn decompress_block(
    scratch: &mut DecompressScratch,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    dict_content: &[u8],
    strict: bool,
) -> R<()> {
    // Part 1: decode the literals block into the reusable literals buffer
    decode_literals(
        &mut scratch.ctx,
        &mut scratch.literals_buf,
        &mut scratch.weights_buf,
        input,
    )?;

    // Part 2 & 3: decode and execute sequences on the fly directly into `out`
    decode_and_execute_sequences(
        &mut scratch.ctx,
        out,
        input,
        &scratch.literals_buf,
        dict_content,
        strict,
    )
}

/******* LITERALS DECODING ****************************************************/

/// `decode_literals`
fn decode_literals(
    ctx: &mut FrameContext,
    literals_buf: &mut Vec<u8>,
    weights_buf: &mut Vec<u8>,
    input: &mut IStream<'_>,
) -> R<()> {
    literals_buf.clear();
    let block_type = input.read_bits(2)? as i32;
    let size_format = input.read_bits(2)? as i32;

    if block_type <= 1 {
        decode_literals_simple(literals_buf, input, block_type, size_format)
    } else {
        decode_literals_compressed(
            ctx,
            literals_buf,
            weights_buf,
            input,
            block_type,
            size_format,
        )
    }
}

/// `decode_literals_simple`: decodes literals blocks in raw or RLE form
fn decode_literals_simple(
    literals_buf: &mut Vec<u8>,
    input: &mut IStream<'_>,
    block_type: i32,
    size_format: i32,
) -> R<()> {
    let size = match size_format {
        0 | 2 => {
            input.rewind_bits(1)?;
            input.read_bits(5)?
        }
        1 => input.read_bits(12)?,
        _ => input.read_bits(20)?,
    } as usize;

    if size > MAX_LITERALS_SIZE {
        return corruption();
    }

    if block_type == 0 {
        let slice = input.get_read_ptr(size)?;
        literals_buf.extend_from_slice(slice);
        Ok(())
    } else {
        let read_ptr = input.get_read_ptr(1)?;
        literals_buf.resize(size, read_ptr[0]);
        Ok(())
    }
}

/// `decode_literals_compressed`: decodes Huffman compressed literals
fn decode_literals_compressed(
    ctx: &mut FrameContext,
    literals_buf: &mut Vec<u8>,
    weights_buf: &mut Vec<u8>,
    input: &mut IStream<'_>,
    block_type: i32,
    size_format: i32,
) -> R<()> {
    let mut num_streams = 4;
    let (regenerated_size, compressed_size) = match size_format {
        0 | 1 => {
            if size_format == 0 {
                num_streams = 1;
            }
            let regenerated_size = input.read_bits(10)?;
            (regenerated_size, input.read_bits(10)?)
        }
        2 => {
            let regenerated_size = input.read_bits(14)?;
            (regenerated_size, input.read_bits(14)?)
        }
        _ => {
            let regenerated_size = input.read_bits(18)?;
            (regenerated_size, input.read_bits(18)?)
        }
    };
    let (regenerated_size, compressed_size) = (regenerated_size as usize, compressed_size as usize);
    if regenerated_size > MAX_LITERALS_SIZE {
        return corruption();
    }

    literals_buf.reserve(regenerated_size);
    let mut lit_stream = OStream::from_vec(literals_buf, regenerated_size);
    let mut huf_stream = input.make_sub_istream(compressed_size)?;

    if block_type == 2 {
        decode_huf_table(&mut ctx.literals_dtable, weights_buf, &mut huf_stream)?;
    } else if ctx.literals_dtable.symbols.is_empty() {
        return corruption();
    }

    let symbols_decoded = if num_streams == 1 {
        huf_decompress_1stream(&ctx.literals_dtable, &mut lit_stream, &mut huf_stream)?
    } else {
        huf_decompress_4stream(&ctx.literals_dtable, &mut lit_stream, &mut huf_stream)?
    };

    if symbols_decoded != regenerated_size {
        return corruption();
    }

    Ok(())
}

/// `decode_huf_table`: decode the Huffman table description
fn decode_huf_table(
    dtable: &mut HufDtable,
    weights_buf: &mut Vec<u8>,
    input: &mut IStream<'_>,
) -> R<()> {
    dtable.clear();
    let header = input.read_bits(8)? as u8;

    let mut weights = [0u8; HUF_MAX_SYMBS];

    let num_symbs;

    if header >= 128 {
        num_symbs = usize::from(header) - 127;
        let bytes = num_symbs.div_ceil(2);

        let weight_src = input.get_read_ptr(bytes)?;

        for i in 0..num_symbs {
            weights[i] = if i % 2 == 0 {
                weight_src[i / 2] >> 4
            } else {
                weight_src[i / 2] & 0xf
            };
        }
    } else {
        let mut fse_stream = input.make_sub_istream(usize::from(header))?;
        weights_buf.clear();
        let mut weight_stream = OStream::from_vec(weights_buf, HUF_MAX_SYMBS);
        fse_decode_hufweights(&mut weight_stream, &mut fse_stream)?;
        num_symbs = weights_buf.len();
        weights[..num_symbs].copy_from_slice(weights_buf);
    }

    huf_init_dtable_usingweights(dtable, &weights, num_symbs)
}

/// `fse_decode_hufweights`
fn fse_decode_hufweights(weights: &mut OStream<'_>, input: &mut IStream<'_>) -> R<()> {
    const MAX_ACCURACY_LOG: i32 = 7;

    let mut dtable = FseDtable::default();
    fse_decode_header(&mut dtable, input, MAX_ACCURACY_LOG)?;
    fse_decompress_interleaved2(&dtable, weights, input)?;
    Ok(())
}

/******* SEQUENCE DECODING & STREAMING EXECUTION ******************************/

/// `sequence_states_t`: the combination of FSE states needed to decode sequences
struct SequenceStates<'t> {
    ll_table: &'t FseDtable,
    of_table: &'t FseDtable,
    ml_table: &'t FseDtable,

    ll_state: u16,
    of_state: u16,
    ml_state: u16,
}

/// `seq_part_t`
#[derive(Clone, Copy)]
enum SeqPart {
    LiteralLength = 0,
    Offset = 1,
    MatchLength = 2,
}

static SEQ_LITERAL_LENGTH_DEFAULT_DIST: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
static SEQ_OFFSET_DEFAULT_DIST: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
static SEQ_MATCH_LENGTH_DEFAULT_DIST: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];

static SEQ_LITERAL_LENGTH_BASELINES: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
static SEQ_LITERAL_LENGTH_EXTRA_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

static SEQ_MATCH_LENGTH_BASELINES: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
static SEQ_MATCH_LENGTH_EXTRA_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

static SEQ_MAX_CODES: [u8; 3] = [35, u8::MAX, 52];

/// Decodes the sequences section and executes each sequence immediately into `out`, avoiding
/// any transient `Vec<SequenceCommand>` allocation.
fn decode_and_execute_sequences(
    ctx: &mut FrameContext,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
    literals: &[u8],
    dict_content: &[u8],
    strict: bool,
) -> R<()> {
    let header = input.read_bits(8)? as usize;
    let num_sequences = if header < 128 {
        header
    } else if header < 255 {
        ((header - 128) << 8) + input.read_bits(8)? as usize
    } else {
        input.read_bits(16)? as usize + 0x7F00
    };

    let mut litstream = IStream::new(literals);
    let block_start_output = ctx.current_total_output;
    let mut total_output = block_start_output;

    if num_sequences != 0 {
        let compression_modes = input.read_bits(8)? as u8;

        if (compression_modes & 3) != 0 {
            return corruption();
        }

        decode_seq_table(
            &mut ctx.ll_dtable,
            input,
            SeqPart::LiteralLength,
            (compression_modes >> 6) & 3,
        )?;

        decode_seq_table(
            &mut ctx.of_dtable,
            input,
            SeqPart::Offset,
            (compression_modes >> 4) & 3,
        )?;

        decode_seq_table(
            &mut ctx.ml_dtable,
            input,
            SeqPart::MatchLength,
            (compression_modes >> 2) & 3,
        )?;

        let len = input.istream_len();
        let src = input.get_read_ptr(len)?;
        if len == 0 {
            return corruption();
        }

        let padding = 8 - highest_set_bit(u64::from(src[len - 1]));
        let bit_offset = (len * 8) as i64 - i64::from(padding);
        let mut reader = BackwardBitReader::new(src, bit_offset);

        let ll_state = fse_init_state(&ctx.ll_dtable, &mut reader)?;
        let of_state = fse_init_state(&ctx.of_dtable, &mut reader)?;
        let ml_state = fse_init_state(&ctx.ml_dtable, &mut reader)?;

        let mut states = SequenceStates {
            ll_table: &ctx.ll_dtable,
            of_table: &ctx.of_dtable,
            ml_table: &ctx.ml_dtable,
            ll_state,
            of_state,
            ml_state,
        };

        let window_size = ctx.header.window_size;
        for i in 0..num_sequences {
            let seq = decode_sequence(&mut states, &mut reader, i == num_sequences - 1, strict)?;

            let step_result = execute_single_sequence(
                seq,
                &mut ctx.previous_offsets,
                window_size,
                dict_content,
                &mut litstream,
                out,
                &mut total_output,
                block_start_output,
                strict,
            );

            if let Err(exec_err) = step_result {
                for rem_i in (i + 1)..num_sequences {
                    decode_sequence(&mut states, &mut reader, rem_i == num_sequences - 1, strict)?;
                }
                if reader.bit_offset != 0 {
                    return corruption();
                }
                return Err(exec_err);
            }
        }

        if reader.bit_offset != 0 {
            return corruption();
        }
    }

    // Copy any leftover literals
    let leftover = litstream.istream_len();
    copy_literals(leftover, &mut litstream, out)?;
    total_output += leftover;

    if strict && total_output - block_start_output > ZSTD_BLOCK_SIZE_MAX {
        return corruption();
    }

    ctx.current_total_output = total_output;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[inline]
fn execute_single_sequence(
    seq: SequenceCommand,
    previous_offsets: &mut [u64; 3],
    window_size: u64,
    dict_content: &[u8],
    litstream: &mut IStream<'_>,
    out: &mut OStream<'_>,
    total_output: &mut usize,
    block_start_output: usize,
    strict: bool,
) -> R<()> {
    let literals_size = copy_literals(seq.literal_length as usize, litstream, out)?;
    *total_output += literals_size;

    let offset = compute_offset(seq, previous_offsets);
    if strict && offset == 0 {
        return corruption();
    }

    let match_length = seq.match_length as usize;
    execute_match_copy(
        window_size,
        dict_content,
        offset,
        match_length,
        *total_output,
        out,
    )?;
    *total_output += match_length;

    if strict && *total_output - block_start_output > ZSTD_BLOCK_SIZE_MAX {
        return corruption();
    }
    Ok(())
}

/// `decode_sequence`: decode a single sequence and update the state
#[inline]
fn decode_sequence(
    states: &mut SequenceStates<'_>,
    reader: &mut BackwardBitReader<'_>,
    last_sequence: bool,
    strict: bool,
) -> R<SequenceCommand> {
    let of_code = fse_peek_symbol(states.of_table, states.of_state);
    let ll_code = fse_peek_symbol(states.ll_table, states.ll_state);
    let ml_code = fse_peek_symbol(states.ml_table, states.ml_state);

    if ll_code > SEQ_MAX_CODES[SeqPart::LiteralLength as usize]
        || ml_code > SEQ_MAX_CODES[SeqPart::MatchLength as usize]
        || (strict && of_code > 31)
    {
        return corruption();
    }

    let offset_value = u64::from(1u32.wrapping_shl(u32::from(of_code)))
        .wrapping_add(reader.read_bits(i32::from(of_code))?) as u32;
    let match_length = (u64::from(SEQ_MATCH_LENGTH_BASELINES[usize::from(ml_code)])
        + reader.read_bits(i32::from(SEQ_MATCH_LENGTH_EXTRA_BITS[usize::from(ml_code)]))?)
        as u32;
    let literal_length = (u64::from(SEQ_LITERAL_LENGTH_BASELINES[usize::from(ll_code)])
        + reader.read_bits(i32::from(
            SEQ_LITERAL_LENGTH_EXTRA_BITS[usize::from(ll_code)],
        ))?) as u32;

    if !last_sequence {
        fse_update_state(states.ll_table, &mut states.ll_state, reader)?;
        fse_update_state(states.ml_table, &mut states.ml_state, reader)?;
        fse_update_state(states.of_table, &mut states.of_state, reader)?;
    }

    Ok(SequenceCommand {
        literal_length,
        match_length,
        offset: offset_value,
    })
}

/// `decode_seq_table`: given a sequence part and table mode, decode the FSE distribution
fn decode_seq_table(
    table: &mut FseDtable,
    input: &mut IStream<'_>,
    part: SeqPart,
    mode: u8,
) -> R<()> {
    const DEFAULT_DISTRIBUTION_ACCURACIES: [i32; 3] = [6, 5, 6];
    const MAX_ACCURACIES: [i32; 3] = [9, 8, 9];
    let default_distributions: [&[i16]; 3] = [
        &SEQ_LITERAL_LENGTH_DEFAULT_DIST,
        &SEQ_OFFSET_DEFAULT_DIST,
        &SEQ_MATCH_LENGTH_DEFAULT_DIST,
    ];

    if mode != 3 {
        table.clear();
    }

    match mode {
        0 => {
            let distribution = default_distributions[part as usize];
            let accuracy_log = DEFAULT_DISTRIBUTION_ACCURACIES[part as usize];
            fse_init_dtable(table, distribution, accuracy_log)?;
        }
        1 => {
            let symb = input.get_read_ptr(1)?[0];
            fse_init_dtable_rle(table, symb);
        }
        2 => {
            fse_decode_header(table, input, MAX_ACCURACIES[part as usize])?;
        }
        _ => {
            if table.symbols.is_empty() {
                return corruption();
            }
        }
    }
    Ok(())
}

/******* SEQUENCE EXECUTION ***************************************************/

/// `copy_literals`
#[inline]
fn copy_literals(
    literal_length: usize,
    litstream: &mut IStream<'_>,
    out: &mut OStream<'_>,
) -> R<usize> {
    if literal_length > litstream.istream_len() {
        return corruption();
    }

    out.reserve_check(literal_length)?;
    let read_ptr = litstream.get_read_ptr(literal_length)?;
    out.extend_slice(read_ptr)?;

    Ok(literal_length)
}

/// `compute_offset`
#[inline]
fn compute_offset(seq: SequenceCommand, offset_hist: &mut [u64; 3]) -> u64 {
    let offset;
    if seq.offset <= 3 {
        let mut idx = seq.offset.wrapping_sub(1);
        if seq.literal_length == 0 {
            idx = idx.wrapping_add(1);
        }

        if idx == 0 {
            offset = offset_hist[0];
        } else {
            offset = if idx < 3 {
                offset_hist[idx as usize]
            } else {
                offset_hist[0].wrapping_sub(1)
            };

            if idx > 1 {
                offset_hist[2] = offset_hist[1];
            }
            offset_hist[1] = offset_hist[0];
            offset_hist[0] = offset;
        }
    } else {
        offset = u64::from(seq.offset - 3);

        offset_hist[2] = offset_hist[1];
        offset_hist[1] = offset_hist[0];
        offset_hist[0] = offset;
    }
    offset
}

/// `execute_match_copy`
#[inline]
fn execute_match_copy(
    window_size: u64,
    dict_content: &[u8],
    offset: u64,
    mut match_length: usize,
    total_output: usize,
    out: &mut OStream<'_>,
) -> R<()> {
    out.reserve_check(match_length)?;
    if total_output as u64 <= window_size {
        if offset > (total_output + dict_content.len()) as u64 {
            return corruption();
        }

        if offset > total_output as u64 {
            let dict_copy = (offset as usize - total_output).min(match_length);
            let dict_offset = dict_content.len() - (offset as usize - total_output);

            out.extend_slice(&dict_content[dict_offset..dict_offset + dict_copy])?;
            match_length -= dict_copy;
        }
    } else if offset > window_size {
        return corruption();
    }

    out.copy_periodic(offset as usize, match_length)
}

/******* OUTPUT SIZE & DICTIONARY ID INSPECTION *******************************/

/// The size a frame's header says it decompresses to, or `None` when the header does not say
/// (`ZSTD_get_decompressed_size`, which gives -1 then).
///
/// # Errors
///
/// A [`DecompressError`] if the frame's header is not valid or is cut short.
#[must_use = "returns the header's pledged content size without modifying the slice"]
pub fn decompressed_size(frame: &[u8]) -> Result<Option<u64>, DecompressError> {
    let mut input = IStream::new(frame);

    let magic_number = input.read_bits(32)? as u32;

    if magic_number == ZSTD_MAGIC_NUMBER {
        let header = parse_frame_header(&mut input)?;
        Ok(header.frame_content_size)
    } else {
        error(
            DecompressErrorKind::InvalidFrameMagic,
            "ZSTD frame magic number did not match",
        )
    }
}

/// The dictionary ID recorded in a Zstandard frame's header (`ZSTD_getDictID_fromFrame`), or
/// `None` if the frame does not specify a dictionary (or is a skippable frame).
///
/// # Errors
///
/// Returns a [`DecompressError`] if `frame` does not start with a valid Zstandard (or
/// skippable) frame header or is truncated.
#[must_use = "returns the frame header's dictionary ID without modifying the slice"]
pub fn frame_dict_id(frame: &[u8]) -> Result<Option<u32>, DecompressError> {
    let mut input = IStream::new(frame);
    let magic_number = input.read_bits(32)? as u32;

    if magic_number == ZSTD_MAGIC_NUMBER {
        let header = parse_frame_header(&mut input)?;
        Ok((header.dictionary_id != 0).then_some(header.dictionary_id))
    } else if (SKIPPABLE_MAGIC_LOW..=SKIPPABLE_MAGIC_HIGH).contains(&magic_number) {
        let _skip_len = input.read_bits(32)?;
        Ok(None)
    } else {
        error(
            DecompressErrorKind::InvalidFrameMagic,
            "ZSTD frame magic number did not match",
        )
    }
}

/******* DICTIONARY PARSING ***************************************************/

impl Dictionary {
    /// A dictionary out of its bytes: `parse_dictionary`. Bytes that do not begin as a
    /// dictionary with tables does are a dictionary of content alone.
    ///
    /// # Errors
    ///
    /// A [`DecompressError`] if the bytes begin as a dictionary but its tables are not
    /// valid, or if `src` is shorter than 8 bytes.
    pub fn parse(src: &[u8]) -> Result<Dictionary, DecompressError> {
        let mut dict = Dictionary::default();
        if src.len() < 8 {
            return error(
                DecompressErrorKind::InvalidDictionary,
                "Dictionary size cannot be less than 8 bytes",
            );
        }

        let mut input = IStream::new(src);

        let magic_number = input.read_bits(32)? as u32;
        if magic_number != 0xEC30_A437 {
            // raw content dict
            input.rewind_bits(32)?;
            init_dictionary_content(&mut dict, &mut input)?;
            return Ok(dict);
        }

        dict.id = input.read_bits(32)? as u32;

        let mut weights_buf = Vec::new();
        decode_huf_table(&mut dict.literals_dtable, &mut weights_buf, &mut input)?;
        decode_seq_table(&mut dict.of_dtable, &mut input, SeqPart::Offset, 2)?;
        decode_seq_table(&mut dict.ml_dtable, &mut input, SeqPart::MatchLength, 2)?;
        decode_seq_table(&mut dict.ll_dtable, &mut input, SeqPart::LiteralLength, 2)?;

        dict.previous_offsets[0] = input.read_bits(32)?;
        dict.previous_offsets[1] = input.read_bits(32)?;
        dict.previous_offsets[2] = input.read_bits(32)?;

        for offset in dict.previous_offsets {
            if offset > src.len() as u64 {
                return error(
                    DecompressErrorKind::InvalidDictionary,
                    "Dictionary corrupted",
                );
            }
        }

        init_dictionary_content(&mut dict, &mut input)?;
        Ok(dict)
    }

    /// The dictionary's 32-bit identifier (`ZSTD_getDictID_fromDDict`), or `0` for a
    /// raw-content or empty dictionary.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// The raw content portion of the dictionary used for backreferences.
    #[must_use]
    pub fn as_content(&self) -> &[u8] {
        &self.content
    }
}

/// `init_dictionary_content`
fn init_dictionary_content(dict: &mut Dictionary, input: &mut IStream<'_>) -> R<()> {
    dict.content = input.get_read_ptr(input.istream_len())?.to_vec();
    dict.has_content = true;
    Ok(())
}

/// `frame_context_apply_dict`
fn frame_context_apply_dict(ctx: &mut FrameContext, dict: &Dictionary) -> R<()> {
    if !dict.has_content {
        return Ok(());
    }

    if ctx.header.dictionary_id != 0 && ctx.header.dictionary_id != dict.id {
        return error(
            DecompressErrorKind::DictionaryMismatch,
            "Wrong dictionary provided",
        );
    }

    if dict.id != 0 {
        ctx.literals_dtable.copy_from_dtable(&dict.literals_dtable);
        ctx.ll_dtable.copy_from_dtable(&dict.ll_dtable);
        ctx.of_dtable.copy_from_dtable(&dict.of_dtable);
        ctx.ml_dtable.copy_from_dtable(&dict.ml_dtable);
        ctx.previous_offsets = dict.previous_offsets;
    }
    Ok(())
}

/******* HUFFMAN PRIMITIVES ***************************************************/

/// `HUF_decode_symbol`: decode a single symbol and read in enough bits to refresh the state
#[inline]
fn huf_decode_symbol(
    dtable: &HufDtable,
    state: &mut u16,
    reader: &mut BackwardBitReader<'_>,
) -> R<u8> {
    let idx = usize::from(*state);
    let symb = dtable.symbols[idx];
    let bits = dtable.num_bits[idx];
    let rest = reader.read_bits(i32::from(bits))? as u16;
    *state = ((u32::from(*state) << bits).wrapping_add(u32::from(rest))
        & ((1u32 << dtable.max_bits) - 1)) as u16;

    Ok(symb)
}

/// `HUF_init_state`: read in a full state's worth of bits to initialize it
#[inline]
fn huf_init_state(dtable: &HufDtable, reader: &mut BackwardBitReader<'_>) -> R<u16> {
    let bits = dtable.max_bits;
    Ok(reader.read_bits(bits)? as u16)
}

/// `HUF_decompress_1stream`: decompresses a single Huffman stream, returns the number of
/// bytes decoded.
fn huf_decompress_1stream(
    dtable: &HufDtable,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
) -> R<usize> {
    let len = input.istream_len();
    if len == 0 {
        return inp_size();
    }
    let src = input.get_read_ptr(len)?;

    let padding = 8 - highest_set_bit(u64::from(src[len - 1]));
    let bit_offset = (len * 8) as i64 - i64::from(padding);
    let mut reader = BackwardBitReader::new(src, bit_offset);

    let mut state = huf_init_state(dtable, &mut reader)?;
    let end_offset = -i64::from(dtable.max_bits);

    let mut symbols_written = 0;
    while reader.bit_offset > end_offset {
        let symb = huf_decode_symbol(dtable, &mut state, &mut reader)?;
        out.write_byte(symb)?;
        symbols_written += 1;
    }

    if reader.bit_offset != end_offset {
        return corruption();
    }

    Ok(symbols_written)
}

/// `HUF_decompress_4stream`
fn huf_decompress_4stream(
    dtable: &HufDtable,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
) -> R<usize> {
    let csize1 = input.read_bits(16)? as usize;
    let csize2 = input.read_bits(16)? as usize;
    let csize3 = input.read_bits(16)? as usize;

    let mut in1 = input.make_sub_istream(csize1)?;
    let mut in2 = input.make_sub_istream(csize2)?;
    let mut in3 = input.make_sub_istream(csize3)?;
    let mut in4 = input.make_sub_istream(input.istream_len())?;

    let mut total_output = 0;
    total_output += huf_decompress_1stream(dtable, out, &mut in1)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in2)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in3)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in4)?;

    Ok(total_output)
}

/// `HUF_init_dtable`
fn huf_init_dtable(table: &mut HufDtable, bits: &[u8]) -> R<()> {
    let num_symbs = bits.len();
    if num_symbs > HUF_MAX_SYMBS {
        return error(
            DecompressErrorKind::CorruptedInput,
            "Too many symbols for Huffman",
        );
    }

    let mut max_bits = 0usize;
    let mut rank_count = [0u16; HUF_MAX_BITS + 1];

    for &b in bits {
        if usize::from(b) > HUF_MAX_BITS {
            return error(
                DecompressErrorKind::CorruptedInput,
                "Huffman table depth too large",
            );
        }
        max_bits = max_bits.max(usize::from(b));
        rank_count[usize::from(b)] += 1;
    }

    let table_size = 1usize << max_bits;
    table.symbols.clear();
    table.symbols.resize(table_size, 0);
    table.num_bits.clear();
    table.num_bits.resize(table_size, 0);
    table.max_bits = max_bits as i32;

    let mut rank_idx = [0u32; HUF_MAX_BITS + 1];
    rank_idx[max_bits] = 0;
    for i in (1..=max_bits).rev() {
        rank_idx[i - 1] = rank_idx[i] + u32::from(rank_count[i]) * (1 << (max_bits - i));
        let (from, to) = (rank_idx[i] as usize, rank_idx[i - 1] as usize);
        if to > table_size {
            return corruption();
        }
        table.num_bits[from..to].fill(i as u8);
    }

    if rank_idx[0] as usize != table_size {
        return corruption();
    }

    for (i, &b) in bits.iter().enumerate() {
        if b != 0 {
            let code = rank_idx[usize::from(b)] as usize;
            let len = 1usize << (max_bits - usize::from(b));
            table.symbols[code..code + len].fill(i as u8);
            rank_idx[usize::from(b)] += len as u32;
        }
    }
    Ok(())
}

/// `HUF_init_dtable_usingweights`
fn huf_init_dtable_usingweights(
    table: &mut HufDtable,
    weights: &[u8; HUF_MAX_SYMBS],
    num_symbs: usize,
) -> R<()> {
    if num_symbs + 1 > HUF_MAX_SYMBS {
        return error(
            DecompressErrorKind::CorruptedInput,
            "Too many symbols for Huffman",
        );
    }

    let mut bits = [0u8; HUF_MAX_SYMBS];

    let mut weight_sum = 0u64;
    for &weight in &weights[..num_symbs] {
        if usize::from(weight) > HUF_MAX_BITS {
            return corruption();
        }
        weight_sum += if weight > 0 { 1u64 << (weight - 1) } else { 0 };
    }

    let max_bits = highest_set_bit(weight_sum) + 1;
    let left_over = (1u64 << max_bits) - weight_sum;
    if left_over & (left_over - 1) != 0 {
        return corruption();
    }

    let last_weight = highest_set_bit(left_over) + 1;

    for i in 0..num_symbs {
        bits[i] = if weights[i] > 0 {
            (max_bits + 1 - i32::from(weights[i])) as u8
        } else {
            0
        };
    }
    bits[num_symbs] = (max_bits + 1 - last_weight) as u8;

    huf_init_dtable(table, &bits[..=num_symbs])
}

/******* FSE PRIMITIVES *******************************************************/

/// `FSE_peek_symbol`: return the symbol for the current state
#[inline]
fn fse_peek_symbol(dtable: &FseDtable, state: u16) -> u8 {
    dtable.symbols[usize::from(state)]
}

/// `FSE_update_state`: read the number of bits necessary to update state, update, and shift
/// offset back to reflect the bits read
#[inline]
fn fse_update_state(
    dtable: &FseDtable,
    state: &mut u16,
    reader: &mut BackwardBitReader<'_>,
) -> R<()> {
    let idx = usize::from(*state);
    let bits = dtable.num_bits[idx];
    let rest = reader.read_bits(i32::from(bits))? as u16;
    *state = dtable.new_state_base[idx].wrapping_add(rest);
    Ok(())
}

/// `FSE_decode_symbol`: decodes a single FSE symbol and updates the offset
#[inline]
fn fse_decode_symbol(
    dtable: &FseDtable,
    state: &mut u16,
    reader: &mut BackwardBitReader<'_>,
) -> R<u8> {
    let symb = fse_peek_symbol(dtable, *state);
    fse_update_state(dtable, state, reader)?;
    Ok(symb)
}

/// `FSE_init_state`: read bits from the stream to initialize the state and shift offset back
#[inline]
fn fse_init_state(dtable: &FseDtable, reader: &mut BackwardBitReader<'_>) -> R<u16> {
    let bits = dtable.accuracy_log;
    Ok(reader.read_bits(bits)? as u16)
}

/// `FSE_decompress_interleaved2`
fn fse_decompress_interleaved2(
    dtable: &FseDtable,
    out: &mut OStream<'_>,
    input: &mut IStream<'_>,
) -> R<usize> {
    let len = input.istream_len();
    if len == 0 {
        return inp_size();
    }
    let src = input.get_read_ptr(len)?;

    let padding = 8 - highest_set_bit(u64::from(src[len - 1]));
    let offset = (len * 8) as i64 - i64::from(padding);
    let mut reader = BackwardBitReader::new(src, offset);

    let mut state1 = fse_init_state(dtable, &mut reader)?;
    let mut state2 = fse_init_state(dtable, &mut reader)?;

    let mut symbols_written = 0;
    loop {
        let symb = fse_decode_symbol(dtable, &mut state1, &mut reader)?;
        out.write_byte(symb)?;
        symbols_written += 1;
        if reader.bit_offset < 0 {
            out.write_byte(fse_peek_symbol(dtable, state2))?;
            symbols_written += 1;
            break;
        }

        let symb = fse_decode_symbol(dtable, &mut state2, &mut reader)?;
        out.write_byte(symb)?;
        symbols_written += 1;
        if reader.bit_offset < 0 {
            out.write_byte(fse_peek_symbol(dtable, state1))?;
            symbols_written += 1;
            break;
        }
    }

    Ok(symbols_written)
}

/// `FSE_init_dtable`: initialize a decoding table using normalized frequencies.
fn fse_init_dtable(dtable: &mut FseDtable, norm_freqs: &[i16], accuracy_log: i32) -> R<()> {
    let num_symbs = norm_freqs.len();
    if accuracy_log > FSE_MAX_ACCURACY_LOG {
        return error(
            DecompressErrorKind::CorruptedInput,
            "FSE accuracy too large",
        );
    }
    if num_symbs > FSE_MAX_SYMBS {
        return error(
            DecompressErrorKind::CorruptedInput,
            "Too many symbols for FSE",
        );
    }

    let size = 1usize << accuracy_log;
    dtable.symbols.clear();
    dtable.symbols.resize(size, 0);
    dtable.num_bits.clear();
    dtable.num_bits.resize(size, 0);
    dtable.new_state_base.clear();
    dtable.new_state_base.resize(size, 0);
    dtable.accuracy_log = accuracy_log;

    let mut state_desc = [0u16; FSE_MAX_SYMBS];

    let mut high_threshold = size;
    for (s, &freq) in norm_freqs.iter().enumerate() {
        if freq == -1 {
            if high_threshold == 0 {
                return corruption();
            }
            high_threshold -= 1;
            dtable.symbols[high_threshold] = s as u8;
            state_desc[s] = 1;
        }
    }

    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos = 0usize;
    for (s, &freq) in norm_freqs.iter().enumerate() {
        if freq <= 0 {
            continue;
        }

        state_desc[s] = freq as u16;

        for _ in 0..freq {
            dtable.symbols[pos] = s as u8;
            loop {
                pos = (pos + step) & mask;
                if pos < high_threshold {
                    break;
                }
                if high_threshold == 0 {
                    return corruption();
                }
            }
        }
    }
    if pos != 0 {
        return corruption();
    }

    for i in 0..size {
        let symbol = usize::from(dtable.symbols[i]);
        let next_state_desc = state_desc[symbol];
        state_desc[symbol] = state_desc[symbol].wrapping_add(1);
        if next_state_desc == 0 {
            return corruption();
        }
        dtable.num_bits[i] = (accuracy_log - highest_set_bit(u64::from(next_state_desc))) as u8;
        dtable.new_state_base[i] =
            ((u32::from(next_state_desc) << dtable.num_bits[i]) as u16).wrapping_sub(size as u16);
    }
    Ok(())
}

/// `FSE_decode_header`
fn fse_decode_header(
    dtable: &mut FseDtable,
    input: &mut IStream<'_>,
    max_accuracy_log: i32,
) -> R<()> {
    if max_accuracy_log > FSE_MAX_ACCURACY_LOG {
        return error(
            DecompressErrorKind::CorruptedInput,
            "FSE accuracy too large",
        );
    }

    let accuracy_log = 5 + input.read_bits(4)? as i32;
    if accuracy_log > max_accuracy_log {
        return error(
            DecompressErrorKind::CorruptedInput,
            "FSE accuracy too large",
        );
    }

    let mut remaining = 1i32 << accuracy_log;
    let mut frequencies = [0i16; FSE_MAX_SYMBS];

    let mut symb = 0;
    while remaining > 0 && symb < FSE_MAX_SYMBS {
        let bits = highest_set_bit((remaining + 1) as u64) + 1;

        let mut val = input.read_bits(bits)? as u16;

        let lower_mask = (1u16 << (bits - 1)) - 1;
        let threshold = ((1u32 << bits) - 1 - (remaining + 1) as u32) as u16;

        if (val & lower_mask) < threshold {
            input.rewind_bits(1)?;
            val &= lower_mask;
        } else if val > lower_mask {
            val = val.wrapping_sub(threshold);
        }

        let proba = (val as i16).wrapping_sub(1);
        remaining -= i32::from(proba).abs();

        frequencies[symb] = proba;
        symb += 1;

        if proba == 0 {
            let mut repeat = input.read_bits(2)?;

            loop {
                for _ in 0..repeat {
                    if symb >= FSE_MAX_SYMBS {
                        break;
                    }
                    frequencies[symb] = 0;
                    symb += 1;
                }
                if repeat == 3 {
                    repeat = input.read_bits(2)?;
                } else {
                    break;
                }
            }
        }
    }
    input.align_stream()?;

    if remaining != 0 || symb >= FSE_MAX_SYMBS {
        return corruption();
    }

    fse_init_dtable(dtable, &frequencies[..symb], accuracy_log)
}

/// `FSE_init_dtable_rle`
fn fse_init_dtable_rle(dtable: &mut FseDtable, symb: u8) {
    dtable.symbols.clear();
    dtable.symbols.push(symb);
    dtable.num_bits.clear();
    dtable.num_bits.push(0);
    dtable.new_state_base.clear();
    dtable.new_state_base.push(0);
    dtable.accuracy_log = 0;
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn bits_are_read_both_ways() {
        let bytes = [0b1010_0110, 0b0000_1111, 0xff];
        assert_eq!(read_bits_le(&bytes, 3, 0), Ok(0b110));
        assert_eq!(read_bits_le(&bytes, 7, 3), Ok(0b111_0100));
        assert_eq!(read_bits_le(&bytes, 24, 0), Ok(0x00ff_0fa6));
        assert_eq!(read_bits_le(&bytes, 0, 5), Ok(0));
        assert!(read_bits_le(&bytes, 65, 0).is_err());
        // From the end, and off the front: what is not there is zeros.
        let mut offset = 16;
        assert_eq!(stream_read_bits(&bytes, 4, &mut offset), Ok(0));
        assert_eq!(stream_read_bits(&bytes, 6, &mut offset), Ok(0b11_1110));
        assert_eq!(stream_read_bits(&bytes, 8, &mut offset), Ok(0b1001_1000));
        assert_eq!(offset, -2);
        assert_eq!(stream_read_bits(&bytes, 3, &mut offset), Ok(0));
        // A stream forward, backed up a bit.
        let mut input = IStream::new(&bytes);
        assert_eq!(input.read_bits(4), Ok(0b0110));
        input.rewind_bits(1).unwrap();
        assert_eq!(input.read_bits(5), Ok(0b10100));
        assert_eq!((input.ptr, input.bit_offset, input.len), (1, 0, 2));
        input.rewind_bits(1).unwrap();
        assert_eq!((input.ptr, input.bit_offset, input.len), (0, 7, 3));
        assert_eq!(input.read_bits(2), Ok(0b11));
        assert!(input.get_read_ptr(1).is_err());
        assert_eq!(highest_set_bit(0), -1);
        assert_eq!(highest_set_bit(1), 0);
        assert_eq!(highest_set_bit(0x8000), 15);
    }

    #[test]
    fn frames_by_hand() {
        // A frame of one raw block, with its size in the header.
        let raw = [
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 0x29, 0, 0, b'h', b'e', b'l', b'l', b'o',
        ];
        assert_eq!(decompress(&raw, 5).as_deref(), Ok(&b"hello"[..]));
        assert_eq!(decompressed_size(&raw), Ok(Some(5)));
        assert_eq!(
            decompress(&raw, 4),
            Err(DecompressError::new(
                DecompressErrorKind::OutputTooSmall,
                "Output buffer too small for output",
            ))
        );
        assert_eq!(
            decompress(&raw[..12], 5),
            Err(DecompressError::new(
                DecompressErrorKind::UnexpectedEof,
                "Input buffer smaller than it should be or input is corrupted",
            ))
        );
        // One block of a byte repeated, with a window and no size.
        let rle = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x53, 0, 0, b'z'];
        assert_eq!(decompress(&rle, 100).as_deref(), Ok(&[b'z'; 10][..]));
        assert_eq!(decompressed_size(&rle), Ok(None));
        // A compressed block: raw literals "abc", and one sequence that copies them twice
        // more (literal length 3, match length 6, offset 3: the predefined codes 3, 3 and 2,
        // with two extra bits for the offset).
        let state = |distribution: &[i16], accuracy_log, code: u8| {
            let mut table = FseDtable::default();
            fse_init_dtable(&mut table, distribution, accuracy_log).unwrap();
            table.symbols.iter().position(|&s| s == code).unwrap() as u32
        };
        let ll = state(&SEQ_LITERAL_LENGTH_DEFAULT_DIST, 6, 3);
        let of = state(&SEQ_OFFSET_DEFAULT_DIST, 5, 2);
        let ml = state(&SEQ_MATCH_LENGTH_DEFAULT_DIST, 6, 3);
        let bits = (1 << 19) | (ll << 13) | (of << 8) | (ml << 2) | 0b10;
        let mut packed = vec![
            0x28, 0xb5, 0x2f, 0xfd, 0x20, 9, 0x4d, 0, 0, 0x18, b'a', b'b', b'c', 1, 0,
        ];
        packed.extend_from_slice(&bits.to_le_bytes()[..3]);
        assert_eq!(decompress(&packed, 9).as_deref(), Ok(&b"abcabcabc"[..]));
        assert_eq!(
            decompress(&packed, 8),
            Err(DecompressError::new(
                DecompressErrorKind::OutputTooSmall,
                "Output buffer too small for output",
            ))
        );
        // The same with one bit more than the sequence takes.
        let mut longer = packed.clone();
        longer[15..18].copy_from_slice(&(((bits & !(1 << 19)) | (1 << 20)).to_le_bytes()[..3]));
        assert_eq!(
            decompress(&longer, 9),
            Err(DecompressError::new(
                DecompressErrorKind::CorruptedInput,
                "Corruption detected while decompressing",
            ))
        );
        // No frame, a reserved bit, a block of the kind there is none of.
        assert_eq!(
            decompress(b"not zstd", 10),
            Err(DecompressError::new(
                DecompressErrorKind::InvalidFrameMagic,
                "Tried to decode non-ZSTD frame",
            ))
        );
        assert_eq!(
            decompressed_size(b"not zstd"),
            Err(DecompressError::new(
                DecompressErrorKind::InvalidFrameMagic,
                "ZSTD frame magic number did not match",
            ))
        );
        assert_eq!(
            decompress(&[0x28, 0xb5, 0x2f, 0xfd, 0x28, 0], 10),
            Err(DecompressError::new(
                DecompressErrorKind::CorruptedInput,
                "Corruption detected while decompressing",
            ))
        );
        assert_eq!(
            decompress(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 0x07, 0, 0], 10),
            Err(DecompressError::new(
                DecompressErrorKind::CorruptedInput,
                "Corruption detected while decompressing",
            ))
        );
        assert_eq!(
            decompress(&[], 10),
            Err(DecompressError::new(
                DecompressErrorKind::UnexpectedEof,
                "Input buffer smaller than it should be or input is corrupted",
            ))
        );
    }

    #[test]
    fn huffman_tables_from_weights() {
        let mut weights = [0u8; HUF_MAX_SYMBS];
        weights[0] = 1;
        weights[1] = 1;
        let mut table = HufDtable::default();
        huf_init_dtable_usingweights(&mut table, &weights, 2).unwrap();
        assert_eq!(
            (table.max_bits, &table.symbols[..], &table.num_bits[..]),
            (2, &[0u8, 1, 2, 2][..], &[2u8, 2, 1, 1][..])
        );
        weights[0] = 3;
        assert!(huf_init_dtable_usingweights(&mut table, &weights, 2).is_err());
        assert!(huf_init_dtable_usingweights(&mut table, &[0; HUF_MAX_SYMBS], 4).is_err());
        assert_eq!(
            huf_init_dtable_usingweights(&mut table, &weights, 256).err(),
            Some(DecompressError::new(
                DecompressErrorKind::CorruptedInput,
                "Too many symbols for Huffman",
            ))
        );
        assert_eq!(
            huf_init_dtable(&mut table, &[17]).err(),
            Some(DecompressError::new(
                DecompressErrorKind::CorruptedInput,
                "Huffman table depth too large",
            ))
        );
    }

    #[test]
    fn the_predefined_tables_are_whole() {
        for (distribution, accuracy_log) in [
            (&SEQ_LITERAL_LENGTH_DEFAULT_DIST[..], 6),
            (&SEQ_OFFSET_DEFAULT_DIST[..], 5),
            (&SEQ_MATCH_LENGTH_DEFAULT_DIST[..], 6),
        ] {
            let mut table = FseDtable::default();
            fse_init_dtable(&mut table, distribution, accuracy_log).unwrap();
            let size = 1usize << accuracy_log;
            assert_eq!(table.symbols.len(), size);
            for i in 0..size {
                assert!(usize::from(table.new_state_base[i]) + (1 << table.num_bits[i]) <= size);
            }
            for (symbol, &share) in distribution.iter().enumerate() {
                assert_eq!(
                    table
                        .symbols
                        .iter()
                        .filter(|&&s| usize::from(s) == symbol)
                        .count(),
                    share.unsigned_abs() as usize
                );
            }
        }
        let mut table = FseDtable::default();
        assert!(fse_init_dtable(&mut table, &[16, 15], 5).is_err());
        assert!(fse_init_dtable(&mut table, &[1], 16).is_err());
    }
}
