//! Streaming `std::io::{Read, Write}` adapters for Zstandard compression and decompression.
//!
//! - [`Encoder`] wraps any [`Write`] sink and compresses bytes written to it
//!   into a Zstandard frame. Call [`Encoder::finish`] when all data has been written to flush
//!   the final block (and optional `XXH64` content checksum) and recover the inner writer.
//! - [`Decoder`] wraps any [`Read`] source and decompresses Zstandard frames
//!   block by block, handling concatenated frames and skippable frames with bounded memory.
//!
//! ```
//! use std::io::{Read, Write};
//! use zstd_nrp::Level;
//! use zstd_nrp::io::{Decoder, Encoder};
//!
//! let input = b"streaming zstandard compression in pure safe Rust! ".repeat(200);
//!
//! let mut encoder = Encoder::new(Vec::new(), Level::DEFAULT);
//! encoder.write_all(&input).unwrap();
//! let compressed = encoder.finish().unwrap();
//!
//! let mut decoder = Decoder::new(&compressed[..]);
//! let mut output = Vec::new();
//! decoder.read_to_end(&mut output).unwrap();
//! assert_eq!(output, input);
//! ```

use core::fmt;
use std::io::{self, Read, Write};

use super::Level;
use super::common::{write_le24, write_le32};
use super::zstd_compress::{CCtx, CompressOptions, Compressor, compress_bound};
use super::zstd_decompress::{
    DecompressError, DecompressErrorKind, DecompressOptions, Dictionary, RawBlock,
    SKIPPABLE_MAGIC_HIGH, SKIPPABLE_MAGIC_LOW, StreamFrameDecoder, ZSTD_BLOCK_SIZE_MAX,
    ZSTD_MAGIC_NUMBER, parse_frame_header_from_slice,
};
use super::zstd_ldm::Xxh64State;

/// Chunk threshold before [`Encoder`] switches from one-shot framing to multi-chunk block
/// streaming (2 MiB).
const STREAM_CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Default upper bound on window memory retained by [`Decoder`] (256 MiB, matching level 22's
/// 128 MiB window with headroom).
const DEFAULT_MAX_WINDOW_SIZE: usize = 256 * 1024 * 1024;

/// Streaming Zstandard compressor implementing [`std::io::Write`].
///
/// If all writes fit under 2 MiB without an intermediate [`Write::flush`], [`Encoder::finish`]
/// emits a single frame identical to [`compress_with_options`](crate::compress_with_options)
/// (including `Frame_Content_Size` when enabled). Larger streams or mid-stream flushes emit
/// non-final blocks incrementally so memory stays bounded.
pub struct Encoder<W: Write> {
    writer: Option<W>,
    options: CompressOptions,
    buf: Vec<u8>,
    out_buf: Vec<u8>,
    one_shot: Compressor,
    stream_cctx: Option<CCtx>,
    xxh64: Xxh64State,
    finished: bool,
}

impl<W: Write + fmt::Debug> fmt::Debug for Encoder<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("writer", &self.writer)
            .field("options", &self.options)
            .field("buffered_bytes", &self.buf.len())
            .field("streaming", &self.stream_cctx.is_some())
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<W: Write> Encoder<W> {
    /// Creates a new [`Encoder`] writing a Zstandard frame at `level` to `writer` (with
    /// `XXH64` content checksum enabled by default for streaming integrity, or customize via
    /// [`Encoder::with_options`]).
    #[must_use]
    pub fn new(writer: W, level: Level) -> Self {
        Self::with_options(writer, CompressOptions::new(level))
    }

    /// Creates a new [`Encoder`] with custom [`CompressOptions`].
    #[must_use]
    pub fn with_options(writer: W, options: CompressOptions) -> Self {
        Encoder {
            writer: Some(writer),
            options,
            buf: Vec::new(),
            out_buf: Vec::new(),
            one_shot: Compressor::new(),
            stream_cctx: None,
            xxh64: Xxh64State::new(0),
            finished: false,
        }
    }

    /// Shared reference to the underlying writer.
    ///
    /// # Panics
    ///
    /// Panics only if called after [`Encoder::finish`] has already taken the writer (which
    /// consumes `self`).
    #[must_use]
    pub fn get_ref(&self) -> &W {
        self.writer
            .as_ref()
            .expect("writer is present until finish")
    }

    /// Mutable reference to the underlying writer.
    ///
    /// # Panics
    ///
    /// Panics only if called after [`Encoder::finish`] has already taken the writer (which
    /// consumes `self`).
    pub fn get_mut(&mut self) -> &mut W {
        self.writer
            .as_mut()
            .expect("writer is present until finish")
    }

    fn flush_chunk(&mut self, is_final: bool) -> io::Result<()> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cannot flush a finished zstd Encoder",
            ));
        };
        let mut header_written = 0usize;
        if self.stream_cctx.is_none() {
            let cctx = CCtx::new_streaming(self.options.level);
            self.out_buf.resize(18, 0);
            header_written = cctx
                .write_frame_header(&mut self.out_buf, None, self.options.checksum)
                .map_err(|_| io::Error::other("failed to write zstd frame header"))?;
            writer.write_all(&self.out_buf[..header_written])?;
            self.stream_cctx = Some(cctx);
        }

        let cctx = self
            .stream_cctx
            .as_mut()
            .ok_or_else(|| io::Error::other("streaming compressor state unexpectedly missing"))?;
        if !self.buf.is_empty() {
            if self.options.checksum {
                self.xxh64.update(&self.buf);
            }
            cctx.reset_match_state_for_chunk();
            let bound = compress_bound(self.buf.len()) + 16;
            self.out_buf.resize(bound, 0);
            let c_size = cctx
                .compress_frame_chunk(&mut self.out_buf, &self.buf, is_final)
                .map_err(|_| io::Error::other("failed to compress zstd stream chunk"))?;
            cctx.record_chunk(self.buf.len(), c_size + header_written);
            writer.write_all(&self.out_buf[..c_size])?;
            self.buf.clear();
        } else if is_final {
            let mut epilogue = [0u8; 3];
            write_le24(&mut epilogue, 0, 1); // last_block = 1, BT_RAW = 0, size = 0
            writer.write_all(&epilogue)?;
        }

        if is_final && self.options.checksum {
            let mut trailer = [0u8; 4];
            write_le32(&mut trailer, 0, self.xxh64.finish() as u32);
            writer.write_all(&trailer)?;
        }
        Ok(())
    }

    /// Finishes the Zstandard frame without consuming `self`. Subsequent writes after
    /// `try_finish` return an error.
    ///
    /// # Errors
    ///
    /// Propagates any [`io::Error`] from writing the final block or checksum to the inner
    /// writer.
    pub fn try_finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if self.stream_cctx.is_none() {
            let bound = compress_bound(self.buf.len());
            self.out_buf.resize(bound, 0);
            let size = self
                .one_shot
                .compress_into_with_options(&self.buf, &mut self.out_buf, self.options)
                .map_err(io::Error::from)?;
            self.buf.clear();
            let Some(writer) = self.writer.as_mut() else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "cannot finish a zstd Encoder whose writer was already taken",
                ));
            };
            writer.write_all(&self.out_buf[..size])?;
        } else {
            self.flush_chunk(true)?;
        }
        self.finished = true;
        Ok(())
    }

    /// Completes the Zstandard frame, writes all remaining compressed blocks and any
    /// configured checksum, and returns the underlying writer.
    ///
    /// # Errors
    ///
    /// Propagates any [`io::Error`] encountered while writing the final frame bytes.
    pub fn finish(mut self) -> io::Result<W> {
        self.try_finish()?;
        self.writer
            .take()
            .ok_or_else(|| io::Error::other("zstd Encoder writer already taken"))
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cannot write to a finished zstd Encoder",
            ));
        }
        let total = data.len();
        while !data.is_empty() {
            let space = STREAM_CHUNK_SIZE - self.buf.len();
            let take = data.len().min(space);
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == STREAM_CHUNK_SIZE {
                self.flush_chunk(false)?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.finished && !self.buf.is_empty() {
            self.flush_chunk(false)?;
        }
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cannot flush a finished zstd Encoder",
            ));
        };
        writer.flush()
    }
}

impl<W: Write> Drop for Encoder<W> {
    fn drop(&mut self) {
        if !self.finished && self.writer.is_some() {
            let _ = self.try_finish();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    FrameStart,
    InFrame,
    Done,
}

/// Streaming Zstandard decompressor implementing [`std::io::Read`].
///
/// Decodes Zstandard frames block by block on demand, verifying `XXH64` content checksums,
/// concatenating multi-frame streams, and skipping skippable frames (`0x184D2A50..=0x184D2A5F`)
/// by default while keeping memory bounded to the active frame's window.
pub struct Decoder<R: Read> {
    reader: R,
    options: DecompressOptions,
    dict: Dictionary,
    frame: StreamFrameDecoder,
    state: DecoderState,
    out_buf: Vec<u8>,
    read_pos: usize,
    block_buf: Vec<u8>,
    xxh64: Xxh64State,
    hash_pos: usize,
    max_window_size: usize,
}

impl<R: Read + fmt::Debug> fmt::Debug for Decoder<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("reader", &self.reader)
            .field("options", &self.options)
            .field("buffered_output", &(self.out_buf.len() - self.read_pos))
            .field("max_window_size", &self.max_window_size)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Decoder<R> {
    /// Creates a new streaming [`Decoder`] over `reader`, enabling `XXH64` checksum
    /// verification, concatenated multi-frame decoding, and skippable frames by default.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, DecompressOptions::new().with_multi_frame(true))
    }

    /// Creates a new streaming [`Decoder`] with custom [`DecompressOptions`].
    #[must_use]
    pub fn with_options(reader: R, options: DecompressOptions) -> Self {
        Self::with_options_and_dictionary(reader, options, Dictionary::default())
    }

    /// Creates a new streaming [`Decoder`] using a parsed [`Dictionary`].
    #[must_use]
    pub fn with_dictionary(reader: R, dictionary: Dictionary) -> Self {
        Self::with_options_and_dictionary(
            reader,
            DecompressOptions::new().with_multi_frame(true),
            dictionary,
        )
    }

    /// Creates a new streaming [`Decoder`] with custom [`DecompressOptions`] and a parsed
    /// [`Dictionary`].
    #[must_use]
    pub fn with_options_and_dictionary(
        reader: R,
        options: DecompressOptions,
        dictionary: Dictionary,
    ) -> Self {
        Decoder {
            reader,
            options,
            dict: dictionary,
            frame: StreamFrameDecoder::default(),
            state: DecoderState::FrameStart,
            out_buf: Vec::new(),
            read_pos: 0,
            block_buf: Vec::new(),
            xxh64: Xxh64State::new(0),
            hash_pos: 0,
            max_window_size: DEFAULT_MAX_WINDOW_SIZE,
        }
    }

    /// Sets the maximum window size (in bytes) that a frame header may request before
    /// [`Decoder`] refuses it with [`io::ErrorKind::InvalidData`] (defaults to 256 MiB).
    pub fn set_max_window_size(&mut self, max_window_size: usize) {
        self.max_window_size = max_window_size;
    }

    /// Shared reference to the underlying reader.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consumes the [`Decoder`] and returns the underlying reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Reads `buf.len()` bytes or `Ok(false)` on clean EOF at the very first byte.
    fn read_exact_or_eof(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
        let mut filled = 0usize;
        while filled < buf.len() {
            match reader.read(&mut buf[filled..]) {
                Ok(0) if filled == 0 => return Ok(false),
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF in zstd frame",
                    ));
                }
                Ok(n) => filled += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(true)
    }

    fn skip_bytes(reader: &mut R, mut count: usize) -> io::Result<()> {
        let mut discard = [0u8; 4096];
        while count > 0 {
            let want = count.min(discard.len());
            let n = loop {
                match reader.read(&mut discard[..want]) {
                    Ok(n) => break n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return Err(err),
                }
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in skippable zstd frame",
                ));
            }
            count -= n;
        }
        Ok(())
    }

    fn begin_next_frame(&mut self) -> io::Result<bool> {
        loop {
            let mut magic_bytes = [0u8; 4];
            if !Self::read_exact_or_eof(&mut self.reader, &mut magic_bytes)? {
                self.state = DecoderState::Done;
                return Ok(false);
            }
            let magic = u32::from_le_bytes(magic_bytes);
            if magic == ZSTD_MAGIC_NUMBER {
                let mut header_buf = [0u8; 14];
                self.reader.read_exact(&mut header_buf[..1])?;
                let desc = header_buf[0];
                let fcs_flag = (desc >> 6) as usize;
                let single_segment = (desc >> 5) & 1 != 0;
                let dict_flag = (desc & 3) as usize;
                let window_bytes = usize::from(!single_segment);
                let dict_bytes = [0usize, 1, 2, 4][dict_flag];
                let fcs_bytes = if single_segment || fcs_flag != 0 {
                    [1usize, 2, 4, 8][fcs_flag]
                } else {
                    0
                };
                let rest = window_bytes + dict_bytes + fcs_bytes;
                if rest > 0 {
                    self.reader.read_exact(&mut header_buf[1..=rest])?;
                }
                let header = parse_frame_header_from_slice(&header_buf[..=rest])?;
                // Single-segment frames set window_size = frame_content_size; check against
                // max_window_size so untrusted headers cannot trigger unbounded retention.
                if header.window_size > self.max_window_size as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "zstd frame window size exceeds configured limit",
                    ));
                }
                self.frame.start_frame(header, &self.dict)?;
                self.out_buf.clear();
                self.read_pos = 0;
                self.hash_pos = 0;
                self.xxh64 = Xxh64State::new(0);
                self.state = DecoderState::InFrame;
                return Ok(true);
            }
            if self.options.allow_skippable
                && (SKIPPABLE_MAGIC_LOW..=SKIPPABLE_MAGIC_HIGH).contains(&magic)
            {
                let mut len_bytes = [0u8; 4];
                self.reader.read_exact(&mut len_bytes)?;
                let skip_len = u32::from_le_bytes(len_bytes) as usize;
                Self::skip_bytes(&mut self.reader, skip_len)?;
                if !self.options.multi_frame {
                    self.state = DecoderState::Done;
                    return Ok(false);
                }
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Tried to decode non-ZSTD frame",
            ));
        }
    }

    fn compact_window_if_needed(&mut self) {
        let keep_window = (self.frame.header().window_size as usize).min(self.max_window_size);
        let threshold = keep_window.saturating_mul(2).max(ZSTD_BLOCK_SIZE_MAX * 2);
        if self.read_pos > ZSTD_BLOCK_SIZE_MAX && self.out_buf.len() > threshold {
            let max_droppable_for_window = self.out_buf.len().saturating_sub(keep_window);
            let drop_len = self.read_pos.min(max_droppable_for_window);
            if drop_len > 0 {
                self.out_buf.drain(..drop_len);
                self.read_pos -= drop_len;
                self.hash_pos -= drop_len;
            }
        }
    }

    fn decode_next_block(&mut self) -> io::Result<()> {
        self.compact_window_if_needed();

        let mut hdr_bytes = [0u8; 3];
        self.reader.read_exact(&mut hdr_bytes)?;
        let hdr = u32::from(hdr_bytes[0])
            | (u32::from(hdr_bytes[1]) << 8)
            | (u32::from(hdr_bytes[2]) << 16);
        let last_block = (hdr & 1) != 0;
        let block_type = ((hdr >> 1) & 3) as u8;
        let block_len = (hdr >> 3) as usize;

        if self.options.strict && block_len > ZSTD_BLOCK_SIZE_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Corruption detected while decompressing",
            ));
        }

        let payload_len = match block_type {
            0 | 2 => block_len,
            1 => 1,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Corruption detected while decompressing",
                ));
            }
        };
        self.block_buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.reader.read_exact(&mut self.block_buf)?;
        }

        let remaining_limit = usize::MAX - self.frame.current_total_output();
        self.frame.decode_block_into_vec(
            RawBlock {
                block_type,
                block_len,
                payload: &self.block_buf,
            },
            &mut self.out_buf,
            remaining_limit,
            &self.dict,
            self.options.strict,
        )?;

        if self.frame.header().content_checksum_flag && self.options.verify_checksum {
            self.xxh64.update(&self.out_buf[self.hash_pos..]);
        }
        self.hash_pos = self.out_buf.len();

        if last_block {
            self.frame.finish_frame(self.options.strict)?;
            if self.frame.header().content_checksum_flag {
                let mut trailer = [0u8; 4];
                self.reader.read_exact(&mut trailer)?;
                if self.options.verify_checksum {
                    let expected = u32::from_le_bytes(trailer);
                    let actual = self.xxh64.finish() as u32;
                    if actual != expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            DecompressError::from_checksum_mismatch(),
                        ));
                    }
                }
            }
            self.state = if self.options.multi_frame {
                DecoderState::FrameStart
            } else {
                DecoderState::Done
            };
        }

        Ok(())
    }
}

impl DecompressError {
    #[cfg(feature = "std")]
    pub(crate) const fn from_checksum_mismatch() -> Self {
        DecompressError::new(
            DecompressErrorKind::ChecksumMismatch,
            "Content checksum did not match",
        )
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.read_pos < self.out_buf.len() {
                let avail = &self.out_buf[self.read_pos..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                self.read_pos += n;
                return Ok(n);
            }
            match self.state {
                DecoderState::Done => return Ok(0),
                DecoderState::FrameStart => {
                    if !self.begin_next_frame()? {
                        return Ok(0);
                    }
                }
                DecoderState::InFrame => {
                    self.decode_next_block()?;
                }
            }
        }
    }
}
