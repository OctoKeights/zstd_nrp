//! The Zstandard decoder: the port of the reference decoder that comes with zstd,
//! `doc/educational_decoder/zstd_decompress.c` (Meta Platforms, BSD licence), the "Zstandard
//! educational decoder implementation". See
//! <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>.
//!
//! It decodes one frame, with or without a dictionary, into no more than the room it is
//! given. Like its original it checks no checksum, and does not check that a frame gave as
//! many bytes as its header says. Where the original stops the program with a message, the
//! port gives the message back in a [`ZstdError`].

// (The arithmetic is written as the original has it.)
#![allow(clippy::manual_div_ceil)]

/// Why a frame was refused: the message the reference decoder stops with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstdError(pub &'static str);

impl std::fmt::Display for ZstdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ZstdError {}

type R<T> = Result<T, ZstdError>;

/******* IMPORTANT CONSTANTS *********************************************/

// Zstandard frame
// "Magic_Number
// 4 Bytes, little-endian format. Value : 0xFD2FB528"
const ZSTD_MAGIC_NUMBER: u32 = 0xFD2FB528;

// The size of `Block_Content` is limited by `Block_Maximum_Size`,
const ZSTD_BLOCK_SIZE_MAX: usize = 128 * 1024;

// literal blocks can't be larger than their block
const MAX_LITERALS_SIZE: usize = ZSTD_BLOCK_SIZE_MAX;

/******* UTILITY MACROS AND TYPES *********************************************/

/// `ERROR`: this decoder calls exit(1) when it encounters an error, however a production
/// library should propagate error codes
fn error<T>(s: &'static str) -> R<T> {
    Err(ZstdError(s))
}
fn inp_size<T>() -> R<T> {
    error("Input buffer smaller than it should be or input is corrupted")
}
fn out_size<T>() -> R<T> {
    error("Output buffer too small for output")
}
fn corruption<T>() -> R<T> {
    error("Corruption detected while decompressing")
}

/*** IO STREAM OPERATIONS *************/

/// `ostream_t`: what is written, and how much room is left. They are written forward.
struct OStream {
    out: Vec<u8>,
    len: usize,
}

/// `istream_t`: wraps the data passed into ZSTD_decompress, so that all IO operations are
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
            return error("Attempt to read an invalid number of bits");
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

    /// `IO_rewind_bits`: backs-up the stream by `num` bits so they can be read again. If the
    /// scan is rewound beyond the start of the stream, undefined behavior may occur: only use
    /// when there is no chance of that. (Here that is refused, as input cut short is.)
    fn rewind_bits(&mut self, num_bits: i32) -> R<()> {
        if num_bits < 0 {
            return error("Attempting to rewind stream by a negative number of bits");
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

    /// `IO_istream_len`: returns the number of bytes left to be read in this stream. The
    /// stream must be byte aligned.
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
            return error("Attempting to operate on a non-byte aligned stream");
        }
        let chunk = &self.src[self.ptr..self.ptr + len];
        self.ptr += len;
        self.len -= len;
        Ok(chunk)
    }

    /// `IO_advance_input`: advance the inner state by `len` bytes. The stream must be byte
    /// aligned.
    fn advance_input(&mut self, len: usize) -> R<()> {
        self.get_read_ptr(len).map(|_| ())
    }

    /// `IO_make_sub_istream`: returns an `istream_t` with the same base as `in`, and length
    /// `len`. Then, advance `in` to account for the consumed bytes. `in` must be byte aligned.
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

impl OStream {
    /// `IO_make_ostream`
    fn new(len: usize) -> OStream {
        OStream {
            out: Vec::new(),
            len,
        }
    }

    /// `IO_write_byte`: write the given byte into the output stream
    fn write_byte(&mut self, symb: u8) -> R<()> {
        if self.len == 0 {
            return out_size();
        }
        self.out.push(symb);
        self.len -= 1;
        Ok(())
    }

    /// `IO_get_write_ptr`, the check and the advance of it: what is to be written there has
    /// to follow at once.
    fn get_write_ptr(&mut self, len: usize) -> R<()> {
        if len > self.len {
            return out_size();
        }
        self.len -= len;
        Ok(())
    }
}

/*** BITSTREAM OPERATIONS *************/

/// `read_bits_LE`: read `num` bits (up to 64) from `src + offset`, where `offset` is in bits,
/// and return them interpreted as a little-endian unsigned integer.
fn read_bits_le(src: &[u8], num_bits: i32, offset: usize) -> R<u64> {
    if num_bits > 64 {
        return error("Attempt to read an invalid number of bits");
    }

    // Skip over bytes that aren't in range
    let mut at = offset / 8;
    let mut bit_offset = offset % 8;
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

/// `STREAM_read_bits`: read bits from the end of a HUF or FSE bitstream. `offset` is in bits,
/// so it updates `offset` to `offset - bits`, and then reads `bits` bits from `src + offset`.
/// If the offset becomes negative, the extra bits at the bottom are filled in with `0` bits
/// instead of reading from before `src`.
fn stream_read_bits(src: &[u8], bits: i32, offset: &mut i64) -> R<u64> {
    *offset -= i64::from(bits);
    let mut actual_off = *offset;
    let mut actual_bits = i64::from(bits);
    // Don't actually read bits from before the start of src, so if `*offset <
    // 0` fix actual_off and actual_bits to reflect the quantity to read
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

/*** BIT COUNTING OPERATIONS **********/

/// `highest_set_bit`: returns the index of the highest set bit in `num`, or `-1` if
/// `num == 0`
fn highest_set_bit(num: u64) -> i32 {
    63 - num.leading_zeros() as i32
}

/*** HUFFMAN PRIMITIVES ***************/

// Table decode method uses exponential memory, so we need to limit depth
const HUF_MAX_BITS: usize = 16;

// Limit the maximum number of symbols to 256 so we can store a symbol in a byte
const HUF_MAX_SYMBS: usize = 256;

/// `HUF_dtable`: structure containing all tables necessary for efficient Huffman decoding.
/// (None of it, when the original's pointers are null.)
#[derive(Clone, Default)]
struct HufDtable {
    symbols: Vec<u8>,
    num_bits: Vec<u8>,
    max_bits: i32,
}

/*** FSE PRIMITIVES *******************/

// For more description of FSE see
// https://github.com/Cyan4973/FiniteStateEntropy/

// FSE table decoding uses exponential memory, so limit the maximum accuracy
const FSE_MAX_ACCURACY_LOG: i32 = 15;
// Limit the maximum number of symbols so they can be stored in a single byte
const FSE_MAX_SYMBS: usize = 256;

/// `FSE_dtable`: the tables needed to decode FSE encoded streams
#[derive(Clone, Default)]
struct FseDtable {
    symbols: Vec<u8>,
    num_bits: Vec<u8>,
    new_state_base: Vec<u16>,
    accuracy_log: i32,
}

/******* ZSTD HELPER STRUCTS AND PROTOTYPES ***********************************/

/// `frame_header_t`: a small structure that can be reused in various places that need to
/// access frame header information
#[derive(Default)]
struct FrameHeader {
    // The size of window that we need to be able to contiguously store for
    // references
    window_size: u64,
    // The total output size of this compressed frame
    frame_content_size: u64,

    // The dictionary id if this frame uses one
    dictionary_id: u32,

    // Whether or not the content of this frame has a checksum
    content_checksum_flag: bool,
    // Whether or not the output for this frame is in a single segment
    single_segment_flag: bool,
}

/// `frame_context_t`: the context needed to decode blocks in a frame
struct FrameContext<'d> {
    header: FrameHeader,

    // The total amount of data available for backreferences, to determine if an
    // offset too large to be correct
    current_total_output: usize,

    dict_content: &'d [u8],

    // Entropy encoding tables so they can be repeated by future blocks instead
    // of retransmitting
    literals_dtable: HufDtable,
    ll_dtable: FseDtable,
    ml_dtable: FseDtable,
    of_dtable: FseDtable,

    // The last 3 offsets for the special "repeat offsets".
    previous_offsets: [u64; 3],
}

/// The parsed contents of a dictionary: `dictionary_t`. This includes Huffman and FSE tables
/// used for decoding and data on offsets. [`Dictionary::default`] is the one that is none.
#[derive(Clone, Default)]
pub struct Dictionary {
    // Entropy tables
    literals_dtable: HufDtable,
    ll_dtable: FseDtable,
    ml_dtable: FseDtable,
    of_dtable: FseDtable,

    // Raw content for backreferences
    content: Vec<u8>,
    /// (Whether there is content, be it of no bytes: the original's pointer is null only for
    /// a dictionary that was never parsed.)
    has_content: bool,

    // Offset history to prepopulate the frame's history
    previous_offsets: [u64; 3],

    dictionary_id: u32,
}

/// `sequence_command_t`: a tuple containing the parts necessary to decode and execute a ZSTD
/// sequence command
#[derive(Clone, Copy)]
struct SequenceCommand {
    literal_length: u32,
    match_length: u32,
    offset: u32,
}

/// Decompresses a Zstandard frame into no more than `dst_len` bytes: `ZSTD_decompress`. The
/// bytes that come after the frame are not looked at.
pub fn decompress(src: &[u8], dst_len: usize) -> Result<Vec<u8>, ZstdError> {
    decompress_with_dict(src, dst_len, &Dictionary::default())
}

/// Decompresses a Zstandard frame that was compressed with a dictionary:
/// `ZSTD_decompress_with_dict`.
pub fn decompress_with_dict(
    src: &[u8],
    dst_len: usize,
    parsed_dict: &Dictionary,
) -> Result<Vec<u8>, ZstdError> {
    let mut input = IStream::new(src);
    let mut out = OStream::new(dst_len);

    /* this decoder assumes decompression of a single frame */
    decode_frame(&mut out, &mut input, parsed_dict)?;

    Ok(out.out)
}

/******* FRAME DECODING ******************************************************/

/// `decode_frame`
fn decode_frame(out: &mut OStream, input: &mut IStream, dict: &Dictionary) -> R<()> {
    let magic_number = input.read_bits(32)? as u32;
    if magic_number == ZSTD_MAGIC_NUMBER {
        // ZSTD frame
        return decode_data_frame(out, input, dict);
    }

    // not a real frame or a skippable frame
    error("Tried to decode non-ZSTD frame")
}

/// `decode_data_frame`: decode a frame that contains compressed data. Not all frames do as
/// there are skippable frames.
/// See "General Structure of Zstandard Frame format" in
/// <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>.
fn decode_data_frame(out: &mut OStream, input: &mut IStream, dict: &Dictionary) -> R<()> {
    // Initialize the context that needs to be carried from block to block
    let mut ctx = init_frame_context(input, dict)?;

    if ctx.header.frame_content_size != 0 && ctx.header.frame_content_size > out.len as u64 {
        return out_size();
    }

    decompress_data(&mut ctx, out, input)
}

/// `init_frame_context`: takes the information provided in the header and dictionary, and
/// initializes the context for this frame
fn init_frame_context<'d>(input: &mut IStream, dict: &'d Dictionary) -> R<FrameContext<'d>> {
    // Most fields in context are correct when initialized to 0
    let mut context = FrameContext {
        // Parse data from the frame header
        header: parse_frame_header(input)?,
        current_total_output: 0,
        dict_content: &[],
        literals_dtable: HufDtable::default(),
        ll_dtable: FseDtable::default(),
        ml_dtable: FseDtable::default(),
        of_dtable: FseDtable::default(),
        // Set up the offset history for the repeat offset commands
        previous_offsets: [1, 4, 8],
    };

    // Apply the dictionary if it exists
    frame_context_apply_dict(&mut context, dict)?;
    Ok(context)
}

/// `parse_frame_header`
fn parse_frame_header(input: &mut IStream) -> R<FrameHeader> {
    let mut header = FrameHeader::default();
    // "The first header's byte is called the Frame_Header_Descriptor. It tells
    // which other fields are present. Decoding this byte is enough to tell the
    // size of Frame_Header.
    //
    // Bit number   Field name
    // 7-6  Frame_Content_Size_flag
    // 5    Single_Segment_flag
    // 4    Unused_bit
    // 3    Reserved_bit
    // 2    Content_Checksum_flag
    // 1-0  Dictionary_ID_flag"
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
        // "Provides guarantees on maximum back-reference distance that will be
        // used within compressed data. This information is important for
        // decoders to allocate enough memory.
        //
        // Bit numbers  7-3         2-0
        // Field name   Exponent    Mantissa"
        let window_descriptor = input.read_bits(8)? as u8;
        let exponent = window_descriptor >> 3;
        let mantissa = window_descriptor & 7;

        // Use the algorithm from the specification to compute window size ("Window_Descriptor" in
        // https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md)
        let window_base = 1u64 << (10 + exponent);
        let window_add = (window_base / 8) * u64::from(mantissa);
        header.window_size = window_base + window_add;
    }

    // decode dictionary id if it exists
    if dictionary_id_flag != 0 {
        // "This is a variable size field, which contains the ID of the
        // dictionary required to properly decode the frame. Note that this
        // field is optional. When it's not present, it's up to the caller to
        // make sure it uses the correct dictionary. Format is little-endian."
        const BYTES_ARRAY: [i32; 4] = [0, 1, 2, 4];
        let bytes = BYTES_ARRAY[usize::from(dictionary_id_flag)];

        header.dictionary_id = input.read_bits(bytes * 8)? as u32;
    } else {
        header.dictionary_id = 0;
    }

    // decode frame content size if it exists
    if single_segment_flag != 0 || frame_content_size_flag != 0 {
        // "This is the original (uncompressed) size. This information is
        // optional. The Field_Size is provided according to value of
        // Frame_Content_Size_flag. The Field_Size can be equal to 0 (not
        // present), 1, 2, 4 or 8 bytes. Format is little-endian."
        //
        // if frame_content_size_flag == 0 but single_segment_flag is set, we
        // still have a 1 byte field
        const BYTES_ARRAY: [i32; 4] = [1, 2, 4, 8];
        let bytes = BYTES_ARRAY[usize::from(frame_content_size_flag)];

        header.frame_content_size = input.read_bits(bytes * 8)?;
        if bytes == 2 {
            // "When Field_Size is 2, the offset of 256 is added."
            header.frame_content_size += 256;
        }
    } else {
        header.frame_content_size = 0;
    }

    if single_segment_flag != 0 {
        // "The Window_Descriptor byte is optional. It is absent when
        // Single_Segment_flag is set. In this case, the maximum back-reference
        // distance is the content size itself, which can be any value from 1 to
        // 2^64-1 bytes (16 EB)."
        header.window_size = header.frame_content_size;
    }

    Ok(header)
}

/// `decompress_data`: decompress the data from a frame block by block
fn decompress_data(ctx: &mut FrameContext, out: &mut OStream, input: &mut IStream) -> R<()> {
    // "A frame encapsulates one or multiple blocks. Each block can be
    // compressed or not, and has a guaranteed maximum content size, which
    // depends on frame parameters. Unlike frames, each block depends on
    // previous blocks for proper decoding. However, each block can be
    // decompressed without waiting for its successor, allowing streaming
    // operations."
    loop {
        // "Last_Block
        //
        // The lowest bit signals if this block is the last one. Frame ends
        // right after this block.
        //
        // Block_Type and Block_Size
        //
        // The next 2 bits represent the Block_Type, while the remaining 21 bits
        // represent the Block_Size. Format is little-endian."
        let last_block = input.read_bits(1)? != 0;
        let block_type = input.read_bits(2)?;
        let block_len = input.read_bits(21)? as usize;

        match block_type {
            0 => {
                // "Raw_Block - this is an uncompressed block. Block_Size is the
                // number of bytes to read and copy."
                let read_ptr = input.get_read_ptr(block_len)?;
                out.get_write_ptr(block_len)?;

                // Copy the raw data into the output
                out.out.extend_from_slice(read_ptr);

                ctx.current_total_output += block_len;
            }
            1 => {
                // "RLE_Block - this is a single byte, repeated N times. In which
                // case, Block_Size is the size to regenerate, while the
                // "compressed" block is just 1 byte (the byte to repeat)."
                let read_ptr = input.get_read_ptr(1)?;
                out.get_write_ptr(block_len)?;

                // Copy `block_len` copies of `read_ptr[0]` to the output
                out.out.resize(out.out.len() + block_len, read_ptr[0]);

                ctx.current_total_output += block_len;
            }
            2 => {
                // "Compressed_Block - this is a Zstandard compressed block,
                // detailed in another section of this specification. Block_Size is
                // the compressed size.

                // Create a sub-stream for the block
                let mut block_stream = input.make_sub_istream(block_len)?;
                decompress_block(ctx, out, &mut block_stream)?;
            }
            _ => {
                // "Reserved - this is not a block. This value cannot be used with
                // current version of this specification."
                return corruption();
            }
        }
        if last_block {
            break;
        }
    }

    if ctx.header.content_checksum_flag {
        // This program does not support checking the checksum, so skip over it
        // if it's present
        input.advance_input(4)?;
    }
    Ok(())
}

/******* BLOCK DECOMPRESSION **************************************************/

/// `decompress_block`
fn decompress_block(ctx: &mut FrameContext, out: &mut OStream, input: &mut IStream) -> R<()> {
    // "A compressed block consists of 2 sections :
    //
    // Literals_Section
    // Sequences_Section"

    // Part 1: decode the literals block
    let literals = decode_literals(ctx, input)?;

    // Part 2: decode the sequences block
    let sequences = decode_sequences(ctx, input)?;

    // Part 3: combine literals and sequence commands to generate output
    execute_sequences(ctx, out, &literals, &sequences)
}

/******* LITERALS DECODING ****************************************************/

/// `decode_literals`
fn decode_literals(ctx: &mut FrameContext, input: &mut IStream) -> R<Vec<u8>> {
    // "Literals can be stored uncompressed or compressed using Huffman prefix
    // codes. When compressed, an optional tree description can be present,
    // followed by 1 or 4 streams."
    //
    // "Literals_Section_Header
    //
    // Header is in charge of describing how literals are packed. It's a
    // byte-aligned variable-size bitfield, ranging from 1 to 5 bytes, using
    // little-endian convention."
    //
    // "Literals_Block_Type
    //
    // This field uses 2 lowest bits of first byte, describing 4 different block
    // types"
    //
    // size_format takes between 1 and 2 bits
    let block_type = input.read_bits(2)? as i32;
    let size_format = input.read_bits(2)? as i32;

    if block_type <= 1 {
        // Raw or RLE literals block
        decode_literals_simple(input, block_type, size_format)
    } else {
        // Huffman compressed literals
        decode_literals_compressed(ctx, input, block_type, size_format)
    }
}

/// `decode_literals_simple`: decodes literals blocks in raw or RLE form
fn decode_literals_simple(input: &mut IStream, block_type: i32, size_format: i32) -> R<Vec<u8>> {
    let size = match size_format {
        // These cases are in the form ?0
        // In this case, the ? bit is actually part of the size field
        0 | 2 => {
            // "Size_Format uses 1 bit. Regenerated_Size uses 5 bits (0-31)."
            input.rewind_bits(1)?;
            input.read_bits(5)?
        }
        // "Size_Format uses 2 bits. Regenerated_Size uses 12 bits (0-4095)."
        1 => input.read_bits(12)?,
        // "Size_Format uses 2 bits. Regenerated_Size uses 20 bits (0-1048575)."
        _ => input.read_bits(20)?,
    } as usize;

    if size > MAX_LITERALS_SIZE {
        return corruption();
    }

    match block_type {
        0 => {
            // "Raw_Literals_Block - Literals are stored uncompressed."
            Ok(input.get_read_ptr(size)?.to_vec())
        }
        _ => {
            // "RLE_Literals_Block - Literals consist of a single byte value repeated N times."
            let read_ptr = input.get_read_ptr(1)?;
            Ok(vec![read_ptr[0]; size])
        }
    }
}

/// `decode_literals_compressed`: decodes Huffman compressed literals
fn decode_literals_compressed(
    ctx: &mut FrameContext,
    input: &mut IStream,
    block_type: i32,
    size_format: i32,
) -> R<Vec<u8>> {
    // Only size_format=0 has 1 stream, so default to 4
    let mut num_streams = 4;
    let (regenerated_size, compressed_size) = match size_format {
        0 | 1 => {
            // "A single stream. Both Compressed_Size and Regenerated_Size use 10
            // bits (0-1023)."
            if size_format == 0 {
                num_streams = 1;
            }
            // "4 streams. Both Compressed_Size and Regenerated_Size use 10 bits
            // (0-1023)."
            let regenerated_size = input.read_bits(10)?;
            (regenerated_size, input.read_bits(10)?)
        }
        2 => {
            // "4 streams. Both Compressed_Size and Regenerated_Size use 14 bits
            // (0-16383)."
            let regenerated_size = input.read_bits(14)?;
            (regenerated_size, input.read_bits(14)?)
        }
        _ => {
            // "4 streams. Both Compressed_Size and Regenerated_Size use 18 bits
            // (0-262143)."
            let regenerated_size = input.read_bits(18)?;
            (regenerated_size, input.read_bits(18)?)
        }
    };
    let (regenerated_size, compressed_size) = (regenerated_size as usize, compressed_size as usize);
    if regenerated_size > MAX_LITERALS_SIZE {
        return corruption();
    }

    let mut lit_stream = OStream::new(regenerated_size);
    let mut huf_stream = input.make_sub_istream(compressed_size)?;

    if block_type == 2 {
        // Decode the provided Huffman table
        // "This section is only present when Literals_Block_Type type is
        // Compressed_Literals_Block (2)."
        ctx.literals_dtable = HufDtable::default();
        ctx.literals_dtable = decode_huf_table(&mut huf_stream)?;
    } else {
        // If the previous Huffman table is being repeated, ensure it exists
        if ctx.literals_dtable.symbols.is_empty() {
            return corruption();
        }
    }

    let symbols_decoded = if num_streams == 1 {
        huf_decompress_1stream(&ctx.literals_dtable, &mut lit_stream, &mut huf_stream)?
    } else {
        huf_decompress_4stream(&ctx.literals_dtable, &mut lit_stream, &mut huf_stream)?
    };

    if symbols_decoded != regenerated_size {
        return corruption();
    }

    Ok(lit_stream.out)
}

/// `decode_huf_table`: decode the Huffman table description
fn decode_huf_table(input: &mut IStream) -> R<HufDtable> {
    // "All literal values from zero (included) to last present one (excluded)
    // are represented by Weight with values from 0 to Max_Number_of_Bits."

    // "This is a single byte value (0-255), which describes how to decode the list of weights."
    let header = input.read_bits(8)? as u8;

    let mut weights = [0u8; HUF_MAX_SYMBS];

    let num_symbs;

    if header >= 128 {
        // "This is a direct representation, where each Weight is written
        // directly as a 4 bits field (0-15). The full representation occupies
        // ((Number_of_Symbols+1)/2) bytes, meaning it uses a last full byte
        // even if Number_of_Symbols is odd. Number_of_Symbols = headerByte -
        // 127"
        num_symbs = usize::from(header) - 127;
        let bytes = (num_symbs + 1) / 2;

        let weight_src = input.get_read_ptr(bytes)?;

        for i in 0..num_symbs {
            // "They are encoded forward, 2
            // weights to a byte with the first weight taking the top four bits
            // and the second taking the bottom four (e.g. the following
            // operations could be used to read the weights:
            // Weight[0] = (Byte[0] >> 4), Weight[1] = (Byte[0] & 0xf), etc.)."
            weights[i] = if i % 2 == 0 {
                weight_src[i / 2] >> 4
            } else {
                weight_src[i / 2] & 0xf
            };
        }
    } else {
        // The weights are FSE encoded, decode them before we can construct the
        // table
        let mut fse_stream = input.make_sub_istream(usize::from(header))?;
        let mut weight_stream = OStream::new(HUF_MAX_SYMBS);
        fse_decode_hufweights(&mut weight_stream, &mut fse_stream)?;
        num_symbs = weight_stream.out.len();
        weights[..num_symbs].copy_from_slice(&weight_stream.out);
    }

    // Construct the table using the decoded weights
    huf_init_dtable_usingweights(&weights, num_symbs)
}

/// `fse_decode_hufweights`
fn fse_decode_hufweights(weights: &mut OStream, input: &mut IStream) -> R<()> {
    const MAX_ACCURACY_LOG: i32 = 7;

    // "An FSE bitstream starts by a header, describing probabilities
    // distribution. It will create a Decoding Table. For a list of Huffman
    // weights, maximum accuracy is 7 bits."
    let dtable = fse_decode_header(input, MAX_ACCURACY_LOG)?;

    // Decode the weights
    fse_decompress_interleaved2(&dtable, weights, input)?;
    Ok(())
}

/******* SEQUENCE DECODING ****************************************************/

/// `sequence_states_t`: the combination of FSE states needed to decode sequences
struct SequenceStates<'t> {
    ll_table: &'t FseDtable,
    of_table: &'t FseDtable,
    ml_table: &'t FseDtable,

    ll_state: u16,
    of_state: u16,
    ml_state: u16,
}

/// `seq_part_t`: different modes to signal to decode_seq_tables what to do
#[derive(Clone, Copy)]
enum SeqPart {
    LiteralLength = 0,
    Offset = 1,
    MatchLength = 2,
}

// The predefined FSE distribution tables for `seq_predefined` mode
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

// The sequence decoding baseline and number of additional bits to read/add ("The codes for
// literals lengths, match lengths, and offsets" in
// https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md)
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

// Offset decoding is simpler so we just need a maximum code value
static SEQ_MAX_CODES: [u8; 3] = [35, u8::MAX, 52];

/// `decode_sequences`
fn decode_sequences(ctx: &mut FrameContext, input: &mut IStream) -> R<Vec<SequenceCommand>> {
    // "A compressed block is a succession of sequences . A sequence is a
    // literal copy command, followed by a match copy command. A literal copy
    // command specifies a length. It is the number of bytes to be copied (or
    // extracted) from the literal section. A match copy command specifies an
    // offset and a length. The offset gives the position to copy from, which
    // can be within a previous block."

    // "Number_of_Sequences
    //
    // This is a variable size field using between 1 and 3 bytes. Let's call its
    // first byte byte0."
    let header = input.read_bits(8)? as usize;
    let num_sequences = if header < 128 {
        // "Number_of_Sequences = byte0 . Uses 1 byte."
        header
    } else if header < 255 {
        // "Number_of_Sequences = ((byte0-128) << 8) + byte1 . Uses 2 bytes."
        ((header - 128) << 8) + input.read_bits(8)? as usize
    } else {
        // "Number_of_Sequences = byte1 + (byte2<<8) + 0x7F00 . Uses 3 bytes."
        input.read_bits(16)? as usize + 0x7F00
    };

    if num_sequences == 0 {
        // "There are no sequences. The sequence section stops there."
        return Ok(Vec::new());
    }

    decompress_sequences(ctx, input, num_sequences)
}

/// `decompress_sequences`: decompress the FSE encoded sequence commands
fn decompress_sequences(
    ctx: &mut FrameContext,
    input: &mut IStream,
    num_sequences: usize,
) -> R<Vec<SequenceCommand>> {
    // "The Sequences_Section regroup all symbols required to decode commands.
    // There are 3 symbol types : literals lengths, offsets and match lengths.
    // They are encoded together, interleaved, in a single bitstream."

    // "Symbol compression modes
    //
    // This is a single byte, defining the compression mode of each symbol
    // type."
    //
    // Bit number : Field name
    // 7-6        : Literals_Lengths_Mode
    // 5-4        : Offsets_Mode
    // 3-2        : Match_Lengths_Mode
    // 1-0        : Reserved
    let compression_modes = input.read_bits(8)? as u8;

    if (compression_modes & 3) != 0 {
        // Reserved bits set
        return corruption();
    }

    // "Following the header, up to 3 distribution tables can be described. When
    // present, they are in this order :
    //
    // Literals lengths
    // Offsets
    // Match Lengths"
    // Update the tables we have stored in the context
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

    let mut states = SequenceStates {
        ll_table: &ctx.ll_dtable,
        of_table: &ctx.of_dtable,
        ml_table: &ctx.ml_dtable,
        ll_state: 0,
        of_state: 0,
        ml_state: 0,
    };

    let len = input.istream_len();
    let src = input.get_read_ptr(len)?;

    // (With no bytes left the original looks at the one before them to learn how many bits
    // are padding. Whatever that byte holds, what follows starts below zero and ends the same
    // way: every read gives zeros, and the check at the end that all the bits were read
    // fails, unless a code out of range does first with the same words.)
    if len == 0 {
        return corruption();
    }

    // "After writing the last bit containing information, the compressor writes
    // a single 1-bit and then fills the byte with 0-7 0 bits of padding."
    let padding = 8 - highest_set_bit(u64::from(src[len - 1]));
    // The offset starts at the end because FSE streams are read backwards
    let mut bit_offset = (len * 8) as i64 - i64::from(padding);

    // "The bitstream starts with initial state values, each using the required
    // number of bits in their respective accuracy, decoded previously from
    // their normalized distribution.
    //
    // It starts by Literals_Length_State, followed by Offset_State, and finally
    // Match_Length_State."
    states.ll_state = fse_init_state(states.ll_table, src, &mut bit_offset)?;
    states.of_state = fse_init_state(states.of_table, src, &mut bit_offset)?;
    states.ml_state = fse_init_state(states.ml_table, src, &mut bit_offset)?;

    let mut sequences = Vec::with_capacity(num_sequences);
    for i in 0..num_sequences {
        // Decode sequences one by one
        sequences.push(decode_sequence(
            &mut states,
            src,
            &mut bit_offset,
            i == num_sequences - 1,
        )?);
    }

    if bit_offset != 0 {
        return corruption();
    }
    Ok(sequences)
}

/// `decode_sequence`: decode a single sequence and update the state
fn decode_sequence(
    states: &mut SequenceStates,
    src: &[u8],
    offset: &mut i64,
    last_sequence: bool,
) -> R<SequenceCommand> {
    // "Each symbol is a code in its own context, which specifies Baseline and
    // Number_of_Bits to add. Codes are FSE compressed, and interleaved with raw
    // additional bits in the same bitstream."

    // Decode symbols, but don't update states
    let of_code = fse_peek_symbol(states.of_table, states.of_state);
    let ll_code = fse_peek_symbol(states.ll_table, states.ll_state);
    let ml_code = fse_peek_symbol(states.ml_table, states.ml_state);

    // Offset doesn't need a max value as it's not decoded using a table
    if ll_code > SEQ_MAX_CODES[SeqPart::LiteralLength as usize]
        || ml_code > SEQ_MAX_CODES[SeqPart::MatchLength as usize]
    {
        return corruption();
    }

    // Read the interleaved bits
    // "Decoding starts by reading the Number_of_Bits required to decode Offset.
    // It then does the same for Match_Length, and then for Literals_Length."
    // (For an offset code of 32 or more the original shifts a 32-bit one further than it is
    // wide: what an x86 processor makes of that.)
    let offset_value = u64::from(1u32.wrapping_shl(u32::from(of_code)))
        .wrapping_add(stream_read_bits(src, i32::from(of_code), offset)?)
        as u32;
    let match_length = (u64::from(SEQ_MATCH_LENGTH_BASELINES[usize::from(ml_code)])
        + stream_read_bits(
            src,
            i32::from(SEQ_MATCH_LENGTH_EXTRA_BITS[usize::from(ml_code)]),
            offset,
        )?) as u32;
    let literal_length = (u64::from(SEQ_LITERAL_LENGTH_BASELINES[usize::from(ll_code)])
        + stream_read_bits(
            src,
            i32::from(SEQ_LITERAL_LENGTH_EXTRA_BITS[usize::from(ll_code)]),
            offset,
        )?) as u32;

    // "If it is not the last sequence in the block, the next operation is to
    // update states. Using the rules pre-calculated in the decoding tables,
    // Literals_Length_State is updated, followed by Match_Length_State, and
    // then Offset_State."
    // If the stream is complete don't read bits to update state
    if !last_sequence {
        fse_update_state(states.ll_table, &mut states.ll_state, src, offset)?;
        fse_update_state(states.ml_table, &mut states.ml_state, src, offset)?;
        fse_update_state(states.of_table, &mut states.of_state, src, offset)?;
    }

    Ok(SequenceCommand {
        literal_length,
        match_length,
        offset: offset_value,
    })
}

/// `decode_seq_table`: given a sequence part and table mode, decode the FSE distribution
fn decode_seq_table(table: &mut FseDtable, input: &mut IStream, part: SeqPart, mode: u8) -> R<()> {
    // Constant arrays indexed by seq_part_t
    let default_distributions: [&[i16]; 3] = [
        &SEQ_LITERAL_LENGTH_DEFAULT_DIST,
        &SEQ_OFFSET_DEFAULT_DIST,
        &SEQ_MATCH_LENGTH_DEFAULT_DIST,
    ];
    const DEFAULT_DISTRIBUTION_ACCURACIES: [i32; 3] = [6, 5, 6];

    // "The maximum accuracy log is 9 for literal and match lengths, and 8 for offsets"
    const MAX_ACCURACIES: [i32; 3] = [9, 8, 9];

    if mode != 3 {
        // Free old one before overwriting
        *table = FseDtable::default();
    }

    match mode {
        0 => {
            // "Predefined_Mode : uses a predefined distribution table."
            let distribution = default_distributions[part as usize];
            let accuracy_log = DEFAULT_DISTRIBUTION_ACCURACIES[part as usize];

            *table = fse_init_dtable(distribution, accuracy_log)?;
        }
        1 => {
            // "RLE_Mode : it's a single code, repeated Number_of_Sequences times."
            let symb = input.get_read_ptr(1)?[0];
            *table = fse_init_dtable_rle(symb);
        }
        2 => {
            // "FSE_Compressed_Mode : standard FSE compression. A distribution table
            // will be present "
            *table = fse_decode_header(input, MAX_ACCURACIES[part as usize])?;
        }
        _ => {
            // "Repeat_Mode : reuse distribution table from previous compressed
            // block."
            // Nothing to do here, table will be unchanged
            if table.symbols.is_empty() {
                // This mode is invalid if we don't already have a table
                return corruption();
            }
        }
    }
    Ok(())
}

/******* SEQUENCE EXECUTION ***************************************************/

/// `execute_sequences`
fn execute_sequences(
    ctx: &mut FrameContext,
    out: &mut OStream,
    literals: &[u8],
    sequences: &[SequenceCommand],
) -> R<()> {
    let mut litstream = IStream::new(literals);

    let mut total_output = ctx.current_total_output;

    for seq in sequences {
        {
            let literals_size = copy_literals(seq.literal_length as usize, &mut litstream, out)?;
            total_output += literals_size;
        }

        let offset = compute_offset(*seq, &mut ctx.previous_offsets);

        let match_length = seq.match_length as usize;

        execute_match_copy(ctx, offset, match_length, total_output, out)?;

        total_output += match_length;
    }

    // Copy any leftover literals
    {
        let len = litstream.istream_len();
        copy_literals(len, &mut litstream, out)?;
        total_output += len;
    }

    ctx.current_total_output = total_output;
    Ok(())
}

/// `copy_literals`
fn copy_literals(literal_length: usize, litstream: &mut IStream, out: &mut OStream) -> R<usize> {
    // If the sequence asks for more literals than are left, the
    // sequence must be corrupted
    if literal_length > litstream.istream_len() {
        return corruption();
    }

    out.get_write_ptr(literal_length)?;
    let read_ptr = litstream.get_read_ptr(literal_length)?;
    // Copy literals to output
    out.out.extend_from_slice(read_ptr);

    Ok(literal_length)
}

/// `compute_offset`
fn compute_offset(seq: SequenceCommand, offset_hist: &mut [u64; 3]) -> u64 {
    let offset;
    // Offsets are special, we need to handle the repeat offsets
    if seq.offset <= 3 {
        // "The first 3 values define a repeated offset and we will call
        // them Repeated_Offset1, Repeated_Offset2, and Repeated_Offset3.
        // They are sorted in recency order, with Repeated_Offset1 meaning
        // 'most recent one'".

        // Use 0 indexing for the array
        let mut idx = seq.offset.wrapping_sub(1);
        if seq.literal_length == 0 {
            // "There is an exception though, when current sequence's
            // literals length is 0. In this case, repeated offsets are
            // shifted by one, so Repeated_Offset1 becomes Repeated_Offset2,
            // Repeated_Offset2 becomes Repeated_Offset3, and Repeated_Offset3
            // becomes Repeated_Offset1 - 1_byte."
            idx = idx.wrapping_add(1);
        }

        if idx == 0 {
            offset = offset_hist[0];
        } else {
            // If idx == 3 then literal length was 0 and the offset was 3,
            // as per the exception listed above
            offset = if idx < 3 {
                offset_hist[idx as usize]
            } else {
                offset_hist[0].wrapping_sub(1)
            };

            // If idx == 1 we don't need to modify offset_hist[2], since
            // we're using the second-most recent code
            if idx > 1 {
                offset_hist[2] = offset_hist[1];
            }
            offset_hist[1] = offset_hist[0];
            offset_hist[0] = offset;
        }
    } else {
        // When it's not a repeat offset:
        // "if (Offset_Value > 3) offset = Offset_Value - 3;"
        offset = u64::from(seq.offset - 3);

        // Shift back history
        offset_hist[2] = offset_hist[1];
        offset_hist[1] = offset_hist[0];
        offset_hist[0] = offset;
    }
    offset
}

/// `execute_match_copy`
fn execute_match_copy(
    ctx: &FrameContext,
    offset: u64,
    mut match_length: usize,
    total_output: usize,
    out: &mut OStream,
) -> R<()> {
    out.get_write_ptr(match_length)?;
    if total_output as u64 <= ctx.header.window_size {
        // In this case offset might go back into the dictionary
        if offset > (total_output + ctx.dict_content.len()) as u64 {
            // The offset goes beyond even the dictionary
            return corruption();
        }

        if offset > total_output as u64 {
            // "The rest of the dictionary is its content. The content act
            // as a "past" in front of data to compress or decompress, so it
            // can be referenced in sequence commands."
            let dict_copy = (offset as usize - total_output).min(match_length);
            let dict_offset = ctx.dict_content.len() - (offset as usize - total_output);

            out.out
                .extend_from_slice(&ctx.dict_content[dict_offset..dict_offset + dict_copy]);
            match_length -= dict_copy;
        }
    } else if offset > ctx.header.window_size {
        return corruption();
    }

    // We must copy byte by byte because the match length might be larger
    // than the offset
    // ex: if the output so far was "abc", a command with offset=3 and
    // match_length=6 would produce "abcabcabc" as the new output
    // (An offset of nothing, which the original lets through, copies each place onto itself:
    // into room that starts as zeros, that is zeros.)
    let offset = offset as usize;
    for _ in 0..match_length {
        let byte = if offset == 0 {
            0
        } else {
            out.out[out.out.len() - offset]
        };
        out.out.push(byte);
    }
    Ok(())
}

/******* OUTPUT SIZE COUNTING *************************************************/

/// The size a frame's header says it decompresses to: `ZSTD_get_decompressed_size`. None when
/// the header does not say (the original gives -1).
pub fn get_decompressed_size(src: &[u8]) -> Result<Option<u64>, ZstdError> {
    let mut input = IStream::new(src);

    // get decompressed size from ZSTD frame header
    let magic_number = input.read_bits(32)? as u32;

    if magic_number == ZSTD_MAGIC_NUMBER {
        // ZSTD frame
        let header = parse_frame_header(&mut input)?;

        if header.frame_content_size == 0 && !header.single_segment_flag {
            // Content size not provided, we can't tell
            return Ok(None);
        }

        Ok(Some(header.frame_content_size))
    } else {
        // not a real frame or skippable frame
        error("ZSTD frame magic number did not match")
    }
}

/******* DICTIONARY PARSING ***************************************************/

impl Dictionary {
    /// A dictionary out of its bytes: `parse_dictionary`. Bytes that do not begin as a
    /// dictionary with tables does are a dictionary of content alone.
    pub fn parse(src: &[u8]) -> Result<Dictionary, ZstdError> {
        let mut dict = Dictionary::default();
        if src.len() < 8 {
            return error("Dictionary size cannot be less than 8 bytes");
        }

        let mut input = IStream::new(src);

        let magic_number = input.read_bits(32)? as u32;
        if magic_number != 0xEC30A437 {
            // raw content dict
            input.rewind_bits(32)?;
            init_dictionary_content(&mut dict, &mut input)?;
            return Ok(dict);
        }

        dict.dictionary_id = input.read_bits(32)? as u32;

        // "Entropy_Tables : following the same format as the tables in compressed
        // blocks. They are stored in following order : Huffman tables for literals,
        // FSE table for offsets, FSE table for match lengths, and FSE table for
        // literals lengths. It's finally followed by 3 offset values, populating
        // recent offsets (instead of using {1,4,8}), stored in order, 4-bytes
        // little-endian each, for a total of 12 bytes. Each recent offset must have
        // a value < dictionary size."
        dict.literals_dtable = decode_huf_table(&mut input)?;
        decode_seq_table(&mut dict.of_dtable, &mut input, SeqPart::Offset, 2)?;
        decode_seq_table(&mut dict.ml_dtable, &mut input, SeqPart::MatchLength, 2)?;
        decode_seq_table(&mut dict.ll_dtable, &mut input, SeqPart::LiteralLength, 2)?;

        // Read in the previous offset history
        dict.previous_offsets[0] = input.read_bits(32)?;
        dict.previous_offsets[1] = input.read_bits(32)?;
        dict.previous_offsets[2] = input.read_bits(32)?;

        // Ensure the provided offsets aren't too large
        // "Each recent offset must have a value < dictionary size."
        for offset in dict.previous_offsets {
            if offset > src.len() as u64 {
                return error("Dictionary corrupted");
            }
        }

        // "Content : The rest of the dictionary is its content. The content act as
        // a "past" in front of data to compress or decompress, so it can be
        // referenced in sequence commands."
        init_dictionary_content(&mut dict, &mut input)?;
        Ok(dict)
    }
}

/// `init_dictionary_content`
fn init_dictionary_content(dict: &mut Dictionary, input: &mut IStream) -> R<()> {
    // Copy in the content
    dict.content = input.get_read_ptr(input.istream_len())?.to_vec();
    dict.has_content = true;
    Ok(())
}

/// `HUF_copy_dtable`
fn huf_copy_dtable(src: &HufDtable) -> HufDtable {
    if src.max_bits == 0 {
        return HufDtable::default();
    }
    src.clone()
}

/// `FSE_copy_dtable`
fn fse_copy_dtable(src: &FseDtable) -> FseDtable {
    if src.accuracy_log == 0 {
        return FseDtable::default();
    }
    src.clone()
}

/// `frame_context_apply_dict`
fn frame_context_apply_dict<'d>(ctx: &mut FrameContext<'d>, dict: &'d Dictionary) -> R<()> {
    // If the content pointer is NULL then it must be an empty dict
    if !dict.has_content {
        return Ok(());
    }

    // If the requested dictionary_id is non-zero, the correct dictionary must
    // be present
    if ctx.header.dictionary_id != 0 && ctx.header.dictionary_id != dict.dictionary_id {
        return error("Wrong dictionary provided");
    }

    // Copy the dict content to the context for references during sequence
    // execution
    ctx.dict_content = &dict.content;

    // If it's a formatted dict copy the precomputed tables in so they can
    // be used in the table repeat modes
    if dict.dictionary_id != 0 {
        // Deep copy the entropy tables so they can be freed independently of
        // the dictionary struct
        ctx.literals_dtable = huf_copy_dtable(&dict.literals_dtable);
        ctx.ll_dtable = fse_copy_dtable(&dict.ll_dtable);
        ctx.of_dtable = fse_copy_dtable(&dict.of_dtable);
        ctx.ml_dtable = fse_copy_dtable(&dict.ml_dtable);

        // Copy the repeated offsets
        ctx.previous_offsets = dict.previous_offsets;
    }
    Ok(())
}

/******* HUFFMAN PRIMITIVES ***************************************************/

/// `HUF_decode_symbol`: decode a single symbol and read in enough bits to refresh the state
fn huf_decode_symbol(dtable: &HufDtable, state: &mut u16, src: &[u8], offset: &mut i64) -> R<u8> {
    // Look up the symbol and number of bits to read
    let symb = dtable.symbols[usize::from(*state)];
    let bits = dtable.num_bits[usize::from(*state)];
    let rest = stream_read_bits(src, i32::from(bits), offset)? as u16;
    // Shift `bits` bits out of the state, keeping the low order bits that
    // weren't necessary to determine this symbol.  Then add in the new bits
    // read from the stream.
    *state = ((u32::from(*state) << bits).wrapping_add(u32::from(rest))
        & ((1u32 << dtable.max_bits) - 1)) as u16;

    Ok(symb)
}

/// `HUF_init_state`: read in a full state's worth of bits to initialize it
fn huf_init_state(dtable: &HufDtable, src: &[u8], offset: &mut i64) -> R<u16> {
    // Read in a full `dtable->max_bits` bits to initialize the state
    let bits = dtable.max_bits;
    Ok(stream_read_bits(src, bits, offset)? as u16)
}

/// `HUF_decompress_1stream`: decompresses a single Huffman stream, returns the number of
/// bytes decoded. `src_len` must be the exact length of the Huffman-coded block.
fn huf_decompress_1stream(dtable: &HufDtable, out: &mut OStream, input: &mut IStream) -> R<usize> {
    let len = input.istream_len();
    if len == 0 {
        return inp_size();
    }
    let src = input.get_read_ptr(len)?;

    // "Each bitstream must be read backward, that is starting from the end down
    // to the beginning. Therefore it's necessary to know the size of each
    // bitstream.
    //
    // It's also necessary to know exactly which bit is the latest. This is
    // detected by a final bit flag : the highest bit of latest byte is a
    // final-bit-flag. Consequently, a last byte of 0 is not possible. And the
    // final-bit-flag itself is not part of the useful bitstream. Hence, the
    // last byte contains between 0 and 7 useful bits."
    let padding = 8 - highest_set_bit(u64::from(src[len - 1]));

    // Offset starts at the end because HUF streams are read backwards
    let mut bit_offset = (len * 8) as i64 - i64::from(padding);

    let mut state = huf_init_state(dtable, src, &mut bit_offset)?;

    let mut symbols_written = 0;
    while bit_offset > -i64::from(dtable.max_bits) {
        // Iterate over the stream, decoding one symbol at a time
        let symb = huf_decode_symbol(dtable, &mut state, src, &mut bit_offset)?;
        out.write_byte(symb)?;
        symbols_written += 1;
    }
    // "The process continues up to reading the required number of symbols per
    // stream. If a bitstream is not entirely and exactly consumed, hence
    // reaching exactly its beginning position with all bits consumed, the
    // decoding process is considered faulty."

    // When all symbols have been decoded, the final state value shouldn't have
    // any data from the stream, so it should have "read" dtable->max_bits from
    // before the start of `src`
    // Therefore `offset`, the edge to start reading new bits at, should be
    // dtable->max_bits before the start of the stream
    if bit_offset != -i64::from(dtable.max_bits) {
        return corruption();
    }

    Ok(symbols_written)
}

/// `HUF_decompress_4stream`: same as previous but decodes 4 streams, formatted as in the
/// Zstandard specification. `src_len` must be the exact length of the Huffman-coded block.
fn huf_decompress_4stream(dtable: &HufDtable, out: &mut OStream, input: &mut IStream) -> R<usize> {
    // "Compressed size is provided explicitly : in the 4-streams variant,
    // bitstreams are preceded by 3 unsigned little-endian 16-bits values. Each
    // value represents the compressed size of one stream, in order. The last
    // stream size is deducted from total compressed size and from previously
    // decoded stream sizes"
    let csize1 = input.read_bits(16)? as usize;
    let csize2 = input.read_bits(16)? as usize;
    let csize3 = input.read_bits(16)? as usize;

    let mut in1 = input.make_sub_istream(csize1)?;
    let mut in2 = input.make_sub_istream(csize2)?;
    let mut in3 = input.make_sub_istream(csize3)?;
    let mut in4 = input.make_sub_istream(input.istream_len())?;

    let mut total_output = 0;
    // Decode each stream independently for simplicity
    // If we wanted to we could decode all 4 at the same time for speed,
    // utilizing more execution units
    total_output += huf_decompress_1stream(dtable, out, &mut in1)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in2)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in3)?;
    total_output += huf_decompress_1stream(dtable, out, &mut in4)?;

    Ok(total_output)
}

/// `HUF_init_dtable`: initializes a Huffman table using canonical Huffman codes. For more
/// explanation on canonical Huffman codes see
/// <https://www.cs.scranton.edu/~mccloske/courses/cmps340/huff_canonical_dec2015.html>. Codes
/// within a level are allocated in symbol order (i.e. smaller symbols get earlier codes).
fn huf_init_dtable(bits: &[u8]) -> R<HufDtable> {
    let num_symbs = bits.len();
    if num_symbs > HUF_MAX_SYMBS {
        return error("Too many symbols for Huffman");
    }

    let mut max_bits = 0usize;
    let mut rank_count = [0u16; HUF_MAX_BITS + 1];

    // Count the number of symbols for each number of bits, and determine the
    // depth of the tree
    for &b in bits {
        if usize::from(b) > HUF_MAX_BITS {
            return error("Huffman table depth too large");
        }
        max_bits = max_bits.max(usize::from(b));
        rank_count[usize::from(b)] += 1;
    }

    let table_size = 1usize << max_bits;
    let mut table = HufDtable {
        symbols: vec![0; table_size],
        num_bits: vec![0; table_size],
        max_bits: max_bits as i32,
    };

    // "Symbols are sorted by Weight. Within same Weight, symbols keep natural
    // order. Symbols with a Weight of zero are removed. Then, starting from
    // lowest weight, prefix codes are distributed in order."

    let mut rank_idx = [0u32; HUF_MAX_BITS + 1];
    // Initialize the starting codes for each rank (number of bits)
    rank_idx[max_bits] = 0;
    for i in (1..=max_bits).rev() {
        rank_idx[i - 1] = rank_idx[i] + u32::from(rank_count[i]) * (1 << (max_bits - i));
        // The entire range takes the same number of bits so we can memset it
        // (Weights that come to more codes than the table holds are refused just below; the
        // original has written past its table by then.)
        let (from, to) = (rank_idx[i] as usize, rank_idx[i - 1] as usize);
        if to > table_size {
            return corruption();
        }
        table.num_bits[from..to].fill(i as u8);
    }

    if rank_idx[0] as usize != table_size {
        return corruption();
    }

    // Allocate codes and fill in the table
    for (i, &b) in bits.iter().enumerate() {
        if b != 0 {
            // Allocate a code for this symbol and set its range in the table
            let code = rank_idx[usize::from(b)] as usize;
            // Since the code doesn't care about the bottom `max_bits - bits[i]`
            // bits of state, it gets a range that spans all possible values of
            // the lower bits
            let len = 1usize << (max_bits - usize::from(b));
            table.symbols[code..code + len].fill(i as u8);
            rank_idx[usize::from(b)] += len as u32;
        }
    }
    Ok(table)
}

/// `HUF_init_dtable_usingweights`: initializes a Huffman table using canonical Huffman codes
/// and weights, the `num_symbs` first of them.
fn huf_init_dtable_usingweights(weights: &[u8; HUF_MAX_SYMBS], num_symbs: usize) -> R<HufDtable> {
    // +1 because the last weight is not transmitted in the header
    if num_symbs + 1 > HUF_MAX_SYMBS {
        return error("Too many symbols for Huffman");
    }

    let mut bits = [0u8; HUF_MAX_SYMBS];

    let mut weight_sum = 0u64;
    for &weight in &weights[..num_symbs] {
        // Weights are in the same range as bit count
        if usize::from(weight) > HUF_MAX_BITS {
            return corruption();
        }
        weight_sum += if weight > 0 { 1u64 << (weight - 1) } else { 0 };
    }

    // Find the first power of 2 larger than the sum
    let max_bits = highest_set_bit(weight_sum) + 1;
    let left_over = (1u64 << max_bits) - weight_sum;
    // If the left over is not a power of 2, the weights are invalid
    if left_over & (left_over - 1) != 0 {
        return corruption();
    }

    // left_over is used to find the last weight as it's not transmitted
    // by inverting 2^(weight - 1) we can determine the value of last_weight
    let last_weight = highest_set_bit(left_over) + 1;

    for i in 0..num_symbs {
        // "Number_of_Bits = Number_of_Bits ? Max_Number_of_Bits + 1 - Weight : 0"
        bits[i] = if weights[i] > 0 {
            (max_bits + 1 - i32::from(weights[i])) as u8
        } else {
            0
        };
    }
    bits[num_symbs] = (max_bits + 1 - last_weight) as u8; // Last weight is always non-zero

    huf_init_dtable(&bits[..num_symbs + 1])
}

/******* FSE PRIMITIVES *******************************************************/
// For more description of FSE see
// https://github.com/Cyan4973/FiniteStateEntropy/

/// `FSE_peek_symbol`: return the symbol for the current state
fn fse_peek_symbol(dtable: &FseDtable, state: u16) -> u8 {
    dtable.symbols[usize::from(state)]
}

/// `FSE_update_state`: read the number of bits necessary to update state, update, and shift
/// offset back to reflect the bits read
fn fse_update_state(dtable: &FseDtable, state: &mut u16, src: &[u8], offset: &mut i64) -> R<()> {
    let bits = dtable.num_bits[usize::from(*state)];
    let rest = stream_read_bits(src, i32::from(bits), offset)? as u16;
    *state = dtable.new_state_base[usize::from(*state)].wrapping_add(rest);
    Ok(())
}

/// `FSE_decode_symbol`: decodes a single FSE symbol and updates the offset
fn fse_decode_symbol(dtable: &FseDtable, state: &mut u16, src: &[u8], offset: &mut i64) -> R<u8> {
    let symb = fse_peek_symbol(dtable, *state);
    fse_update_state(dtable, state, src, offset)?;
    Ok(symb)
}

/// `FSE_init_state`: read bits from the stream to initialize the state and shift offset back
fn fse_init_state(dtable: &FseDtable, src: &[u8], offset: &mut i64) -> R<u16> {
    // Read in a full `accuracy_log` bits to initialize the state
    let bits = dtable.accuracy_log;
    Ok(stream_read_bits(src, bits, offset)? as u16)
}

/// `FSE_decompress_interleaved2`: decompress two interleaved bitstreams (e.g. compressed
/// Huffman weights) using an FSE decoding table. `src_len` must be the exact length of the
/// block.
fn fse_decompress_interleaved2(
    dtable: &FseDtable,
    out: &mut OStream,
    input: &mut IStream,
) -> R<usize> {
    let len = input.istream_len();
    if len == 0 {
        return inp_size();
    }
    let src = input.get_read_ptr(len)?;

    // "Each bitstream must be read backward, that is starting from the end down
    // to the beginning. Therefore it's necessary to know the size of each
    // bitstream.
    //
    // It's also necessary to know exactly which bit is the latest. This is
    // detected by a final bit flag : the highest bit of latest byte is a
    // final-bit-flag. Consequently, a last byte of 0 is not possible. And the
    // final-bit-flag itself is not part of the useful bitstream. Hence, the
    // last byte contains between 0 and 7 useful bits."
    let padding = 8 - highest_set_bit(u64::from(src[len - 1]));
    let mut offset = (len * 8) as i64 - i64::from(padding);

    // "The first state (State1) encodes the even indexed symbols, and the
    // second (State2) encodes the odd indexes. State1 is initialized first, and
    // then State2, and they take turn decoding a single symbol and updating
    // their state."
    let mut state1 = fse_init_state(dtable, src, &mut offset)?;
    let mut state2 = fse_init_state(dtable, src, &mut offset)?;

    // Decode until we overflow the stream
    // Since we decode in reverse order, overflowing the stream is offset going
    // negative
    let mut symbols_written = 0;
    loop {
        // "The number of symbols to decode is determined by tracking bitStream
        // overflow condition: If updating state after decoding a symbol would
        // require more bits than available in the stream, it is assumed the
        // extra bits are filled with 0. Therefore, iterating beyond the last
        // bit of the stream will produce up to 2 erroneous symbols which will
        // not be written"
        let symb = fse_decode_symbol(dtable, &mut state1, src, &mut offset)?;
        out.write_byte(symb)?;
        symbols_written += 1;
        if offset < 0 {
            // There's still a symbol to decode in state2
            out.write_byte(fse_peek_symbol(dtable, state2))?;
            symbols_written += 1;
            break;
        }

        let symb = fse_decode_symbol(dtable, &mut state2, src, &mut offset)?;
        out.write_byte(symb)?;
        symbols_written += 1;
        if offset < 0 {
            // There's still a symbol to decode in state1
            out.write_byte(fse_peek_symbol(dtable, state1))?;
            symbols_written += 1;
            break;
        }
    }

    Ok(symbols_written)
}

/// `FSE_init_dtable`: initialize a decoding table using normalized frequencies.
fn fse_init_dtable(norm_freqs: &[i16], accuracy_log: i32) -> R<FseDtable> {
    let num_symbs = norm_freqs.len();
    if accuracy_log > FSE_MAX_ACCURACY_LOG {
        return error("FSE accuracy too large");
    }
    if num_symbs > FSE_MAX_SYMBS {
        return error("Too many symbols for FSE");
    }

    let size = 1usize << accuracy_log;
    let mut dtable = FseDtable {
        symbols: vec![0; size],
        num_bits: vec![0; size],
        new_state_base: vec![0; size],
        accuracy_log,
    };

    // Used to determine how many bits need to be read for each state,
    // and where the destination range should start
    // Needs to be u16 because max value is 2 * max number of symbols,
    // which can be larger than a byte can store
    let mut state_desc = [0u16; FSE_MAX_SYMBS];

    // "Symbols are scanned in their natural order for "less than 1"
    // probabilities. Symbols with this probability are being attributed a
    // single cell, starting from the end of the table. These symbols define a
    // full state reset, reading Accuracy_Log bits."
    let mut high_threshold = size;
    for (s, &freq) in norm_freqs.iter().enumerate() {
        // Scan for low probability symbols to put at the top
        if freq == -1 {
            // (More of them than the table has cells is no table. The original writes
            // before its table.)
            if high_threshold == 0 {
                return corruption();
            }
            high_threshold -= 1;
            dtable.symbols[high_threshold] = s as u8;
            state_desc[s] = 1;
        }
    }

    // "All remaining symbols are sorted in their natural order. Starting from
    // symbol 0 and table position 0, each symbol gets attributed as many cells
    // as its probability. Cell allocation is spread, not linear."
    // Place the rest in the table
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos = 0usize;
    for (s, &freq) in norm_freqs.iter().enumerate() {
        if freq <= 0 {
            continue;
        }

        state_desc[s] = freq as u16;

        for _ in 0..freq {
            // Give `norm_freqs[s]` states to symbol s
            dtable.symbols[pos] = s as u8;
            // "A position is skipped if already occupied, typically by a "less
            // than 1" probability symbol."
            loop {
                pos = (pos + step) & mask;
                if pos < high_threshold {
                    break;
                }
                // (With no cell below the low-probability ones there is nowhere to go. The
                // original goes round for ever.)
                if high_threshold == 0 {
                    return corruption();
                }
            }
            // Note: no other collision checking is necessary as `step` is
            // coprime to `size`, so the cycle will visit each position exactly
            // once
        }
    }
    if pos != 0 {
        return corruption();
    }

    // Now we can fill baseline and num bits
    for i in 0..size {
        let symbol = usize::from(dtable.symbols[i]);
        let next_state_desc = state_desc[symbol];
        state_desc[symbol] = state_desc[symbol].wrapping_add(1);
        // (A cell no symbol was given holds a symbol of no states, which the original takes
        // from memory it has not set. Tables from a header or from the format leave none.)
        if next_state_desc == 0 {
            return corruption();
        }
        // Fills in the table appropriately, next_state_desc increases by symbol
        // over time, decreasing number of bits
        dtable.num_bits[i] = (accuracy_log - highest_set_bit(u64::from(next_state_desc))) as u8;
        // Baseline increases until the bit threshold is passed, at which point
        // it resets to 0
        dtable.new_state_base[i] =
            ((u32::from(next_state_desc) << dtable.num_bits[i]) as u16).wrapping_sub(size as u16);
    }
    Ok(dtable)
}

/// `FSE_decode_header`: decode an FSE header as defined in the Zstandard format specification
/// and use the decoded frequencies to initialize a decoding table.
fn fse_decode_header(input: &mut IStream, max_accuracy_log: i32) -> R<FseDtable> {
    // "An FSE distribution table describes the probabilities of all symbols
    // from 0 to the last present one (included) on a normalized scale of 1 <<
    // Accuracy_Log .
    //
    // It's a bitstream which is read forward, in little-endian fashion. It's
    // not necessary to know its exact size, since it will be discovered and
    // reported by the decoding process.
    if max_accuracy_log > FSE_MAX_ACCURACY_LOG {
        return error("FSE accuracy too large");
    }

    // The bitstream starts by reporting on which scale it operates.
    // Accuracy_Log = low4bits + 5. Note that maximum Accuracy_Log for literal
    // and match lengths is 9, and for offsets is 8. Higher values are
    // considered errors."
    let accuracy_log = 5 + input.read_bits(4)? as i32;
    if accuracy_log > max_accuracy_log {
        return error("FSE accuracy too large");
    }

    // "Then follows each symbol value, from 0 to last present one. The number
    // of bits used by each field is variable. It depends on :
    //
    // Remaining probabilities + 1 : example : Presuming an Accuracy_Log of 8,
    // and presuming 100 probabilities points have already been distributed, the
    // decoder may read any value from 0 to 255 - 100 + 1 == 156 (inclusive).
    // Therefore, it must read log2sup(156) == 8 bits.
    //
    // Value decoded : small values use 1 less bit : example : Presuming values
    // from 0 to 156 (inclusive) are possible, 255-156 = 99 values are remaining
    // in an 8-bits field. They are used this way : first 99 values (hence from
    // 0 to 98) use only 7 bits, values from 99 to 156 use 8 bits. "

    let mut remaining = 1i32 << accuracy_log;
    let mut frequencies = [0i16; FSE_MAX_SYMBS];

    let mut symb = 0;
    while remaining > 0 && symb < FSE_MAX_SYMBS {
        // Log of the number of possible values we could read
        let bits = highest_set_bit((remaining + 1) as u64) + 1;

        let mut val = input.read_bits(bits)? as u16;

        // Try to mask out the lower bits to see if it qualifies for the "small
        // value" threshold
        let lower_mask = (1u16 << (bits - 1)) - 1;
        let threshold = ((1u32 << bits) - 1 - (remaining + 1) as u32) as u16;

        if (val & lower_mask) < threshold {
            input.rewind_bits(1)?;
            val &= lower_mask;
        } else if val > lower_mask {
            val = val.wrapping_sub(threshold);
        }

        // "Probability is obtained from Value decoded by following formula :
        // Proba = value - 1"
        let proba = (val as i16).wrapping_sub(1);

        // "It means value 0 becomes negative probability -1. -1 is a special
        // probability, which means "less than 1". Its effect on distribution
        // table is described in next paragraph. For the purpose of calculating
        // cumulated distribution, it counts as one."
        remaining -= i32::from(proba).abs();

        frequencies[symb] = proba;
        symb += 1;

        // "When a symbol has a probability of zero, it is followed by a 2-bits
        // repeat flag. This repeat flag tells how many probabilities of zeroes
        // follow the current one. It provides a number ranging from 0 to 3. If
        // it is a 3, another 2-bits repeat flag follows, and so on."
        if proba == 0 {
            // Read the next two bits to see how many more 0s
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

    // "When last symbol reaches cumulated total of 1 << Accuracy_Log, decoding
    // is complete. If the last symbol makes cumulated total go above 1 <<
    // Accuracy_Log, distribution is considered corrupted."
    if remaining != 0 || symb >= FSE_MAX_SYMBS {
        return corruption();
    }

    // Initialize the decoding table using the determined weights
    fse_init_dtable(&frequencies[..symb], accuracy_log)
}

/// `FSE_init_dtable_rle`: initialize an FSE table that will always return the same symbol and
/// consume 0 bits per symbol, to be used for RLE mode in sequence commands
fn fse_init_dtable_rle(symb: u8) -> FseDtable {
    // This table only has one symbol, and it never needs any more bits to transition
    FseDtable {
        symbols: vec![symb],
        num_bits: vec![0],
        new_state_base: vec![0],
        accuracy_log: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_read_both_ways() {
        let bytes = [0b1010_0110, 0b0000_1111, 0xff];
        assert_eq!(read_bits_le(&bytes, 3, 0), Ok(0b110));
        assert_eq!(read_bits_le(&bytes, 7, 3), Ok(0b111_0100));
        assert_eq!(read_bits_le(&bytes, 24, 0), Ok(0xff0fa6));
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
        assert_eq!(get_decompressed_size(&raw), Ok(Some(5)));
        assert_eq!(
            decompress(&raw, 4),
            Err(ZstdError("Output buffer too small for output"))
        );
        assert_eq!(
            decompress(&raw[..12], 5),
            Err(ZstdError(
                "Input buffer smaller than it should be or input is corrupted"
            ))
        );
        // One block of a byte repeated, with a window and no size.
        let rle = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x53, 0, 0, b'z'];
        assert_eq!(decompress(&rle, 100).as_deref(), Ok(&[b'z'; 10][..]));
        assert_eq!(get_decompressed_size(&rle), Ok(None));
        // A compressed block: raw literals "abc", and one sequence that copies them twice
        // more (literal length 3, match length 6, offset 3: the predefined codes 3, 3 and 2,
        // with two extra bits for the offset). Its bits, from the last read to the first:
        // the two extra bits, the three states, and the bit that marks the end.
        let state = |distribution: &[i16], accuracy_log, code: u8| {
            fse_init_dtable(distribution, accuracy_log)
                .unwrap()
                .symbols
                .iter()
                .position(|&s| s == code)
                .unwrap() as u32
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
            Err(ZstdError("Output buffer too small for output"))
        );
        // The same with one bit more than the sequence takes.
        let mut longer = packed.clone();
        longer[15..18].copy_from_slice(&(((bits & !(1 << 19)) | (1 << 20)).to_le_bytes()[..3]));
        assert_eq!(
            decompress(&longer, 9),
            Err(ZstdError("Corruption detected while decompressing"))
        );
        // No frame, a reserved bit, a block of the kind there is none of.
        assert_eq!(
            decompress(b"not zstd", 10),
            Err(ZstdError("Tried to decode non-ZSTD frame"))
        );
        assert_eq!(
            get_decompressed_size(b"not zstd"),
            Err(ZstdError("ZSTD frame magic number did not match"))
        );
        assert_eq!(
            decompress(&[0x28, 0xb5, 0x2f, 0xfd, 0x28, 0], 10),
            Err(ZstdError("Corruption detected while decompressing"))
        );
        assert_eq!(
            decompress(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 0x07, 0, 0], 10),
            Err(ZstdError("Corruption detected while decompressing"))
        );
        assert_eq!(
            decompress(&[], 10),
            Err(ZstdError(
                "Input buffer smaller than it should be or input is corrupted"
            ))
        );
    }

    #[test]
    fn huffman_tables_from_weights() {
        // Weights 1, 1 and (worked out) 2: codes of two bits, two bits and one bit.
        let mut weights = [0u8; HUF_MAX_SYMBS];
        weights[0] = 1;
        weights[1] = 1;
        let table = huf_init_dtable_usingweights(&weights, 2).unwrap();
        assert_eq!(
            (table.max_bits, &table.symbols[..], &table.num_bits[..]),
            (2, &[0u8, 1, 2, 2][..], &[2u8, 2, 1, 1][..])
        );
        // Weights that leave no power of two for the last, and none at all.
        weights[0] = 3;
        assert!(huf_init_dtable_usingweights(&weights, 2).is_err());
        assert!(huf_init_dtable_usingweights(&[0; HUF_MAX_SYMBS], 4).is_err());
        assert_eq!(
            huf_init_dtable_usingweights(&weights, 256).err(),
            Some(ZstdError("Too many symbols for Huffman"))
        );
        assert_eq!(
            huf_init_dtable(&[17]).err(),
            Some(ZstdError("Huffman table depth too large"))
        );
    }

    #[test]
    fn the_predefined_tables_are_whole() {
        for (distribution, accuracy_log) in [
            (&SEQ_LITERAL_LENGTH_DEFAULT_DIST[..], 6),
            (&SEQ_OFFSET_DEFAULT_DIST[..], 5),
            (&SEQ_MATCH_LENGTH_DEFAULT_DIST[..], 6),
        ] {
            let table = fse_init_dtable(distribution, accuracy_log).unwrap();
            let size = 1usize << accuracy_log;
            assert_eq!(table.symbols.len(), size);
            // Every state leads to states of the table.
            for i in 0..size {
                assert!(usize::from(table.new_state_base[i]) + (1 << table.num_bits[i]) <= size);
            }
            // Each symbol has as many cells as its share (one for "less than one").
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
        // Shares that do not come to the size of the table.
        assert!(fse_init_dtable(&[16, 15], 5).is_err());
        assert!(fse_init_dtable(&[1], 16).is_err());
    }
}
