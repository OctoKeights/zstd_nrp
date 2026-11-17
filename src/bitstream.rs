//! The writing half of zstd's bit stream: a port of the encoder in `lib/common/bitstream.h`
//! of zstd v1.5.7, as a 64-bit build has it.
//!
//! Bits go in from the low end of a 64-bit container; whole bytes leave it for the output
//! when it is flushed. A flush always writes eight bytes at the current place, which is why
//! the stream keeps eight bytes of the output in hand.

const BIT_MASK: [u32; 32] = [
    0, 1, 3, 7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF, 0x3FFF, 0x7FFF,
    0xFFFF, 0x1FFFF, 0x3FFFF, 0x7FFFF, 0xFFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF, 0x1FFFFFF,
    0x3FFFFFF, 0x7FFFFFF, 0xFFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF,
];

/// `BIT_CStream_t`.
pub(crate) struct BitCStream<'a> {
    bit_container: u64,
    bit_pos: u32,
    /// From `startPtr`, for `dstCapacity` bytes.
    dst: &'a mut [u8],
    ptr: usize,
    end_ptr: usize,
}

impl<'a> BitCStream<'a> {
    /// `BIT_initCStream`. `None` where the original answers `dstSize_tooSmall`.
    pub(crate) fn init(dst: &'a mut [u8]) -> Option<BitCStream<'a>> {
        if dst.len() <= 8 {
            return None;
        }
        let end_ptr = dst.len() - 8;
        Some(BitCStream {
            bit_container: 0,
            bit_pos: 0,
            dst,
            ptr: 0,
            end_ptr,
        })
    }

    /// `BIT_addBits`: the low `nb_bits` bits of `value`. `nb_bits` is under 32.
    #[inline]
    pub(crate) fn add_bits(&mut self, value: u64, nb_bits: u32) {
        self.bit_container |= (value & BIT_MASK[nb_bits as usize] as u64) << self.bit_pos;
        self.bit_pos += nb_bits;
    }

    /// `BIT_addBitsFast`: `value` has nothing above its low `nb_bits` bits.
    #[inline]
    pub(crate) fn add_bits_fast(&mut self, value: u64, nb_bits: u32) {
        self.bit_container |= value << self.bit_pos;
        self.bit_pos += nb_bits;
    }

    #[inline]
    fn write_container(&mut self) -> usize {
        let nb_bytes = (self.bit_pos >> 3) as usize;
        self.dst[self.ptr..self.ptr + 8].copy_from_slice(&self.bit_container.to_le_bytes());
        nb_bytes
    }

    /// `BIT_flushBitsFast`: for a caller that knows the output is large enough.
    #[inline]
    pub(crate) fn flush_bits_fast(&mut self) {
        let nb_bytes = self.write_container();
        self.ptr += nb_bytes;
        self.bit_pos &= 7;
        self.bit_container = self
            .bit_container
            .checked_shr(nb_bytes as u32 * 8)
            .unwrap_or(0);
    }

    /// `BIT_flushBits`: stops at the end of the output; [`BitCStream::close`] then reports
    /// the overflow.
    #[inline]
    pub(crate) fn flush_bits(&mut self) {
        let nb_bytes = self.write_container();
        self.ptr += nb_bytes;
        if self.ptr > self.end_ptr {
            self.ptr = self.end_ptr;
        }
        self.bit_pos &= 7;
        self.bit_container = self
            .bit_container
            .checked_shr(nb_bytes as u32 * 8)
            .unwrap_or(0);
    }

    /// `BIT_closeCStream`: the size of the stream in bytes, or 0 if it did not fit.
    pub(crate) fn close(mut self) -> usize {
        self.add_bits_fast(1, 1);
        self.flush_bits();
        if self.ptr >= self.end_ptr {
            return 0;
        }
        self.ptr + usize::from(self.bit_pos > 0)
    }
}
