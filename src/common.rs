//! What the files of the compressor share: the error codes, and the small helpers of
//! `lib/common/bits.h` and `lib/common/mem.h` of zstd v1.5.7.

/// The codes of `lib/zstd_errors.h` that the compressor's own functions answer with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CError {
    Generic,
    DstSizeTooSmall,
    TableLogTooLarge,
    MaxSymbolValueTooLarge,
    SrcSizeWrong,
}

pub(crate) type CResult<T> = Result<T, CError>;

/// `ZSTD_highbit32`: the place of the highest set bit. The original leaves 0 undefined;
/// nothing asks for it.
#[inline]
pub(crate) fn highbit32(val: u32) -> u32 {
    debug_assert!(val != 0);
    31 - (val | 1).leading_zeros()
}

/// `MEM_read16`, little-endian.
#[inline]
pub(crate) fn read16(src: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([src[pos], src[pos + 1]])
}

/// `MEM_read32`, little-endian.
#[inline]
pub(crate) fn read32(src: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]])
}

/// `MEM_read64`, little-endian.
#[inline]
pub(crate) fn read64(src: &[u8], pos: usize) -> u64 {
    let b = &src[pos..pos + 8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `MEM_writeLE16`.
#[inline]
pub(crate) fn write_le16(dst: &mut [u8], pos: usize, value: u16) {
    dst[pos..pos + 2].copy_from_slice(&value.to_le_bytes());
}

/// `MEM_writeLE24`.
#[inline]
pub(crate) fn write_le24(dst: &mut [u8], pos: usize, value: u32) {
    dst[pos..pos + 3].copy_from_slice(&value.to_le_bytes()[..3]);
}

/// `MEM_writeLE32`.
#[inline]
pub(crate) fn write_le32(dst: &mut [u8], pos: usize, value: u32) {
    dst[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
}
