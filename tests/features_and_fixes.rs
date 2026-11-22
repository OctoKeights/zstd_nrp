//! Integration and regression tests for all bug fixes, safety hardening, `no_std`-compatible
//! APIs, reusable contexts, options, skippable/concatenated frames, and `std::io` adapters.

use std::io::{Cursor, Read, Write};

use zstd_nrp::compare_hooks;
use zstd_nrp::io::{Decoder, Encoder};
use zstd_nrp::{
    CompressError, CompressOptions, Compressor, DecompressErrorKind, DecompressOptions,
    Decompressor, Dictionary, Level, checked_compress_bound, compress, compress_bound,
    compress_into, compress_into_with_options, compress_with_options, decompress, decompress_frame,
    decompress_frame_with_options, decompress_into, decompress_into_with_options,
    decompress_stream, decompress_with_dict, decompress_with_options, decompressed_size,
    frame_dict_id,
};

#[test]
fn compare_hooks_fse_normalize_and_table_log_hardening() {
    // strategy_of edge cases
    for level in [i32::MIN, -131_073, -131_072, -1, 0, 3, 22, 23, i32::MAX] {
        for size in [0usize, 1, 1024, usize::MAX] {
            let s = compare_hooks::strategy_of(level, size);
            assert!((1..=9).contains(&s));
        }
    }

    // fse_optimal_table_log edge cases: src_size 0, 1, > u32::MAX, max_symbol_value 0, > 255
    for src_size in [0usize, 1, 2, usize::try_from(u32::MAX).unwrap(), usize::MAX] {
        for max_sv in [0u32, 1, 255, 256, u32::MAX] {
            for max_log in [0u32, 4, 5, 11, 12, 30, u32::MAX] {
                let log = compare_hooks::fse_optimal_table_log(max_log, src_size, max_sv);
                assert!((5..=12).contains(&log));
            }
        }
    }

    #[cfg(target_pointer_width = "64")]
    {
        for src_size in [1usize << 32, (1usize << 32) + 1] {
            let log = compare_hooks::fse_optimal_table_log(11, src_size, 10);
            assert!((5..=12).contains(&log));
        }
    }

    // fse_normalize_count hardening: div-by-zero, total > u32::MAX, OOB slices, mismatched sums,
    // table_log out of bounds, max_symbol_value > 255, and normalize_m2 corner cases.
    let mut norm = [0i16; 256];
    let mut count = [0u32; 256];
    count[0] = 10;
    count[1] = 20;

    // total == 0 must not divide by zero
    assert!(compare_hooks::fse_normalize_count(&mut norm, 5, &count, 0, 1, false).is_err());
    #[cfg(target_pointer_width = "64")]
    {
        // total == 1 << 32 previously truncated `total as u32` to 0 and divided by zero!
        assert!(
            compare_hooks::fse_normalize_count(&mut norm, 5, &count, 1usize << 32, 1, false)
                .is_err()
        );
    }
    // max_symbol_value > 255 -> MaxSymbolValueTooLarge (46)
    assert_eq!(
        compare_hooks::fse_normalize_count(&mut norm, 5, &count, 30, 256, false),
        Err(46)
    );
    // table_log > 12 -> TableLogTooLarge (44); table_log in 1..5 -> Generic (1)
    assert_eq!(
        compare_hooks::fse_normalize_count(&mut norm, 13, &count, 30, 1, false),
        Err(44)
    );
    assert_eq!(
        compare_hooks::fse_normalize_count(&mut norm, 4, &count, 30, 1, false),
        Err(1)
    );
    // Short slices must not index OOB
    assert!(compare_hooks::fse_normalize_count(&mut norm[..1], 5, &count, 30, 1, false).is_err());
    assert!(compare_hooks::fse_normalize_count(&mut norm, 5, &count[..1], 30, 1, false).is_err());
    // Mismatched count sum vs total (previously underflowed `total -= count[s]` or looped forever!)
    assert!(compare_hooks::fse_normalize_count(&mut norm, 5, &count, 5, 1, true).is_err());
    assert!(compare_hooks::fse_normalize_count(&mut norm, 5, &count, 500, 1, true).is_err());
    let ones = [1u32; 16];
    assert!(compare_hooks::fse_normalize_count(&mut norm, 5, &ones, 64, 15, true).is_err());

    // Valid single-symbol RLE case with max_symbol_value == 0
    assert_eq!(
        compare_hooks::fse_normalize_count(&mut norm, 5, &[30], 30, 0, false),
        Ok(0)
    );
}

#[test]
fn compare_hooks_fse_write_compress_and_huf_literals_hardening() {
    let norm = [0i16; 256];
    // fse_write_ncount hardening
    let mut header = [0u8; 512];
    assert_eq!(
        compare_hooks::fse_write_ncount(&mut header, &norm, 256, 5),
        Err(46)
    );
    assert_eq!(
        compare_hooks::fse_write_ncount(&mut header, &norm, 1, 13),
        Err(44)
    );
    assert_eq!(
        compare_hooks::fse_write_ncount(&mut header, &norm, 1, 4),
        Err(1)
    );
    assert!(compare_hooks::fse_write_ncount(&mut header, &norm[..1], 1, 5).is_err());
    assert!(compare_hooks::fse_write_ncount(&mut header, &[i16::MIN, 32], 1, 5).is_err());
    assert!(compare_hooks::fse_write_ncount(&mut header, &[-2, 34], 1, 5).is_err());
    assert!(compare_hooks::fse_write_ncount(&mut header, &[i16::MAX, 1], 1, 5).is_err());
    assert_eq!(
        compare_hooks::fse_write_ncount(&mut [], &[16, 16], 1, 5),
        Err(70)
    );
    assert_eq!(
        compare_hooks::fse_write_ncount(&mut [0u8; 1], &[16, 16], 1, 5),
        Err(70)
    );

    // fse_compress hardening
    let mut dst = [0u8; 256];
    let src = [0u8, 1, 0, 1, 0, 1];
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[16, 16], 256, 5),
        0
    );
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[16, 16], 1, 4),
        0
    );
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[16, 16], 1, 13),
        0
    );
    assert_eq!(compare_hooks::fse_compress(&mut dst, &src, &[16], 1, 5), 0);
    // Invalid norm sum or negative < -1
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[10, 10], 1, 5),
        0
    );
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[20, 20], 1, 5),
        0
    );
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &src, &[-2, 34], 1, 5),
        0
    );
    // Symbol in `src` above max_symbol_value or with zero probability in `norm`
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &[0, 1, 2, 0], &[16, 16], 1, 5),
        0
    );
    assert_eq!(
        compare_hooks::fse_compress(&mut dst, &[0, 1, 0, 1], &[32, 0], 1, 5),
        0
    );
    // Valid single-symbol table with matching symbols
    assert!(compare_hooks::fse_compress(&mut dst, &[0, 0, 0, 0], &[32, 0], 1, 5) > 0);
}

#[test]
fn compare_hooks_huf_and_literals_hardening() {
    let mut dst = [0u8; 256];
    // Huf & Literals Debug + bounds hardening
    let mut huf = compare_hooks::Huf::default();
    assert!(format!("{huf:?}").contains("Huf"));
    let mut repeat = 99;
    assert_eq!(
        huf.compress(&mut dst, b"aaaaabbbbb", false, &mut repeat, false, false),
        Err(1)
    );
    // Repeat::Valid (2) on an uninitialized Huf table must be rejected cleanly
    let mut repeat_valid = 2;
    assert_eq!(
        huf.compress(
            &mut dst,
            b"aaaaabbbbb",
            false,
            &mut repeat_valid,
            true,
            false
        ),
        Err(1)
    );
    // Oversized Huf input (> 128 KiB) -> SrcSizeWrong (72)
    let huge = vec![b'a'; 128 * 1024 + 1];
    let mut big_dst = vec![0u8; 200_000];
    let mut r0 = 0;
    assert_eq!(
        huf.compress(&mut big_dst, &huge, false, &mut r0, false, false),
        Err(72)
    );

    let mut literals = compare_hooks::Literals::default();
    assert!(format!("{literals:?}").contains("Literals"));
    assert_eq!(
        literals.compress(&mut dst, b"hello", 0, false, false),
        Err(1)
    );
    assert_eq!(
        literals.compress(&mut dst, b"hello", 10, false, false),
        Err(1)
    );
    assert_eq!(
        literals.compress(&mut big_dst, &huge, 1, false, false),
        Err(72)
    );
}

#[test]
fn compress_bound_saturates_and_checked_compress_bound_detects_overflow() {
    assert_eq!(compress_bound(0), 64);
    assert_eq!(checked_compress_bound(0), Some(64));
    assert_eq!(checked_compress_bound(128 << 10), Some((128 << 10) + 512));

    assert_eq!(compress_bound(usize::MAX), usize::MAX);
    assert_eq!(compress_bound(usize::MAX - 1024), usize::MAX);
    assert_eq!(checked_compress_bound(usize::MAX), None);
    assert_eq!(checked_compress_bound(usize::MAX - (usize::MAX >> 9)), None);
}

#[test]
fn decompressed_size_distinguishes_explicit_zero_content_size_from_absent() {
    // 1) Single_Segment_Flag == 0, FCS_Flag == 0 (absent): returns Ok(None)
    let absent_fcs = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x01, 0x00, 0x00];
    assert_eq!(decompressed_size(&absent_fcs), Ok(None));
    assert_eq!(decompress(&absent_fcs, 10).unwrap(), b"");

    // 2) Single_Segment_Flag == 0, FCS_Flag == 2 (explicit 4-byte FCS == 0): MUST be Ok(Some(0))!
    let explicit_4byte_zero = [
        0x28, 0xB5, 0x2F, 0xFD, // magic
        0x80, // FCS_Flag = 2 (4 bytes), Single_Segment = 0
        0x00, // Window_Descriptor (1 KiB)
        0x00, 0x00, 0x00, 0x00, // Frame_Content_Size = 0
        0x01, 0x00, 0x00, // last empty raw block
    ];
    assert_eq!(decompressed_size(&explicit_4byte_zero), Ok(Some(0)));
    assert_eq!(decompress(&explicit_4byte_zero, 0).unwrap(), b"");

    // 3) Single_Segment_Flag == 0, FCS_Flag == 3 (explicit 8-byte FCS == 0): MUST be Ok(Some(0))!
    let explicit_8byte_zero = [
        0x28, 0xB5, 0x2F, 0xFD, // magic
        0xC0, // FCS_Flag = 3 (8 bytes), Single_Segment = 0
        0x00, // Window_Descriptor
        0, 0, 0, 0, 0, 0, 0, 0, // Frame_Content_Size = 0
        0x01, 0x00, 0x00, // last empty raw block
    ];
    assert_eq!(decompressed_size(&explicit_8byte_zero), Ok(Some(0)));
    assert_eq!(decompress(&explicit_8byte_zero, 0).unwrap(), b"");

    // 4) Single_Segment_Flag == 0, FCS_Flag == 1 (2-byte FCS == 0 + 256 = 256)
    let explicit_2byte = [
        0x28, 0xB5, 0x2F, 0xFD, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];
    assert_eq!(decompressed_size(&explicit_2byte), Ok(Some(256)));
}

#[test]
fn large_sequence_count_header_stops_at_max_len_without_transient_allocation() {
    // Block 1 emits 4 raw bytes so `total_output` is 4; Block 2 claims 0x7F00 + 0xFFFF = 98,047
    // RLE sequences of (ll=0, rep1=1, ml=3). With max_len = 32, on-the-fly execution stops
    // immediately without allocating a 1.18 MiB Vec<SequenceCommand>.
    let block_payload = [
        0x08,
        b'A', // Raw_Literals_Block of 1 byte ('A')
        0xFF,
        0xFF,
        0xFF,          // Number_of_Sequences = 98,047
        0b01_01_01_00, // LL = RLE, OF = RLE, ML = RLE
        0,             // LL symbol 0 (0 literals)
        0,             // OF symbol 0 (offset_value = 1)
        0,             // ML symbol 0 (match_length = 3)
        0x01,          // bitstream: 1-bit end mark at bit 0 (0 bits consumed by RLE states/extras)
    ];
    let mut two_block = vec![
        0x28,
        0xB5,
        0x2F,
        0xFD,
        0x00,
        0x40, // frame header (window 256 KiB)
        (4 << 3),
        0,
        0,
        b'X',
        b'Y',
        b'Z',
        b'W', // Block 1 (not last, raw, 4 bytes)
    ];
    let b2_hdr = 1u32 | (2u32 << 1) | ((block_payload.len() as u32) << 3);
    two_block.extend_from_slice(&b2_hdr.to_le_bytes()[..3]);
    two_block.extend_from_slice(&block_payload);

    let err = decompress(&two_block, 32).unwrap_err();
    assert_eq!(err.kind(), DecompressErrorKind::OutputTooSmall);
    assert_eq!(err.message(), "Output buffer too small for output");

    // With sufficient room, all 98,047 sequences decode cleanly (4 + 98_047 * 3 + 1 = 294,146 bytes).
    let full = decompress(&two_block, 300_000).unwrap();
    assert_eq!(full.len(), 4 + 98_047 * 3 + 1);
}

#[test]
fn periodic_overlapping_matches_decode_identically_in_vec_and_slice_modes() {
    // Periodic patterns with periods 2, 3, 5, 7, 13 repeated thousands of times force
    // overlapping matches (`offset < match_length`) that exercise doubling `extend_from_within`
    // and `copy_within`.
    for period in [1usize, 2, 3, 4, 5, 7, 13, 37] {
        let pattern: Vec<u8> = (0..period).map(|i| b'a' + (i % 26) as u8).collect();
        let data: Vec<u8> = pattern.iter().copied().cycle().take(50_000).collect();
        let frame = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(decompress(&frame, data.len()).unwrap(), data);

        let mut slice_out = vec![0u8; data.len()];
        let written = decompress_into(&frame, &mut slice_out).unwrap();
        assert_eq!(written, data.len());
        assert_eq!(slice_out, data);
    }
}

#[test]
fn reusable_compressor_and_decompressor_match_oneshot_bit_for_bit() {
    let mut compressor = Compressor::new();
    let mut decompressor = Decompressor::new();
    assert!(format!("{compressor:?}").contains("Compressor"));
    assert!(format!("{decompressor:?}").contains("Decompressor"));

    let inputs: [Vec<u8>; 4] = [
        b"".to_vec(),
        b"short text".to_vec(),
        b"the quick brown fox jumps over the lazy dog. ".repeat(1200),
        (0..90_000u32)
            .map(|i| ((i.wrapping_mul(2_654_435_761)) >> 24) as u8)
            .collect(),
    ];

    for level_num in [-10, -1, 1, 3, 6, 13, 19] {
        let level = Level::new(level_num).unwrap();
        for data in &inputs {
            let expected = compress(data, level).unwrap();
            let reused = compressor.compress(data, level).unwrap();
            assert_eq!(reused, expected, "level {level_num}, len {}", data.len());

            // compress_into with exact bound and oversized buffer
            let mut exact_buf = vec![0u8; compress_bound(data.len())];
            let n1 = compressor
                .compress_into(data, &mut exact_buf, level)
                .unwrap();
            assert_eq!(&exact_buf[..n1], &expected[..]);

            let mut over_buf = vec![0xAAu8; compress_bound(data.len()) + 512];
            let n2 = compress_into(data, &mut over_buf, level).unwrap();
            assert_eq!(&over_buf[..n2], &expected[..]);

            // compress_into with too-small buffer
            let mut tiny = [0u8; 4];
            assert_eq!(
                compressor.compress_into(data, &mut tiny, level),
                Err(CompressError::OutputTooSmall)
            );

            // Decompressor reuse + decompress_into
            let decoded = decompressor.decompress(&reused, data.len()).unwrap();
            assert_eq!(&decoded, data);

            let mut dst = vec![0u8; data.len() + 16];
            let written = decompressor.decompress_into(&reused, &mut dst).unwrap();
            assert_eq!(written, data.len());
            assert_eq!(&dst[..written], &data[..]);

            if !data.is_empty() {
                let mut short_dst = vec![0u8; data.len() - 1];
                let err = decompressor
                    .decompress_into(&reused, &mut short_dst)
                    .unwrap_err();
                assert_eq!(err.kind(), DecompressErrorKind::OutputTooSmall);
            }
        }
    }
}

#[test]
fn dictionary_inspection_and_frame_dict_id() {
    let empty_dict = Dictionary::default();
    assert_eq!(empty_dict.id(), 0);
    assert_eq!(empty_dict.as_content(), b"");
    assert!(format!("{empty_dict:?}").contains("Dictionary"));

    let raw_bytes = b"shared dictionary prefix bytes for backreferences";
    let raw_dict = Dictionary::parse(raw_bytes).unwrap();
    assert_eq!(raw_dict.id(), 0);
    assert_eq!(raw_dict.as_content(), raw_bytes);

    let short_err = Dictionary::parse(b"short").unwrap_err();
    assert_eq!(short_err.kind(), DecompressErrorKind::InvalidDictionary);

    // Normal frame without dictionary -> frame_dict_id is Ok(None)
    let normal_frame = compress(b"hello", Level::DEFAULT).unwrap();
    assert_eq!(frame_dict_id(&normal_frame), Ok(None));

    // Hand-crafted frame headers with 1-byte, 2-byte, and 4-byte Dictionary_ID
    let frame_dict_1 = [0x28, 0xB5, 0x2F, 0xFD, 0x21, 0x42, 0x00, 0x01, 0x00, 0x00];
    assert_eq!(frame_dict_id(&frame_dict_1), Ok(Some(0x42)));

    let frame_dict_4 = [
        0x28, 0xB5, 0x2F, 0xFD, // magic
        0x23, // Single_Segment = 1, Dict_ID_Flag = 3 (4 bytes)
        0x78, 0x56, 0x34, 0x12, // Dict_ID = 0x12345678
        0x00, // FCS = 0
        0x01, 0x00, 0x00, // empty last block
    ];
    assert_eq!(frame_dict_id(&frame_dict_4), Ok(Some(0x1234_5678)));

    // Decompressing frame_dict_4 with raw_dict (id == 0 != 0x12345678) yields DictionaryMismatch
    let mismatch = decompress_with_dict(&frame_dict_4, 10, &raw_dict).unwrap_err();
    assert_eq!(mismatch.kind(), DecompressErrorKind::DictionaryMismatch);
    assert_eq!(mismatch.message(), "Wrong dictionary provided");

    // Skippable frame has no dictionary ID
    let skippable = [0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0];
    assert_eq!(frame_dict_id(&skippable), Ok(None));
    assert_eq!(
        frame_dict_id(b"bad!").unwrap_err().kind(),
        DecompressErrorKind::InvalidFrameMagic
    );
}

#[test]
fn compress_options_checksum_and_content_size_flag() {
    let payload = b"checksummed zstandard frame payload! ".repeat(500);

    // Checksum enabled, content size omitted
    let opts = CompressOptions::new(Level::DEFAULT)
        .with_checksum(true)
        .with_content_size(false);
    let mut frame = compress_with_options(&payload, opts).unwrap();

    // Header has no content size, and bit 2 (Content_Checksum_Flag) is set
    assert_eq!(frame[4] & 0x04, 0x04);
    assert_eq!(decompressed_size(&frame), Ok(None));

    // Round-trips with checksum verification enabled (default in DecompressOptions)
    let decoded = decompress_with_options(&frame, payload.len(), DecompressOptions::new()).unwrap();
    assert_eq!(decoded, payload);

    // Corrupting the 4-byte XXH64 checksum trailer triggers ChecksumMismatch
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    let err = decompress_with_options(&frame, payload.len(), DecompressOptions::new()).unwrap_err();
    assert_eq!(err.kind(), DecompressErrorKind::ChecksumMismatch);

    // Disabling checksum verification allows decoding despite the flipped trailer bit
    let unchecked = decompress_with_options(
        &frame,
        payload.len(),
        DecompressOptions::new().with_verify_checksum(false),
    )
    .unwrap();
    assert_eq!(unchecked, payload);
    assert_eq!(decompress(&frame, payload.len()).unwrap(), payload);

    // compress_into_with_options matches compress_with_options
    let mut buf = vec![0u8; compress_bound(payload.len())];
    let n = compress_into_with_options(&payload, &mut buf, opts).unwrap();
    frame[last] ^= 0x01; // restore valid checksum
    assert_eq!(&buf[..n], &frame[..]);
}

#[test]
fn strict_rfc8878_validation_catches_content_size_block_size_and_zero_offset() {
    let strict_opts = DecompressOptions::strict();
    let lax_opts = DecompressOptions::new();

    // 1) Pledged Frame_Content_Size larger than actual decoded output (pledged 10, actual 5)
    let pledged_too_big = [
        0x28, 0xB5, 0x2F, 0xFD, 0x20, 10, // Single_Segment, FCS = 10
        0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', // last raw block of 5 bytes
    ];
    assert_eq!(
        decompress_with_options(&pledged_too_big, 20, lax_opts).unwrap(),
        b"hello"
    );
    assert_eq!(
        decompress_with_options(&pledged_too_big, 20, strict_opts)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::ContentSizeMismatch
    );

    // 2) Pledged Frame_Content_Size smaller than actual decoded output (4-byte FCS = 3, actual 5)
    let pledged_too_small = [
        0x28, 0xB5, 0x2F, 0xFD, 0x80, 0x00, 3, 0, 0, 0, // FCS = 3
        0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', // 5 bytes
    ];
    assert_eq!(
        decompress_with_options(&pledged_too_small, 20, lax_opts).unwrap(),
        b"hello"
    );
    assert_eq!(
        decompress_with_options(&pledged_too_small, 20, strict_opts)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::ContentSizeMismatch
    );

    // 3) RLE block exceeding ZSTD_BLOCK_SIZE_MAX (128 KiB + 1 = 131,073)
    let oversize_len = 128 * 1024 + 1;
    let rle_hdr = 1u32 | (1u32 << 1) | ((oversize_len as u32) << 3);
    let mut oversize_rle = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x10];
    oversize_rle.extend_from_slice(&rle_hdr.to_le_bytes()[..3]);
    oversize_rle.push(b'Z');
    assert_eq!(
        decompress_with_options(&oversize_rle, oversize_len, lax_opts)
            .unwrap()
            .len(),
        oversize_len
    );
    assert_eq!(
        decompress_with_options(&oversize_rle, oversize_len, strict_opts)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::CorruptedInput
    );

    // 4) Sequence with offset == 0: ll = 0, of_code = 1 + extra bit 1 -> seq.offset = 3
    // (Repeated_Offset3 with ll == 0 -> rep[0] - 1 = 1 - 1 = 0!)
    let mut zero_offset_frame = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
    let block_body = [
        0x00,          // 0 raw literals
        0x01,          // 1 sequence
        0b01_01_01_00, // RLE tables for LL, OF, ML
        0,             // LL code 0 (ll = 0)
        1,             // OF code 1 (1 extra bit; 2 + 1 = 3 -> rep3 with ll==0 -> rep[0]-1 = 0!)
        0,             // ML code 0 (ml = 3)
        0b11,          // 1 extra bit (1) + final 1-bit end mark
    ];
    let b_hdr = 1u32 | (2u32 << 1) | ((block_body.len() as u32) << 3);
    zero_offset_frame.extend_from_slice(&b_hdr.to_le_bytes()[..3]);
    zero_offset_frame.extend_from_slice(&block_body);

    assert_eq!(
        decompress_with_options(&zero_offset_frame, 10, lax_opts).unwrap(),
        [0, 0, 0]
    );
    assert_eq!(
        decompress_with_options(&zero_offset_frame, 10, strict_opts)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::CorruptedInput
    );
}

fn make_skippable_frame(low_nibble: u8, payload: &[u8]) -> Vec<u8> {
    let magic = 0x184D_2A50u32 | u32::from(low_nibble & 0x0F);
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn concatenated_multiframe_streams_and_skippable_frames() {
    assert_eq!(decompress_stream(&[], 100).unwrap(), b"");

    let part1 = b"First frame in concatenated stream. ".repeat(40);
    let part2 = b"Second frame with checksum! ".repeat(60);
    let part3 = b"Third frame without content size.";

    let f1 = compress(&part1, Level::new(1).unwrap()).unwrap();
    let f2 = compress_with_options(
        &part2,
        CompressOptions::new(Level::DEFAULT).with_checksum(true),
    )
    .unwrap();
    let f3 = compress_with_options(
        part3,
        CompressOptions::new(Level::new(9).unwrap())
            .with_checksum(true)
            .with_content_size(false),
    )
    .unwrap();
    let skip0 = make_skippable_frame(0x0, b"metadata header");
    let skipf = make_skippable_frame(0xF, &[0xAB; 1024]);

    let mut stream = Vec::new();
    stream.extend_from_slice(&skip0);
    stream.extend_from_slice(&f1);
    stream.extend_from_slice(&skipf);
    stream.extend_from_slice(&f2);
    stream.extend_from_slice(&f3);

    let mut expected = Vec::new();
    expected.extend_from_slice(&part1);
    expected.extend_from_slice(&part2);
    expected.extend_from_slice(part3);

    // Whole-stream decode
    let decoded = decompress_stream(&stream, expected.len()).unwrap();
    assert_eq!(decoded, expected);

    // decompress_into_with_options in multi-frame mode
    let mut into_buf = vec![0u8; expected.len()];
    let n = decompress_into_with_options(
        &stream,
        &mut into_buf,
        DecompressOptions::strict().with_multi_frame(true),
    )
    .unwrap();
    assert_eq!(n, expected.len());
    assert_eq!(into_buf, expected);

    // max_len enforced across concatenated frames
    assert_eq!(
        decompress_stream(&stream, expected.len() - 1)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::OutputTooSmall
    );

    // Frame-by-frame stepping with decompress_frame
    let mut cursor = &stream[..];
    let mut stepped = Vec::new();
    let mut frame_count = 0;
    while !cursor.is_empty() {
        let (chunk, consumed) =
            decompress_frame_with_options(cursor, expected.len(), DecompressOptions::strict())
                .unwrap();
        assert!(consumed > 0);
        stepped.extend_from_slice(&chunk);
        cursor = &cursor[consumed..];
        frame_count += 1;
    }
    assert_eq!(frame_count, 5);
    assert_eq!(stepped, expected);

    // Single-frame decompress_frame also works directly
    let (single_out, single_used) = decompress_frame(&stream[skip0.len()..], part1.len()).unwrap();
    assert_eq!(single_out, part1);
    assert_eq!(single_used, f1.len());

    // Truncated skippable frame -> UnexpectedEof
    assert_eq!(
        decompress_stream(&skipf[..skipf.len() - 1], 100)
            .unwrap_err()
            .kind(),
        DecompressErrorKind::UnexpectedEof
    );

    // Skippable frames rejected when allow_skippable == false
    assert_eq!(
        decompress_with_options(&skip0, 100, DecompressOptions::new().with_skippable(false))
            .unwrap_err()
            .kind(),
        DecompressErrorKind::InvalidFrameMagic
    );
}

/// Reader wrapper that yields at most `max_chunk` bytes per `read()` call to exercise true
/// incremental streaming in `io::Decoder`.
struct TrickleReader<'a> {
    data: &'a [u8],
    pos: usize,
    max_chunk: usize,
}

impl Read for TrickleReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - self.pos)
            .min(buf.len())
            .min(self.max_chunk);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn std_io_encoder_and_decoder_streaming_roundtrips() {
    // 1) Empty stream on Decoder and Encoder
    let mut empty_dec = Decoder::new(Cursor::new(Vec::<u8>::new()));
    let mut out = Vec::new();
    empty_dec.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"");

    let empty_enc = Encoder::new(Vec::new(), Level::DEFAULT).finish().unwrap();
    Decoder::new(&empty_enc[..]).read_to_end(&mut out).unwrap();
    assert_eq!(out, b"");

    // 2) Small chunked writes, scoped Drop finish, checksums, and trickle 1-byte reads
    let payload = b"Zstandard io::Encoder and io::Decoder streaming test! ".repeat(800);
    let mut drop_compressed = Vec::new();
    {
        let mut enc = Encoder::with_options(
            &mut drop_compressed,
            CompressOptions::new(Level::DEFAULT).with_checksum(true),
        );
        for chunk in payload.chunks(17) {
            enc.write_all(chunk).unwrap();
        }
        // Dropped without explicit finish(): Drop finalizes the frame!
    }
    assert_eq!(
        decompress(&drop_compressed, payload.len()).unwrap(),
        payload
    );

    let mut trickle_dec = Decoder::new(TrickleReader {
        data: &drop_compressed,
        pos: 0,
        max_chunk: 1,
    });
    let mut trickle_out = Vec::new();
    let mut small_buf = [0u8; 13];
    loop {
        let n = trickle_dec.read(&mut small_buf).unwrap();
        if n == 0 {
            break;
        }
        trickle_out.extend_from_slice(&small_buf[..n]);
    }
    assert_eq!(trickle_out, payload);

    // 3) Explicit mid-stream Write::flush() forcing multi-block streaming mode
    let mut flushed_enc = Encoder::with_options(
        Vec::new(),
        CompressOptions::new(Level::new(6).unwrap()).with_checksum(true),
    );
    flushed_enc.write_all(&payload[..10_000]).unwrap();
    flushed_enc.flush().unwrap();
    flushed_enc.write_all(&payload[10_000..25_000]).unwrap();
    flushed_enc.flush().unwrap();
    flushed_enc.write_all(&payload[25_000..]).unwrap();
    let flushed_frame = flushed_enc.finish().unwrap();

    // Must still be a single valid Zstandard frame with verified checksum!
    assert_eq!(
        decompress_with_options(&flushed_frame, payload.len(), DecompressOptions::strict())
            .unwrap(),
        payload
    );
    let mut dec_out = Vec::new();
    Decoder::with_options(&flushed_frame[..], DecompressOptions::strict())
        .read_to_end(&mut dec_out)
        .unwrap();
    assert_eq!(dec_out, payload);
}

#[test]
fn std_io_large_stream_and_multiframe_checksum_errors() {
    let payload = b"Zstandard io::Encoder and io::Decoder streaming test! ".repeat(800);
    let drop_compressed = compress_with_options(
        &payload,
        CompressOptions::new(Level::DEFAULT).with_checksum(true),
    )
    .unwrap();
    let flushed_frame = compress_with_options(
        &payload,
        CompressOptions::new(Level::new(6).unwrap())
            .with_checksum(true)
            .with_content_size(false),
    )
    .unwrap();

    // Large > 4.5 MiB stream crossing STREAM_CHUNK_SIZE (2 MiB) twice + window compaction
    let mut large = Vec::with_capacity(4_600_000);
    let phrase = b"long streaming block across multiple 2 MiB chunks and 128 KiB blocks; ";
    while large.len() < 4_600_000 {
        large.extend_from_slice(phrase);
        large.push((large.len() >> 10) as u8);
    }
    let mut large_enc = Encoder::with_options(
        Vec::new(),
        CompressOptions::new(Level::DEFAULT).with_checksum(true),
    );
    for chunk in large.chunks(100_000) {
        large_enc.write_all(chunk).unwrap();
    }
    let large_compressed = large_enc.finish().unwrap();

    let mut large_decoded = Vec::new();
    Decoder::new(&large_compressed[..])
        .read_to_end(&mut large_decoded)
        .unwrap();
    assert_eq!(large_decoded, large);

    // 5) Concatenated frames + skippable frames + corruption detection in io::Decoder
    let mut multi = Vec::new();
    multi.extend_from_slice(&make_skippable_frame(3, b"skip me"));
    multi.extend_from_slice(&drop_compressed);
    multi.extend_from_slice(&make_skippable_frame(9, &[0u8; 5000]));
    multi.extend_from_slice(&flushed_frame);

    let mut multi_decoded = Vec::new();
    Decoder::new(&multi[..])
        .read_to_end(&mut multi_decoded)
        .unwrap();
    assert_eq!(multi_decoded.len(), payload.len() * 2);
    assert_eq!(&multi_decoded[..payload.len()], &payload[..]);
    assert_eq!(&multi_decoded[payload.len()..], &payload[..]);

    // Corrupted checksum in io::Decoder returns InvalidData
    let mut bad_checksum = drop_compressed.clone();
    let end = bad_checksum.len() - 1;
    bad_checksum[end] ^= 0xFF;
    let io_err = Decoder::new(&bad_checksum[..])
        .read_to_end(&mut Vec::new())
        .unwrap_err();
    assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
}
