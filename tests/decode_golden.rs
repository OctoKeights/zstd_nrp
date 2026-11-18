//! The port of zstd's reference decoder against results recorded from the original, so that a
//! change shows without a C compiler at hand.
//!
//! `tests/data/zstd_frames.bin` holds the frames `compare/dump_zstd.c` made with the zstd
//! library for `zstd_decode_small 6 120` (see `compare/compare.sh`): synthetic data compressed
//! at every level and with every kind of setting, with and without dictionaries, a third of
//! the frames damaged. `tests/data/zstd_decode_expected.txt` is what that program printed for
//! them: a hash of what the reference decoder makes of each, or of the message it stops with.

mod made_up;

#[test]
fn decodes_as_the_reference_decoder_does() {
    let printed = made_up::zstd_decode(
        "zstd_decode_small",
        120,
        include_bytes!("data/zstd_frames.bin"),
    );
    let expected = include_str!("data/zstd_decode_expected.txt");
    for (line, (ours, theirs)) in printed.lines().zip(expected.lines()).enumerate() {
        assert_eq!(ours, theirs, "line {}", line + 1);
    }
    assert_eq!(printed.lines().count(), expected.lines().count());
}

/// Frames damaged far worse than the comparison's: whatever is in them, the decoder gives
/// bytes or a message, and does not panic. (`ROUNDS` over the recorded frames; more by hand
/// when the decoder is changed.)
#[test]
fn badly_damaged_frames_are_decoded_or_refused() {
    use zstd_nrp::{Dictionary, decompress_with_dict, decompressed_size};
    const ROUNDS: u32 = 40;
    let file = include_bytes!("data/zstd_frames.bin");
    let mut r = made_up::Random { state: 5 };
    let (mut decoded, mut refused) = (0, 0);
    for _ in 0..ROUNDS {
        let mut at = 0;
        while at < file.len() {
            let number = |at: &mut usize| {
                *at += 4;
                u32::from_le_bytes(file[*at - 4..*at].try_into().unwrap()) as usize
            };
            let dst_len = number(&mut at);
            let dict_size = number(&mut at);
            let mut dict = file[at..at + dict_size].to_vec();
            at += dict_size;
            let frame_size = number(&mut at);
            let mut frame = file[at..at + frame_size].to_vec();
            at += frame_size;
            // A few bytes made up, in the frame and now and then in the dictionary; now and
            // then the end cut off.
            if !frame.is_empty() {
                for _ in 0..=(r.next() % 4) {
                    let place = r.next() as usize % frame.len();
                    frame[place] = r.next() as u8;
                }
                if r.next().is_multiple_of(8) {
                    frame.truncate(r.next() as usize % frame.len());
                }
            }
            if !dict.is_empty() && r.next().is_multiple_of(4) {
                for _ in 0..=(r.next() % 4) {
                    let place = r.next() as usize % dict.len().min(300);
                    dict[place] = r.next() as u8;
                }
            }
            let _ = decompressed_size(&frame);
            let parsed = if dict.is_empty() {
                Ok(Dictionary::default())
            } else {
                Dictionary::parse(&dict)
            };
            match parsed.and_then(|parsed| decompress_with_dict(&frame, dst_len + 100, &parsed)) {
                Ok(bytes) => {
                    assert!(bytes.len() <= dst_len + 100);
                    decoded += 1;
                }
                Err(_) => refused += 1,
            }
        }
    }
    assert!(
        decoded > 100 && refused > 1000,
        "{decoded} decoded, {refused} refused"
    );
}
