//! Synthetic data, generated from a seed exactly as the C side of the comparison
//! (`compare/`) generates it, and the dumps that both the golden tests and
//! `examples/dump.rs` run.

// (The arithmetic is written as the C side has it; not every user of this module uses all of
// it.)
#![allow(
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::manual_div_ceil,
    clippy::manual_checked_ops,
    dead_code
)]

/// The two programs make the same blocks from the same seed: a 64-bit linear congruential
/// generator, the high half of its state.
pub struct Random {
    pub state: u64,
}

impl Random {
    pub fn next(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
}

/// FNV-1a, 64 bits.
pub struct Hash {
    pub value: u64,
}

impl Hash {
    pub fn new() -> Hash {
        Hash {
            value: 14695981039346656037,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        for &byte in data {
            self.value ^= u64::from(byte);
            self.value = self.value.wrapping_mul(1099511628211);
        }
    }
}

/// The `zstd_decode` dumps: the frames `compare/dump_zstd.c` made with the zstd library and
/// wrote to a file (for each: the room to decode into, a dictionary or none, and the frame),
/// each asked its size and decoded, as that program does with the reference decoder.
pub fn zstd_decode(name: &str, count: u32, file: &[u8]) -> String {
    use zstd_nrp::{Dictionary, decompress_with_dict, decompressed_size};
    let mut hash = Hash::new();
    let (mut decoded, mut refused) = (0u32, 0u32);
    let mut frame_total = 0u64;
    let mut out = String::new();
    let mut at = 0;
    let number = |at: &mut usize| {
        let value = u32::from_le_bytes(file[*at..*at + 4].try_into().unwrap()) as usize;
        *at += 4;
        value
    };
    for i in 0..count {
        let dst_len = number(&mut at);
        let dict_size = number(&mut at);
        let dict = &file[at..at + dict_size];
        at += dict_size;
        let frame_size = number(&mut at);
        let frame = &file[at..at + frame_size];
        at += frame_size;
        frame_total += frame_size as u64;

        match decompressed_size(frame) {
            Ok(size) => hash.add(&(size.map_or(-2i64, |size| size as i64)).to_le_bytes()),
            Err(error) => {
                hash.add(&(-1i64).to_le_bytes());
                hash.add(error.message().as_bytes());
                hash.add(&[0]);
            }
        }
        let parsed = if dict_size != 0 {
            Dictionary::parse(dict)
        } else {
            Ok(Dictionary::default())
        };
        match parsed.and_then(|parsed| decompress_with_dict(frame, dst_len, &parsed)) {
            Ok(bytes) => {
                hash.add(&(bytes.len() as u32).to_le_bytes());
                hash.add(&bytes);
                decoded += 1;
            }
            Err(error) => {
                hash.add(&0xffffffffu32.to_le_bytes());
                hash.add(error.message().as_bytes());
                hash.add(&[0]);
                refused += 1;
            }
        }

        if (i + 1) % 200 == 0 || i + 1 == count {
            out += &format!("{name} {} {:016x}\n", i + 1, hash.value);
        }
    }
    out + &format!(
        "{name} bytes of frames: {frame_total}; decoded: {decoded}, refused: {refused}\n"
    )
}

const ZSTD_WORDS: [&str; 16] = [
    "the", "texture", "block", "of", "and", "compress", "a", "level", "mip", "to", "pixels", "in",
    "format", "is", "cube", "data",
];

/// Synthetic bytes of one of thirteen kinds, as `FillData` in `compare/dump_zstd_compress.c`
/// makes them.
pub fn fill_data(r: &mut Random, buf: &mut [u8], kind: u32) {
    let len = buf.len();
    let mut at = 0;
    match kind {
        // noise
        0 => {
            for byte in buf.iter_mut() {
                *byte = (r.next() >> 13) as u8;
            }
        }
        // four letters
        1 => {
            for byte in buf.iter_mut() {
                *byte = b'a' + (r.next() % 4) as u8;
            }
        }
        // words
        2 => {
            while at < len {
                let word = ZSTD_WORDS[(r.next() % 16) as usize].as_bytes();
                for &letter in word {
                    if at >= len {
                        break;
                    }
                    buf[at] = letter;
                    at += 1;
                }
                if at < len {
                    buf[at] = b' ';
                    at += 1;
                }
            }
        }
        // runs
        3 => {
            while at < len {
                let byte = r.next() as u8;
                let run = 1 + r.next() % 300;
                for _ in 0..run {
                    if at >= len {
                        break;
                    }
                    buf[at] = byte;
                    at += 1;
                }
            }
        }
        // copies of what came before
        4 => {
            while at < len {
                let pick = if at < 64 { 0 } else { r.next() % 4 };
                if pick == 0 {
                    buf[at] = (r.next() >> 9) as u8;
                    at += 1;
                } else {
                    let reach = at.min(40000);
                    let dist = 1 + r.next() as usize % reach;
                    let n = 3 + r.next() % 260;
                    for _ in 0..n {
                        if at >= len {
                            break;
                        }
                        buf[at] = buf[at - dist];
                        at += 1;
                    }
                }
            }
        }
        // nothing
        5 => buf.fill(0),
        // a slope
        6 => {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = (i / 7 + i % 13) as u8;
            }
        }
        // stretches of noise, of one value and of counting
        7 => {
            while at < len {
                let stretch = 1 + r.next() % 2000;
                let what = r.next() % 3;
                let value = r.next();
                for i in 0..stretch {
                    if at >= len {
                        break;
                    }
                    buf[at] = if what == 0 {
                        (r.next() >> 11) as u8
                    } else if what == 1 {
                        value as u8
                    } else {
                        value.wrapping_add(i) as u8
                    };
                    at += 1;
                }
            }
        }
        // parts of the kinds above, one after the other
        8 => {
            while at < len {
                let mut n = 1 + r.next() as usize % 200000;
                let part = r.next() % 8;
                if n > len - at {
                    n = len - at;
                }
                fill_data(r, &mut buf[at..at + n], part);
                at += n;
            }
        }
        // the same few bytes over and over, changed in a few places
        9 => {
            let period = 1 + r.next() as usize % 5000;
            for i in 0..period.min(len) {
                buf[i] = (r.next() >> 11) as u8;
            }
            for i in period..len {
                buf[i] = buf[i - period];
            }
            let changes = r.next() % 6;
            if len != 0 {
                for _ in 0..changes {
                    let place = r.next() as usize % len;
                    buf[place] ^= (1 + r.next() % 255) as u8;
                }
            }
        }
        // a few low values
        11 => {
            let m = 2 + r.next() % 14;
            for byte in buf.iter_mut() {
                *byte = (r.next() % m) as u8;
            }
        }
        // words of four bytes of noise, in any order
        12 => {
            let words = 1000 + r.next() as usize % 3000;
            for i in 0..(words * 4).min(len) {
                buf[i] = (r.next() >> 12) as u8;
            }
            at = words * 4;
            while at < len {
                let word = r.next() as usize % words * 4;
                for i in 0..4 {
                    if at >= len {
                        break;
                    }
                    buf[at] = buf[word + i];
                    at += 1;
                }
            }
        }
        // sixty-four letters, with a rare copy of what came before
        _ => {
            while at < len {
                let pick = if at > 1000 { r.next() % 30000 } else { 1 };
                if pick == 0 {
                    let reach = at.min(100000);
                    let dist = 1 + r.next() as usize % reach;
                    let n = 8 + r.next() % 300;
                    for _ in 0..n {
                        if at >= len {
                            break;
                        }
                        buf[at] = buf[at - dist];
                        at += 1;
                    }
                } else {
                    buf[at] = (48 + (r.next() >> 10) % 64) as u8;
                    at += 1;
                }
            }
        }
    }
}

const ZSTD_LEVELS: [i32; 20] = [
    1, 1, 2, 2, 3, 3, 3, 0, 4, 4, -1, -1, -2, -3, -5, -7, -20, -100, -1000, -200000,
];

/// The `zstd_compress` dumps: synthetic data compressed at the levels that are ported, as
/// `compare/dump_zstd_compress.c` does with `ZSTD_compress`. With `check`, each frame is
/// also decoded by the port of the reference decoder and compared with its data.
/// A level as the C side passes it to `ZSTD_compress`, which takes those above 22 as 22 and
/// those below its lowest as its lowest.
fn zstd_level(level: i32) -> zstd_nrp::Level {
    zstd_nrp::Level::new(level.clamp(zstd_nrp::Level::MIN.get(), zstd_nrp::Level::MAX.get()))
        .expect("a level zstd takes")
}

pub fn zstd_compress(name: &str, seed: u64, count: u32, check: bool) -> String {
    zstd_compress_up_to(name, seed, count, check, 9)
}

/// The `zstd_compress` dumps, and the `zstd_compress_more` ones (levels 4 to 22), where a
/// level whose strategy for the size is past `highest` is taken as level 3.
pub fn zstd_compress_up_to(name: &str, seed: u64, count: u32, check: bool, highest: u32) -> String {
    const MAX_DATA: u32 = 5000000;
    let small = name == "zstd_compress_small";
    let more = name.starts_with("zstd_compress_more");
    let more_small = name == "zstd_compress_more_small";
    let mut r = Random { state: seed };
    let mut hash = Hash::new();
    let (mut in_total, mut frame_total) = (0u64, 0u64);
    let mut out = String::new();
    let mut data = Vec::new();
    for i in 0..count {
        let kind = r.next() % 13;
        let size = r.next() % 16;
        let mut max = match size {
            0 => 16,
            1..=4 => 300,
            5..=8 => 5000,
            9..=11 => 40000,
            12..=13 => 300000,
            14 => 1500000,
            _ => MAX_DATA,
        };
        if small && max > 300000 {
            max = 300000;
        }
        if more_small && max > 40000 {
            max = 40000;
        }
        let mut len = (r.next() % (max + 1)) as usize;
        let mut level;
        if more {
            level = 4 + (r.next() % 19) as i32;
            if r.next().is_multiple_of(20) {
                level = 23 + (r.next() % 5) as i32;
            }
            if zstd_nrp::compare_hooks::strategy_of(level, len.max(1)) > highest {
                level = 3;
            }
        } else {
            level = ZSTD_LEVELS[(r.next() % 20) as usize];
        }
        // A block of nothing but matches of four bytes has so many sequences that their
        // number is written the long way: it takes level 3 and a source of exactly this size.
        if kind == 12 && r.next() % 2 == 0 {
            len = 262144;
            level = 3;
        }
        // Level 4 takes a strategy that is ported for these sizes only.
        if !more && level == 4 && !(len > 256 * 1024 || (len > 16 * 1024 && len <= 128 * 1024)) {
            level = 3;
        }
        data.clear();
        data.resize(len, 0);
        fill_data(&mut r, &mut data, kind);
        let frame = zstd_nrp::compress(&data, zstd_level(level)).expect("data under 2 GiB");
        if check {
            assert_eq!(
                zstd_nrp::decompress(&frame, len).as_deref(),
                Ok(&data[..]),
                "frame {i} does not give its data back"
            );
        }
        hash.add(&(len as u32).to_le_bytes());
        hash.add(&(level as u32).to_le_bytes());
        hash.add(&(frame.len() as u32).to_le_bytes());
        hash.add(&frame);
        if std::env::var_os("SHOW_EACH").is_some() {
            eprintln!(
                "frame {i}: {len} bytes at level {level}, {} bytes, {:016x}",
                frame.len(),
                hash.value
            );
        }
        in_total += len as u64;
        frame_total += frame.len() as u64;
        if (i + 1) % 10 == 0 || i + 1 == count {
            out.push_str(&format!("{name} {} {:016x}\n", i + 1, hash.value));
        }
    }
    out.push_str(&format!(
        "{name} bytes: {in_total}; bytes of frames: {frame_total}\n"
    ));
    out
}

/// The `zstd_compress_long` dump: synthetic data of 64 to 80 megabytes, as `FillLong` in
/// `compare/dump_zstd_compress.c` makes it, compressed at level 22, which takes
/// long-distance matching for so much.
pub fn zstd_compress_long(name: &str, seed: u64, count: u32, check: bool) -> String {
    let mut r = Random { state: seed };
    let mut hash = Hash::new();
    let (mut in_total, mut frame_total) = (0u64, 0u64);
    let mut out = String::new();
    for i in 0..count {
        let len = 64 * 1024 * 1024 + (r.next() % 16000000) as usize;
        let level = 22;
        let mut data = vec![0u8; len];
        let mut at = 0;
        while at < len {
            let piece = (1 + (r.next() % 4000000) as usize).min(len - at);
            if at > 1000000 && r.next().is_multiple_of(2) {
                let dist = 1 + r.next() as usize % at.min(70000000);
                let changes = r.next() % 16;
                for i in at..at + piece {
                    data[i] = data[i - dist];
                }
                for _ in 0..changes {
                    let place = at + r.next() as usize % piece;
                    data[place] = r.next() as u8;
                }
            } else {
                let kind = r.next() % 13;
                fill_data(&mut r, &mut data[at..at + piece], kind);
            }
            at += piece;
        }
        let frame = zstd_nrp::compress(&data, zstd_level(level)).expect("data under 2 GiB");
        if check {
            assert_eq!(
                zstd_nrp::decompress(&frame, len).as_deref(),
                Ok(&data[..]),
                "frame {i} does not give its data back"
            );
        }
        hash.add(&(len as u32).to_le_bytes());
        hash.add(&(level as u32).to_le_bytes());
        hash.add(&(frame.len() as u32).to_le_bytes());
        hash.add(&frame);
        in_total += len as u64;
        frame_total += frame.len() as u64;
        out.push_str(&format!("{name} {} {:016x}\n", i + 1, hash.value));
    }
    out.push_str(&format!(
        "{name} bytes: {in_total}; bytes of frames: {frame_total}\n"
    ));
    out
}

/// Synthetic literals of one of six kinds, as `MakeLiterals` in `compare/dump_zstd_entropy.c`
/// makes them.
fn make_literals(r: &mut Random, buf: &mut [u8]) {
    let len = buf.len();
    let shape = r.next() % 6;
    match shape {
        // one value
        0 => {
            let value = r.next();
            buf.fill(value as u8);
        }
        // a few low values
        1 => {
            let m = 2 + r.next() % 15;
            for byte in buf.iter_mut() {
                *byte = (r.next() % m) as u8;
            }
        }
        // values with few bits set more often
        2 => {
            for byte in buf.iter_mut() {
                let value = r.next();
                *byte = (value & (value >> 8) & (value >> 16)) as u8;
            }
        }
        // noise
        3 => {
            for byte in buf.iter_mut() {
                *byte = (r.next() >> 13) as u8;
            }
        }
        // letters and spaces
        4 => {
            for byte in buf.iter_mut() {
                let value = r.next();
                *byte = if value % 7 == 0 {
                    b' '
                } else {
                    b'a' + ((value >> 8) % 26) as u8
                };
            }
        }
        // a few low values, then noise
        _ => {
            let m = 2 + r.next() % 15;
            for (i, byte) in buf.iter_mut().enumerate() {
                let value = r.next();
                *byte = if i < len / 2 {
                    (value % m) as u8
                } else {
                    (value >> 13) as u8
                };
            }
        }
    }
}

/// An answer as a number: a size, or an error's code with the top bit set.
fn entropy_code(answer: &Result<usize, u32>) -> u32 {
    match answer {
        Ok(size) => *size as u32,
        Err(code) => 0x80000000 + code,
    }
}

/// What the `zstd_entropy` dump keeps from one round to the next.
struct Entropy {
    r: Random,
    hash: Hash,
    outputs: u32,
    errors: u32,
    lit: Vec<u8>,
    out: Vec<u8>,
    huf: zstd_nrp::compare_hooks::Huf,
    fresh: bool,
    literals: zstd_nrp::compare_hooks::Literals,
}

impl Entropy {
    fn number(&mut self, value: u32) {
        self.hash.add(&value.to_le_bytes());
    }

    fn try_fse(&mut self) {
        use zstd_nrp::compare_hooks as hooks;
        let mut count = [0u32; 256];
        let mut norm = [0i16; 256];
        let mut header = [0u8; 512];
        let mut pool = [0u8; 4096];
        let mut symbols = [0u8; 600];
        let r = &mut self.r;
        let max = if r.next() % 4 == 0 {
            1 + r.next() % 255
        } else {
            1 + r.next() % 52
        };
        let shape = r.next() % 8;
        let big = 1 + r.next() % 5000;
        for s in 0..=max {
            count[s as usize] = match shape {
                0 => 1 + r.next() % 3,
                1 => {
                    if s < 64 {
                        big >> (s / 2)
                    } else {
                        0
                    }
                }
                2 => {
                    let c = r.next() % 5;
                    if c == 0 { 1 + r.next() % 40 } else { 0 }
                }
                3 => {
                    if s == 0 {
                        big * 20
                    } else {
                        r.next() % 3
                    }
                }
                4 => big % 4 + 1,
                5 => r.next() % 1000,
                6 => {
                    if s < 3 {
                        big * 30
                    } else if s < 6 {
                        big * 3
                    } else {
                        1 + r.next() % 2
                    }
                }
                _ => u32::from(r.next() % 16 < 11),
            };
        }
        if count[max as usize] == 0 {
            count[max as usize] = 1;
        }
        let mut total: usize = count[..=max as usize].iter().map(|&c| c as usize).sum();
        if total < 2 {
            count[0] += 2;
            total += 2;
        }
        let mut table_log = if r.next() % 4 == 0 {
            r.next() % 14
        } else {
            hooks::fse_optimal_table_log(5 + r.next() % 8, total, max)
        };
        let low = r.next() & 1 != 0;

        let answer = hooks::fse_normalize_count(&mut norm, table_log, &count, total, max, low);
        self.number(entropy_code(&answer.map(|log| log as usize)));
        match answer {
            Ok(log) if log != 0 => table_log = log,
            _ => {
                self.errors += 1;
                return;
            }
        }
        for s in 0..=max as usize {
            self.number(norm[s] as i32 as u32);
        }

        let mut room = 512;
        if self.r.next() % 3 == 0 {
            room = 2 + self.r.next() % 22;
        }
        let answer = hooks::fse_write_ncount(&mut header[..room as usize], &norm, max, table_log);
        self.number(entropy_code(&answer));
        match answer {
            Ok(size) => self.hash.add(&header[..size]),
            Err(_) => {
                self.errors += 1;
                return;
            }
        }

        let mut p = 0;
        for s in 0..=max as usize {
            for _ in 0..norm[s].unsigned_abs() {
                pool[p] = s as u8;
                p += 1;
            }
        }
        let n = self.r.next() % 600;
        for symbol in symbols.iter_mut().take(n as usize) {
            *symbol = pool[self.r.next() as usize % p];
        }
        let mut room = n + (n >> 7) + 12 + self.r.next() % 64;
        if self.r.next() % 3 == 0 {
            room = self.r.next() % (n + 16);
        }
        let size = hooks::fse_compress(
            &mut self.out[..room as usize],
            &symbols[..n as usize],
            &norm,
            max,
            table_log,
        );
        self.number(size as u32);
        self.hash.add(&self.out[..size]);
        self.outputs += 1;
    }

    fn try_huf(&mut self) {
        let mut again = false;
        if self.fresh {
            again = self.r.next() % 4 == 0;
        }
        let mut repeat;
        if again {
            repeat = if self.r.next() % 2 != 0 { 2 } else { 1 };
        } else {
            let size = self.r.next() % 8;
            let pick = self.r.next();
            let len = match size {
                0 => pick % 70,
                1..=2 => 40 + pick % 300,
                3..=4 => pick % 3000,
                5 => 900 + pick % 300,
                6 => 16000 + pick % 1000,
                _ => pick % 131200,
            };
            self.lit.clear();
            self.lit.resize(len as usize, 0);
            make_literals(&mut self.r, &mut self.lit);
            repeat = if self.r.next() % 3 == 0 { 1 } else { 0 };
        }
        let four = self.r.next() & 1 != 0;
        let prefer = self.r.next() & 1 != 0;
        let suspect = self.r.next() & 1 != 0;
        let len = self.lit.len();
        let mut room = len + (len >> 8) + 200;
        if self.r.next() % 3 == 0 {
            room = self.r.next() as usize % (len + 32);
        }
        let answer = self.huf.compress(
            &mut self.out[..room],
            &self.lit,
            four,
            &mut repeat,
            prefer,
            suspect,
        );
        self.number(entropy_code(&answer));
        self.number(repeat);
        match answer {
            Ok(size) => {
                self.hash.add(&self.out[..size]);
                self.outputs += 1;
            }
            Err(_) => self.errors += 1,
        }
        // A new table was made and used: it has a code for every byte of these literals.
        self.fresh = matches!(answer, Ok(size) if size > 1) && repeat == 0;
    }

    fn try_literals(&mut self) {
        let size = self.r.next() % 6;
        let pick = self.r.next();
        let len = match size {
            0 => pick % 70,
            1 => 60 + pick % 10,
            2 => pick % 2000,
            3 => 1000 + pick % 50,
            4 => 16370 + pick % 30,
            _ => pick % 70000,
        } as usize;
        // The literals of the Huffman rounds are gone: no going over them again.
        self.fresh = false;
        self.lit.clear();
        self.lit.resize(len, 0);
        make_literals(&mut self.r, &mut self.lit);
        let strategy = 1 + self.r.next() % 2;
        let disable = self.r.next() % 8 == 0;
        let suspect = self.r.next() & 1 != 0;
        let mut room = len + 300;
        if self.r.next() % 3 == 0 {
            room = self.r.next() as usize % (len + 16);
        }
        let answer =
            self.literals
                .compress(&mut self.out[..room], &self.lit, strategy, disable, suspect);
        self.number(entropy_code(&answer));
        self.number(self.literals.next_repeat_mode());
        match answer {
            Ok(size) => {
                self.hash.add(&self.out[..size]);
                self.outputs += 1;
                // As a block that is kept does: the tables of this one are the next one's.
                if self.r.next() % 2 != 0 {
                    self.literals.keep();
                }
            }
            Err(_) => self.errors += 1,
        }
    }
}

/// The `zstd_entropy` dump: the entropy coders of the Zstandard compressor one function at
/// a time, as `compare/dump_zstd_entropy.c` asks the originals.
pub fn zstd_entropy(seed: u64, count: u32) -> String {
    let name = "zstd_entropy";
    let mut e = Entropy {
        r: Random { state: seed },
        hash: Hash::new(),
        outputs: 0,
        errors: 0,
        lit: Vec::new(),
        out: vec![0u8; 150000],
        huf: Default::default(),
        fresh: false,
        literals: Default::default(),
    };
    let mut out = String::new();
    for i in 0..count {
        let what = e.r.next() % 20;
        if what < 12 {
            e.try_fse();
        } else if what < 17 {
            e.try_huf();
        } else {
            e.try_literals();
        }
        if (i + 1) % 1000 == 0 || i + 1 == count {
            out.push_str(&format!("{name} {} {:016x}\n", i + 1, e.hash.value));
        }
    }
    out.push_str(&format!(
        "{name} outputs: {}, refused: {}\n",
        e.outputs, e.errors
    ));
    out
}
