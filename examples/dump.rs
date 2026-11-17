//! The Rust half of the comparison with zstd: runs the port over made-up data and
//! prints a running hash of what comes out, as `compare/dump_zstd*.c` does with the original.
//! `compare/compare.sh` compares the two.
//!
//!   dump zstd_decode <seed> <count> <file>         the frames compare/dump_zstd.c wrote to the
//!   dump zstd_decode_small <seed> <count> <file>   file, each asked its size and decoded
//!   dump zstd_compress <seed> <count>              made-up data compressed at levels 1 to 4,
//!   dump zstd_compress_small <seed> <count>        0 and the negative ones
//!   dump zstd_compress_more <seed> <count>         the same at levels 4 to 22
//!   dump zstd_compress_more_small <seed> <count>
//!   dump zstd_compress_long <seed> <count>         64 to 80 megabytes at level 22
//!   dump zstd_entropy <seed> <count>               the entropy coders one function at a time

#[path = "../tests/made_up/mod.rs"]
mod made_up;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(what), Some(seed), Some(count)) = (
        args.get(1),
        args.get(2).and_then(|s| s.parse::<u64>().ok()),
        args.get(3).and_then(|s| s.parse::<u32>().ok()),
    ) else {
        eprintln!("usage: dump <what> <seed> <count>   (see the top of dump.rs)");
        std::process::exit(2);
    };
    let _ = seed;
    match what.as_str() {
        "zstd_decode" | "zstd_decode_small" => {
            let Some(file) = args.get(4).and_then(|path| std::fs::read(path).ok()) else {
                eprintln!(
                    "usage: dump {what} <seed> <count> <file of frames from compare/dump_zstd.c>"
                );
                std::process::exit(2);
            };
            print!("{}", made_up::zstd_decode(what, count, &file));
        }
        "zstd_compress" | "zstd_compress_small" => {
            print!("{}", made_up::zstd_compress(what, seed, count, false))
        }
        "zstd_compress_long" => {
            print!("{}", made_up::zstd_compress_long(what, seed, count, false))
        }
        "zstd_compress_more" | "zstd_compress_more_small" => {
            let highest = args
                .get(4)
                .map_or(9, |arg| arg.parse().expect("a strategy"));
            print!(
                "{}",
                made_up::zstd_compress_up_to(what, seed, count, false, highest)
            );
        }
        "zstd_entropy" => print!("{}", made_up::zstd_entropy(seed, count)),
        _ => {
            eprintln!("unknown dump {what}");
            std::process::exit(2);
        }
    }
}
