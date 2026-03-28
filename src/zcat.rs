use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{self, Write};

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: zcat <file1.gz> [file2.gz] ...");
        return Ok(());
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();

    for (idx, file) in args.iter().enumerate() {
        let input = File::open(file)?;
        let mut decoder = GzDecoder::new(input);
        io::copy(&mut decoder, &mut out)?;

        if idx + 1 < args.len() {
            out.write_all(b"\n")?;
        }
    }

    Ok(())
}
