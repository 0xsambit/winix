use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::{self, BufReader};

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: gzip [-k] <file1> [file2] ...");
        return Ok(());
    }

    let mut keep_original = false;
    let mut files = Vec::new();

    for arg in args {
        if arg == "-k" {
            keep_original = true;
        } else {
            files.push(arg);
        }
    }

    if files.is_empty() {
        eprintln!("gzip: missing file operand");
        return Ok(());
    }

    for file in files {
        let input = File::open(file)?;
        let output_path = format!("{}.gz", file);
        let output = File::create(&output_path)?;

        let mut encoder = GzEncoder::new(output, Compression::default());
        let mut reader = BufReader::new(input);
        io::copy(&mut reader, &mut encoder)?;
        encoder.finish()?;

        if !keep_original {
            fs::remove_file(file)?;
        }

        println!("compressed '{}' -> '{}'", file, output_path);
    }

    Ok(())
}
