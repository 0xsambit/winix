use std::fs;
use std::io;

/// Run the `cp` command
/// `args` should contain exactly 2 arguments: source and destination
pub fn run(args: &[String]) -> io::Result<()> {
    if args.len() != 2 {
        eprintln!("Usage: cp <source> <destination>");
        return Ok(()); // Do not panic
    }

    let src = &args[0];
    let dest = &args[1];

    match fs::copy(src, dest) {
        Ok(bytes) => println!("✅ Copied {} bytes from '{}' → '{}'", bytes, src, dest),
        Err(e) => eprintln!(" Error copying file '{}': {}", src, e),
    }

    Ok(())
}
