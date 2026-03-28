use std::io;

#[cfg(unix)]
use std::process::Command;

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: nice [-n increment] <command> [args...]");
        return Ok(());
    }

    #[cfg(windows)]
    {
        eprintln!("nice: not supported on Windows in this build");
        Ok(())
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    let mut idx = 0usize;
    let mut increment = 10i32;

    if args.get(0).map(String::as_str) == Some("-n") {
        if args.len() < 3 {
            eprintln!("Usage: nice [-n increment] <command> [args...]");
            return Ok(());
        }
        increment = args[1]
            .parse::<i32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid increment"))?;
        idx = 2;
    } else if args[0].starts_with('-') && args[0] != "--" {
        if let Ok(parsed) = args[0].parse::<i32>() {
            increment = parsed;
            idx = 1;
        }
    }

    if idx >= args.len() {
        eprintln!("Usage: nice [-n increment] <command> [args...]");
        return Ok(());
    }

    // Adjust niceness for this process before spawning the child command.
    unsafe {
        let current = libc::getpriority(libc::PRIO_PROCESS, 0);
        let new_priority = current.saturating_add(increment);
        if libc::setpriority(libc::PRIO_PROCESS, 0, new_priority) != 0 {
            eprintln!("nice: failed to set priority (permission denied or invalid range)");
        }
    }

    let status = Command::new(&args[idx]).args(&args[idx + 1..]).status()?;
    if !status.success() {
        eprintln!("nice: command exited with status {}", status);
    }

    Ok(())
}
