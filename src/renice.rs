use std::io;

pub fn run(args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: renice <priority> <pid1> [pid2] ...");
        return Ok(());
    }

    #[cfg(windows)]
    {
        eprintln!("renice: not supported on Windows in this build");
        Ok(())
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    let priority = args[0]
        .parse::<i32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid priority"))?;

    for pid in &args[1..] {
        let parsed_pid = pid
            .parse::<u32>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;

        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, parsed_pid, priority) };
        if rc != 0 {
            eprintln!("renice: failed to update pid {}", parsed_pid);
        }
    }

    Ok(())
}
