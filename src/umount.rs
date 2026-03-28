use std::io;

#[cfg(unix)]
use std::process::Command;

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: umount <target>");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("umount: not supported on Windows in this build");
        return Ok(());
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    let status = Command::new("umount").args(args).status()?;
    if !status.success() {
        eprintln!("umount: command exited with status {}", status);
    }
    Ok(())
}
