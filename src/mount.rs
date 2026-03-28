use std::io;

#[cfg(unix)]
use std::process::Command;

pub fn run(args: &[String]) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("mount: not supported on Windows in this build");
        Ok(())
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    let status = Command::new("mount").args(args).status()?;
    if !status.success() {
        eprintln!("mount: command exited with status {}", status);
    }
    Ok(())
}
