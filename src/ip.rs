use std::io;

#[cfg(unix)]
use std::process::Command;

pub fn run(args: &[String]) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("ip: not supported on Windows in this build");
        Ok(())
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    let mut cmd = Command::new("ip");

    if args.is_empty() {
        cmd.args(["addr", "show"]);
    } else {
        cmd.args(args);
    }

    let status = cmd.status()?;
    if !status.success() {
        eprintln!("ip: command exited with status {}", status);
    }

    Ok(())
}
