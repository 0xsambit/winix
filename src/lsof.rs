use std::io;

pub fn run(args: &[String]) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("lsof: not supported on Windows in this build");
        Ok(())
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    use std::fs;
    use std::path::Path;

    let pid_filter = args.first().map(String::as_str);

    println!("{:<8} {:<6} TARGET", "PID", "FD");

    for proc_entry in fs::read_dir("/proc")? {
        let proc_entry = proc_entry?;
        let pid_str = proc_entry.file_name().to_string_lossy().to_string();

        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        if let Some(filter) = pid_filter {
            if filter != pid_str {
                continue;
            }
        }

        let fd_path = Path::new("/proc").join(&pid_str).join("fd");
        if !fd_path.exists() {
            continue;
        }

        let fd_entries = match fs::read_dir(&fd_path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for fd_entry in fd_entries {
            let fd_entry = match fd_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let fd_name = fd_entry.file_name().to_string_lossy().to_string();
            let target = match fs::read_link(fd_entry.path()) {
                Ok(link) => link.display().to_string(),
                Err(_) => "<unreadable>".to_string(),
            };

            println!("{:<8} {:<6} {}", pid_str, fd_name, target);
        }
    }

    Ok(())
}
