use std::io;

pub fn run(args: &[String]) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("ulimit: not supported on Windows in this build");
        return Ok(());
    }

    #[cfg(unix)]
    {
        run_unix(args)
    }
}

#[cfg(unix)]
fn run_unix(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        print_limit(libc::RLIMIT_NOFILE, "open files")?;
        print_limit(libc::RLIMIT_STACK, "stack size")?;
        return Ok(());
    }

    match args[0].as_str() {
        "-n" => handle_resource(libc::RLIMIT_NOFILE, "open files", &args[1..]),
        "-s" => handle_resource(libc::RLIMIT_STACK, "stack size", &args[1..]),
        _ => {
            eprintln!("Usage: ulimit [-n|-s] [value]");
            Ok(())
        }
    }
}

#[cfg(unix)]
fn handle_resource(
    resource: libc::__rlimit_resource_t,
    name: &str,
    rest: &[String],
) -> io::Result<()> {
    if rest.is_empty() {
        return print_limit(resource, name);
    }

    let value = rest[0]
        .parse::<libc::rlim_t>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ulimit value"))?;

    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let get_rc = unsafe { libc::getrlimit(resource, &mut lim) };
    if get_rc != 0 {
        return Err(io::Error::last_os_error());
    }

    lim.rlim_cur = value;
    let set_rc = unsafe { libc::setrlimit(resource, &lim) };
    if set_rc != 0 {
        return Err(io::Error::last_os_error());
    }

    print_limit(resource, name)
}

#[cfg(unix)]
fn print_limit(resource: libc::__rlimit_resource_t, label: &str) -> io::Result<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let rc = unsafe { libc::getrlimit(resource, &mut lim) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    if lim.rlim_cur == libc::RLIM_INFINITY {
        println!("{}: unlimited", label);
    } else {
        println!("{}: {}", label, lim.rlim_cur);
    }

    Ok(())
}
