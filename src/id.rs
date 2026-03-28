use std::io;

pub fn run(args: &[String]) -> io::Result<()> {
    let mut mode: Option<&str> = None;

    for arg in args {
        match arg.as_str() {
            "-u" => mode = Some("u"),
            "-g" => mode = Some("g"),
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("id: unknown option '{}'", other),
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "id: user operand is not supported in this build",
                ));
            }
        }
    }

    #[cfg(unix)]
    {
        run_unix(mode);
        return Ok(());
    }

    #[cfg(windows)]
    {
        run_windows(mode);
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(unix)]
fn run_unix(mode: Option<&str>) {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    match mode {
        Some("u") => println!("{}", uid),
        Some("g") => println!("{}", gid),
        _ => {
            let mut groups = vec![0 as libc::gid_t; 64];
            let count = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
            let group_list = if count > 0 {
                groups
                    .into_iter()
                    .take(count as usize)
                    .map(|g| g.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                gid.to_string()
            };

            println!("uid={} gid={} groups={}", uid, gid, group_list);
        }
    }
}

#[cfg(windows)]
fn run_windows(mode: Option<&str>) {
    match mode {
        Some("u") => println!("0"),
        Some("g") => println!("0"),
        _ => {
            let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
            println!(
                "uid=0({}) gid=0(Users) groups=0(Users)",
                username
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn id_no_args_non_fatal() {
        let args: Vec<String> = Vec::new();
        assert!(run(&args).is_ok());
    }

    #[test]
    fn id_u_non_fatal() {
        let args = vec!["-u".to_string()];
        assert!(run(&args).is_ok());
    }
}
