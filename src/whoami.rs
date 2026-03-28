#[cfg(unix)]
use std::ffi::CStr;
use std::io;

fn current_username() -> String {
    #[cfg(unix)]
    {
        unsafe {
            let uid = libc::geteuid();
            let pwd = libc::getpwuid(uid);
            if !pwd.is_null() {
                let name_ptr = (*pwd).pw_name;
                if !name_ptr.is_null() {
                    if let Ok(name) = CStr::from_ptr(name_ptr).to_str() {
                        if !name.is_empty() {
                            return name.to_string();
                        }
                    }
                }
            }
        }

        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    if !args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "whoami: this build does not support additional arguments",
        ));
    }

    println!("{}", current_username());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::current_username;

    #[test]
    fn username_is_non_empty() {
        assert!(!current_username().is_empty());
    }
}
