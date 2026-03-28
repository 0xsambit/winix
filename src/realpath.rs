use std::fs;
use std::io;

fn parse_args(args: &[String]) -> io::Result<(bool, Vec<String>)> {
    let mut quiet = false;
    let mut paths = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-q" => quiet = true,
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("realpath: unknown option '{}'", other),
                ));
            }
            _ => paths.push(arg.clone()),
        }
    }

    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Usage: realpath [-q] PATH...",
        ));
    }

    Ok((quiet, paths))
}

pub fn resolve_path(path: &str) -> io::Result<String> {
    fs::canonicalize(path).map(|p| p.display().to_string())
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (quiet, paths) = parse_args(args)?;
    let mut has_error = false;

    for path in paths {
        match resolve_path(&path) {
            Ok(resolved) => println!("{}", resolved),
            Err(err) => {
                has_error = true;
                if !quiet {
                    eprintln!("realpath: {}: {}", path, err);
                }
            }
        }
    }

    if has_error {
        return Err(io::Error::other("realpath: one or more paths could not be resolved"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_path;

    #[test]
    fn resolves_existing_path() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let resolved = resolve_path(dir.path().to_string_lossy().as_ref()).expect("resolve failed");
        assert!(!resolved.is_empty());
    }
}
