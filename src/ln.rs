use std::fs;
use std::io;

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ln: usage: ln [-s] <target> <link_name>",
        ));
    }

    let mut symbolic = false;
    let mut positionals = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-s" => symbolic = true,
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ln: unknown option '{}'", other),
                ));
            }
            _ => positionals.push(arg),
        }
    }

    if positionals.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ln: usage: ln [-s] <target> <link_name>",
        ));
    }

    let target = positionals[0];
    let link_name = positionals[1];

    if symbolic {
        create_symlink(target, link_name)
    } else {
        fs::hard_link(target, link_name)
    }
}

#[cfg(unix)]
fn create_symlink(target: &str, link_name: &str) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link_name)
}

#[cfg(windows)]
fn create_symlink(target: &str, link_name: &str) -> io::Result<()> {
    let md = fs::metadata(target)?;
    if md.is_dir() {
        std::os::windows::fs::symlink_dir(target, link_name)
    } else {
        std::os::windows::fs::symlink_file(target, link_name)
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn creates_hard_link() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");
        fs::write(&target, "data").unwrap();

        let args = vec![
            target.to_string_lossy().to_string(),
            link.to_string_lossy().to_string(),
        ];

        run(&args).unwrap();
        assert!(link.exists());
        assert_eq!(fs::read_to_string(link).unwrap(), "data");
    }
}
