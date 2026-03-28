use std::fs::OpenOptions;
use std::io::{self, Read, Write};

fn parse_args(args: &[String]) -> io::Result<(bool, Vec<String>)> {
    let mut append = false;
    let mut files = Vec::new();

    for arg in args {
        if arg == "-a" {
            append = true;
        } else if arg.starts_with('-') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tee: unknown option '{}'", arg),
            ));
        } else {
            files.push(arg.clone());
        }
    }

    Ok((append, files))
}

pub fn write_to_files(input: &[u8], append: bool, files: &[String]) -> io::Result<()> {
    for file in files {
        let mut handle = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(file)?;
        handle.write_all(input)?;
    }
    Ok(())
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (append, files) = parse_args(args)?;

    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;

    io::stdout().write_all(&buffer)?;
    write_to_files(&buffer, append, &files)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_to_files;
    use tempfile::NamedTempFile;

    #[test]
    fn writes_and_appends() {
        let file = NamedTempFile::new().expect("failed to create temp file");
        let path = file.path().to_string_lossy().to_string();

        write_to_files(b"first\n", false, std::slice::from_ref(&path)).expect("write failed");
        write_to_files(b"second\n", true, std::slice::from_ref(&path)).expect("append failed");

        let content = std::fs::read_to_string(path).expect("failed to read output");
        assert_eq!(content, "first\nsecond\n");
    }
}
