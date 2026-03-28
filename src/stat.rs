use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

fn parse_args(args: &[String]) -> io::Result<(Option<String>, Vec<String>)> {
    let mut format = None;
    let mut files = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "stat: -c requires a format")
                })?;
                format = Some(value.clone());
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("stat: unknown option '{}'", other),
                ));
            }
            _ => files.push(args[i].clone()),
        }
        i += 1;
    }

    if files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Usage: stat [-c FORMAT] FILE...",
        ));
    }

    Ok((format, files))
}

fn file_type_text(meta: &fs::Metadata) -> &'static str {
    let ft = meta.file_type();
    if ft.is_dir() {
        "directory"
    } else if ft.is_file() {
        "regular file"
    } else if ft.is_symlink() {
        "symbolic link"
    } else {
        "special file"
    }
}

fn modified_text(meta: &fs::Metadata) -> String {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn render_with_format(path: &Path, meta: &fs::Metadata, fmt: &str) -> String {
    fmt.replace("%n", &path.display().to_string())
        .replace("%s", &meta.len().to_string())
        .replace("%F", file_type_text(meta))
        .replace("%y", &modified_text(meta))
}

fn render_default(path: &Path, meta: &fs::Metadata) {
    println!("  File: {}", path.display());
    println!("  Size: {}", meta.len());
    println!("  Type: {}", file_type_text(meta));
    println!("Modify: {}", modified_text(meta));
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (format, files) = parse_args(args)?;

    for (idx, file) in files.iter().enumerate() {
        let path = Path::new(file);
        let meta = fs::symlink_metadata(path)?;

        if let Some(fmt) = &format {
            println!("{}", render_with_format(path, &meta, fmt));
        } else {
            render_default(path, &meta);
            if idx + 1 < files.len() {
                println!();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::render_with_format;

    #[test]
    fn supports_basic_placeholders() {
        let file = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let path = file.path();
        let meta = std::fs::metadata(path).expect("failed to read metadata");

        let out = render_with_format(path, &meta, "%n %s %F");
        assert!(out.contains(path.to_string_lossy().as_ref()));
        assert!(out.contains("regular file"));
    }
}
