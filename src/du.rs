use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn format_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut size = bytes as f64;
    let mut unit = 0usize;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{}{}", bytes, UNITS[unit])
    } else {
        format!("{:.1}{}", size, UNITS[unit])
    }
}

fn format_default_blocks(bytes: u64) -> String {
    let blocks = bytes.div_ceil(1024);
    blocks.to_string()
}

fn parse_args(args: &[String]) -> io::Result<(bool, bool, Vec<PathBuf>)> {
    let mut human = false;
    let mut summary = false;
    let mut paths = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            for flag in arg.chars().skip(1) {
                match flag {
                    'h' => human = true,
                    's' => summary = true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("du: unknown option '-{}'", flag),
                        ));
                    }
                }
            }
        } else {
            paths.push(PathBuf::from(arg));
        }
    }

    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }

    Ok((human, summary, paths))
}

fn collect_sizes(path: &Path, rows: &mut Vec<(PathBuf, u64)>) -> io::Result<u64> {
    let md = fs::symlink_metadata(path)?;

    if md.is_file() || md.file_type().is_symlink() {
        let size = md.len();
        rows.push((path.to_path_buf(), size));
        return Ok(size);
    }

    if md.is_dir() {
        let mut total = 0u64;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            total += collect_sizes(&entry.path(), rows)?;
        }
        rows.push((path.to_path_buf(), total));
        return Ok(total);
    }

    Ok(0)
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (human, summary, paths) = parse_args(args)?;

    for path in paths {
        let mut rows = Vec::new();
        let _ = collect_sizes(&path, &mut rows)?;

        if summary {
            if let Some((p, size)) = rows.iter().find(|(p, _)| p == &path) {
                let size_text = if human {
                    format_human(*size)
                } else {
                    format_default_blocks(*size)
                };
                println!("{}\t{}", size_text, p.display());
            }
            continue;
        }

        for (p, size) in rows {
            let size_text = if human {
                format_human(size)
            } else {
                format_default_blocks(size)
            };
            println!("{}\t{}", size_text, p.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format_default_blocks, format_human};

    #[test]
    fn formats_human_sizes() {
        assert_eq!(format_human(1024), "1.0K");
    }

    #[test]
    fn formats_default_blocks() {
        assert_eq!(format_default_blocks(1025), "2");
    }
}
