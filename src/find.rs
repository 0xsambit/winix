use regex::Regex;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
enum EntryType {
    File,
    Dir,
}

fn glob_to_regex(glob: &str) -> io::Result<Regex> {
    let mut pattern = String::from("^");
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            '.' => pattern.push_str("\\."),
            c if "\\+()^$|{}[]".contains(c) => {
                pattern.push('\\');
                pattern.push(c);
            }
            c => pattern.push(c),
        }
    }
    pattern.push('$');

    Regex::new(&pattern).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn parse_args(args: &[String]) -> io::Result<(PathBuf, Option<Regex>, Option<EntryType>)> {
    let mut root = PathBuf::from(".");
    let mut name_pattern: Option<Regex> = None;
    let mut entry_type: Option<EntryType> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-name" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "find: -name requires a pattern",
                    )
                })?;
                name_pattern = Some(glob_to_regex(value)?);
            }
            "-type" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "find: -type requires f or d")
                })?;
                entry_type = Some(match value.as_str() {
                    "f" => EntryType::File,
                    "d" => EntryType::Dir,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "find: -type accepts only 'f' or 'd'",
                        ));
                    }
                });
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("find: unknown option '{}'", other),
                ));
            }
            path => {
                root = PathBuf::from(path);
            }
        }
        i += 1;
    }

    Ok((root, name_pattern, entry_type))
}

fn matches_filters(
    path: &Path,
    md: &fs::Metadata,
    name_re: &Option<Regex>,
    ty: Option<EntryType>,
) -> bool {
    if let Some(re) = name_re {
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(v) => v,
            None => return false,
        };
        if !re.is_match(name) {
            return false;
        }
    }

    match ty {
        Some(EntryType::File) => md.is_file(),
        Some(EntryType::Dir) => md.is_dir(),
        None => true,
    }
}

fn walk(
    path: &Path,
    name_re: &Option<Regex>,
    ty: Option<EntryType>,
    out: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if matches_filters(path, &md, name_re, ty) {
        out.push(path.to_path_buf());
    }

    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            walk(&entry.path(), name_re, ty, out)?;
        }
    }

    Ok(())
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (root, name_re, ty) = parse_args(args)?;
    let mut out = Vec::new();
    walk(&root, &name_re, ty, &mut out)?;

    for path in out {
        println!("{}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::glob_to_regex;

    #[test]
    fn glob_matches_txt() {
        let re = glob_to_regex("*.txt").unwrap();
        assert!(re.is_match("a.txt"));
        assert!(!re.is_match("a.log"));
    }

    #[test]
    fn glob_matches_single_char() {
        let re = glob_to_regex("file?.md").unwrap();
        assert!(re.is_match("file1.md"));
        assert!(!re.is_match("file12.md"));
    }
}
