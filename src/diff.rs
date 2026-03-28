use std::fs;
use std::io;

fn parse_args(args: &[String]) -> io::Result<(bool, bool, String, String)> {
    let mut quiet = false;
    let mut unified = false;
    let mut files = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            for flag in arg.chars().skip(1) {
                match flag {
                    'q' => quiet = true,
                    'u' => unified = true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("diff: unknown option '-{}'", flag),
                        ));
                    }
                }
            }
        } else {
            files.push(arg.clone());
        }
    }

    if files.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "diff: usage: diff [-q] [-u] <file1> <file2>",
        ));
    }

    Ok((quiet, unified, files[0].clone(), files[1].clone()))
}

fn print_simple_diff(file1: &str, file2: &str, a: &[String], b: &[String], unified: bool) {
    if unified {
        println!("--- {}", file1);
        println!("+++ {}", file2);
    }

    let max = usize::max(a.len(), b.len());
    for i in 0..max {
        let left = a.get(i);
        let right = b.get(i);
        if left == right {
            continue;
        }

        if !unified {
            println!("line {} differs", i + 1);
        }

        if let Some(v) = left {
            println!("-{}", v);
        }
        if let Some(v) = right {
            println!("+{}", v);
        }
    }
}

pub fn files_equal(a: &str, b: &str) -> io::Result<bool> {
    Ok(fs::read(a)? == fs::read(b)?)
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (quiet, unified, file1, file2) = parse_args(args)?;

    if files_equal(&file1, &file2)? {
        return Ok(());
    }

    if quiet {
        println!("Files {} and {} differ", file1, file2);
        return Ok(());
    }

    let left = fs::read_to_string(&file1)?;
    let right = fs::read_to_string(&file2)?;
    let left_lines = left.lines().map(|s| s.to_string()).collect::<Vec<_>>();
    let right_lines = right.lines().map(|s| s.to_string()).collect::<Vec<_>>();

    print_simple_diff(&file1, &file2, &left_lines, &right_lines, unified);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::files_equal;
    use tempfile::NamedTempFile;

    #[test]
    fn detects_equal_files() {
        let f1 = NamedTempFile::new().unwrap();
        let f2 = NamedTempFile::new().unwrap();
        std::fs::write(f1.path(), "abc\n").unwrap();
        std::fs::write(f2.path(), "abc\n").unwrap();

        assert!(files_equal(
            &f1.path().to_string_lossy(),
            &f2.path().to_string_lossy()
        )
        .unwrap());
    }
}
