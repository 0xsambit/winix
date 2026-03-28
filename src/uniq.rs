use std::fs;
use std::io::{self, Read};

fn parse_args(args: &[String]) -> io::Result<(bool, Vec<String>)> {
    let mut count = false;
    let mut files = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            for flag in arg.chars().skip(1) {
                match flag {
                    'c' => count = true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("uniq: unknown option '-{}'", flag),
                        ));
                    }
                }
            }
        } else {
            files.push(arg.clone());
        }
    }

    Ok((count, files))
}

pub fn uniq_lines(lines: Vec<String>, show_count: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = lines.into_iter();

    if let Some(mut current) = iter.next() {
        let mut count = 1usize;

        for line in iter {
            if line == current {
                count += 1;
            } else {
                if show_count {
                    out.push(format!("{:>7} {}", count, current));
                } else {
                    out.push(current);
                }
                current = line;
                count = 1;
            }
        }

        if show_count {
            out.push(format!("{:>7} {}", count, current));
        } else {
            out.push(current);
        }
    }

    out
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (show_count, files) = parse_args(args)?;
    let mut lines = Vec::new();

    if files.is_empty() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        lines.extend(input.lines().map(|s| s.to_string()));
    } else {
        for file in files {
            let content = fs::read_to_string(file)?;
            lines.extend(content.lines().map(|s| s.to_string()));
        }
    }

    let out = uniq_lines(lines, show_count);
    if !out.is_empty() {
        println!("{}", out.join("\n"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::uniq_lines;

    #[test]
    fn uniq_basic() {
        let lines = vec![
            "a".to_string(),
            "a".to_string(),
            "b".to_string(),
            "b".to_string(),
            "c".to_string(),
        ];
        let out = uniq_lines(lines, false);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn uniq_count() {
        let lines = vec!["x".to_string(), "x".to_string(), "y".to_string()];
        let out = uniq_lines(lines, true);
        assert_eq!(out, vec!["      2 x", "      1 y"]);
    }
}
