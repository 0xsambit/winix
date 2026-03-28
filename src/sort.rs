use std::cmp::Ordering;
use std::fs;
use std::io::{self, Read};

fn parse_args(args: &[String]) -> io::Result<(bool, bool, Vec<String>)> {
    let mut reverse = false;
    let mut numeric = false;
    let mut files = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            for flag in arg.chars().skip(1) {
                match flag {
                    'r' => reverse = true,
                    'n' => numeric = true,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("sort: unknown option '-{}'", flag),
                        ));
                    }
                }
            }
        } else {
            files.push(arg.clone());
        }
    }

    Ok((reverse, numeric, files))
}

fn compare_lines(a: &str, b: &str, numeric: bool) -> Ordering {
    if numeric {
        let a_num = a.trim().parse::<f64>();
        let b_num = b.trim().parse::<f64>();

        match (a_num, b_num) {
            (Ok(x), Ok(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            _ => a.cmp(b),
        }
    } else {
        a.cmp(b)
    }
}

pub fn sort_lines(mut lines: Vec<String>, reverse: bool, numeric: bool) -> Vec<String> {
    lines.sort_by(|a, b| compare_lines(a, b, numeric));
    if reverse {
        lines.reverse();
    }
    lines
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (reverse, numeric, files) = parse_args(args)?;
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

    let sorted = sort_lines(lines, reverse, numeric);
    if !sorted.is_empty() {
        println!("{}", sorted.join("\n"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sort_lines;

    #[test]
    fn sort_lexicographic() {
        let input = vec!["b".to_string(), "a".to_string(), "c".to_string()];
        let out = sort_lines(input, false, false);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn sort_numeric_desc() {
        let input = vec!["10".to_string(), "2".to_string(), "1".to_string()];
        let out = sort_lines(input, true, true);
        assert_eq!(out, vec!["10", "2", "1"]);
    }
}
