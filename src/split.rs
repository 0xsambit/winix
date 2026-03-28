use std::fs;
use std::io::{self, Read};

fn parse_args(args: &[String]) -> io::Result<(usize, Option<String>, String)> {
    let mut lines_per = 1000usize;
    let mut positional = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-l" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "split: -l requires a value")
                })?;
                lines_per = value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "split: invalid line count")
                })?;
                if lines_per == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "split: -l must be >= 1",
                    ));
                }
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("split: unknown option '{}'", other),
                ));
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    let input = positional.first().cloned();
    let prefix = positional.get(1).cloned().unwrap_or_else(|| "x".to_string());

    Ok((lines_per, input, prefix))
}

fn index_to_suffix(index: usize) -> String {
    let first = (index / 26) % 26;
    let second = index % 26;
    format!(
        "{}{}",
        (b'a' + first as u8) as char,
        (b'a' + second as u8) as char
    )
}

pub fn split_lines_to_chunks(lines: &[String], lines_per: usize) -> Vec<Vec<String>> {
    if lines.is_empty() {
        return Vec::new();
    }

    lines
        .chunks(lines_per)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>()
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (lines_per, input_file, prefix) = parse_args(args)?;

    let content = if let Some(file) = input_file {
        fs::read_to_string(file)?
    } else {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        input
    };

    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let chunks = split_lines_to_chunks(&lines, lines_per);

    for (idx, chunk) in chunks.iter().enumerate() {
        let name = format!("{}{}", prefix, index_to_suffix(idx));
        let mut body = chunk.join("\n");
        body.push('\n');
        fs::write(name, body)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{index_to_suffix, split_lines_to_chunks};

    #[test]
    fn splits_into_equal_chunks() {
        let lines = vec!["1", "2", "3", "4"]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let chunks = split_lines_to_chunks(&lines, 2);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec!["1", "2"]);
        assert_eq!(chunks[1], vec!["3", "4"]);
    }

    #[test]
    fn suffix_uses_two_letters() {
        assert_eq!(index_to_suffix(0), "aa");
        assert_eq!(index_to_suffix(27), "bb");
    }
}
