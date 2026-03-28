use std::io::{self, Read};
use std::process::Command;

fn parse_args(args: &[String]) -> io::Result<(usize, Vec<String>)> {
    let mut chunk_size = usize::MAX;
    let mut command = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "xargs: -n requires a value")
                })?;
                chunk_size = value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "xargs: invalid -n value")
                })?;
                if chunk_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "xargs: -n must be >= 1",
                    ));
                }
            }
            value => command.push(value.to_string()),
        }
        i += 1;
    }

    Ok((chunk_size, command))
}

pub fn chunk_tokens(tokens: &[String], chunk_size: usize) -> Vec<Vec<String>> {
    if tokens.is_empty() {
        return Vec::new();
    }

    if chunk_size == usize::MAX {
        return vec![tokens.to_vec()];
    }

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < tokens.len() {
        let end = usize::min(i + chunk_size, tokens.len());
        out.push(tokens[i..end].to_vec());
        i = end;
    }
    out
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (chunk_size, command) = parse_args(args)?;

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let tokens: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();

    let groups = chunk_tokens(&tokens, chunk_size);
    if groups.is_empty() {
        return Ok(());
    }

    if command.is_empty() {
        for group in groups {
            println!("{}", group.join(" "));
        }
        return Ok(());
    }

    let program = &command[0];
    let base_args = &command[1..];

    for group in groups {
        let status = Command::new(program)
            .args(base_args)
            .args(group.iter())
            .status()?;

        if !status.success() {
            return Err(io::Error::other(format!(
                "xargs: command '{}' failed with status {}",
                program, status
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::chunk_tokens;

    #[test]
    fn chunks_in_groups_of_two() {
        let tokens = vec!["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let groups = chunk_tokens(&tokens, 2);

        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0], vec!["a", "b"]);
        assert_eq!(groups[1], vec!["c", "d"]);
        assert_eq!(groups[2], vec!["e"]);
    }
}
