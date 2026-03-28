use std::io::{self, Read};

fn parse_args(args: &[String]) -> io::Result<TrMode> {
    if args.len() == 2 && args[0] == "-d" {
        return Ok(TrMode::Delete {
            set: args[1].clone(),
        });
    }

    if args.len() == 2 {
        return Ok(TrMode::Translate {
            set1: args[0].clone(),
            set2: args[1].clone(),
        });
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "Usage: tr SET1 SET2 | tr -d SET",
    ))
}

enum TrMode {
    Translate { set1: String, set2: String },
    Delete { set: String },
}

pub fn translate_text(input: &str, set1: &str, set2: &str) -> String {
    if set1.is_empty() {
        return input.to_string();
    }

    let source: Vec<char> = set1.chars().collect();
    let target: Vec<char> = set2.chars().collect();
    let fallback = target.last().copied();

    input
        .chars()
        .map(|ch| {
            if let Some(idx) = source.iter().position(|c| *c == ch) {
                target.get(idx).copied().or(fallback).unwrap_or(ch)
            } else {
                ch
            }
        })
        .collect()
}

pub fn delete_text(input: &str, set: &str) -> String {
    input.chars().filter(|ch| !set.contains(*ch)).collect()
}

pub fn run(args: &[String]) -> io::Result<()> {
    let mode = parse_args(args)?;
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let out = match mode {
        TrMode::Translate { set1, set2 } => translate_text(&input, &set1, &set2),
        TrMode::Delete { set } => delete_text(&input, &set),
    };

    print!("{}", out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{delete_text, translate_text};

    #[test]
    fn translates_characters() {
        let out = translate_text("abc cab", "abc", "xyz");
        assert_eq!(out, "xyz zxy");
    }

    #[test]
    fn deletes_characters() {
        let out = delete_text("a-b-c", "-");
        assert_eq!(out, "abc");
    }
}
