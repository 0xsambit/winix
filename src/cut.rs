use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};

fn parse_fields(spec: &str) -> io::Result<BTreeSet<usize>> {
    let mut fields = BTreeSet::new();

    for part in spec.split(',') {
        let value = part.trim().parse::<usize>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cut: invalid field list '{}': must be positive integers",
                    spec
                ),
            )
        })?;

        if value == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cut: field numbers are 1-based",
            ));
        }

        fields.insert(value);
    }

    Ok(fields)
}

fn parse_args(args: &[String]) -> io::Result<(char, BTreeSet<usize>, Vec<String>)> {
    let mut delimiter = '\t';
    let mut fields: Option<BTreeSet<usize>> = None;
    let mut files = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "cut: -d requires a delimiter")
                })?;
                let mut chars = value.chars();
                let first = chars.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "cut: empty delimiter")
                })?;
                if chars.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "cut: delimiter must be a single character",
                    ));
                }
                delimiter = first;
            }
            "-f" => {
                i += 1;
                let spec = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "cut: -f requires a field list")
                })?;
                fields = Some(parse_fields(spec)?);
            }
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cut: unknown option '{}'", other),
                ));
            }
            file => files.push(file.to_string()),
        }
        i += 1;
    }

    let fields = fields.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cut: missing required -f <field-list>",
        )
    })?;

    Ok((delimiter, fields, files))
}

pub fn cut_line(line: &str, delimiter: char, fields: &BTreeSet<usize>) -> String {
    let parts: Vec<&str> = line.split(delimiter).collect();
    let selected: Vec<&str> = fields
        .iter()
        .filter_map(|idx| parts.get(idx - 1).copied())
        .collect();
    selected.join(&delimiter.to_string())
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (delimiter, fields, files) = parse_args(args)?;
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

    let out: Vec<String> = lines
        .iter()
        .map(|line| cut_line(line, delimiter, &fields))
        .collect();

    if !out.is_empty() {
        println!("{}", out.join("\n"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{cut_line, parse_fields};

    #[test]
    fn cut_select_two_fields() {
        let fields = parse_fields("1,3").unwrap();
        let out = cut_line("a,b,c,d", ',', &fields);
        assert_eq!(out, "a,c");
    }

    #[test]
    fn cut_missing_fields_are_skipped() {
        let fields = parse_fields("2,5").unwrap();
        let out = cut_line("x|y|z", '|', &fields);
        assert_eq!(out, "y");
    }
}
