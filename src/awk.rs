use regex::Regex;
use std::fs;
use std::io::{self, Read};

enum Condition {
    Always,
    Contains(String),
    Regex(Regex),
}

enum Action {
    PrintAll,
    PrintField(usize),
}

fn parse_condition(text: &str) -> io::Result<Condition> {
    let value = text.trim();
    if value.is_empty() {
        return Ok(Condition::Always);
    }

    if value.starts_with('/') && value.ends_with('/') && value.len() >= 2 {
        let re_src = &value[1..value.len() - 1];
        let re = Regex::new(re_src).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Condition::Regex(re))
    } else {
        Ok(Condition::Contains(value.to_string()))
    }
}

fn parse_action(text: &str) -> io::Result<Action> {
    let value = text.trim();
    if value.is_empty() || value == "print" {
        return Ok(Action::PrintAll);
    }

    if let Some(rest) = value.strip_prefix("print") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Ok(Action::PrintAll);
        }

        if let Some(field) = rest.strip_prefix('$') {
            let idx = field.parse::<usize>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("awk: invalid field selector '{}': expected $N", rest),
                )
            })?;

            if idx == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "awk: field index is 1-based",
                ));
            }

            return Ok(Action::PrintField(idx));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("awk: unsupported action '{}'", value),
    ))
}

fn parse_script(script: &str) -> io::Result<(Condition, Action)> {
    let trimmed = script.trim();
    if let (Some(open), Some(close)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if close <= open {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "awk: invalid script"));
        }

        let cond_text = trimmed[..open].trim();
        let action_text = trimmed[open + 1..close].trim();
        let cond = parse_condition(cond_text)?;
        let action = parse_action(action_text)?;
        return Ok((cond, action));
    }

    let cond = parse_condition(trimmed)?;
    Ok((cond, Action::PrintAll))
}

fn condition_matches(line: &str, cond: &Condition) -> bool {
    match cond {
        Condition::Always => true,
        Condition::Contains(v) => line.contains(v),
        Condition::Regex(re) => re.is_match(line),
    }
}

fn apply_action(line: &str, action: &Action, field_delimiter: Option<char>) -> Option<String> {
    match action {
        Action::PrintAll => Some(line.to_string()),
        Action::PrintField(idx) => {
            let value = if let Some(delim) = field_delimiter {
                line.split(delim).nth(*idx - 1)
            } else {
                line.split_whitespace().nth(*idx - 1)
            };
            value.map(|s| s.to_string())
        }
    }
}

pub fn process_lines(
    lines: &[String],
    script: &str,
    field_delimiter: Option<char>,
) -> io::Result<Vec<String>> {
    let (cond, action) = parse_script(script)?;
    let mut out = Vec::new();

    for line in lines {
        if condition_matches(line, &cond) {
            if let Some(v) = apply_action(line, &action, field_delimiter) {
                out.push(v);
            }
        }
    }

    Ok(out)
}

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "awk: usage: awk [-F delimiter] '<script>' [file ...]",
        ));
    }

    let mut delimiter: Option<char> = None;
    let mut script: Option<String> = None;
    let mut files = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-F" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "awk: -F requires a delimiter")
                })?;
                let mut chars = value.chars();
                let first = chars.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "awk: empty delimiter")
                })?;
                if chars.next().is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "awk: delimiter must be a single character",
                    ));
                }
                delimiter = Some(first);
            }
            item if item.starts_with('-') && item != "-" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("awk: unknown option '{}'", item),
                ));
            }
            value => {
                if script.is_none() {
                    script = Some(value.to_string());
                } else {
                    files.push(value.to_string());
                }
            }
        }
        i += 1;
    }

    let script = script.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "awk: missing script expression",
        )
    })?;

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

    let out = process_lines(&lines, &script, delimiter)?;
    if !out.is_empty() {
        println!("{}", out.join("\n"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::process_lines;

    #[test]
    fn matches_regex_and_prints_line() {
        let lines = vec!["foo 1".to_string(), "bar 2".to_string()];
        let out = process_lines(&lines, "/foo/", None).unwrap();
        assert_eq!(out, vec!["foo 1"]);
    }

    #[test]
    fn prints_selected_field_with_delimiter() {
        let lines = vec!["a,b,c".to_string(), "d,e,f".to_string()];
        let out = process_lines(&lines, "{print $2}", Some(','));
        assert_eq!(out.unwrap(), vec!["b", "e"]);
    }
}
