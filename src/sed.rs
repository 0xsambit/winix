use regex::Regex;
use std::fs;
use std::io::{self, Read};

enum Script {
    Substitute {
        regex: Regex,
        replacement: String,
        global: bool,
    },
    Delete {
        regex: Regex,
    },
    Print {
        regex: Regex,
    },
}

fn parse_substitute(script: &str) -> io::Result<Script> {
    let delimiter = script
        .chars()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sed: invalid substitute"))?;

    let payload = &script[2..];
    let parts: Vec<&str> = payload.split(delimiter).collect();
    if parts.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sed: invalid substitute expression",
        ));
    }

    let regex = Regex::new(parts[0]).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let replacement = parts[1].to_string();
    let flags = parts[2];
    let global = flags.contains('g');

    Ok(Script::Substitute {
        regex,
        replacement,
        global,
    })
}

fn parse_script(script: &str) -> io::Result<Script> {
    let value = script.trim();

    if value.starts_with('s') {
        return parse_substitute(value);
    }

    if value.starts_with('/') && value.ends_with("/d") && value.len() >= 3 {
        let src = &value[1..value.len() - 2];
        let regex = Regex::new(src).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        return Ok(Script::Delete { regex });
    }

    if value.starts_with('/') && value.ends_with("/p") && value.len() >= 3 {
        let src = &value[1..value.len() - 2];
        let regex = Regex::new(src).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        return Ok(Script::Print { regex });
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "sed: supported scripts are s/old/new/[g], /re/d, /re/p",
    ))
}

pub fn apply_script(line: &str, script: &str) -> io::Result<(Option<String>, bool)> {
    match parse_script(script)? {
        Script::Substitute {
            regex,
            replacement,
            global,
        } => {
            let out = if global {
                regex.replace_all(line, replacement.as_str()).into_owned()
            } else {
                regex.replace(line, replacement.as_str()).into_owned()
            };
            Ok((Some(out), false))
        }
        Script::Delete { regex } => {
            if regex.is_match(line) {
                Ok((None, false))
            } else {
                Ok((Some(line.to_string()), false))
            }
        }
        Script::Print { regex } => {
            if regex.is_match(line) {
                Ok((Some(line.to_string()), true))
            } else {
                Ok((Some(line.to_string()), false))
            }
        }
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sed: usage: sed [-n] [-e script] [script] [file ...]",
        ));
    }

    let mut quiet = false;
    let mut script: Option<String> = None;
    let mut files = Vec::new();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => quiet = true,
            "-e" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "sed: -e requires a script")
                })?;
                script = Some(value.to_string());
            }
            item if item.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("sed: unknown option '{}'", item),
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
        io::Error::new(io::ErrorKind::InvalidInput, "sed: missing script expression")
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

    let mut out = Vec::new();
    for line in lines {
        let (processed, explicit_print) = apply_script(&line, &script)?;
        if let Some(value) = processed {
            if !quiet {
                out.push(value.clone());
            }
            if explicit_print {
                out.push(value);
            }
        }
    }

    if !out.is_empty() {
        println!("{}", out.join("\n"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::apply_script;

    #[test]
    fn substitute_global() {
        let (line, _) = apply_script("a a a", "s/a/b/g").unwrap();
        assert_eq!(line.unwrap(), "b b b");
    }

    #[test]
    fn delete_matching_line() {
        let (line, _) = apply_script("hello", "/ell/d").unwrap();
        assert!(line.is_none());
    }
}
