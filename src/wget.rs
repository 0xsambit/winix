use reqwest::blocking::Client;
use reqwest::Url;
use std::fs;
use std::io;

fn parse_args(args: &[String]) -> io::Result<(bool, Option<String>, String)> {
    let mut quiet = false;
    let mut output: Option<String> = None;
    let mut url: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-q" => quiet = true,
            "-O" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "wget: -O requires a file path")
                })?;
                output = Some(value.to_string());
            }
            value if value.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("wget: unknown option '{}'", value),
                ));
            }
            value => {
                if url.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wget: only one URL is supported in this build",
                    ));
                }
                url = Some(value.to_string());
            }
        }
        i += 1;
    }

    let url = url.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "wget: usage: wget [-q] [-O file] <url>",
        )
    })?;

    Ok((quiet, output, url))
}

fn derive_output_name(url: &str) -> io::Result<String> {
    let parsed = Url::parse(url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("wget: {}", e)))?;

    let name = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|s| !s.is_empty())
        .unwrap_or("index.html")
        .to_string();

    Ok(name)
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (quiet, output, url) = parse_args(args)?;

    let client = Client::new();
    let response = client
        .get(&url)
        .send()
        .map_err(|e| io::Error::other(format!("wget: request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "wget: request returned HTTP status {}",
            response.status()
        )));
    }

    let body = response
        .bytes()
        .map_err(|e| io::Error::other(format!("wget: failed reading body: {}", e)))?;

    let output_name = match output {
        Some(path) => path,
        None => derive_output_name(&url)?,
    };

    fs::write(&output_name, &body)?;

    if !quiet {
        println!("Saved '{}' ({} bytes)", output_name, body.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::derive_output_name;

    #[test]
    fn derives_name_from_url() {
        let out = derive_output_name("https://example.com/file.txt").unwrap();
        assert_eq!(out, "file.txt");
    }
}
