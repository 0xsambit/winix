use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::fs;
use std::io::{self, Write};

fn parse_args(args: &[String]) -> io::Result<(bool, Option<String>, String)> {
    let mut follow_redirects = false;
    let mut output_file: Option<String> = None;
    let mut url: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-L" => follow_redirects = true,
            "-o" => {
                i += 1;
                let file = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "curl: -o requires a file path")
                })?;
                output_file = Some(file.to_string());
            }
            value if value.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("curl: unknown option '{}'", value),
                ));
            }
            value => {
                if url.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "curl: multiple URLs provided; only one URL is supported",
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
            "curl: usage: curl [-L] [-o file] <url>",
        )
    })?;

    Ok((follow_redirects, output_file, url))
}

pub fn fetch_url(url: &str, follow_redirects: bool) -> io::Result<Vec<u8>> {
    let client = Client::builder()
        .redirect(if follow_redirects {
            Policy::limited(10)
        } else {
            Policy::none()
        })
        .build()
        .map_err(|e| io::Error::other(format!("curl: failed to initialize client: {}", e)))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| io::Error::other(format!("curl: request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "curl: request returned HTTP status {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .map_err(|e| io::Error::other(format!("curl: failed reading body: {}", e)))?;

    Ok(bytes.to_vec())
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (follow_redirects, output_file, url) = parse_args(args)?;
    let body = fetch_url(&url, follow_redirects)?;

    if let Some(path) = output_file {
        fs::write(path, body)?;
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&body)?;
        if !body.ends_with(b"\n") {
            stdout.write_all(b"\n")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::fetch_url;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn fetches_from_local_http_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
                let _ = stream.write_all(response);
                let _ = stream.flush();
            }
        });

        let url = format!("http://{}/", addr);
        let body = fetch_url(&url, false).unwrap();
        assert_eq!(body, b"hello");

        handle.join().unwrap();
    }
}
