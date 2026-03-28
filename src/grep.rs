use bytes::Bytes;
use futures::stream::{self, Stream, StreamExt};
use regex::Regex;
use std::io::{self, BufRead};
use std::path::Path;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};

// Sync version for benchmarking
pub fn grep_sync<S: AsRef<Path>>(pattern: &str, files: Vec<S>) -> io::Result<String> {
    let regex = Regex::new(pattern).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut result = String::new();

    for file_path in files {
        let file = std::fs::File::open(&file_path)?;
        let reader = std::io::BufReader::new(file);

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if regex.is_match(&line) {
                result.push_str(&format!(
                    "{}:{}",
                    file_path.as_ref().display(),
                    line_num + 1
                ));
                result.push_str(": ");
                result.push_str(&line);
                result.push('\n');
            }
        }
    }

    Ok(result)
}

// Async version that returns a Stream<Bytes>
pub async fn grep_async<S: AsRef<Path> + Send + 'static>(
    pattern: &str,
    files: Vec<S>,
) -> impl Stream<Item = io::Result<Bytes>> {
    let regex = match Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            return stream::once(
                async move { Err(io::Error::new(io::ErrorKind::InvalidInput, e)) },
            )
            .boxed();
        }
    };

    if files.is_empty() {
        return stream::empty().boxed();
    }

    let path = files[0].as_ref().to_path_buf();

    async move {
        match TokioFile::open(&path).await {
            Ok(file) => {
                let reader = TokioBufReader::new(file);
                let lines = reader.lines();

                stream::unfold(
                    (lines, 0, path, regex),
                    |(mut lines, line_num, path, regex)| async move {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
                                if regex.is_match(&line) {
                                    let output =
                                        format!("{}:{}: {}\n", path.display(), line_num + 1, line);
                                    Some((
                                        Ok(Bytes::from(output)),
                                        (lines, line_num + 1, path, regex),
                                    ))
                                } else {
                                    // Skip non-matching lines by returning empty bytes
                                    Some((Ok(Bytes::new()), (lines, line_num + 1, path, regex)))
                                }
                            }
                            Ok(None) => None,
                            Err(e) => Some((Err(e), (lines, line_num, path, regex))),
                        }
                    },
                )
                .filter_map(|result| async move {
                    match result {
                        Ok(bytes) => {
                            if bytes.is_empty() {
                                None
                            } else {
                                Some(Ok(bytes))
                            }
                        }
                        Err(e) => Some(Err(e)),
                    }
                })
                .boxed()
            }
            Err(e) => stream::once(async move { Err(e) }).boxed(),
        }
    }
    .await
}

// Convenience function that collects the stream into a String
pub async fn grep_async_to_string<S: AsRef<Path> + Send + 'static>(
    pattern: &str,
    files: Vec<S>,
) -> io::Result<String> {
    let mut result = String::new();
    let mut stream = grep_async(pattern, files).await;

    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(bytes) => {
                if let Ok(chunk_str) = String::from_utf8(bytes.to_vec()) {
                    result.push_str(&chunk_str);
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_grep_sync() {
        let file_path = "test_grep.txt";
        let content = "hello world\nthis is a test\nhello again\nbye world";

        std::fs::write(file_path, content).unwrap();

        let result = grep_sync("hello", vec![file_path]).unwrap();
        assert!(result.contains("hello world"));
        assert!(result.contains("hello again"));

        std::fs::remove_file(file_path).unwrap();
    }

    #[tokio::test]
    async fn test_grep_async() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_grep_async.txt");
        let content = "hello world\nthis is a test\nhello again\nbye world";

        tokio::fs::write(&file_path, content).await.unwrap();

        let result = grep_async_to_string("hello", vec![file_path])
            .await
            .unwrap();
        assert!(result.contains("hello world"));
        assert!(result.contains("hello again"));
    }
}
