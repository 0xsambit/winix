use std::fs;
use std::io::{self, Read};

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: usize,
    words: usize,
    bytes: usize,
    chars: usize,
}

fn count_bytes(data: &[u8]) -> Counts {
    let text = String::from_utf8_lossy(data);
    Counts {
        lines: data.iter().filter(|&&b| b == b'\n').count(),
        words: text.split_whitespace().count(),
        bytes: data.len(),
        chars: text.chars().count(),
    }
}

fn format_counts(
    counts: Counts,
    show_lines: bool,
    show_words: bool,
    show_bytes: bool,
    show_chars: bool,
) -> String {
    let mut parts = Vec::new();
    if show_lines {
        parts.push(format!("{:>8}", counts.lines));
    }
    if show_words {
        parts.push(format!("{:>8}", counts.words));
    }
    if show_bytes {
        parts.push(format!("{:>8}", counts.bytes));
    }
    if show_chars {
        parts.push(format!("{:>8}", counts.chars));
    }
    parts.join(" ")
}

pub fn run(args: &[String]) -> io::Result<()> {
    let mut show_lines = false;
    let mut show_words = false;
    let mut show_bytes = false;
    let mut show_chars = false;
    let mut any_flag = false;
    let mut files = Vec::new();

    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            for flag in arg.chars().skip(1) {
                match flag {
                    'l' => {
                        any_flag = true;
                        show_lines = true;
                    }
                    'w' => {
                        any_flag = true;
                        show_words = true;
                    }
                    'c' => {
                        any_flag = true;
                        show_bytes = true;
                    }
                    'm' => {
                        any_flag = true;
                        show_chars = true;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unknown option '-{}'", flag),
                        ));
                    }
                }
            }
        } else {
            files.push(arg.clone());
        }
    }

    if !any_flag {
        show_lines = true;
        show_words = true;
        show_bytes = true;
    }

    if files.is_empty() {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        let counts = count_bytes(&data);
        println!(
            "{}",
            format_counts(counts, show_lines, show_words, show_bytes, show_chars)
        );
        return Ok(());
    }

    let mut total = Counts::default();
    let file_count = files.len();

    for file in files {
        let data = fs::read(&file)?;
        let counts = count_bytes(&data);
        total.lines += counts.lines;
        total.words += counts.words;
        total.bytes += counts.bytes;
        total.chars += counts.chars;

        println!(
            "{} {}",
            format_counts(counts, show_lines, show_words, show_bytes, show_chars),
            file
        );
    }

    if file_count > 1 {
        println!(
            "{} total",
            format_counts(total, show_lines, show_words, show_bytes, show_chars)
        );
    }

    Ok(())
}
