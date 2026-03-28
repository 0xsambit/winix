use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use sysinfo::System;

#[derive(Debug, Clone)]
pub struct ProcRow {
    pub pid: String,
    pub name: String,
    pub cpu: f32,
    pub memory: u64,
}

fn parse_args(args: &[String]) -> io::Result<(usize, u64, usize, bool)> {
    let mut iterations = 1usize;
    let mut delay_secs = 2u64;
    let mut limit = 15usize;
    let mut interactive = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: -n requires a value")
                })?;
                iterations = value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: invalid -n value")
                })?;
                if iterations == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "top: -n must be >= 1",
                    ));
                }
            }
            "-d" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: -d requires seconds")
                })?;
                delay_secs = value.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: invalid -d value")
                })?;
            }
            "-c" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: -c requires a value")
                })?;
                limit = value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "top: invalid -c value")
                })?;
                if limit == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "top: -c must be >= 1",
                    ));
                }
            }
            "-i" => interactive = true,
            other if other.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("top: unknown option '{}'", other),
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "top: unexpected positional argument",
                ));
            }
        }
        i += 1;
    }

    Ok((iterations, delay_secs, limit, interactive))
}

pub fn process_snapshot(limit: usize) -> Vec<ProcRow> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut rows: Vec<ProcRow> = sys
        .processes()
        .iter()
        .map(|(pid, process)| ProcRow {
            pid: pid.to_string(),
            name: process.name().to_string_lossy().to_string(),
            cpu: process.cpu_usage(),
            memory: process.memory(),
        })
        .collect();

    rows.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(limit);
    rows
}

fn print_snapshot(rows: &[ProcRow]) {
    println!("{:<8} {:<30} {:<8} {:<12}", "PID", "NAME", "CPU%", "MEM");
    println!("{}", "-".repeat(64));
    for row in rows {
        let name = if row.name.len() > 29 {
            format!("{}...", &row.name[..26])
        } else {
            row.name.clone()
        };
        println!(
            "{:<8} {:<30} {:<8.1} {:<12}",
            row.pid, name, row.cpu, row.memory
        );
    }
}

pub fn run(args: &[String]) -> io::Result<()> {
    let (iterations, delay_secs, limit, interactive) = parse_args(args)?;

    let mut remaining = if interactive { usize::MAX } else { iterations };

    loop {
        print!("\x1B[2J\x1B[1;1H");
        io::stdout().flush()?;

        let rows = process_snapshot(limit);
        print_snapshot(&rows);

        if remaining != usize::MAX {
            remaining = remaining.saturating_sub(1);
            if remaining == 0 {
                break;
            }
        }

        thread::sleep(Duration::from_secs(delay_secs));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::process_snapshot;

    #[test]
    fn snapshot_has_rows() {
        let rows = process_snapshot(5);
        assert!(!rows.is_empty());
    }
}
