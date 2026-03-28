use colored::Colorize;
use rm::rm;
use rustyline::error::ReadlineError;
use std::env as std_env;
use std::fs;
use std::io::{self};
use winix::{echo, env, nproc, touch};

mod cat;
mod cd;
#[cfg(windows)]
mod chmod;
#[cfg(windows)]
mod chown;
mod cp;
mod df;
mod free;
mod git;
mod grep;
mod gzip;
mod head;
mod input;
mod ip;
#[cfg(windows)]
mod kill;
mod lsof;
mod mkdir;
mod mount;
mod nice;
mod powershell;
mod ps;
mod renice;
mod rm;
mod rmdir;
mod sensors;
mod sysinfo;
mod tail;
mod traceroute;
mod tree;
mod tui;
mod ulimit;
mod umount;
mod uname;
mod uptime;
mod wc;
mod zcat;

fn main() {
    let args: Vec<String> = std_env::args().collect();
    if args.contains(&"--interactive".to_string()) {
        git::interactive_mode();
    }
    if args.len() > 1 && args[1] == "--cli" {
        run_cli();
    } else {
        if let Err(err) = tui::run_tui() {
            eprintln!("Error running TUI: {}", err);
            eprintln!("Falling back to CLI mode...");
            run_cli();
        }
    }
}

fn run_cli() {
    let mut editor = input::LineEditor::new();
    show_splash_screen();

    loop {
        let readline = editor.read_line();
        match readline {
            Ok(line) => {
                editor.add_history_entry(line.as_str());

                if line.trim() == "exit" || line.trim() == "quit" {
                    println!("{}", "Goodbye!".bold().blue());
                    println!(
                        "{}{}",
                        "Want to contribute? Check out: ".bold().white(),
                        "https://github.com/0xsambit/winix".bold().green()
                    );
                    break;
                }

                handle_command(&line);
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
}

fn handle_command(line: &str) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    let command = parts[0].to_lowercase();
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    match command.as_str() {
        "cd" => {
            if args.is_empty() {
                println!("{}", "Usage: cd <directory>".red());
            } else if let Err(e) = cd_command(&args[0]) {
                println!("{}", format!("cd: {}", e).red());
            }
        }

        "pwd" => {
            if let Err(e) = pwd_command() {
                println!("{}", format!("pwd: {}", e).red());
            }
        }

        "ls" => {
            let dir = if args.is_empty() { "." } else { &args[0] };
            if let Err(e) = ls_command(dir) {
                println!("{}", format!("ls: {}", e).red());
            }
        }

        "echo" => echo::run(&args),
        "touch" => touch::run(&args),
        "cat" => {
            if args.is_empty() {
                println!("{}", "Usage: cat <file1> [file2] ...".red());
            } else {
                match cat::cat(args.iter().map(String::as_str).collect()) {
                    Ok(output) => print!("{}", output),
                    Err(e) => println!("{}", format!("cat: {}", e).red()),
                }
            }
        }
        "grep" => {
            if args.len() < 2 {
                println!("{}", "Usage: grep <pattern> <file1> [file2] ...".red());
            } else {
                let pattern = &args[0];
                let files: Vec<&str> = args[1..].iter().map(String::as_str).collect();
                match grep::grep_sync(pattern, files) {
                    Ok(output) => print!("{}", output),
                    Err(e) => println!("{}", format!("grep: {}", e).red()),
                }
            }
        }
        "head" => {
            if args.is_empty() {
                println!("{}", "Usage: head <file1> [file2] ...".red());
            } else {
                let files: Vec<&str> = args.iter().map(String::as_str).collect();
                match head::head_sync(files, 10) {
                    Ok(output) => print!("{}", output),
                    Err(e) => println!("{}", format!("head: {}", e).red()),
                }
            }
        }
        "tail" => {
            if args.is_empty() {
                println!("{}", "Usage: tail <file1> [file2] ...".red());
            } else {
                let files: Vec<&str> = args.iter().map(String::as_str).collect();
                match tail::tail_sync(files, 10) {
                    Ok(output) => print!("{}", output),
                    Err(e) => println!("{}", format!("tail: {}", e).red()),
                }
            }
        }
        "uname" => uname::execute(),
        "ps" => ps::execute(),
        "sensors" => sensors::execute(),
        "free" => free::execute(),
        "uptime" => uptime::execute(),
        "df" => df::execute(),

        #[cfg(windows)]
        "kill" => {
            if args.is_empty() {
                println!("{}", "Usage: kill <pid|name> [options]".red());
            } else if let Err(e) =
                kill::execute(&args.iter().map(String::as_str).collect::<Vec<_>>())
            {
                println!("{}", format!("kill: {}", e).red());
            }
        }

        #[cfg(windows)]
        "chmod" => {
            if args.is_empty() {
                println!("{}", "Usage: chmod <mode> <file>...".red());
            } else {
                let mode = &args[0];
                let files: Vec<&str> = args[1..].iter().map(String::as_str).collect();
                if files.is_empty() {
                    println!("{}", "Usage: chmod <mode> <file>...".red());
                } else {
                    // Call into library implementation for each file
                    for f in files {
                        let _ = chmod::execute(&[mode, f]);
                    }
                }
            }
        }
        #[cfg(windows)]
        "chown" => {
            if args.is_empty() {
                println!("{}", "Usage: chown <owner>[:group] <file>...".red());
            } else {
                let mode = &args[0];
                let files: Vec<&str> = args[1..].iter().map(String::as_str).collect();
                if files.is_empty() {
                    println!("{}", "Usage: chown <owner>[:group] <file>...".red());
                } else {
                    chown::execute(
                        &std::iter::once(mode.as_str())
                            .chain(files.into_iter())
                            .collect::<Vec<&str>>(),
                    );
                }
            }
        }

        "rm" => {
            if args.is_empty() {
                println!("{}", "Usage: rm <file1> [file2] ...".red());
            } else {
                match rm(args.iter().map(String::as_str).collect()) {
                    Ok(_) => {}
                    Err(e) => println!("{}", format!("rm: {}", e).red()),
                }
            }
        }
        "env" => {
            let code = env::execute(&args);
            if code != 0 {
                eprintln!("env exited with code {}", code);
            }
        }
        "nproc" => {
            let code = nproc::execute(&args);
            if code != 0 {
                eprintln!("nproc exited with code {}", code);
            }
        }
        "git" => {
            let git_args: Vec<&str> = args.iter().map(String::as_str).collect();
            git::execute(&git_args);
        }
        "psh" | "powershell" => {
            if args.get(0).map(String::as_str) == Some("--interactive") {
                powershell::interactive_mode();
            } else {
                powershell::execute(&args.iter().map(String::as_str).collect::<Vec<_>>());
            }
        }

        "help" => {
            show_splash_screen();
        }
        "mkdir" => {
            if let Err(e) = mkdir::run(&args) {
                println!("{}", format!("mkdir: {}", e).red());
            }
        }

        "rmdir" => {
            rmdir::run(&args);
        }

        "tree" => {
            if let Err(e) = tree::run(&args) {
                println!("{}", format!("tree: {}", e).red());
            }
        }

        "cp" => {
            if let Err(e) = cp::run(&args) {
                println!("{}", format!("cp: {}", e).red());
            }
        }

        "wc" => {
            if let Err(e) = wc::run(&args) {
                println!("{}", format!("wc: {}", e).red());
            }
        }

        "gzip" => {
            if let Err(e) = gzip::run(&args) {
                println!("{}", format!("gzip: {}", e).red());
            }
        }

        "zcat" => {
            if let Err(e) = zcat::run(&args) {
                println!("{}", format!("zcat: {}", e).red());
            }
        }

        "nice" => {
            if let Err(e) = nice::run(&args) {
                println!("{}", format!("nice: {}", e).red());
            }
        }

        "renice" => {
            if let Err(e) = renice::run(&args) {
                println!("{}", format!("renice: {}", e).red());
            }
        }

        "lsof" => {
            if let Err(e) = lsof::run(&args) {
                println!("{}", format!("lsof: {}", e).red());
            }
        }

        "ip" => {
            if let Err(e) = ip::run(&args) {
                println!("{}", format!("ip: {}", e).red());
            }
        }

        "ulimit" => {
            if let Err(e) = ulimit::run(&args) {
                println!("{}", format!("ulimit: {}", e).red());
            }
        }

        "mount" => {
            if let Err(e) = mount::run(&args) {
                println!("{}", format!("mount: {}", e).red());
            }
        }

        "umount" => {
            if let Err(e) = umount::run(&args) {
                println!("{}", format!("umount: {}", e).red());
            }
        }

        "traceroute" => {
            if args.is_empty() {
                traceroute::print_usage("traceroute");
                return;
            }

            // let host = &args[1];
            // let max_hops: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
            // let probes: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
            // let timeout_ms: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(2000);
            // let start_port: u16 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(33434u16);
            let host = &args[0];
            let max_hops: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(30);
            let probes: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
            let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
            #[cfg(not(target_os = "windows"))]
            let start_port: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(33434u16);

            #[cfg(target_os = "windows")]
            {
                traceroute::windows_traceroute(host, max_hops, probes, timeout_ms);
                return;
            }

            #[cfg(not(target_os = "windows"))]
            {
                if let Err(e) =
                    traceroute::run_traceroute_unix(host, max_hops, probes, timeout_ms, start_port)
                {
                    eprintln!("Traceroute failed: {}", e);
                }
            }
        }

        "sysinfo" => {
            sysinfo::run();
        }

        _ => {
            println!("{}", format!("Unknown command: '{}'", command).red());
            println!("{}", "Type 'help' for available commands".dimmed());
        }
    }
}

fn show_splash_screen() {
    println!(
        "{}",
        r#"██     ██ ██ ███    ██ ██ ██   ██
██     ██ ██ ████   ██ ██  ██ ██
██  █  ██ ██ ██ ██  ██ ██   ███
██ ███ ██ ██ ██  ██ ██ ██  ██ ██
 ███ ███  ██ ██   ████ ██ ██   ██"#
            .bold()
    );

    println!(
        "{}",
        "-----------Your Most Useful Linux Commands directly on Your Windows without WSL or a Linux Distro-------------"
            .bold()
            .blue()
    );
    println!();
    println!(
        "{}",
        "💡 RECOMMENDED: Launch the beautiful TUI interface with: winix --tui"
            .bold()
            .green()
    );
    println!(
        "{}",
        "   Experience all commands in a modern, responsive terminal interface!"
            .bold()
            .cyan()
    );
    println!();
    println!("{}", "Available Commands:".bold().white());
    println!(
        "  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}",
        "cd".bold().yellow(),
        "chmod".bold().yellow(),
        "chown".bold().yellow(),
        "df".bold().yellow(),
        "exit".bold().red(),
        "free".bold().yellow(),
        "git".bold().yellow(),
        "kill".bold().yellow(),
        "ls".bold().yellow(),
        "ps".bold().yellow(),
        "psh/powershell".bold().cyan(),
        "pwd".bold().yellow(),
        "sensors".bold().yellow(),
        "uptime".bold().yellow(),
        "uname".bold().yellow(),
        "env".bold().yellow(),
        "nproc".bold().yellow(),
    );
    println!(
        "  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}",
        "wc".bold().yellow(),
        "gzip".bold().yellow(),
        "zcat".bold().yellow(),
        "nice".bold().yellow(),
        "renice".bold().yellow(),
        "lsof".bold().yellow(),
        "ip".bold().yellow(),
        "ulimit".bold().yellow(),
        "mount".bold().yellow(),
        "umount".bold().yellow(),
    );
    println!();
}

// Utility commands
fn cd_command(path: &str) -> io::Result<()> {
    std_env::set_current_dir(path)
}

fn pwd_command() -> io::Result<()> {
    let cwd = std_env::current_dir()?;
    println!("{}", cwd.display().to_string().bold().cyan());
    Ok(())
}

fn ls_command(path: &str) -> io::Result<()> {
    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            println!("{}", file_name.blue().bold());
        } else {
            println!("{}", file_name.white());
        }
    }
    Ok(())
}
