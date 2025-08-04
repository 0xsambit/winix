use colored::*;
use std::env;
use std::fs;
use std::io::{self};
use winix::{echo, touch};
use rustyline::error::ReadlineError;
use rm::rm;

mod cd;
mod disown;
mod df;
mod free;
mod git;
#[cfg(windows)]
mod kill;
#[cfg(windows)]
mod nice;
mod powershell;
mod ps;
mod sensors;
mod sudo;
mod tui;
mod uname;
mod uptime;
mod cat;
mod rm;
mod input;
#[cfg(windows)]
mod chmod;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--interactive".to_string()) {
        git::interactive_mode();
    }
    let _ = rm(vec!["test.txt"]).expect("Failed to remove file");
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
            } else if let Err(e) = kill::execute(&args.iter().map(String::as_str).collect::<Vec<_>>()) {
                println!("{}", format!("kill: {}", e).red());
            }
        }
        
        #[cfg(windows)]
        "nice" => {
            let args: Vec<&str> = parts[1..].iter().copied().collect();
            match winix::nice::execute(&args) {
                Ok(_) => {}
                Err(e) => println!("{}", format!("nice: {}", e).red()),
            }
        }

        #[cfg(windows)]
        "chmod" | "chown" => {
            eprintln!("{} command is currently unavailable.", command);
        }

        "rm" => {
            if args.is_empty() {
                println!("{}", "Usage: rm <file1> [file2] ...".red());
            } else {
                for file in &args {
                    match fs::remove_file(file) {
                        Ok(_) => println!("Deleted {}", file),
                        Err(e) => eprintln!("Failed to delete {}: {}", file, e),
                    }
                }
            }
        }
        "git" => {
        let git_args = &["status"]; // Replace with real input
        git::execute(git_args);
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
 ███ ███  ██ ██   ████ ██ ██   ██"#.bold()
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
        "  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}\n  {}",
        "cd".bold().yellow(),
        "chmod".bold().yellow(),
        "chown".bold().yellow(),
        "df".bold().yellow(),
        "exit".bold().red(),
        "free".bold().yellow(),
        "git".bold().yellow(),
        "kill".bold().yellow(),
        "ls".bold().yellow(),
        "nice".bold().yellow(),
        "ps".bold().yellow(),
        "psh/powershell".bold().cyan(),
        "pwd".bold().yellow(),
        "sensors".bold().yellow(),
        "uptime".bold().yellow(),
        "uname".bold().yellow(),
    );
    println!();
}

// Utility commands
fn cd_command(path: &str) -> io::Result<()> {
    env::set_current_dir(path)
}

fn pwd_command() -> io::Result<()> {
    let cwd = env::current_dir()?;
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
