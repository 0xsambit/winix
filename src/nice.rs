/*
This file implements the Unix `nice` command for Windows,
allowing users to run processes with modified priority levels.

The Unix definition for 'nice' is:
nice [-Increment | -n Increment] Command [Argument...]

Arguments breakdown:
- -Increment: Directly specify priority increment (e.g., -10, -5)
- -n Increment: Alternative increment specification (e.g., -n 10)
- Command: The command/program to execute
- Argument...: Arguments to pass to the command

Priority levels:
- Unix nice values: -20 (highest) to +19 (lowest)
- Windows priority classes will be mapped accordingly
- Default increment: +10 (lower priority)

Key features:
1. Parse nice increment arguments (-n or direct)
2. Map Unix nice values to Windows priority classes
3. Spawn process with specified priority
4. Handle command execution and argument passing
*/

#![cfg(windows)]

use colored::*;
use log::debug;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt};
use std::ptr;
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::{
    CREATE_NEW_CONSOLE, NORMAL_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, 
    HIGH_PRIORITY_CLASS, REALTIME_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    ABOVE_NORMAL_PRIORITY_CLASS
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::errhandlingapi::GetLastError;
use winapi::shared::minwindef::{DWORD, FALSE};

#[derive(Debug, Clone)]
pub struct NiceOptions {
    pub increment: Option<i32>,          // Priority increment (-20 to +19)
    pub explicit_increment: Option<i32>, // Increment from -n flag
    pub command: String,                 // Command to execute
    pub arguments: Vec<String>,          // Command arguments
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum WindowsPriority {
    Realtime,      // -20 to -16
    High,          // -15 to -11  
    AboveNormal,   // -10 to -6
    Normal,        // -5 to +5 (default)
    BelowNormal,   // +6 to +10
    Idle,          // +11 to +19
}

impl Default for NiceOptions {
    fn default() -> Self {
        NiceOptions {
            increment: None,
            explicit_increment: None,
            command: String::new(),
            arguments: Vec::new(),
        }
    }
}

pub fn execute(args: &[&str]) -> Result<(), String> {
    if args.is_empty() {
        return Err(format!("{}",
            "Usage: nice [-increment | -n increment] command [argument...]\n\
            \n\
            Priority increments (Unix nice values):\n\
            -20 to -16  Realtime priority (requires admin)\n\
            -15 to -11  High priority\n\
            -10 to -6   Above normal priority\n\
            -5 to +5    Normal priority (default)\n\
            +6 to +10   Below normal priority\n\
            +11 to +19  Idle priority\n\
            \n\
            Examples:\n\
            nice notepad.exe        # Run notepad with default +10 increment\n\
            nice -10 calc.exe       # Run calculator with high priority\n\
            nice -n 15 ping google.com  # Run ping with idle priority"
        ));
    }

    let options = parse_arguments(args)?;
    validate_options(&options)?;
    debug!("Parsed options: {:?}", options);
    
    handle_nice_execution(&options)
}

fn handle_nice_execution(options: &NiceOptions) -> Result<(), String> {
    debug!("Starting nice execution for command: {}", options.command);
    
    // Determine the priority level to use
    let increment = options.increment
        .or(options.explicit_increment)
        .unwrap_or(10); // Default increment is +10 (lower priority)
    
    let priority_class = increment_to_windows_priority(increment)?;
    debug!("Using Windows priority class: {:?}", priority_class);
    
    execute_command_with_priority(&options.command, &options.arguments, priority_class)
}

// ============================================================================
// Helper Functions 
// ============================================================================

fn parse_arguments(args: &[&str]) -> Result<NiceOptions, String> {
    let mut options = NiceOptions::default();
    let mut i = 0;
    
    // Parse increment arguments first, then command and arguments
    while i < args.len() {
        let arg = args[i];
        
        match arg {
            // Handle -n increment format
            "-n" => {
                i += 1;
                if i >= args.len() {
                    return Err("Option -n requires an increment value".to_string());
                }
                match args[i].parse::<i32>() {
                    Ok(increment) => {
                        if increment < -20 || increment > 19 {
                            return Err(format!("Invalid nice increment: {} (must be between -20 and 19)", increment));
                        }
                        options.explicit_increment = Some(increment);
                    }
                    Err(_) => return Err(format!("Invalid increment value: {}", args[i])),
                }
            }
            
            // Handle direct -increment format (e.g., -10, -5)
            arg if arg.starts_with('-') && arg.len() > 1 => {
                let increment_str = &arg[1..]; // Remove the leading '-'
                match increment_str.parse::<i32>() {
                    Ok(increment) => {
                        // Make it negative since it started with '-'
                        let increment = -increment;
                        if increment < -20 || increment > 19 {
                            return Err(format!("Invalid nice increment: {} (must be between -20 and 19)", increment));
                        }
                        options.increment = Some(increment);
                    }
                    Err(_) => {
                        // Not a number, treat as command
                        options.command = arg.to_string();
                        break;
                    }
                }
            }
            
            // Everything else is command and arguments
            _ => {
                options.command = arg.to_string();
                // Collect remaining arguments
                i += 1;
                while i < args.len() {
                    options.arguments.push(args[i].to_string());
                    i += 1;
                }
                break;
            }
        }
        i += 1;
    }
    
    Ok(options)
}

fn validate_options(options: &NiceOptions) -> Result<(), String> {
    // Must have a command to execute
    if options.command.is_empty() {
        return Err("No command specified".to_string());
    }
    
    // Cannot specify increment in both ways
    if options.increment.is_some() && options.explicit_increment.is_some() {
        return Err("Cannot specify increment with both -increment and -n options".to_string());
    }
    
    // Validate command exists (basic check)
    if options.command.trim().is_empty() {
        return Err("Command cannot be empty".to_string());
    }
    
    // Check for common Windows executable extensions or assume it's valid
    let command_lower = options.command.to_lowercase();
    if !command_lower.ends_with(".exe") && 
       !command_lower.ends_with(".com") && 
       !command_lower.ends_with(".bat") && 
       !command_lower.ends_with(".cmd") &&
       !command_lower.contains('\\') && 
       !command_lower.contains('/') {
        // Might be a system command, let Windows handle validation during execution
    }
    
    Ok(())
}

fn increment_to_windows_priority(increment: i32) -> Result<WindowsPriority, String> {
    match increment {
        -20..=-16 => Ok(WindowsPriority::Realtime),
        -15..=-11 => Ok(WindowsPriority::High),
        -10..=-6 => Ok(WindowsPriority::AboveNormal),
        -5..=5 => Ok(WindowsPriority::Normal),
        6..=10 => Ok(WindowsPriority::BelowNormal),
        11..=19 => Ok(WindowsPriority::Idle),
        _ => Err(format!("Invalid nice increment: {} (must be between -20 and 19)", increment)),
    }
}

fn windows_priority_to_class(priority: WindowsPriority) -> DWORD {
    match priority {
        WindowsPriority::Realtime => REALTIME_PRIORITY_CLASS,
        WindowsPriority::High => HIGH_PRIORITY_CLASS,
        WindowsPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
        WindowsPriority::Normal => NORMAL_PRIORITY_CLASS,
        WindowsPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
        WindowsPriority::Idle => IDLE_PRIORITY_CLASS,
    }
}

fn execute_command_with_priority(command: &str, arguments: &[String], priority: WindowsPriority) -> Result<(), String> {
    debug!("Executing command '{}' with priority {:?}", command, priority);
    
    let priority_class = windows_priority_to_class(priority);
    
    unsafe {
        let command_line = build_command_line(command, arguments)?;
        let mut command_line_wide = string_to_wide(&command_line);
        
        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
        
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
        
        let result = CreateProcessW(
            ptr::null(),                    // lpApplicationName
            command_line_wide.as_mut_ptr(), // lpCommandLine
            ptr::null_mut(),                // lpProcessAttributes
            ptr::null_mut(),                // lpThreadAttributes
            FALSE,                          // bInheritHandles
            priority_class | CREATE_NEW_CONSOLE, // dwCreationFlags
            ptr::null_mut(),                // lpEnvironment
            ptr::null(),                    // lpCurrentDirectory
            &mut startup_info,              // lpStartupInfo
            &mut process_info,              // lpProcessInformation
        );
        
        if result == 0 {
            let error_code = GetLastError();
            return Err(format!("Failed to create process '{}': Windows error code {}", command, error_code));
        }
        
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
        
        println!("{}", format!("Successfully started '{}' with {} priority", command, format_priority_name(priority)).green());
    }
    
    Ok(())
}

fn build_command_line(command: &str, arguments: &[String]) -> Result<String, String> {
    // Build proper command line string with escaping for spaces
    let mut cmd_line = if command.contains(' ') && !command.starts_with('"') {
        format!("\"{}\"", command)
    } else {
        command.to_string()
    };
    
    for arg in arguments {
        cmd_line.push(' ');
        if arg.contains(' ') || arg.contains('"') {
            // Escape quotes and wrap in quotes
            let escaped_arg = arg.replace('"', "\\\"");
            cmd_line.push('"');
            cmd_line.push_str(&escaped_arg);
            cmd_line.push('"');
        } else {
            cmd_line.push_str(arg);
        }
    }
    Ok(cmd_line)
}

fn string_to_wide(s: &str) -> Vec<u16> {
    // Convert UTF-8 string to UTF-16 for Windows API
    OsString::from(s).encode_wide().chain(Some(0)).collect()
}

fn format_priority_name(priority: WindowsPriority) -> &'static str {
    match priority {
        WindowsPriority::Realtime => "realtime",
        WindowsPriority::High => "high",
        WindowsPriority::AboveNormal => "above normal",
        WindowsPriority::Normal => "normal",
        WindowsPriority::BelowNormal => "below normal",
        WindowsPriority::Idle => "idle",
    }
}

