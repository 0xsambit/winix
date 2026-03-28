use colored::*;
use std::collections::HashMap;
use std::env as std_env;
use std::process::Command;

/// Configuration for the env command
#[derive(Debug, Default)]
struct EnvConfig {
    ignore_environment: bool,
    unset_vars: Vec<String>,
    set_vars: HashMap<String, String>,
    null_terminate: bool,
    command_args: Vec<String>,
}

/// Result type for env operations
type EnvResult<T> = Result<T, String>;

/// Execute the env command with given arguments
/// Returns exit code: 0 for success, non-zero for errors
pub fn execute(args: &[String]) -> i32 {
    if args.is_empty() {
        display_environment_variables();
        return 0;
    }

    match parse_arguments(args) {
        Ok(config) => {
            if !config.command_args.is_empty() {
                run_command_with_env(&config)
            } else {
                display_modified_environment(&config);
                0
            }
        }
        Err(e) => {
            eprintln!("{}", e.red());
            1
        }
    }
}

/// Parse command line arguments into configuration
fn parse_arguments(args: &[String]) -> EnvResult<EnvConfig> {
    let mut config = EnvConfig::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "-i" | "--ignore-environment" => {
                config.ignore_environment = true;
                i += 1;
            }
            "-u" | "--unset" => {
                if i + 1 < args.len() {
                    config.unset_vars.push(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("env: option requires an argument -- 'u'".to_string());
                }
            }
            "-0" | "--null" => {
                config.null_terminate = true;
                i += 1;
            }
            "--help" => {
                show_help();
                return Err("".to_string()); // Special case: help shown, exit cleanly
            }
            "--version" => {
                println!("env (winix) 1.0.0");
                return Err("".to_string()); // Special case: version shown, exit cleanly
            }
            arg if arg.starts_with('-') && config.command_args.is_empty() => {
                return Err(format!("env: invalid option -- '{}'", arg));
            }
            _ => {
                // Check if it's a variable assignment or command
                if arg.contains('=') && config.command_args.is_empty() {
                    parse_variable_assignment(arg, &mut config.set_vars)?;
                    i += 1;
                } else {
                    // Rest are command arguments
                    config.command_args.extend_from_slice(&args[i..]);
                    break;
                }
            }
        }
    }

    Ok(config)
}

/// Parse a variable assignment (KEY=VALUE)
fn parse_variable_assignment(arg: &str, set_vars: &mut HashMap<String, String>) -> EnvResult<()> {
    let parts: Vec<&str> = arg.splitn(2, '=').collect();
    if parts.len() == 2 {
        let key = parts[0];
        let value = parts[1];

        // Validate variable name
        if !is_valid_var_name(key) {
            return Err(format!("env: invalid variable name: '{}'", key));
        }

        set_vars.insert(key.to_string(), value.to_string());
        Ok(())
    } else {
        Err(format!("env: invalid assignment: '{}'", arg))
    }
}

/// Check if a variable name is valid
fn is_valid_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Variable names should start with letter or underscore
    // and contain only letters, numbers, and underscores
    name.chars().enumerate().all(|(i, c)| {
        if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        }
    })
}

/// Display all current environment variables
fn display_environment_variables() {
    let env_vars = get_sorted_env_vars();
    print_env_vars(&env_vars, false);
}

/// Get sorted environment variables
fn get_sorted_env_vars() -> Vec<(String, String)> {
    let mut env_vars: Vec<_> = std_env::vars().collect();
    env_vars.sort_by(|a, b| a.0.cmp(&b.0));
    env_vars
}

/// Display environment variables with modifications
fn display_modified_environment(config: &EnvConfig) {
    let env_vars = build_modified_environment(config);
    let mut sorted_vars: Vec<_> = env_vars.into_iter().collect();
    sorted_vars.sort_by(|a, b| a.0.cmp(&b.0));
    print_env_vars(&sorted_vars, config.null_terminate);
}

/// Build the modified environment based on configuration
fn build_modified_environment(config: &EnvConfig) -> HashMap<String, String> {
    let mut env_vars = HashMap::new();

    // Start with current environment unless ignoring it
    if !config.ignore_environment {
        for (key, value) in std_env::vars() {
            env_vars.insert(key, value);
        }
    }

    // Remove unset variables
    for var in &config.unset_vars {
        env_vars.remove(var);
    }

    // Add/override with set variables
    for (key, value) in &config.set_vars {
        env_vars.insert(key.clone(), value.clone());
    }

    env_vars
}

/// Print environment variables
fn print_env_vars(vars: &[(String, String)], null_terminate: bool) {
    for (key, value) in vars {
        if null_terminate {
            print!("{}={}\0", key.cyan(), value);
        } else {
            println!("{}={}", key.cyan(), value);
        }
    }
}

/// Run a command with modified environment
/// Returns the exit code of the executed command
fn run_command_with_env(config: &EnvConfig) -> i32 {
    if config.command_args.is_empty() {
        eprintln!("{}", "env: no command specified".red());
        return 127;
    }

    let program = &config.command_args[0];
    let args = &config.command_args[1..];

    // Try to run directly first
    let status = run_directly(program, args, config);

    match status {
        Ok(exit_status) => exit_status.code().unwrap_or(1),
        Err(e) => {
            // If direct execution fails, it might be a shell built-in or need shell expansion
            // Try with shell
            match run_with_shell(program, args, config) {
                Ok(exit_status) => exit_status.code().unwrap_or(1),
                Err(_shell_err) => {
                    eprintln!("{}", format!("env: cannot run '{}': {}", program, e).red());
                    127
                }
            }
        }
    }
}

/// Run command directly without shell
fn run_directly(
    program: &str,
    args: &[String],
    config: &EnvConfig,
) -> Result<std::process::ExitStatus, std::io::Error> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    apply_environment_to_command(&mut cmd, config);
    cmd.status()
}

/// Run command through shell for built-in commands or when direct execution fails
fn run_with_shell(
    program: &str,
    args: &[String],
    config: &EnvConfig,
) -> Result<std::process::ExitStatus, std::io::Error> {
    #[cfg(windows)]
    {
        // On Windows, we need to be careful with command construction
        // Check if this is a Unix-style shell (bash, sh) being invoked
        if program == "bash"
            || program == "sh"
            || program.ends_with("/bash")
            || program.ends_with("/sh")
        {
            // For Unix shells on Windows (e.g., Git Bash, WSL), pass arguments directly
            let mut cmd = Command::new(program);
            cmd.args(args);
            apply_environment_to_command(&mut cmd, config);
            return cmd.status();
        }

        // For Windows native commands, use cmd.exe
        let mut cmd = Command::new("cmd");
        cmd.args(&["/C"]);

        // Build the command string
        let mut full_command = String::new();

        // Add the program
        if program.contains(' ') {
            full_command.push_str(&format!("\"{}\"", program));
        } else {
            full_command.push_str(program);
        }

        // Add arguments
        for arg in args {
            full_command.push(' ');

            // Check if the argument needs quoting
            if arg.contains(' ') || arg.contains('"') {
                // Escape internal quotes and wrap in quotes
                let escaped = arg.replace('"', "\\\"");
                full_command.push_str(&format!("\"{}\"", escaped));
            } else {
                full_command.push_str(arg);
            }
        }

        cmd.arg(&full_command);
        apply_environment_to_command(&mut cmd, config);
        cmd.status()
    }

    #[cfg(not(windows))]
    {
        // On Unix-like systems, if we're calling bash or sh directly with -c,
        // we should pass the arguments as-is, not reconstruct them
        if program == "bash"
            || program == "sh"
            || program.ends_with("/bash")
            || program.ends_with("/sh")
        {
            let mut cmd = Command::new(program);
            cmd.args(args);
            apply_environment_to_command(&mut cmd, config);
            return cmd.status();
        }

        // For other commands that need shell interpretation, use sh -c
        let mut cmd = Command::new("sh");
        cmd.arg("-c");

        // Build the command string
        let mut full_command = String::new();

        // Add the program
        if program.contains(' ') || program.contains('\'') {
            full_command.push_str(&format!("'{}'", program.replace('\'', "'\\''")));
        } else {
            full_command.push_str(program);
        }

        // Add arguments - be careful with quoting
        for arg in args {
            full_command.push(' ');

            // If argument contains special characters, quote it
            if arg.contains(' ')
                || arg.contains('\'')
                || arg.contains('"')
                || arg.contains('$')
                || arg.contains('*')
                || arg.contains('?')
                || arg.contains('&')
                || arg.contains('|')
                || arg.contains(';')
                || arg.contains('(')
                || arg.contains(')')
                || arg.contains('<')
                || arg.contains('>')
                || arg.contains('`')
                || arg.contains('\\')
            {
                // Use single quotes and escape any single quotes in the argument
                full_command.push_str(&format!("'{}'", arg.replace('\'', "'\\''")));
            } else {
                full_command.push_str(arg);
            }
        }

        cmd.arg(&full_command);
        apply_environment_to_command(&mut cmd, config);
        cmd.status()
    }
}

#[allow(dead_code)]
/// Expand environment variables in a string
fn expand_env_vars(input: &str, config: &EnvConfig) -> String {
    let env_map = build_modified_environment(config);
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            // Check for ${VAR} syntax
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                let mut found_closing = false;

                while let Some(ch) = chars.next() {
                    if ch == '}' {
                        found_closing = true;
                        break;
                    }
                    var_name.push(ch);
                }

                if found_closing {
                    if let Some(value) = env_map.get(&var_name) {
                        result.push_str(value);
                    } else {
                        // Variable not found, keep original
                        result.push_str(&format!("${{{}}}", var_name));
                    }
                } else {
                    // No closing brace, keep original
                    result.push('$');
                    result.push('{');
                    result.push_str(&var_name);
                }
            } else {
                // $VAR syntax - collect variable name
                let mut var_name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        var_name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }

                if !var_name.is_empty() {
                    if let Some(value) = env_map.get(&var_name) {
                        result.push_str(value);
                    } else {
                        // Variable not found, keep original
                        result.push('$');
                        result.push_str(&var_name);
                    }
                } else {
                    // Just a lone $
                    result.push('$');
                }
            }
        } else {
            result.push(ch);
        }
    }

    // Handle %VAR% syntax on Windows
    #[cfg(windows)]
    {
        let mut windows_result = String::new();
        let mut chars = result.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                let mut var_name = String::new();
                let mut found_closing = false;

                while let Some(ch) = chars.next() {
                    if ch == '%' {
                        found_closing = true;
                        break;
                    }
                    var_name.push(ch);
                }

                if found_closing && !var_name.is_empty() {
                    if let Some(value) = env_map.get(&var_name) {
                        windows_result.push_str(value);
                    } else {
                        // Variable not found, keep original
                        windows_result.push('%');
                        windows_result.push_str(&var_name);
                        windows_result.push('%');
                    }
                } else {
                    // No closing % or empty name, keep original
                    windows_result.push('%');
                    if !var_name.is_empty() {
                        windows_result.push_str(&var_name);
                    }
                }
            } else {
                windows_result.push(ch);
            }
        }

        return windows_result;
    }

    result
}

/// Apply environment configuration to a command
fn apply_environment_to_command(cmd: &mut Command, config: &EnvConfig) {
    if config.ignore_environment {
        cmd.env_clear();
    }

    // Remove unset variables
    for var in &config.unset_vars {
        cmd.env_remove(var);
    }

    // Add/override with set variables
    for (key, value) in &config.set_vars {
        cmd.env(key, value);
    }
}

/// Show help information
fn show_help() {
    println!(
        "{}",
        "env - Display and modify environment variables".bold()
    );
    println!();
    println!("{}", "USAGE:".bold());
    println!("    env [OPTION]... [NAME=VALUE]... [COMMAND [ARG]...]");
    println!();
    println!("{}", "OPTIONS:".bold());
    println!("    -i, --ignore-environment    Start with an empty environment");
    println!("    -u, --unset NAME            Remove variable NAME from the environment");
    println!("    -0, --null                  End each output line with NUL, not newline");
    println!("    --version                   Output version information and exit");
    println!("    --help                      Display this help and exit");
    println!();
    println!("{}", "DESCRIPTION:".bold());
    println!("    Set each NAME to VALUE in the environment and run COMMAND.");
    println!("    If no COMMAND, print the resulting environment.");
    println!();
    println!("{}", "EXAMPLES:".bold());
    println!("    env                         Display all environment variables");
    println!("    env -i                      Display empty environment");
    println!("    env -u PATH                 Display environment without PATH");

    #[cfg(windows)]
    {
        println!("    env FOO=bar cmd /c echo %FOO%  Run cmd with FOO set to bar");
        println!("    env FOO=bar echo $FOO           Shell expansion of $FOO");
    }

    #[cfg(not(windows))]
    {
        println!("    env FOO=bar echo $FOO           Run echo with FOO expanded");
        println!("    env -i NEW=value bash           Run bash with only NEW set");
    }
}

/// Get environment variables for TUI display
pub fn get_env_for_tui() -> Vec<(String, String)> {
    get_sorted_env_vars()
}

/// Get a specific environment variable
pub fn get_env_var(name: &str) -> Option<String> {
    std_env::var(name).ok()
}

/// Set environment variable (for TUI interaction)
pub fn set_env_var(name: &str, value: &str) -> Result<(), String> {
    if !is_valid_var_name(name) {
        return Err(format!("Invalid variable name: {}", name));
    }
    unsafe {
        std_env::set_var(name, value);
    }
    Ok(())
}

/// Remove environment variable (for TUI interaction)
pub fn remove_env_var(name: &str) -> Result<(), String> {
    if !is_valid_var_name(name) {
        return Err(format!("Invalid variable name: {}", name));
    }
    unsafe {
        std_env::remove_var(name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_variable_assignment() {
        let mut vars = HashMap::new();

        // Valid assignments
        assert!(parse_variable_assignment("TEST_VAR=value", &mut vars).is_ok());
        assert_eq!(vars.get("TEST_VAR"), Some(&"value".to_string()));

        assert!(parse_variable_assignment("EMPTY=", &mut vars).is_ok());
        assert_eq!(vars.get("EMPTY"), Some(&"".to_string()));

        assert!(parse_variable_assignment("WITH_EQUALS=a=b=c", &mut vars).is_ok());
        assert_eq!(vars.get("WITH_EQUALS"), Some(&"a=b=c".to_string()));

        // Invalid assignments
        assert!(parse_variable_assignment("", &mut vars).is_err());
        assert!(parse_variable_assignment("NO_EQUALS", &mut vars).is_err());
        assert!(parse_variable_assignment("123_INVALID=value", &mut vars).is_err());
    }

    #[test]
    fn test_is_valid_var_name() {
        // Valid names
        assert!(is_valid_var_name("PATH"));
        assert!(is_valid_var_name("_underscore"));
        assert!(is_valid_var_name("VAR_123"));
        assert!(is_valid_var_name("a"));

        // Invalid names
        assert!(!is_valid_var_name(""));
        assert!(!is_valid_var_name("123_start"));
        assert!(!is_valid_var_name("var-with-dash"));
        assert!(!is_valid_var_name("var.with.dot"));
        assert!(!is_valid_var_name("var with space"));
    }

    #[test]
    fn test_expand_env_vars() {
        let mut config = EnvConfig::default();
        config
            .set_vars
            .insert("TEST".to_string(), "value".to_string());
        config.set_vars.insert("FOO".to_string(), "bar".to_string());
        config
            .set_vars
            .insert("TEST_suffix".to_string(), "another_value".to_string());

        // Test $VAR expansion
        assert_eq!(expand_env_vars("$TEST", &config), "value");
        assert_eq!(expand_env_vars("prefix_$TEST", &config), "prefix_value");

        // This is the key test case - $TEST_suffix should NOT expand $TEST
        // because TEST_suffix is a different variable name
        assert_eq!(expand_env_vars("$TEST_suffix", &config), "another_value");

        // Test with actual underscore after variable
        assert_eq!(expand_env_vars("${TEST}_suffix", &config), "value_suffix");

        // Test ${VAR} expansion
        assert_eq!(expand_env_vars("${TEST}", &config), "value");
        assert_eq!(
            expand_env_vars("prefix_${TEST}_suffix", &config),
            "prefix_value_suffix"
        );

        // Test multiple variables
        assert_eq!(expand_env_vars("$TEST and $FOO", &config), "value and bar");
        assert_eq!(
            expand_env_vars("${TEST} and ${FOO}", &config),
            "value and bar"
        );

        // Test non-existent variable (should remain unchanged)
        assert_eq!(expand_env_vars("$NONEXISTENT", &config), "$NONEXISTENT");
        assert_eq!(expand_env_vars("${NONEXISTENT}", &config), "${NONEXISTENT}");

        // Test edge cases
        assert_eq!(expand_env_vars("$", &config), "$");
        assert_eq!(expand_env_vars("${", &config), "${");
        assert_eq!(expand_env_vars("${TEST", &config), "${TEST");
        assert_eq!(expand_env_vars("$$TEST", &config), "$value");

        // Test with special characters that end variable names
        assert_eq!(expand_env_vars("$TEST-dash", &config), "value-dash");
        assert_eq!(expand_env_vars("$TEST.dot", &config), "value.dot");
        assert_eq!(expand_env_vars("$TEST/slash", &config), "value/slash");
        assert_eq!(expand_env_vars("$TEST$FOO", &config), "valuebar");
    }

    #[test]
    fn test_build_modified_environment() {
        let mut config = EnvConfig::default();
        config
            .set_vars
            .insert("TEST_VAR".to_string(), "test_value".to_string());

        let env = build_modified_environment(&config);
        assert_eq!(env.get("TEST_VAR"), Some(&"test_value".to_string()));

        // Test with ignore environment
        config.ignore_environment = true;
        let env = build_modified_environment(&config);
        assert_eq!(env.len(), 1);
        assert_eq!(env.get("TEST_VAR"), Some(&"test_value".to_string()));
    }

    #[test]
    fn test_return_codes() {
        // Test successful display
        let code = execute(&vec![]);
        assert_eq!(code, 0);

        // Test invalid option
        let code = execute(&vec!["--invalid".to_string()]);
        assert_eq!(code, 1);
    }
}
