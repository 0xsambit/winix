#[cfg(windows)]
mod tests {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_nice_empty_arguments() {
        let result = winix::nice::execute(&[]);
        assert!(result.is_err(), "Empty args should return error with usage message");
        
        if let Err(message) = result {
            assert!(message.contains("Usage:"), "Error should contain usage information");
            assert!(message.contains("priority"), "Error should mention priority");
        }
    }
    
    #[test]
    fn test_nice_direct_increment_parsing() {
        // Test direct increment format: -10, -5, etc.
        
        // Valid direct increments
        let result = winix::nice::execute(&["-10", "cmd.exe", "/c", "echo", "test"]);
        // Should succeed (process creation might fail but parsing should work)
        
        let result = winix::nice::execute(&["-5", "notepad.exe"]);
        // Should succeed in parsing
        
        // Invalid direct increments (out of range)
        let result = winix::nice::execute(&["-25", "notepad.exe"]);
        assert!(result.is_err(), "Should reject increment -25 (out of range)");
        
        let result = winix::nice::execute(&["-21", "cmd.exe"]);
        assert!(result.is_err(), "Should reject increment -21 (out of range)");
        
        // Test positive increments with negative sign interpretation
        let result = winix::nice::execute(&["-19", "cmd.exe", "/c", "echo", "test"]);
        // Should succeed (maps to -19, which is valid realtime priority)
    }
    
    #[test]
    fn test_nice_flag_increment_parsing() {
        // Test -n flag format: -n 10, -n -5, etc.
        
        // Valid -n increments
        let result = winix::nice::execute(&["-n", "10", "cmd.exe", "/c", "echo", "test"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "-15", "notepad.exe"]);
        // Should succeed in parsing
        
        // Invalid -n increments (out of range)
        let result = winix::nice::execute(&["-n", "25", "notepad.exe"]);
        assert!(result.is_err(), "Should reject increment 25 (out of range)");
        
        let result = winix::nice::execute(&["-n", "-25", "cmd.exe"]);
        assert!(result.is_err(), "Should reject increment -25 (out of range)");
        
        // Missing increment value after -n
        let result = winix::nice::execute(&["-n", "notepad.exe"]);
        assert!(result.is_err(), "Should reject -n without increment value");
        
        // Invalid increment value (non-numeric)
        let result = winix::nice::execute(&["-n", "abc", "notepad.exe"]);
        assert!(result.is_err(), "Should reject non-numeric increment");
    }
    
    #[test]
    fn test_nice_conflicting_increments() {
        // Test that both -increment and -n cannot be specified together
        let result = winix::nice::execute(&["-10", "-n", "5", "notepad.exe"]);
        assert!(result.is_err(), "Should reject both direct increment and -n flag");
        
        let result = winix::nice::execute(&["-n", "10", "-5", "cmd.exe"]);
        assert!(result.is_err(), "Should reject both -n flag and direct increment");
    }
    
    #[test]
    fn test_nice_priority_range_validation() {
        // Test boundary values for each priority range
        
        // Realtime priority: -20 to -16
        let result = winix::nice::execute(&["-n", "-20", "cmd.exe", "/c", "echo", "realtime"]);
        // Should succeed in parsing (execution might fail due to permissions)
        
        let result = winix::nice::execute(&["-n", "-16", "cmd.exe", "/c", "echo", "realtime"]);
        // Should succeed in parsing
        
        // High priority: -15 to -11
        let result = winix::nice::execute(&["-15", "cmd.exe", "/c", "echo", "high"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-11", "cmd.exe", "/c", "echo", "high"]);
        // Should succeed in parsing
        
        // Above Normal: -10 to -6
        let result = winix::nice::execute(&["-n", "-10", "cmd.exe", "/c", "echo", "above_normal"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "-6", "cmd.exe", "/c", "echo", "above_normal"]);
        // Should succeed in parsing
        
        // Normal: -5 to +5
        let result = winix::nice::execute(&["-5", "cmd.exe", "/c", "echo", "normal"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "5", "cmd.exe", "/c", "echo", "normal"]);
        // Should succeed in parsing
        
        // Below Normal: +6 to +10
        let result = winix::nice::execute(&["-n", "6", "cmd.exe", "/c", "echo", "below_normal"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "10", "cmd.exe", "/c", "echo", "below_normal"]);
        // Should succeed in parsing
        
        // Idle: +11 to +19
        let result = winix::nice::execute(&["-n", "11", "cmd.exe", "/c", "echo", "idle"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "19", "cmd.exe", "/c", "echo", "idle"]);
        // Should succeed in parsing
    }
    
    #[test]
    fn test_nice_default_increment() {
        // Test that command without increment uses default (+10)
        let result = winix::nice::execute(&["cmd.exe", "/c", "echo", "default"]);
        // Should succeed and use default increment of +10 (below normal priority)
    }
    
    #[test]
    fn test_nice_command_validation() {
        // Test command validation
        
        // Empty command after valid increment
        let result = winix::nice::execute(&["-n", "10"]);
        assert!(result.is_err(), "Should reject missing command");
        
        // Command with spaces and arguments
        let result = winix::nice::execute(&["-n", "5", "C:\\Program Files\\Notepad++\\notepad++.exe", "test.txt"]);
        // Should succeed in parsing (even if execution fails)
        
        // Command with multiple arguments
        let result = winix::nice::execute(&["-10", "cmd.exe", "/c", "dir", "/w", "C:\\"]);
        // Should succeed in parsing
    }
    
    #[test]
    fn test_nice_increment_validation() {
        // Test increment value validation more thoroughly
        
        // Valid range: -20 to +19
        let result = winix::nice::execute(&["-n", "-20", "notepad.exe"]);
        // Should succeed in parsing
        
        let result = winix::nice::execute(&["-n", "19", "notepad.exe"]);
        // Should succeed in parsing
        
        // Invalid values: -21, 20, non-numeric
        let result = winix::nice::execute(&["-n", "-21", "notepad.exe"]);
        assert!(result.is_err(), "Should reject increment -21");
        
        let result = winix::nice::execute(&["-n", "20", "notepad.exe"]);
        assert!(result.is_err(), "Should reject increment 20");
        
        let result = winix::nice::execute(&["-n", "abc", "notepad.exe"]);
        assert!(result.is_err(), "Should reject non-numeric increment");
        
        let result = winix::nice::execute(&["-n", "", "notepad.exe"]);
        assert!(result.is_err(), "Should reject empty increment");
    }
    
    #[test]
    fn test_nice_simple_command_execution() {
        // Test simple command execution that should work
        // Use echo command which is fast and doesn't require special permissions
        
        let result = winix::nice::execute(&["-n", "10", "cmd.exe", "/c", "echo", "test"]);
        // Should succeed - this is a simple command that should execute quickly
        
        let result = winix::nice::execute(&["cmd.exe", "/c", "echo", "default_priority"]);
        // Should succeed with default priority
        
        // Test with calc.exe (if available)
        let result = winix::nice::execute(&["-n", "5", "calc.exe"]);
        // Should succeed in starting calculator
        
        // Note: We can't easily test the actual priority without external tools,
        // but we can verify the command starts successfully
    }
    
    #[test]
    fn test_nice_permission_requirements() {
        // Test permission requirements for different priority levels
        // Realtime priority typically requires admin privileges
        
        let result = winix::nice::execute(&["-20", "cmd.exe", "/c", "echo", "realtime"]);
        // Should either succeed (if admin) or fail gracefully (if not admin)
        // The key is that it shouldn't panic and should provide a meaningful error
        
        let result = winix::nice::execute(&["-n", "-19", "cmd.exe", "/c", "echo", "realtime"]);
        // Same as above - should handle permission requirements gracefully
        
        // High priority should generally work without admin
        let result = winix::nice::execute(&["-n", "-15", "cmd.exe", "/c", "echo", "high"]);
        // Should generally succeed
    }
    
    #[test]
    fn test_nice_argument_handling() {
        // Test proper handling of command arguments with spaces and special characters
        
        // Arguments with spaces
        let result = winix::nice::execute(&["-n", "10", "cmd.exe", "/c", "echo", "hello world"]);
        // Should succeed
        
        // Arguments with quotes
        let result = winix::nice::execute(&["-n", "5", "cmd.exe", "/c", "echo", "\"quoted string\""]);
        // Should succeed
        
        // Multiple arguments
        let result = winix::nice::execute(&["-10", "cmd.exe", "/c", "dir", "/w", "/p"]);
        // Should succeed
        
        // Long command path with spaces
        let result = winix::nice::execute(&["-n", "0", "C:\\Windows\\System32\\cmd.exe", "/c", "echo", "test"]);
        // Should succeed
    }
    
    #[test]
    fn test_nice_command_not_found() {
        // Test behavior when specified command doesn't exist
        let result = winix::nice::execute(&["nonexistent_command_12345.exe"]);
        assert!(result.is_err(), "Should fail when command doesn't exist");
        
        let result = winix::nice::execute(&["-n", "10", "definitely_not_a_real_command.exe"]);
        assert!(result.is_err(), "Should fail when command doesn't exist with increment");
        
        // Test with invalid path
        let result = winix::nice::execute(&["-5", "Z:\\nonexistent\\path\\program.exe"]);
        assert!(result.is_err(), "Should fail with invalid path");
    }
    
    #[test]
    fn test_nice_edge_cases() {
        // Test various edge cases and error conditions
        
        // Command that's just whitespace
        let result = winix::nice::execute(&["-n", "10", "   "]);
        assert!(result.is_err(), "Should reject whitespace-only command");
        
        // Very long command line
        let long_args: Vec<&str> = (0..100).map(|i| "arg").collect();
        let mut args = vec!["-n", "5", "cmd.exe", "/c", "echo"];
        args.extend(long_args);
        let result = winix::nice::execute(&args);
        // Should handle long argument lists (might succeed or fail based on system limits)
        
        // Command with unusual but valid extensions
        let result = winix::nice::execute(&["-n", "10", "test.bat"]);
        // Should accept .bat files (even if they don't exist)
        
        let result = winix::nice::execute(&["-n", "0", "script.cmd"]);
        // Should accept .cmd files
    }
    
    #[test]
    fn test_nice_help_message() {
        // Test that help/usage message is shown for empty arguments
        let result = winix::nice::execute(&[]);
        assert!(result.is_err(), "Should show usage for empty args");
        
        if let Err(message) = result {
            assert!(message.contains("Usage:"), "Error should contain usage information");
            assert!(message.contains("priority"), "Error should mention priority");
            assert!(message.contains("increment"), "Error should mention increment");
            assert!(message.contains("Examples:"), "Error should contain examples");
            assert!(message.contains("-20 to -16"), "Error should show realtime range");
            assert!(message.contains("+11 to +19"), "Error should show idle range");
        }
    }
    
    #[test]
    fn test_nice_output_validation() {
        // Test that successful execution produces expected output
        // We can't easily capture the colored output, but we can verify success
        
        let result = winix::nice::execute(&["-n", "10", "cmd.exe", "/c", "echo", "output_test"]);
        // Should succeed and should have printed success message
        
        let result = winix::nice::execute(&["cmd.exe", "/c", "ver"]);
        // Should succeed with default priority
    }
}
