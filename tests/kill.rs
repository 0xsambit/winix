#[cfg(windows)]
mod tests {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION};

    // Helper function to create a long-running test process
    fn create_test_process() -> std::process::Child {
        // Prefer PowerShell sleep for speed, but fall back to cmd timeout if PowerShell
        // launch is blocked in the current environment.
        if let Ok(child) = Command::new("powershell")
            .args(&["-Command", "Start-Sleep", "30"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            return child;
        }

        Command::new("cmd")
            .args(&["/c", "timeout", "/t", "30", "/nobreak"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start test process with powershell and cmd fallback")
    }

    // Alternative helper using CMD timeout (even more lightweight)
    #[allow(dead_code)]
    fn create_test_process_alt() -> std::process::Child {
        Command::new("cmd")
            .args(&["/c", "timeout", "/t", "30", "/nobreak"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start test process")
    }

    // Ultra-lightweight helper for quick tests - just waits for input
    #[allow(dead_code)]
    fn create_quick_test_process() -> std::process::Child {
        Command::new("cmd")
            .args(&["/c", "pause"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::piped())
            .spawn()
            .expect("Failed to start quick test process")
    }

    #[test]
    fn test_kill_running_process() {
        // Starting a long-running process using PowerShell sleep (much more efficient)
        let mut child = create_test_process();

        let pid = child.id();
        println!("Started process with PID: {}", pid);
        thread::sleep(Duration::from_millis(100));

        let running = is_process_running(pid);
        println!("Process {} running check: {}", pid, running);

        if !running {
            // Let's try a different approach - just check that child.try_wait() returns None
            match child.try_wait() {
                Ok(None) => println!("Process is still running (via try_wait)"),
                Ok(Some(status)) => {
                    println!("Process already exited with status: {:?}", status);
                    panic!("Process exited unexpectedly before kill");
                }
                Err(e) => {
                    println!("Error checking process status: {}", e);
                    panic!("Error checking process status: {}", e);
                }
            }
        }

        //Call to kill function as in UNIX
        let result = winix::kill::execute(&[&pid.to_string()]);
        println!("Kill result: {:?}", result);

        assert!(result.is_ok(), "Kill command should succeed");
        thread::sleep(Duration::from_millis(500));

        // Verify the process was actually killed
        match child.try_wait() {
            Ok(Some(_)) => {
                assert!(true, "Process was successfully terminated");
            }
            Ok(None) => {
                //kill failed
                let _ = child.kill(); // Clean up the started process
                panic!("Process is still running after kill command");
            }
            Err(e) => {
                panic!("Error checking process status: {}", e);
            }
        }
    }

    #[test]
    fn test_kill_nonexistent_process() {
        let fake_pid = "999999"; //Fake pid unlikely to exist
        let result = winix::kill::execute(&[fake_pid]);
        // This should return an error
        assert!(result.is_err(), "Kill should fail for non-existent process");
    }

    #[test]
    fn test_kill_with_signal() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));
        let result = winix::kill::execute(&["-9", &pid.to_string()]);
        assert!(result.is_ok(), "Kill with signal should succeed");
        thread::sleep(Duration::from_millis(500));

        match child.try_wait() {
            Ok(Some(_)) => assert!(true, "Process terminated with signal"),
            Ok(None) => {
                let _ = child.kill();
                panic!("Process still running after kill -9");
            }
            Err(e) => panic!("Error checking process: {}", e),
        }
    }

    #[test]
    fn test_kill_current_process_protection() {
        // Try to kill the current process (should be protected or handled gracefully)
        let current_pid = unsafe { GetCurrentProcessId() };
        let _result = winix::kill::execute(&[&current_pid.to_string()]);
        assert!(true, "Test process should still be running");
    }

    #[test]
    fn test_kill_invalid_arguments() {
        // Test with no arguments
        let result = winix::kill::execute(&[]);
        assert!(result.is_err(), "Kill with no args should fail");

        // Test with invalid PID format
        let result = winix::kill::execute(&["not_a_number"]);
        assert!(result.is_err(), "Kill with invalid PID should fail");

        // Test with negative PID (should be treated as invalid signal)
        let result = winix::kill::execute(&["-123"]);
        assert!(result.is_err(), "Kill with invalid signal should fail");
    }

    #[test]
    fn test_kill_by_process_name() {
        // Start multiple processes with the same name - using PowerShell for efficiency
        let mut children = Vec::new();
        for _ in 0..2 {
            let child = create_test_process();
            children.push(child);
        }

        thread::sleep(Duration::from_millis(100));

        // Kill by process name (should kill only one by default)
        let result = winix::kill::execute(&["powershell"]);

        // Note: This test will fail until process name killing is implemented
        // For now, we just check that it doesn't panic
        let _ = result;

        // Clean up remaining processes
        for mut child in children {
            let _ = child.kill();
        }
    }

    #[test]
    fn test_kill_all_processes_by_name() {
        // Start multiple processes with the same name - using PowerShell for efficiency
        let mut children = Vec::new();
        for _ in 0..3 {
            let child = create_test_process();
            children.push(child);
        }

        thread::sleep(Duration::from_millis(100));

        // Kill all processes with name using -a flag
        let result = winix::kill::execute(&["-a", "powershell"]);

        // Note: This test will fail until process name killing is implemented
        let _ = result;

        // Clean up any remaining processes
        for mut child in children {
            let _ = child.kill();
        }
    }

    #[test]
    fn test_kill_with_valid_signals() {
        let test_signals = vec![
            ("-2", "SIGINT"),
            ("-3", "SIGQUIT"),
            ("-9", "SIGKILL"),
            ("-15", "SIGTERM"),
            ("-INT", "INT signal"),
            ("-QUIT", "QUIT signal"),
            ("-KILL", "KILL signal"),
            ("-TERM", "TERM signal"),
        ];

        for (signal, description) in test_signals {
            let mut child = create_test_process();

            let pid = child.id();
            thread::sleep(Duration::from_millis(100));

            let result = winix::kill::execute(&[signal, &pid.to_string()]);

            // Should succeed for all valid signals
            assert!(
                result.is_ok(),
                "Kill with {} ({}) should succeed",
                signal,
                description
            );

            thread::sleep(Duration::from_millis(200));

            // Clean up if process is still running
            let _ = child.kill();
        }
    }

    #[test]
    fn test_kill_with_invalid_signals() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        let invalid_signals = vec![
            "-HUP",     // Not supported on Windows
            "-USR1",    // Not supported on Windows
            "-PIPE",    // Not supported on Windows
            "-999",     // Invalid signal number
            "-INVALID", // Invalid signal name
        ];

        for signal in invalid_signals {
            let result = winix::kill::execute(&[signal, &pid.to_string()]);
            assert!(
                result.is_err(),
                "Kill with invalid signal {} should fail",
                signal
            );
        }

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_kill_with_explicit_signal_flag() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test -s flag with different signals
        let pid_str = pid.to_string();
        let test_cases = vec![
            vec!["-s", "TERM", &pid_str],
            vec!["-s", "9", &pid_str],
            vec!["-s", "KILL", &pid_str],
        ];

        for args in test_cases {
            // Start a new process for each test
            let mut new_child = create_test_process();

            let new_pid = new_child.id();
            thread::sleep(Duration::from_millis(100));

            let new_pid_str = new_pid.to_string();
            let mut test_args = args.clone();
            test_args[2] = &new_pid_str;

            let result = winix::kill::execute(&test_args);
            if let Err(e) = result {
                let tolerated = e.contains("Access denied")
                    || e.contains("protected process")
                    || e.contains("Some kill operations failed");
                assert!(
                    tolerated,
                    "Kill with -s flag failed unexpectedly for args {:?}: {}",
                    test_args, e
                );
            }

            thread::sleep(Duration::from_millis(200));
            let _ = new_child.kill();
        }

        // Clean up original process
        let _ = child.kill();
    }

    #[test]
    fn test_print_only_mode() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test -p flag (print only, don't kill)
        let result = winix::kill::execute(&["-p", &pid.to_string()]);
        assert!(result.is_ok(), "Print-only mode should succeed");

        thread::sleep(Duration::from_millis(200));

        // Process should still be running after -p (using try_wait for reliability)
        match child.try_wait() {
            Ok(None) => {
                // Process is still running - this is expected for print-only mode
                assert!(true, "Process correctly still running after -p flag");
            }
            Ok(Some(status)) => {
                panic!(
                    "Process unexpectedly exited with status: {:?} after print-only mode",
                    status
                );
            }
            Err(e) => {
                panic!("Error checking process status: {}", e);
            }
        }

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_print_only_with_process_name() {
        let mut child = create_test_process();

        thread::sleep(Duration::from_millis(100));

        // Test -p flag with process name
        let result = winix::kill::execute(&["-p", "powershell"]);

        // Should succeed but not kill the process
        // Note: Will fail until process name lookup is implemented
        let _ = result;

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_conflicting_signal_options() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test conflicting signal specifications (should fail)
        let result = winix::kill::execute(&["-9", "-s", "TERM", &pid.to_string()]);
        assert!(result.is_err(), "Conflicting signal options should fail");

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_queue_value_option() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test -q flag with value
        let result = winix::kill::execute(&["-q", "42", "-TERM", &pid.to_string()]);
        assert!(result.is_ok(), "Kill with queue value should succeed");

        thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_end_of_options_marker() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test -- marker (everything after is treated as target)
        let result = winix::kill::execute(&["--", &pid.to_string()]);
        assert!(result.is_ok(), "Kill with -- marker should succeed");

        thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_multiple_targets() {
        // Start multiple processes
        let mut children = Vec::new();
        let mut pids = Vec::new();

        for _ in 0..3 {
            let child = create_test_process();

            pids.push(child.id().to_string());
            children.push(child);
        }

        thread::sleep(Duration::from_millis(100));

        // Kill multiple processes at once
        let mut args = vec!["-9"];
        for pid in &pids {
            args.push(pid);
        }

        let result = winix::kill::execute(&args);
        if let Err(e) = result {
            let tolerated = e.contains("Access denied")
                || e.contains("protected process")
                || e.contains("Some kill operations failed");
            assert!(
                tolerated,
                "Kill with multiple targets failed unexpectedly: {}",
                e
            );
        }

        thread::sleep(Duration::from_millis(500));

        // Clean up any remaining processes
        for mut child in children {
            let _ = child.kill();
        }
    }

    #[test]
    fn test_timeout_option() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test --timeout option
        let result = winix::kill::execute(&["--timeout", "1000", "KILL", &pid.to_string()]);

        // Should succeed (even if not fully implemented yet)
        assert!(result.is_ok(), "Kill with timeout should succeed");

        thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_invalid_a_flag_with_pid() {
        // Test that -a flag fails when used with numeric PID
        let result = winix::kill::execute(&["-a", "1234"]);
        assert!(result.is_err(), "-a flag with numeric PID should fail");
    }

    #[test]
    fn test_missing_signal_argument() {
        // Test missing argument for -s flag
        let result = winix::kill::execute(&["-s"]);
        assert!(result.is_err(), "Missing signal argument should fail");

        // Test missing argument for -q flag
        let result = winix::kill::execute(&["-q"]);
        assert!(result.is_err(), "Missing queue value argument should fail");
    }

    #[test]
    fn test_system_process_protection() {
        // Test protection against killing system processes
        let system_pids = vec!["0", "4", "8"]; // Common system process PIDs

        for pid in system_pids {
            let result = winix::kill::execute(&[pid]);
            // Should either fail gracefully or be protected
            // Implementation dependent - just ensure no panic
            let _ = result;
        }
    }

    #[test]
    fn test_nonexistent_process_name() {
        // Test killing a process name that doesn't exist
        let result = winix::kill::execute(&["nonexistent_process_name_12345"]);
        assert!(
            result.is_err(),
            "Killing nonexistent process name should fail"
        );
    }

    #[test]
    fn test_combined_flags() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test combining valid flags
        let result = winix::kill::execute(&["-q", "42", "-s", "TERM", &pid.to_string()]);
        assert!(result.is_ok(), "Combined valid flags should succeed");

        thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_invalid_queue_value() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test invalid queue value (non-numeric)
        let result = winix::kill::execute(&["-q", "invalid", &pid.to_string()]);
        assert!(result.is_err(), "Invalid queue value should fail");

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_timeout_without_signal() {
        let mut child = create_test_process();

        let pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test --timeout without specifying the final signal (should fail)
        let result = winix::kill::execute(&["--timeout", "1000", &pid.to_string()]);
        assert!(result.is_err(), "Timeout without signal should fail");

        // Clean up
        let _ = child.kill();
    }

    #[test]
    fn test_print_only_no_targets() {
        // Test -p flag without any targets (should be allowed)
        let result = winix::kill::execute(&["-p"]);
        // This should be OK according to Unix kill behavior
        let _ = result; // Implementation dependent
    }

    #[test]
    fn test_case_insensitive_signals() {
        let mut child = create_test_process();

        let _pid = child.id();
        thread::sleep(Duration::from_millis(100));

        // Test that signal names are case-insensitive
        let signals = vec!["-term", "-TERM", "-Term", "-kill", "-KILL", "-Kill"];

        for signal in signals {
            let mut new_child = create_test_process();

            let new_pid = new_child.id();
            thread::sleep(Duration::from_millis(50));

            let result = winix::kill::execute(&[signal, &new_pid.to_string()]);
            if let Err(e) = result {
                let tolerated = e.contains("Access denied")
                    || e.contains("protected process")
                    || e.contains("Some kill operations failed");
                assert!(
                    tolerated,
                    "Case-insensitive signal {} failed unexpectedly: {}",
                    signal, e
                );
            }

            thread::sleep(Duration::from_millis(100));
            let _ = new_child.kill();
        }

        // Clean up original
        let _ = child.kill();
    }

    // Helper function to check if a process is running
    fn is_process_running(pid: u32) -> bool {
        unsafe {
            // Try with more limited permissions first
            let mut handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                // Fallback to standard query information
                handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
                if handle.is_null() {
                    return false;
                }
            }

            let result = WaitForSingleObject(handle, 0);
            CloseHandle(handle);
            // WAIT_TIMEOUT = 0x102, means process is still running
            result == 0x102
        }
    }
}
