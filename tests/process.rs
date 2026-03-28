#[cfg(windows)]
mod tests {
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;
    use winix::process::{ProcessError, spawn};

    #[test]
    fn test_spawn_success_cmd() {
        let result = spawn("C:\\Windows\\System32\\cmd.exe", &["/C", "exit"], None);
        assert!(result.is_ok(), "Expected success, got: {:?}", result);
        let handle = result.unwrap();
        unsafe {
            WaitForSingleObject(handle.process_handle, INFINITE);
        }
    }

    #[test]
    fn test_spawn_invalid_path() {
        let result = spawn("C:\\not_a_real_exe.exe", &[], None);
        assert!(result.is_err(), "Expected error for invalid path");
        match result {
            Err(ProcessError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected Io error for invalid path"),
        }
    }

    #[test]
    fn test_spawn_malformed_args() {
        let result = spawn("C:\\Windows\\System32\\cmd.exe", &["/C\0"], None);
        assert!(result.is_err(), "Expected error for malformed args");
        match result {
            Err(ProcessError::NullTermination) => {}
            _ => panic!("Expected NullTermination error"),
        }
    }
}
