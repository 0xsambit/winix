#![allow(non_snake_case)]
use std::ffi::OsStr;
use std::io;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::FALSE;
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::NULL;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use winapi::um::jobapi2::{AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject};
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::OpenProcess;
#[cfg(target_os = "windows")]
use winapi::um::winnt::PROCESS_ALL_ACCESS;

#[cfg(target_os = "windows")]
pub struct Job {
    handle: winapi::shared::ntdef::HANDLE,
}

#[cfg(target_os = "windows")]
impl Job {
    /// Create a new unnamed Job object.
    pub fn create() -> io::Result<Self> {
        // CreateJobObjectW(LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName)
        // Use a null name for unnamed job
        unsafe {
            // pass null ptrs for security attributes and name
            let handle = CreateJobObjectW(ptr::null_mut(), ptr::null());

            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }

            Ok(Job { handle })
        }
    }

    /// Assign an existing process (by PID) to this Job.
    pub fn assign(&self, pid: u32) -> io::Result<()> {
        unsafe {
            // Open process with full access (simplest)
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if process_handle.is_null() {
                return Err(io::Error::last_os_error());
            }

            let result = AssignProcessToJobObject(self.handle, process_handle);
            // Close process handle regardless
            CloseHandle(process_handle);

            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Terminate all processes associated with this job object.
    /// Useful for tests: kills children assigned to job.
    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        unsafe {
            let result = TerminateJobObject(self.handle, exit_code);
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Return the raw handle (if needed elsewhere). Use carefully.
    pub fn raw_handle(&self) -> winapi::shared::ntdef::HANDLE {
        self.handle
    }
}

#[cfg(target_os = "windows")]
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                CloseHandle(self.handle);
                self.handle = ptr::null_mut();
            }
        }
    }
}
