#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use winapi::shared::winerror::ERROR_SUCCESS;
#[cfg(windows)]
use winapi::um::accctrl::SE_FILE_OBJECT;
#[cfg(windows)]
use winapi::um::aclapi::SetNamedSecurityInfoW;
#[cfg(windows)]
use winapi::um::winnt::*;
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(windows)]
use winapi::um::winbase::FormatMessageW;
#[cfg(windows)]
use winapi::um::winbase::{FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_IGNORE_INSERTS};
#[cfg(windows)]
use winapi::um::winbase::LocalFree;
#[cfg(windows)]
use std::ffi::OsString;

use colored::*;

/// Main entry point for chown command (only works on Windows)
#[cfg(windows)]
pub fn execute(args: &[&str]) {
    if args.len() < 2 {
        println!("{}", "Usage: chown [OPTION]... [OWNER][:[GROUP]] FILE...".red());
        println!("{}", "   or: chown [OPTION]... --reference=RFILE FILE...".red());
        println!();
        println!("{}", "Examples:".yellow());
        println!("  {}", "chown alice file.txt".dimmed());
        println!("  {}", "chown alice:developers file.txt".dimmed());
        println!("  {}", "chown :developers file.txt".dimmed());
        println!("  {}", "chown --recursive alice:developers /mydir".dimmed());
        println!("  {}", "chown --reference=ref.txt file.txt".dimmed());
        return;
    }

    let mode = args[0];
    let files = &args[1..];

    for filename in files {
        if !std::path::Path::new(filename).exists() {
            println!("{}", format!("chown: cannot access '{}': No such file or directory", filename).red());
            continue;
        }

        match parse_and_mode(filename, mode) {
            Ok(_) => {
                println!("{}", format!("Owner changed for '{}'", filename).green());
            }
            Err(e) => {
                println!("{}", format!("chown: {}", e).red());
            }
        }
    }
}

/// Parses user:group mode string and calls `change_owner_with_only_sid`
#[cfg(windows)]
fn parse_and_mode(file: &str, mode: &str) -> Result<bool, String> {
    let (user, group) = if let Some(colon_pos) = mode.find(':') {
        let user_part = &mode[..colon_pos];
        let group_part = &mode[colon_pos + 1..];

        let user = if user_part.is_empty() { None } else { Some(user_part) };
        let group = if group_part.is_empty() { None } else { Some(group_part) };

        (user, group)
    } else {
        (Some(mode), None)
    };

    if let Some(username) = user {
        change_owner_with_only_sid(file, username)?;
    }

    if let Some(_groupname) = group {
        println!("Note: Group ownership changes are not fully supported on Windows");
    }

    Ok(true)
}

/// Changes file owner using SID derived from username
#[cfg(windows)]
fn change_owner_with_only_sid(file: &str, username: &str) -> Result<(), String> {
    let user_sid = match name_to_sid(username, None) {
        Ok(sid) => sid,
        Err(0) => return Err(format!("invalid user: {}", username)),
        Err(code) => return Err(format!("error looking up user '{}': Error code '{}'", username, code)),
    };

    let file_wide: Vec<u16> = OsStr::new(file)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let res = SetNamedSecurityInfoW(
            file_wide.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            user_sid.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if res != ERROR_SUCCESS {
            return Err(format!(
                "failed to change owner of '{}': {}",
                file,
                get_last_error_message()
            ));
        }
    }

    Ok(())
}

/// Retrieves readable Windows error message from last error code
#[cfg(windows)]
fn get_last_error_message() -> String {
    unsafe {
        let mut buf: *mut u16 = ptr::null_mut();
        let len = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null(),
            GetLastError(),
            0,
            &mut buf as *mut *mut u16 as *mut u16,
            0,
            ptr::null_mut(),
        );

        if len == 0 {
            return format!("Unknown error ({})", GetLastError());
        }

        let slice = std::slice::from_raw_parts(buf, len as usize);
        let message = OsString::from_wide(slice).to_string_lossy().trim().to_string();
        LocalFree(buf as *mut _);
        message
    }
}

#[cfg(windows)]
fn name_to_sid(name: &str, _domain: Option<&str>) -> Result<Vec<u8>, u32> {
    use std::mem;
    use std::ptr::null_mut;
    use winapi::um::winbase::LookupAccountNameW;
    use winapi::um::winnt::SID_NAME_USE;

    let name_wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_name_use: SID_NAME_USE = mem::zeroed();

        // First call to get sizes
        LookupAccountNameW(
            null_mut(),                      // Local computer
            name_wide.as_ptr(),              // Name to lookup
            null_mut(),                      // SID ptr (null)
            &mut sid_len,                    // Required size
            null_mut(),                      // Domain buffer (null)
            &mut domain_len,                 // Required domain size
            &mut sid_name_use,               // SID name use
        );

        let error = GetLastError();
        if error != winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER {
            return Err(error);
        }

        let mut sid_buffer = vec![0u8; sid_len as usize];
        let mut domain_buffer: Vec<u16> = vec![0; domain_len as usize];

        let success = LookupAccountNameW(
            null_mut(),
            name_wide.as_ptr(),
            sid_buffer.as_mut_ptr() as *mut _,
            &mut sid_len,
            domain_buffer.as_mut_ptr(),
            &mut domain_len,
            &mut sid_name_use,
        );

        if success == 0 {
            return Err(GetLastError());
        }

        Ok(sid_buffer)
    }
}


/// Dummy stub for non-Windows platforms
#[cfg(not(windows))]
pub fn execute(_args: &[&str]) {
    eprintln!("Error: `chown` command is only supported on Windows platforms.");
}
