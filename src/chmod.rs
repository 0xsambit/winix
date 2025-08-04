use colored::*;
#[cfg(windows)]
use winapi::um::winnt::*;
#[cfg(windows)]
use windows_acl::acl::ACL;
#[cfg(windows)]
use windows_acl::helper::*;

#[cfg(windows)]
use winapi::um::winnt::{PSID};
#[cfg(windows)]
const TOKEN_QUERY: u32 = 0x0008;

pub fn execute(args: &[&str]) {
    if args.len() < 2 {
        println!(
            "{}",
            "Usage: chmod [OPTION]... MODE[,MODE]... FILE...".red()
        );
        println!("{}", "   or: chmod [OPTION]... OCTAL-MODE FILE...".red());
        println!();
        println!("{}", "Examples:".yellow());
        println!("  {}", "chmod 755 myfile.txt".dimmed());
        println!("  {}", "chmod u+x script.sh".dimmed());
        println!("  {}", "chmod g-w,o-w file.txt".dimmed());
        println!("  {}", "chmod a=r file.txt".dimmed());
        println!("  {}", "chmod u=rwx,g=rx,o=r file.txt".dimmed());
        return;
    }

    let mode = args[0];
    let files = &args[1..];

    for filename in files {
        if !std::path::Path::new(filename).exists() {
            println!(
                "{}",
                format!(
                    "chmod: cannot access '{}': No such file or directory",
                    filename
                )
                .red()
            );
            continue;
        }

        match parse_and_mode(filename, mode) {
            Ok(_) => {
                println!(
                    "{}",
                    format!("Permissions changed for '{}'", filename).green()
                );
            }
            Err(e) => {
                println!("{}", format!("chmod: {}", e).red());
            }
        }
    }
}

fn parse_and_mode(filename: &str, mode: &str) -> Result<bool, String> {
    if mode.chars().all(|c| c.is_ascii_digit()) {
        parse_octal(filename, mode)
    } else {
        parse_symbolic(filename, mode)
    }
}

fn parse_octal(filename: &str, mode: &str) -> Result<bool, String> {
    if mode.len() < 1 || mode.len() > 4 {
        return Err("Invalid mode".to_string());
    }

    if !mode.chars().all(|c| c.is_ascii_digit() && c <= '7') {
        return Err("Invalid mode".to_string());
    }

    apply_win_perm(filename, mode)
}

fn parse_symbolic(filename: &str, mode: &str) -> Result<bool, String> {
    let expressions: Vec<&str> = mode.split(',').collect();

    for expr in expressions {
        apply_symbolic_expression(filename, expr.trim())?;
    }

    Ok(true)
}

fn apply_symbolic_expression(filename: &str, expr: &str) -> Result<(), String> {
    if expr.is_empty() {
        return Err("Empty expression".to_string());
    }

    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;

    let mut who = String::new();
    while i < chars.len() && "ugoa".contains(chars[i]) {
        who.push(chars[i]);
        i += 1;
    }

    if who.is_empty() {
        who = "a".to_string();
    }

    if i >= chars.len() {
        return Err("Invalid symbolic expression: missing operation".to_string());
    }

    let operation = chars[i];
    if !"+-=".contains(operation) {
        return Err("Invalid operation: must be +, -, or =".to_string());
    }
    i += 1;

    let mut permissions = String::new();
    while i < chars.len() {
        let ch = chars[i];
        if "rwxXst".contains(ch) || "ugo".contains(ch) {
            permissions.push(ch);
        } else {
            return Err(format!("Invalid permission character: '{}'", ch));
        }
        i += 1;
    }

    apply_symbolic_to_file(filename, &who, operation, &permissions)
}

fn apply_symbolic_to_file(
    filename: &str,
    who: &str,
    operation: char,
    permissions: &str,
) -> Result<(), String> {
    let current_perms = get_current_permissions(filename)?;

    let mut new_perms = current_perms;

    for who_char in who.chars() {
        let targets = match who_char {
            'u' => vec!["owner"],
            'g' => vec!["group"],
            'o' => vec!["other"],
            'a' => vec!["owner", "group", "other"],
            _ => continue,
        };

        for target in targets {
            match operation {
                '+' => {
                    for perm in permissions.chars() {
                        add_permission(&mut new_perms, target, perm, filename)?;
                    }
                }
                '-' => {
                    for perm in permissions.chars() {
                        remove_permission(&mut new_perms, target, perm, filename)?;
                    }
                }
                '=' => {
                    clear_permissions(&mut new_perms, target);
                    for perm in permissions.chars() {
                        add_permission(&mut new_perms, target, perm, filename)?;
                    }
                }
                _ => return Err("Invalid operation".to_string()),
            }
        }
    }

    apply_permissions_to_file(filename, &new_perms)
}

#[derive(Debug, Clone)]
struct FilePermissions {
    owner_read: bool,
    owner_write: bool,
    owner_execute: bool,
    group_read: bool,
    group_write: bool,
    group_execute: bool,
    other_read: bool,
    other_write: bool,
    other_execute: bool,
}

impl Default for FilePermissions {
    fn default() -> Self {
        FilePermissions {
            owner_read: false,
            owner_write: false,
            owner_execute: false,
            group_read: false,
            group_write: false,
            group_execute: false,
            other_read: false,
            other_write: false,
            other_execute: false,
        }
    }
}

fn get_current_permissions(_filename: &str) -> Result<FilePermissions, String> {
    Ok(FilePermissions::default())
}

fn add_permission(
    perms: &mut FilePermissions,
    target: &str,
    perm_char: char,
    filename: &str,
) -> Result<(), String> {
    match (target, perm_char) {
        ("owner", 'r') => perms.owner_read = true,
        ("owner", 'w') => perms.owner_write = true,
        ("owner", 'x') => perms.owner_execute = true,
        ("group", 'r') => perms.group_read = true,
        ("group", 'w') => perms.group_write = true,
        ("group", 'x') => perms.group_execute = true,
        ("other", 'r') => perms.other_read = true,
        ("other", 'w') => perms.other_write = true,
        ("other", 'x') => perms.other_execute = true,
        (_, 'X') => {
            let path = std::path::Path::new(filename);
            if path.is_dir() || perm_char == 'x' {
                match target {
                    "owner" => perms.owner_execute = true,
                    "group" => perms.group_execute = true,
                    "other" => perms.other_execute = true,
                    _ => {}
                }
            }
        }
        (_, 's') | (_, 't') => {
            return Ok(());
        }
        _ => return Err(format!("Invalid permission: {} for {}", perm_char, target)),
    }
    Ok(())
}

fn remove_permission(
    perms: &mut FilePermissions,
    target: &str,
    perm_char: char,
    _filename: &str,
) -> Result<(), String> {
    match (target, perm_char) {
        ("owner", 'r') => perms.owner_read = false,
        ("owner", 'w') => perms.owner_write = false,
        ("owner", 'x') => perms.owner_execute = false,
        ("group", 'r') => perms.group_read = false,
        ("group", 'w') => perms.group_write = false,
        ("group", 'x') => perms.group_execute = false,
        ("other", 'r') => perms.other_read = false,
        ("other", 'w') => perms.other_write = false,
        ("other", 'x') => perms.other_execute = false,
        (_, 'X') => match target {
            "owner" => perms.owner_execute = false,
            "group" => perms.group_execute = false,
            "other" => perms.other_execute = false,
            _ => {}
        },
        (_, 's') | (_, 't') => {
            return Ok(());
        }
        _ => return Err(format!("Invalid permission: {} for {}", perm_char, target)),
    }
    Ok(())
}

fn clear_permissions(perms: &mut FilePermissions, target: &str) {
    match target {
        "owner" => {
            perms.owner_read = false;
            perms.owner_write = false;
            perms.owner_execute = false;
        }
        "group" => {
            perms.group_read = false;
            perms.group_write = false;
            perms.group_execute = false;
        }
        "other" => {
            perms.other_read = false;
            perms.other_write = false;
            perms.other_execute = false;
        }
        _ => {}
    }
}

fn apply_permissions_to_file(filename: &str, perms: &FilePermissions) -> Result<(), String> {
    let owner_octal =
        permissions_to_octal(perms.owner_read, perms.owner_write, perms.owner_execute);
    let group_octal =
        permissions_to_octal(perms.group_read, perms.group_write, perms.group_execute);
    let other_octal =
        permissions_to_octal(perms.other_read, perms.other_write, perms.other_execute);

    let octal_mode = format!("{}{}{}", owner_octal, group_octal, other_octal);
    apply_win_perm(filename, &octal_mode).map(|_| ())
}

fn permissions_to_octal(read: bool, write: bool, execute: bool) -> u8 {
    let mut octal = 0;
    if read {
        octal += 4;
    }
    if write {
        octal += 2;
    }
    if execute {
        octal += 1;
    }
    octal
}

fn apply_win_perm(filename: &str, octal_mode: &str) -> Result<bool, String> {
    let mut acl =
        ACL::from_file_path(filename, false).map_err(|e| format!("Failed to load ACL: {}", e))?;

    let entries = acl
        .all()
        .map_err(|e| format!("Failed to get ACL entries: {}", e))?;

    for entry in entries {
        if let Some(sid_vec) = entry.sid {
            match acl.remove(sid_vec.as_ptr() as *mut winapi::ctypes::c_void, None, None) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Warning: Failed to remove entry: {}", e);
                }
            }
        }
    }

    let mode_chars: Vec<char> = octal_mode.chars().collect();
    let start_idx = if mode_chars.len() == 4 { 1 } else { 0 };

    if mode_chars.len() < 3 {
        return Err("Octal mode must be at least 3 digits".to_string());
    }

    let owner_perm = mode_chars[start_idx].to_digit(8).unwrap() as u8;
    let group_perm = mode_chars[start_idx + 1].to_digit(8).unwrap() as u8;
    let other_perm = mode_chars[start_idx + 2].to_digit(8).unwrap() as u8;

    if owner_perm > 0 {
        match get_current_user_sid() {
            Ok(owner_sid) => {
                let permissions = map_octal_to_permissions(owner_perm);
                let combined_perms = permissions.iter().fold(0u32, |acc, &perm| acc | perm);

                if combined_perms > 0 {
                    acl.allow(owner_sid, true, combined_perms)
                        .map_err(|e| format!("Failed to set owner permission: {}", e))?;
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not get current user SID: {}", e);
                match string_to_sid("S-1-5-32-544") {
                    Ok(admin_sid) => {
                        let permissions = map_octal_to_permissions(owner_perm);
                        let combined_perms = permissions.iter().fold(0u32, |acc, &perm| acc | perm);

                        if combined_perms > 0 {
                            acl.allow(admin_sid.as_ptr() as PSID, true, combined_perms)
                                .map_err(|e| format!("Failed to set admin permission: {}", e))?;
                        }
                    }
                    Err(sid_err) => {
                        return Err(format!("Failed to get any valid SID: {}", sid_err));
                    }
                }
            }
        }
    }

    if group_perm > 0 {
        match string_to_sid("S-1-5-32-545") {
            Ok(users_sid) => {
                let permissions = map_octal_to_permissions(group_perm);
                let combined_perms = permissions.iter().fold(0u32, |acc, &perm| acc | perm);

                if combined_perms > 0 {
                    acl.allow(users_sid.as_ptr() as PSID, true, combined_perms)
                        .map_err(|e| format!("Failed to set group permission: {}", e))?;
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not set group permissions: {}", e);
            }
        }
    }

    if other_perm > 0 {
        match string_to_sid("S-1-1-0") {
            Ok(everyone_sid) => {
                let permissions = map_octal_to_permissions(other_perm);
                let combined_perms = permissions.iter().fold(0u32, |acc, &perm| acc | perm);

                if combined_perms > 0 {
                    acl.allow(everyone_sid.as_ptr() as PSID, true, combined_perms)
                        .map_err(|e| format!("Failed to set other permission: {}", e))?;
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not set other permissions: {}", e);
            }
        }
    }

    Ok(true)
}

fn map_octal_to_permissions(octal_digit: u8) -> Vec<u32> {
    let mut permissions = Vec::new();

    match octal_digit {
        0 => {}
        1 => permissions.push(FILE_GENERIC_EXECUTE),
        2 => permissions.push(FILE_GENERIC_WRITE),
        3 => {
            permissions.push(FILE_GENERIC_WRITE);
            permissions.push(FILE_GENERIC_EXECUTE);
        }
        4 => permissions.push(FILE_GENERIC_READ),
        5 => {
            permissions.push(FILE_GENERIC_READ);
            permissions.push(FILE_GENERIC_EXECUTE);
        }
        6 => {
            permissions.push(FILE_GENERIC_READ);
            permissions.push(FILE_GENERIC_WRITE);
        }
        7 => {
            permissions.push(FILE_GENERIC_READ);
            permissions.push(FILE_GENERIC_WRITE);
            permissions.push(FILE_GENERIC_EXECUTE);
        }
        _ => {}
    }

    permissions
}

fn get_current_user_sid() -> Result<PSID, String> {
    use winapi::um::handleapi::*;
    use winapi::um::processthreadsapi::*;
    use winapi::um::securitybaseapi::*;
    use winapi::um::winnt::*;

    unsafe {
        let mut token_handle = std::ptr::null_mut();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == 0 {
            return Err("Failed to open process token".to_string());
        }

        let mut token_user_size = 0;
        GetTokenInformation(
            token_handle,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut token_user_size,
        );

        let mut token_user_buffer = vec![0u8; token_user_size as usize];

        if GetTokenInformation(
            token_handle,
            TokenUser,
            token_user_buffer.as_mut_ptr() as *mut _,
            token_user_size,
            &mut token_user_size,
        ) == 0
        {
            CloseHandle(token_handle);
            return Err("Failed to get token information".to_string());
        }

        CloseHandle(token_handle);

        let token_user = token_user_buffer.as_ptr() as *const TOKEN_USER;
        Ok((*token_user).User.Sid)
    }
}
