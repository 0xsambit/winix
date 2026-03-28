use std::io::Write;

use tempfile::NamedTempFile;
use winix::{gzip, ip, lsof, mount, nice, renice, ulimit, umount, wc, zcat};

#[test]
fn test_wc_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "hello world").expect("failed to write temp content");

    let args = vec![file.path().to_string_lossy().to_string()];
    let result = wc::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_gzip_creates_archive_and_keeps_source() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "compress me").expect("failed to write temp content");

    let source = file.path().to_string_lossy().to_string();
    let gz_path = format!("{}.gz", source);

    let args = vec!["-k".to_string(), source.clone()];
    let result = gzip::run(&args);
    assert!(result.is_ok());
    assert!(std::path::Path::new(&source).exists());
    assert!(std::path::Path::new(&gz_path).exists());

    let _ = std::fs::remove_file(gz_path);
}

#[test]
fn test_zcat_reads_valid_gzip_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "decompress me").expect("failed to write temp content");

    let source = file.path().to_string_lossy().to_string();
    let gz_path = format!("{}.gz", source);

    let gzip_args = vec!["-k".to_string(), source.clone()];
    assert!(gzip::run(&gzip_args).is_ok());

    let zcat_args = vec![gz_path.clone()];
    let result = zcat::run(&zcat_args);
    assert!(result.is_ok());

    let _ = std::fs::remove_file(gz_path);
}

#[test]
fn test_nice_usage_is_non_fatal() {
    let args: Vec<String> = Vec::new();
    let result = nice::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_renice_usage_is_non_fatal() {
    let args = vec!["5".to_string()];
    let result = renice::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_lsof_basic_call_is_non_fatal() {
    let args: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let result = lsof::run(&args);
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let result = lsof::run(&args);
        assert!(result.is_ok());
    }
}

#[test]
fn test_ip_command_or_fallback_is_non_fatal() {
    let args: Vec<String> = Vec::new();

    #[cfg(unix)]
    {
        if which::which("ip").is_ok() {
            let result = ip::run(&args);
            assert!(result.is_ok());
        }
    }

    #[cfg(windows)]
    {
        let result = ip::run(&args);
        assert!(result.is_ok());
    }
}

#[test]
fn test_ulimit_or_fallback_is_non_fatal() {
    let args = vec!["-n".to_string()];
    let result = ulimit::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_mount_call_or_fallback_is_non_fatal() {
    let args: Vec<String> = Vec::new();

    #[cfg(unix)]
    {
        if which::which("mount").is_ok() {
            let result = mount::run(&args);
            assert!(result.is_ok());
        }
    }

    #[cfg(windows)]
    {
        let result = mount::run(&args);
        assert!(result.is_ok());
    }
}

#[test]
fn test_umount_usage_is_non_fatal() {
    let args: Vec<String> = Vec::new();
    let result = umount::run(&args);
    assert!(result.is_ok());
}
