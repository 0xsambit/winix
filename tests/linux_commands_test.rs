use std::io::Write;
use std::net::TcpListener;
use std::thread;

use tempfile::NamedTempFile;
use winix::{
    awk, curl, cut, diff, du, find, gzip, id, ip, ln, lsof, mount, nice, renice, sed, sort,
    split, stat, tee, top, tr, ulimit, umount, uniq, wc, wget, whoami, xargs, zcat, realpath,
};

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

#[test]
fn test_awk_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "foo 1").expect("failed to write temp content");
    writeln!(file, "bar 2").expect("failed to write temp content");

    let args = vec![
        "/foo/".to_string(),
        file.path().to_string_lossy().to_string(),
    ];
    let result = awk::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_sed_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "hello world").expect("failed to write temp content");

    let args = vec![
        "s/world/winix/".to_string(),
        file.path().to_string_lossy().to_string(),
    ];
    let result = sed::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_find_runs_with_name_filter() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let file_path = temp.path().join("sample.txt");
    std::fs::write(&file_path, "content").expect("failed to create test file");

    let args = vec![
        temp.path().to_string_lossy().to_string(),
        "-name".to_string(),
        "*.txt".to_string(),
    ];
    let result = find::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_xargs_chunking_logic() {
    let tokens = vec!["a", "b", "c", "d"]
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let chunks = xargs::chunk_tokens(&tokens, 2);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0], vec!["a", "b"]);
    assert_eq!(chunks[1], vec!["c", "d"]);
}

#[test]
fn test_cut_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "a,b,c").expect("failed to write temp content");

    let args = vec![
        "-d".to_string(),
        ",".to_string(),
        "-f".to_string(),
        "1,3".to_string(),
        file.path().to_string_lossy().to_string(),
    ];
    let result = cut::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_sort_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "3").expect("failed to write temp content");
    writeln!(file, "1").expect("failed to write temp content");

    let args = vec!["-n".to_string(), file.path().to_string_lossy().to_string()];
    let result = sort::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_uniq_runs_on_file() {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    writeln!(file, "x").expect("failed to write temp content");
    writeln!(file, "x").expect("failed to write temp content");

    let args = vec!["-c".to_string(), file.path().to_string_lossy().to_string()];
    let result = uniq::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_ln_creates_hard_link() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let target = temp.path().join("target.txt");
    let link = temp.path().join("link.txt");
    std::fs::write(&target, "hello").expect("failed to write target");

    let args = vec![
        target.to_string_lossy().to_string(),
        link.to_string_lossy().to_string(),
    ];
    let result = ln::run(&args);
    assert!(result.is_ok());
    assert!(link.exists());
}

#[test]
fn test_id_non_fatal() {
    let args: Vec<String> = Vec::new();
    let result = id::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_curl_fetch_url_local_server() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind listener");
    let addr = listener.local_addr().expect("failed to get local addr");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest";
            let _ = std::io::Write::write_all(&mut stream, response);
            let _ = std::io::Write::flush(&mut stream);
        }
    });

    let url = format!("http://{}/", addr);
    let body = curl::fetch_url(&url, false).expect("fetch should succeed");
    assert_eq!(body, b"test");

    server.join().expect("server thread failed");
}

#[test]
fn test_whoami_non_fatal() {
    let args: Vec<String> = Vec::new();
    let result = whoami::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_du_summary_non_fatal() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let file_path = temp.path().join("a.txt");
    std::fs::write(&file_path, "content").expect("failed to write temp file");

    let args = vec!["-s".to_string(), temp.path().to_string_lossy().to_string()];
    let result = du::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_diff_quiet_non_fatal() {
    let left = NamedTempFile::new().expect("failed to create left file");
    let right = NamedTempFile::new().expect("failed to create right file");
    std::fs::write(left.path(), "alpha\n").expect("failed writing left file");
    std::fs::write(right.path(), "beta\n").expect("failed writing right file");

    let args = vec![
        "-q".to_string(),
        left.path().to_string_lossy().to_string(),
        right.path().to_string_lossy().to_string(),
    ];
    let result = diff::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_wget_local_server_non_fatal() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind listener");
    let addr = listener.local_addr().expect("failed to get local addr");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfile";
            let _ = std::io::Write::write_all(&mut stream, response);
            let _ = std::io::Write::flush(&mut stream);
        }
    });

    let out_file = NamedTempFile::new().expect("failed to create output file");
    let out_path = out_file.path().to_string_lossy().to_string();
    let url = format!("http://{}/", addr);

    let args = vec!["-O".to_string(), out_path.clone(), url];
    let result = wget::run(&args);
    assert!(result.is_ok());
    assert_eq!(std::fs::read(out_path).expect("failed to read output"), b"file");

    server.join().expect("server thread failed");
}

#[test]
fn test_top_snapshot_non_empty() {
    let rows = top::process_snapshot(5);
    assert!(!rows.is_empty());
}

#[test]
fn test_tr_translate_helper() {
    let out = tr::translate_text("abc", "abc", "xyz");
    assert_eq!(out, "xyz");
}

#[test]
fn test_tee_writes_to_file() {
    let file = NamedTempFile::new().expect("failed to create temp file");
    let path = file.path().to_string_lossy().to_string();

    let args = std::slice::from_ref(&path);
    tee::write_to_files(b"line\n", false, args).expect("tee write should succeed");

    let content = std::fs::read_to_string(path).expect("failed to read tee output");
    assert_eq!(content, "line\n");
}

#[test]
fn test_split_runs_on_file() {
    let temp = tempfile::tempdir().expect("failed to create temp dir");
    let input_path = temp.path().join("input.txt");
    std::fs::write(&input_path, "a\nb\nc\n").expect("failed to write input");

    let prefix = temp.path().join("part").to_string_lossy().to_string();
    let args = vec![
        "-l".to_string(),
        "2".to_string(),
        input_path.to_string_lossy().to_string(),
        prefix.clone(),
    ];
    let result = split::run(&args);
    assert!(result.is_ok());
    assert!(std::path::Path::new(&(prefix.clone() + "aa")).exists());
    assert!(std::path::Path::new(&(prefix + "ab")).exists());
}

#[test]
fn test_stat_format_non_fatal() {
    let file = NamedTempFile::new().expect("failed to create temp file");
    let args = vec![
        "-c".to_string(),
        "%s".to_string(),
        file.path().to_string_lossy().to_string(),
    ];
    let result = stat::run(&args);
    assert!(result.is_ok());
}

#[test]
fn test_realpath_non_fatal() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let args = vec![dir.path().to_string_lossy().to_string()];
    let result = realpath::run(&args);
    assert!(result.is_ok());
}
