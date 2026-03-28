use std::fs;
use tempfile::tempdir;
use winix::rmdir;

#[test]
fn test_rmdir_removes_empty_directory() {
    let tmp = tempdir().unwrap();
    let dir_path = tmp.path().join("empty_dir");
    fs::create_dir(&dir_path).unwrap();
    assert!(dir_path.exists());

    let args = vec![dir_path.to_string_lossy().to_string()];
    rmdir::run(&args);

    assert!(!dir_path.exists());
}

#[test]
fn test_rmdir_recursive_removes_non_empty_directory() {
    let tmp = tempdir().unwrap();
    let dir_path = tmp.path().join("non_empty");
    let child = dir_path.join("child.txt");
    fs::create_dir_all(&dir_path).unwrap();
    fs::write(&child, "data").unwrap();

    let args = vec!["-r".to_string(), dir_path.to_string_lossy().to_string()];
    rmdir::run(&args);

    assert!(!dir_path.exists());
}
