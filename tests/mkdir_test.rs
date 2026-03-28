use tempfile::tempdir;
use winix::mkdir;

#[test]
fn test_mkdir_creates_directory() {
    let tmp = tempdir().unwrap();
    let dir_path = tmp.path().join("created_dir");
    let args = vec![dir_path.to_string_lossy().to_string()];

    let result = mkdir::run(&args);
    assert!(result.is_ok());
    assert!(dir_path.is_dir());
}

#[test]
fn test_mkdir_recursive_flag_creates_nested_directories() {
    let tmp = tempdir().unwrap();
    let nested = tmp.path().join("a").join("b").join("c");
    let args = vec!["-p".to_string(), nested.to_string_lossy().to_string()];

    let result = mkdir::run(&args);
    assert!(result.is_ok());
    assert!(nested.is_dir());
}
