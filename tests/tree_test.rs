use std::fs;
use tempfile::tempdir;
use winix::tree;

#[test]
fn test_tree_runs_for_existing_directory() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("root");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("nested").join("file.txt"), "x").unwrap();

    let args = vec![root.to_string_lossy().to_string()];
    let result = tree::run(&args);

    assert!(result.is_ok());
}
