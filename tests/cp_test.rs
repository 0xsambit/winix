use std::fs;
use tempfile::tempdir;
use winix::cp;

#[test]
fn test_cp_copies_file_content() {
    let tmp = tempdir().unwrap();
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("dst.txt");
    fs::write(&src, "copy me").unwrap();

    let args = vec![
        src.to_string_lossy().to_string(),
        dst.to_string_lossy().to_string(),
    ];
    let result = cp::run(&args);

    assert!(result.is_ok());
    assert!(dst.exists());
    assert_eq!(fs::read_to_string(dst).unwrap(), "copy me");
}
