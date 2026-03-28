use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Print the tree structure of a directory
fn print_tree(path: &Path, prefix: &str, is_last: bool) {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();

    println!(
        "{}{}{}",
        prefix,
        if is_last { "└── " } else { "├── " },
        file_name
    );

    if let Ok(entries) = fs::read_dir(path) {
        let entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        let count = entries.len();

        for (i, entry) in entries.into_iter().enumerate() {
            let is_last_entry = i == count - 1;
            let new_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
            print_tree(&entry.path(), &new_prefix, is_last_entry);
        }
    }
}

/// Run the `tree` command
/// `args` can contain optional directory path to start from
pub fn run(args: &[String]) -> io::Result<()> {
    let root: PathBuf = if !args.is_empty() {
        PathBuf::from(&args[0])
    } else {
        env::current_dir()?
    };

    println!("{}", root.display());
    print_tree(&root, "", true);

    Ok(())
}
