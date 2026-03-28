use std::fs;
use std::io;
use std::path::Path;

pub fn rm<S: AsRef<Path>>(files: Vec<S>) -> io::Result<()> {
    for file_path in files {
        let path = file_path.as_ref();

        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File '{}' not found", path.display()),
            ));
        }

        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{}' is not a file", path.display()),
            ));
        }

        fs::remove_file(path)?;
        println!("Removed file: {}", path.display());
    }
    Ok(())
}
