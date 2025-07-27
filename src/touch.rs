use std::fs::{File};
use std::path::Path;

#[cfg(unix)]
use filetime::{FileTime, set_file_times};

pub fn run(args: &[String]) {
    for file_name in args {
        let path = Path::new(file_name);

        // If the file doesn't exist, create it
        if !path.exists() {
            match File::create(&path) {
                Ok(_) => println!("Created '{}'", file_name),
                Err(e) => eprintln!("touch: cannot create file '{}': {}", file_name, e),
            }
        } else {
            #[cfg(unix)]
            {
                // Update the access and modification times
                let now = FileTime::now();
                if let Err(e) = set_file_times(&path, now, now) {
                    eprintln!("touch: failed to update timestamps for '{}': {}", file_name, e);
                } else {
                    println!("Updated timestamp for '{}'", file_name);
                }
            }

            #[cfg(windows)]
            {
                // On Windows, simulate a timestamp update by opening in append mode
                match OpenOptions::new().append(true).open(&path) {
                    Ok(mut file) => {
                        // Optionally write 0 bytes to trigger timestamp update
                        let _ = file.write(&[]);
                        println!("Simulated timestamp update for '{}'", file_name);
                    },
                    Err(e) => eprintln!("touch: failed to open file '{}': {}", file_name, e),
                }
            }
        }
    }
}
