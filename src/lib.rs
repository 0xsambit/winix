pub mod ansi;
pub mod cat;
#[cfg(windows)]
pub mod chmod;
pub mod chown;
pub mod cp;
pub mod df;
pub mod echo;
pub mod env;
pub mod free;
pub mod git;
pub mod grep;
pub mod gzip;
pub mod head;
pub mod input;
pub mod ip;
#[cfg(target_os = "windows")]
#[path = "commands/job.rs"]
pub mod job;
pub mod kill;
pub mod lsof;
pub mod mkdir;
pub mod mount;
pub mod nice;
pub mod nproc;
pub mod pipeline;
pub mod powershell;
pub mod process;
pub mod ps;
pub mod renice;
pub mod rm;
pub mod rmdir;
pub mod sensors;
pub mod tail;
pub mod touch;
pub mod tree;
pub mod tui;
pub mod ulimit;
pub mod umount;
pub mod uname;
pub mod uptime;
pub mod wc;
pub mod zcat;

#[cfg(test)]
mod tests {
    #[test]
    fn sanity_check() {
        assert_eq!(1 + 1, 2);
    }
}
