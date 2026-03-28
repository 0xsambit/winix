pub mod ansi;
pub mod awk;
pub mod cat;
#[cfg(windows)]
pub mod chmod;
pub mod chown;
pub mod cp;
pub mod curl;
pub mod cut;
pub mod df;
pub mod diff;
pub mod du;
pub mod echo;
pub mod env;
pub mod find;
pub mod free;
pub mod git;
pub mod grep;
pub mod gzip;
pub mod head;
pub mod id;
pub mod input;
pub mod ip;
#[cfg(target_os = "windows")]
#[path = "commands/job.rs"]
pub mod job;
pub mod kill;
pub mod ln;
pub mod lsof;
pub mod mkdir;
pub mod mount;
pub mod nice;
pub mod nproc;
pub mod pipeline;
pub mod powershell;
pub mod process;
pub mod ps;
pub mod realpath;
pub mod renice;
pub mod rm;
pub mod rmdir;
pub mod sed;
pub mod sensors;
pub mod sort;
pub mod split;
pub mod stat;
pub mod tail;
pub mod tee;
pub mod top;
pub mod touch;
pub mod tr;
pub mod tree;
pub mod tui;
pub mod ulimit;
pub mod umount;
pub mod uname;
pub mod uniq;
pub mod uptime;
pub mod wc;
pub mod wget;
pub mod whoami;
pub mod xargs;
pub mod zcat;

#[cfg(test)]
mod tests {
    #[test]
    fn sanity_check() {
        assert_eq!(1 + 1, 2);
    }
}
