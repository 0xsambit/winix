pub mod process;
pub mod kill; 
pub mod echo;
pub mod touch;
pub mod ansi;
pub mod cat;
pub mod rm;
pub mod input;
#[cfg(windows)]
pub mod chmod;
pub mod chown;
pub mod disown;
pub mod df;
pub mod free;
pub mod git;
#[cfg(windows)]
pub mod nice;
pub mod powershell;
pub mod ps;
pub mod sensors;
pub mod sudo;
pub mod tui;
pub mod uname;
pub mod uptime;
pub mod grep;
pub mod head;
pub mod tail;
pub mod pipeline;

#[cfg(test)]
mod tests {
    #[test]
    fn sanity_check() {
        assert_eq!(1 + 1, 2);
    }
}

