use colored::*;
use std::thread;

#[cfg(windows)]
use winapi::{
    shared::basetsd::DWORD_PTR,
    um::{
        processthreadsapi::GetCurrentProcess,
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        winbase::GetProcessAffinityMask,
    },
};

/// Configuration for nproc command
#[derive(Debug, Default)]
struct NprocConfig {
    show_all: bool,
    ignore_count: usize,
}

#[derive(Debug)]
enum NprocAction {
    Run(NprocConfig),
    ShowHelp,
    ShowVersion,
}

/// CPU information structure
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CpuInfo {
    pub available: usize,
    pub total: usize,
    pub online: usize,
}

impl std::fmt::Display for CpuInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.available == self.total {
            write!(f, "{} CPUs", self.total)
        } else {
            write!(
                f,
                "{}/{} CPUs (available/total)",
                self.available, self.total
            )
        }
    }
}

/// Execute the nproc command to display number of processing units
pub fn execute(args: &[String]) -> i32 {
    match parse_arguments(args) {
        Ok(NprocAction::Run(config)) => {
            let count = get_processor_count(&config);
            println!("{}", count.to_string().green());
            0
        }
        Ok(NprocAction::ShowHelp) => {
            show_help();
            0
        }
        Ok(NprocAction::ShowVersion) => {
            println!("nproc (winix) 1.0.0");
            0
        }
        Err(e) => {
            eprintln!("{}", e.red());
            1
        }
    }
}

/// Parse command line arguments
fn parse_arguments(args: &[String]) -> Result<NprocAction, String> {
    let mut config = NprocConfig::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "--all" => {
                config.show_all = true;
                i += 1;
            }
            "--ignore" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(n) => {
                            config.ignore_count = n;
                            i += 2;
                        }
                        Err(_) => {
                            return Err(format!("nproc: invalid number: '{}'", args[i + 1]));
                        }
                    }
                } else {
                    return Err("nproc: option '--ignore' requires an argument".to_string());
                }
            }
            arg if arg.starts_with("--ignore=") => {
                let value = &arg[9..]; // Skip "--ignore="
                match value.parse::<usize>() {
                    Ok(n) => {
                        config.ignore_count = n;
                        i += 1;
                    }
                    Err(_) => {
                        return Err(format!("nproc: invalid number: '{}'", value));
                    }
                }
            }
            "--help" => {
                return Ok(NprocAction::ShowHelp);
            }
            "--version" => {
                return Ok(NprocAction::ShowVersion);
            }
            arg if arg.starts_with('-') => {
                return Err(format!("nproc: invalid option -- '{}'", arg));
            }
            _ => {
                return Err(format!("nproc: extra operand '{}'", arg));
            }
        }
    }

    Ok(NprocAction::Run(config))
}

/// Get processor count based on configuration
fn get_processor_count(config: &NprocConfig) -> usize {
    let count = if config.show_all {
        get_total_cpus()
    } else {
        get_available_cpus()
    };

    // Apply ignore count, but ensure at least 1 processor
    if count > config.ignore_count {
        count - config.ignore_count
    } else {
        1
    }
}

/// Get number of available CPUs (considering affinity/restrictions)
pub fn get_available_cpus() -> usize {
    // Try to get from thread::available_parallelism (most accurate for current process)
    if let Ok(parallelism) = thread::available_parallelism() {
        return parallelism.get();
    }

    // Platform-specific fallback
    #[cfg(windows)]
    {
        get_windows_available_cpus()
    }

    #[cfg(not(windows))]
    {
        get_unix_available_cpus()
    }
}

/// Get total number of CPUs in the system
pub fn get_total_cpus() -> usize {
    #[cfg(windows)]
    {
        get_windows_total_cpus()
    }

    #[cfg(not(windows))]
    {
        get_unix_total_cpus()
    }
}

/// Get number of online CPUs (currently active)
#[allow(dead_code)]
pub fn get_online_cpus() -> usize {
    // For most systems, online CPUs equals available CPUs
    // This could be extended to check CPU hotplug status on supported systems
    get_available_cpus()
}

#[cfg(windows)]
fn get_windows_total_cpus() -> usize {
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwNumberOfProcessors as usize
    }
}

#[cfg(windows)]
fn get_windows_available_cpus() -> usize {
    unsafe {
        let mut process_mask: DWORD_PTR = 0;
        let mut system_mask: DWORD_PTR = 0;

        if GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask) != 0 {
            // Count the number of set bits in the process affinity mask
            let count = process_mask.count_ones() as usize;
            if count > 0 {
                return count;
            }
        }

        // Fallback to total CPUs if affinity mask fails
        get_windows_total_cpus()
    }
}

#[cfg(not(windows))]
fn get_unix_total_cpus() -> usize {
    // Try to read from /proc/cpuinfo first
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let count = cpuinfo
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();
        if count > 0 {
            return count;
        }
    }

    // Fallback to sysconf
    #[cfg(target_os = "linux")]
    unsafe {
        let count = libc::sysconf(libc::_SC_NPROCESSORS_CONF);
        if count > 0 {
            return count as usize;
        }
    }

    // Last resort : return 1
    1
}

#[cfg(not(windows))]
fn get_unix_available_cpus() -> usize {
    // Check CPU affinity using sched_getaffinity on Linux
    #[cfg(target_os = "linux")]
    {
        use std::mem;

        unsafe {
            let mut set: libc::cpu_set_t = mem::zeroed();
            if libc::sched_getaffinity(0, mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
                let mut count = 0;
                for i in 0..libc::CPU_SETSIZE as usize {
                    if libc::CPU_ISSET(i, &set) {
                        count += 1;
                    }
                }
                if count > 0 {
                    return count;
                }
            }
        }
    }

    // Fallback to online processors
    #[cfg(unix)]
    unsafe {
        let count = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if count > 0 {
            return count as usize;
        }
    }

    // Last resort
    1
}

/// Get comprehensive CPU information
#[allow(dead_code)]
pub fn get_cpu_info() -> CpuInfo {
    CpuInfo {
        available: get_available_cpus(),
        total: get_total_cpus(),
        online: get_online_cpus(),
    }
}

/// Get CPU count for use in build systems (considers load average on Unix)
#[allow(dead_code)]
pub fn get_build_cpu_count(leave_free: usize) -> usize {
    let available = get_available_cpus();

    // On unix systems, consider load average
    #[cfg(unix)]
    {
        let load_adjusted = get_load_adjusted_cpu_count(available);
        return load_adjusted.saturating_sub(leave_free).max(1);
    }

    // On windows, just use available CPUs
    #[cfg(windows)]
    {
        available.saturating_sub(leave_free).max(1)
    }
}

#[allow(dead_code)]
#[cfg(unix)]
fn get_load_adjusted_cpu_count(available: usize) -> usize {
    unsafe {
        let mut loadavg: [f64; 3] = [0.0; 3];
        if libc::getloadavg(loadavg.as_mut_ptr(), 3) != -1 {
            let load_1min = loadavg[0];
            // If load is high, reduce the number of CPUs to use
            let adjusted = (available as f64 - load_1min + 1.0).max(1.0) as usize;
            return adjusted.min(available);
        }
    }
    available
}

fn show_help() {
    println!(
        "{}",
        "nproc - print the number of processing units available".bold()
    );
    println!();
    println!("{}", "USAGE:".bold());
    println!("    nproc [OPTION]...");
    println!();
    println!("{}", "OPTIONS:".bold());
    println!("    --all          Print the number of installed processors");
    println!("    --ignore=N     If possible, exclude N processing units");
    println!("    --ignore N     Same as --ignore=N");
    println!("    --version      Output version information and exit");
    println!("    --help         Display this help and exit");
    println!();
    println!("{}", "DESCRIPTION:".bold());
    println!("    Print the number of processing units available to the current process,");
    println!("    which may be less than the number of online processors due to process");
    println!("    affinity settings or container restrictions.");
    println!();
    println!("{}", "EXIT STATUS:".bold());
    println!("    0   if successful");
    println!("    1   if an error occurs");
    println!();
    println!("{}", "EXAMPLES:".bold());
    println!("    nproc                    Show available processors");
    println!("    nproc --all              Show all installed processors");
    println!("    nproc --ignore=1         Show available processors minus 1");
    println!();
    println!("{}", "COMMON USES:".bold());
    println!("    make -j$(nproc)                      Parallel build using all CPUs");
    println!("    cargo build --jobs $(nproc --ignore=2)  Leave 2 CPUs free");
    println!("    parallel -j$(nproc) command ::: files   GNU parallel with all CPUs");
}

/// Get processor count for TUI display with additional info
#[allow(dead_code)]
pub fn get_cpu_info_for_tui() -> String {
    let info = get_cpu_info();
    format!(
        "Available: {} | Total: {} | Online: {}",
        info.available, info.total, info.online
    )
}

/// Check if hyper-threading is likely enabled (heuristic)
#[allow(dead_code)]
pub fn is_hyperthreading_likely() -> bool {
    let total = get_total_cpus();

    // Common CPU core counts without HT: 1, 2, 4, 6, 8, 10, 12, 16
    // With HT, these become: 2, 4, 8, 12, 16, 20, 24, 32
    // This is a heuristic and may not be accurate for all systems

    #[cfg(windows)]
    {
        // On Windows, we can try to detect logical vs physical cores
        // This would require additional WMI queries or registry access
        // For now, use a simple heuristic
        total > 4 && total % 2 == 0
    }

    #[cfg(not(windows))]
    {
        // On Linux, check /proc/cpuinfo for siblings vs cpu cores
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            let mut siblings = 0;
            let mut cores = 0;

            for line in cpuinfo.lines() {
                if line.starts_with("siblings") {
                    if let Some(val) = line.split(':').nth(1) {
                        siblings = val.trim().parse().unwrap_or(0);
                    }
                }
                if line.starts_with("cpu cores") {
                    if let Some(val) = line.split(':').nth(1) {
                        cores = val.trim().parse().unwrap_or(0);
                    }
                }
            }

            return siblings > 0 && cores > 0 && siblings > cores;
        }

        // Fallback heuristic
        total > 4 && total % 2 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_count_validity() {
        let available = get_available_cpus();
        let total = get_total_cpus();
        let online = get_online_cpus();

        assert!(available > 0, "Available CPUs should be at least 1");
        assert!(total > 0, "Total CPUs should be at least 1");
        assert!(online > 0, "Online CPUs should be at least 1");
        assert!(
            available <= total,
            "Available CPUs should not exceed total CPUs"
        );
        assert!(online <= total, "Online CPUs should not exceed total CPUs");
    }

    #[test]
    fn test_parse_arguments() {
        // --all
        let action = parse_arguments(&vec!["--all".to_string()]).unwrap();
        match action {
            NprocAction::Run(cfg) => {
                assert!(cfg.show_all);
                assert_eq!(cfg.ignore_count, 0);
            }
            _ => panic!("expected Run config for --all"),
        }

        // --ignore <n>
        let action = parse_arguments(&vec!["--ignore".to_string(), "2".to_string()]).unwrap();
        match action {
            NprocAction::Run(cfg) => {
                assert!(!cfg.show_all);
                assert_eq!(cfg.ignore_count, 2);
            }
            _ => panic!("expected Run config for --ignore 2"),
        }

        // --ignore=N
        let action = parse_arguments(&vec!["--ignore=3".to_string()]).unwrap();
        match action {
            NprocAction::Run(cfg) => assert_eq!(cfg.ignore_count, 3),
            _ => panic!("expected Run config for --ignore=3"),
        }

        // combined options
        let action = parse_arguments(&vec!["--all".to_string(), "--ignore=1".to_string()]).unwrap();
        match action {
            NprocAction::Run(cfg) => {
                assert!(cfg.show_all);
                assert_eq!(cfg.ignore_count, 1);
            }
            _ => panic!("expected Run config for combined options"),
        }

        // invalid number
        let result = parse_arguments(&vec!["--ignore".to_string(), "abc".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid number"));

        // missing argument
        let result = parse_arguments(&vec!["--ignore".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires an argument"));

        // invalid option
        let result = parse_arguments(&vec!["--invalid".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid option"));

        // extra operand
        let result = parse_arguments(&vec!["extra".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("extra operand"));
    }

    #[test]
    fn test_get_processor_count() {
        // default (available)
        let cfg = NprocConfig {
            show_all: false,
            ignore_count: 0,
        };
        let count = get_processor_count(&cfg);
        assert!(count > 0);

        // ignore 1
        let cfg = NprocConfig {
            show_all: false,
            ignore_count: 1,
        };
        let count = get_processor_count(&cfg);
        assert!(count > 0); // always at least 1

        // large ignore -> clamped to 1
        let cfg = NprocConfig {
            show_all: false,
            ignore_count: 1000,
        };
        let count = get_processor_count(&cfg);
        assert_eq!(count, 1);

        // show all
        let cfg = NprocConfig {
            show_all: true,
            ignore_count: 0,
        };
        let count = get_processor_count(&cfg);
        assert!(count > 0);
    }

    #[test]
    fn test_cpu_info() {
        let info = get_cpu_info();
        assert!(info.available > 0);
        assert!(info.total > 0);
        assert!(info.online > 0);
        assert!(info.available <= info.total);
    }

    #[test]
    fn test_cpu_info_display() {
        let info = CpuInfo {
            available: 4,
            total: 8,
            online: 8,
        };
        let display = format!("{}", info);
        assert!(display.contains("4/8"));

        let info2 = CpuInfo {
            available: 8,
            total: 8,
            online: 8,
        };
        let display2 = format!("{}", info2);
        assert!(display2.contains("8 CPUs"));
    }

    #[test]
    fn test_get_build_cpu_count() {
        let count = get_build_cpu_count(0);
        assert!(count > 0);

        let count_leave_one = get_build_cpu_count(1);
        assert!(count_leave_one > 0);
        assert!(count_leave_one <= count);

        let count_leave_many = get_build_cpu_count(1000);
        assert_eq!(count_leave_many, 1);
    }

    #[test]
    fn test_cpu_info_for_tui() {
        let info_str = get_cpu_info_for_tui();
        assert!(info_str.contains("Available:"));
        assert!(info_str.contains("Total:"));
        assert!(info_str.contains("Online:"));
    }

    #[test]
    fn test_is_hyperthreading_likely() {
        let _ = is_hyperthreading_likely();
    }

    #[test]
    fn test_help_display() {
        show_help();
    }
}
