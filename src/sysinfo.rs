use std::env;
use std::error::Error;
use std::fs;
use std::process; // to exit the process without panic
use sys_info;

pub fn run() {
    println!("OS: {}", sys_info::os_type().unwrap());
    println!("OS release: {}", sys_info::os_release().unwrap());
    println!("Hostname: {}", sys_info::hostname().unwrap());
    println!("CPU cores: {}", sys_info::cpu_num().unwrap());
    println!("CPU speed (MHz): {}", sys_info::cpu_speed().unwrap());
    println!(
        "Total RAM: {} MB",
        sys_info::mem_info().unwrap().total / 1024
    );
}
