use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(not(target_os = "windows"))]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(not(target_os = "windows"))]
use std::mem::MaybeUninit;

pub fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {} <host> [max_hops] [probes_per_hop] [timeout_ms] [start_port]",
        prog
    );
    eprintln!("Example: {} google.com 30 3 2000 33434", prog);
}

fn resolve_host(host: &str) -> Option<IpAddr> {
    // prefer IPv4 for this traceroute
    match (host, 0).to_socket_addrs() {
        Ok(mut iter) => iter.find_map(|s| match s.ip() {
            IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
            _ => None,
        }),
        Err(_) => None,
    }
}

#[cfg(target_os = "windows")]
pub fn windows_traceroute(host: &str, max_hops: u32, probes: u32, timeout_ms: u64) {
    // Use system tracert for Windows; build command with count and timeout approximations
    // tracert doesn't allow probes count directly, but this is a pragmatic fallback.
    // We'll call tracert -d (no DNS) -h max_hops host
    let mut cmd = Command::new("tracert");
    cmd.arg("-d").arg("-h").arg(max_hops.to_string()).arg(host);

    match cmd.output() {
        Ok(out) => {
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => eprintln!("Failed to run tracert: {}", e),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_traceroute_unix(
    host: &str,
    max_hops: u32,
    probes: u32,
    timeout_ms: u64,
    start_port: u16,
) -> std::io::Result<()> {
    // Resolve host IPv4
    let ip = match resolve_host(host) {
        Some(IpAddr::V4(v4)) => v4,
        Some(_) => {
            eprintln!("Only IPv4 is supported by this traceroute implementation.");
            return Ok(());
        }
        None => {
            eprintln!("Failed to resolve host: {}", host);
            return Ok(());
        }
    };

    println!(
        "traceroute to {} ({}), {} hops max, {} probes per hop",
        host, ip, max_hops, probes
    );

    // Raw socket to receive ICMP replies (needs root)
    // socket2 v0.5 doesn't expose Type::RAW on this target, so use the raw OS constant.
    let recv_sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )?;
    recv_sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    // UDP socket for sending probes
    let send_sock = UdpSocket::bind(("0.0.0.0", 0))?;
    // Use non-blocking? we'll use timeout on recv instead

    // We'll send to destination IP at high ports starting from start_port
    let mut dst_port = start_port;

    for ttl in 1..=max_hops {
        // set TTL on UDP socket
        send_sock.set_ttl(ttl)?;
        print!("{:2}  ", ttl);
        let mut hop_ips: Vec<Option<IpAddr>> = Vec::new();
        let mut rtts: Vec<Option<u128>> = Vec::new();

        for p in 0..probes {
            let probe_port = dst_port + (p as u16);
            let dest_sockaddr = SocketAddr::new(IpAddr::V4(ip), probe_port);

            let probe_id = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_nanos(),
                Err(_) => ((ttl as u128) << 64) | ((p as u128) << 32) | (probe_port as u128),
            };
            let payload = format!("TRACEROUTE_RUST_{}_{}_{}", ttl, p, probe_id);
            // send probe
            let start = Instant::now();
            if let Err(e) = send_sock.send_to(payload.as_bytes(), dest_sockaddr) {
                eprintln!(" send error: {}", e);
                hop_ips.push(None);
                rtts.push(None);
                continue;
            }

            // receive ICMP reply on raw socket
            // recv expects MaybeUninit buffer in socket2
            let mut buf: [MaybeUninit<u8>; 1500] = unsafe { MaybeUninit::uninit().assume_init() };
            match recv_sock.recv(&mut buf) {
                Ok(n) => {
                    let elapsed = start.elapsed();
                    // convert MaybeUninit buffer to slice
                    let slice: &[u8] = unsafe { std::mem::transmute(&buf[..n]) };
                    // parse IPv4 header length
                    if slice.len() < 1 {
                        hop_ips.push(None);
                        rtts.push(Some(elapsed.as_millis()));
                        continue;
                    }
                    let ip_header_len = ((slice[0] & 0x0f) * 4) as usize;
                    if slice.len() >= ip_header_len + 1 {
                        let icmp_type = slice[ip_header_len];
                        let icmp_code = slice[ip_header_len + 1];
                        // source IP is provided by recv_from via socket2? we only have raw buffer; easier is to use recv_from in socket2
                        // but socket2::recv didn't give source; instead use recv_from below:
                        // (we'll re-recv using recv_from to get source)
                        match recv_sock.recv_from(&mut buf) {
                            Ok((m, addr)) => {
                                let elapsed_ms = start.elapsed().as_millis();
                                hop_ips.push(Some(addr.as_socket().unwrap().ip()));
                                rtts.push(Some(elapsed_ms));
                                if icmp_type == 3 { // Destination Unreachable (ICMP type 3) - destination reached when port unreachable
                                    // If code is 3 (port unreachable) this means destination reached for UDP traceroute.
                                } else if icmp_type == 0 {
                                    // Echo reply
                                } else if icmp_type == 11 {
                                    // Time exceeded - intermediate hop
                                }
                            }
                            Err(_) => {
                                hop_ips.push(None);
                                rtts.push(Some(elapsed.as_millis()));
                            }
                        }
                    } else {
                        hop_ips.push(None);
                        rtts.push(Some(elapsed.as_millis()));
                    }
                }
                Err(_) => {
                    // timeout
                    hop_ips.push(None);
                    rtts.push(None);
                }
            }
        }

        // print results for this ttl
        // If any ip present, print first unique ip and times
        let mut printed_addr: Option<IpAddr> = None;
        for i in 0..(hop_ips.len()) {
            if let Some(ipaddr) = hop_ips[i] {
                if printed_addr.is_none() {
                    printed_addr = Some(ipaddr);
                    print!("{}  ", ipaddr);
                }
                if let Some(ms) = rtts[i] {
                    print!("{:>4} ms  ", ms);
                } else {
                    print!("  *    ");
                }
            } else {
                print!("  *    ");
            }
        }
        println!();

        // If any rtt corresponds to destination (ICMP type 3 code 3 port unreachable), we should stop.
        // Simpler heuristic: if printed_addr is destination IP then stop
        if let Some(a) = printed_addr {
            if a == IpAddr::V4(ip) {
                println!("Reached destination.");
                break;
            }
        }

        dst_port = dst_port.wrapping_add(probes as u16); // advance ports
    }

    Ok(())
}
