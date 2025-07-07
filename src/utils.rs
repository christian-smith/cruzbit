use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;

use crate::error::ParsingError;

/// Returns a non-negative pseudo-random 31-bit integer as a u32
pub fn rand_int31() -> u32 {
    rand::rng().random_range(0..=i32::MAX) as u32
}

/// Returns duration since Unix epoch
pub fn now_as_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
}

/// Returns number of seconds since Unix epoch
pub fn now_as_secs() -> u64 {
    now_as_duration().as_secs()
}

/// Parse and resolve host to a SocketAddr
pub fn resolve_host(host: &str) -> Result<SocketAddr, ParsingError> {
    let mut addrs = host.to_socket_addrs().map_err(ParsingError::ToSocketAddr)?;
    match addrs.next() {
        Some(addr) => Ok(addr),
        None => Err(ParsingError::ToSocketAddr(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("failed to parse address: {host}"),
        ))),
    }
}

/// Determine if an ip address is in the reserved space
pub fn addr_is_reserved(socket_addr: &SocketAddr) -> bool {
    match socket_addr.ip() {
        IpAddr::V4(v4) => {
            // 127.0.0.0/8
            v4.is_loopback()
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_private()
            // 169.254.0.0/16
            || v4.is_link_local()
            // 0.0.0.0
            || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() // ::1/128

            // fc00::/7 (nightly only)
            // || v6.is_unique_local()
            // fe80::/10 (nightly only)
            // || v6.is_unicast_link_local()
        }
    }
}
