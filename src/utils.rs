use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngExt;

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
    match socket_addr.ip().to_canonical() {
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
            // ::1/128
            v6.is_loopback()
            // fc00::/7
            || v6.is_unique_local()
            // fe80::/10
            || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use super::addr_is_reserved;

    #[test]
    fn test_addr_is_reserved_matches_go_private_blocks() {
        for addr in [
            "127.0.0.1:8831",
            "10.0.0.1:8831",
            "172.16.0.1:8831",
            "192.168.0.1:8831",
            "[::1]:8831",
            "[fe80::1]:8831",
            "[fc00::1]:8831",
            // IPv4-mapped IPv6 uses the IPv4 reserved-address rules
            "[::ffff:10.0.0.1]:8831",
            "[::ffff:127.0.0.1]:8831",
            "[::ffff:192.168.0.1]:8831",
            "[::ffff:172.16.0.1]:8831",
        ] {
            assert!(
                addr_is_reserved(&addr.parse::<SocketAddr>().unwrap()),
                "expected reserved: {addr}"
            );
        }

        for addr in [
            "8.8.8.8:8831",
            "[2001:4860:4860::8888]:8831",
            // IPv4-mapped public IPv4 remains allowed
            "[::ffff:8.8.8.8]:8831",
        ] {
            assert!(
                !addr_is_reserved(&addr.parse::<SocketAddr>().unwrap()),
                "expected NOT reserved: {addr}"
            );
        }
    }
}
