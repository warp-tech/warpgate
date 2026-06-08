use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct Entry {
    at: Instant,
    ttl: Duration,
    ip: IpAddr,
}

impl Entry {
    fn is_fresh(&self) -> bool {
        self.at.elapsed() <= self.ttl
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[derive(Default)]
pub struct ActiveWebSessions {
    by_user: HashMap<String, Entry>,
}

impl ActiveWebSessions {
    pub fn touch(&mut self, username: &str, ttl: Duration, ip: IpAddr) {
        self.by_user.insert(
            username.to_string(),
            Entry {
                at: Instant::now(),
                ttl,
                ip: canonical_ip(ip),
            },
        );
    }

    pub fn forget(&mut self, username: &str) {
        self.by_user.remove(username);
    }

    pub fn has_fresh(&self, username: &str, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.by_user
            .get(username)
            .map(|e| e.is_fresh() && e.ip == ip)
            .unwrap_or(false)
    }

    pub fn vacuum(&mut self) {
        self.by_user.retain(|_, e| e.is_fresh());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MIN: Duration = Duration::from_secs(60);
    const NS: Duration = Duration::from_nanos(1);
    const IP1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn matches_same_ip() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", MIN, IP1);
        assert!(s.has_fresh("ssh.user", IP1));
    }

    #[test]
    fn rejects_different_ip() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", MIN, IP1);
        assert!(!s.has_fresh("ssh.user", IP2));
    }

    #[test]
    fn rejects_unknown_user() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", MIN, IP1);
        assert!(!s.has_fresh("ssh.unknown", IP1));
    }

    #[test]
    fn expires_after_ttl() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", NS, IP1);
        assert!(!s.has_fresh("ssh.user", IP1));
    }

    #[test]
    fn touch_overrides_ip_and_ttl() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", NS, IP1);
        s.touch("ssh.user", MIN, IP2);
        assert!(!s.has_fresh("ssh.user", IP1));
        assert!(s.has_fresh("ssh.user", IP2));
    }

    #[test]
    fn vacuum_drops_stale() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", NS, IP1);
        s.vacuum();
        assert!(!s.has_fresh("ssh.user", IP1));
    }

    #[test]
    fn forget_drops_entry() {
        let mut s = ActiveWebSessions::default();
        s.touch("ssh.user", MIN, IP1);
        s.forget("ssh.user");
        assert!(!s.has_fresh("ssh.user", IP1));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4() {
        use std::net::Ipv6Addr;
        let mut s = ActiveWebSessions::default();
        // Stored over a dual-stack IPv6 socket as ::ffff:10.0.0.1
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
        s.touch("ssh.user", MIN, mapped);
        // Looked up with the plain IPv4 form -> must still match.
        assert!(s.has_fresh("ssh.user", IP1));
    }
}
