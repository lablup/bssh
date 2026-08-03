use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

pub trait ToSocketAddrsWithHostname {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>>;
    fn hostname(&self) -> String;
}

impl ToSocketAddrsWithHostname for String {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.as_str().to_socket_addrs().map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.clone()
    }
}

impl ToSocketAddrsWithHostname for &str {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.to_string()
    }
}

impl ToSocketAddrsWithHostname for (&str, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.to_string()
    }
}

impl ToSocketAddrsWithHostname for (String, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.clone()
    }
}

impl ToSocketAddrsWithHostname for (IpAddr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for (Ipv4Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for (Ipv6Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for SocketAddr {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![*self])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV4 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V4(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV6 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V6(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for &[SocketAddr] {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.to_vec())
    }

    fn hostname(&self) -> String {
        self.first()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::ToSocketAddrsWithHostname;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn socket_addr_slice_hostname_uses_first_address_only() {
        let addrs = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 22),
        ];

        assert_eq!(addrs.as_slice().hostname(), "127.0.0.1");
    }

    #[test]
    fn empty_socket_addr_slice_hostname_is_empty() {
        let addrs: [SocketAddr; 0] = [];

        assert_eq!(addrs.as_slice().hostname(), "");
    }
}
