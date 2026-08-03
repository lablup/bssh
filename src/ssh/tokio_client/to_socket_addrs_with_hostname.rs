use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

pub trait ToSocketAddrsWithHostname {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>>;
    fn hostname(&self) -> String;
    fn host_port(&self) -> io::Result<(String, u16)>;
}

impl ToSocketAddrsWithHostname for String {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.as_str().to_socket_addrs().map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.clone()
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        parse_host_port(self)
    }
}

impl ToSocketAddrsWithHostname for &str {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.to_string()
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        parse_host_port(self)
    }
}

impl ToSocketAddrsWithHostname for (&str, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.to_string()
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.0.to_string(), self.1))
    }
}

impl ToSocketAddrsWithHostname for (String, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.clone()
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.0.clone(), self.1))
    }
}

impl ToSocketAddrsWithHostname for (IpAddr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.0.to_string(), self.1))
    }
}

impl ToSocketAddrsWithHostname for (Ipv4Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.0.to_string(), self.1))
    }
}

impl ToSocketAddrsWithHostname for (Ipv6Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.0.to_string(), self.1))
    }
}

impl ToSocketAddrsWithHostname for SocketAddr {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![*self])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.ip().to_string(), self.port()))
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV4 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V4(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.ip().to_string(), self.port()))
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV6 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V6(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        Ok((self.ip().to_string(), self.port()))
    }
}

impl ToSocketAddrsWithHostname for &[SocketAddr] {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.to_vec())
    }

    fn hostname(&self) -> String {
        self.iter()
            .map(|addr| addr.ip().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    fn host_port(&self) -> io::Result<(String, u16)> {
        self.first()
            .map(|addr| (addr.ip().to_string(), addr.port()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket address"))
    }
}

fn parse_host_port(target: &str) -> io::Result<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing closing bracket in IPv6 host",
            )
        })?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing port separator"))?;
        (host, port)
    } else {
        target
            .rsplit_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing port separator"))?
    };

    if host.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "missing host"));
    }

    let port = port
        .parse::<u16>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::{ToSocketAddrsWithHostname, parse_host_port};

    #[test]
    fn host_port_parses_domain_without_resolution() {
        assert_eq!(
            "server-only.internal:5432".host_port().unwrap(),
            ("server-only.internal".to_string(), 5432)
        );
    }

    #[test]
    fn host_port_parses_bracketed_ipv6_literal() {
        assert_eq!(
            parse_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }
}
