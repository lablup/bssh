//! Port forwarding specification parsing
//!
//! This module handles parsing of SSH port forwarding specifications in OpenSSH format:
//!
//! - Local forwarding (-L): `[bind_address:]port:host:hostport`
//! - Remote forwarding (-R): `[bind_address:]port:host:hostport`
//! - Dynamic forwarding (-D): `[bind_address:]port`
//!
//! # Examples
//!
//! ```rust
//! use bssh::forwarding::spec::ForwardingSpec;
//!
//! // Local forwarding: localhost:8080 -> remote:80 via SSH
//! let spec = ForwardingSpec::parse_local("8080:example.com:80").unwrap();
//!
//! // Remote forwarding: remote:8080 -> localhost:80
//! let spec = ForwardingSpec::parse_remote("8080:localhost:80").unwrap();
//!
//! // Dynamic SOCKS proxy on localhost:1080
//! let spec = ForwardingSpec::parse_dynamic("1080").unwrap();
//! ```

use super::{parse_bind_spec, ForwardingType, SocksVersion};
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};

/// Port forwarding specification parser
pub struct ForwardingSpec;

impl ForwardingSpec {
    /// Parse local port forwarding specification (-L)
    ///
    /// Format: `[bind_address:]port:host:hostport`
    ///
    /// Examples:
    /// - `8080:example.com:80` -> localhost:8080 forwards to example.com:80
    /// - `192.168.1.1:8080:example.com:80` -> 192.168.1.1:8080 forwards to example.com:80
    /// - `*:8080:example.com:80` -> all interfaces:8080 forwards to example.com:80
    pub fn parse_local(spec: &str) -> Result<ForwardingType> {
        let parts: Vec<&str> = spec.split(':').collect();

        match parts.len() {
            3 => {
                // Format: port:host:hostport
                let bind_port = parts[0].parse::<u16>()
                    .with_context(|| format!("Invalid local port: {}", parts[0]))?;
                let remote_host = parts[1].to_string();
                let remote_port = parts[2].parse::<u16>()
                    .with_context(|| format!("Invalid remote port: {}", parts[2]))?;

                Ok(ForwardingType::Local {
                    bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    bind_port,
                    remote_host,
                    remote_port,
                })
            }
            4 => {
                // Format: bind_address:port:host:hostport
                let bind_spec = format!("{}:{}", parts[0], parts[1]);
                let bind_addr = parse_bind_spec(&bind_spec)?;
                let remote_host = parts[2].to_string();
                let remote_port = parts[3].parse::<u16>()
                    .with_context(|| format!("Invalid remote port: {}", parts[3]))?;

                Ok(ForwardingType::Local {
                    bind_addr: bind_addr.ip(),
                    bind_port: bind_addr.port(),
                    remote_host,
                    remote_port,
                })
            }
            _ => Err(anyhow::anyhow!(
                "Invalid local forwarding specification: '{spec}'. Expected format: [bind_address:]port:host:hostport"
            )),
        }
    }

    /// Parse remote port forwarding specification (-R)
    ///
    /// Format: `[bind_address:]port:host:hostport`
    ///
    /// Examples:
    /// - `8080:localhost:80` -> remote:8080 forwards to localhost:80
    /// - `*:8080:localhost:80` -> remote all interfaces:8080 forwards to localhost:80
    pub fn parse_remote(spec: &str) -> Result<ForwardingType> {
        let parts: Vec<&str> = spec.split(':').collect();

        match parts.len() {
            3 => {
                // Format: port:host:hostport
                let bind_port = parts[0].parse::<u16>()
                    .with_context(|| format!("Invalid remote port: {}", parts[0]))?;
                let local_host = parts[1].to_string();
                let local_port = parts[2].parse::<u16>()
                    .with_context(|| format!("Invalid local port: {}", parts[2]))?;

                Ok(ForwardingType::Remote {
                    bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    bind_port,
                    local_host,
                    local_port,
                })
            }
            4 => {
                // Format: bind_address:port:host:hostport
                let bind_spec = format!("{}:{}", parts[0], parts[1]);
                let bind_addr = parse_bind_spec(&bind_spec)?;
                let local_host = parts[2].to_string();
                let local_port = parts[3].parse::<u16>()
                    .with_context(|| format!("Invalid local port: {}", parts[3]))?;

                Ok(ForwardingType::Remote {
                    bind_addr: bind_addr.ip(),
                    bind_port: bind_addr.port(),
                    local_host,
                    local_port,
                })
            }
            _ => Err(anyhow::anyhow!(
                "Invalid remote forwarding specification: '{spec}'. Expected format: [bind_address:]port:host:hostport"
            )),
        }
    }

    /// Parse dynamic port forwarding specification (-D)
    ///
    /// Format: `[bind_address:]port[/socks_version]`
    ///
    /// Examples:
    /// - `1080` -> SOCKS5 proxy on localhost:1080
    /// - `*:1080` -> SOCKS5 proxy on all interfaces:1080
    /// - `1080/4` -> SOCKS4 proxy on localhost:1080
    /// - `192.168.1.1:1080/5` -> SOCKS5 proxy on 192.168.1.1:1080
    pub fn parse_dynamic(spec: &str) -> Result<ForwardingType> {
        // Check for SOCKS version specification
        let (bind_spec, socks_version) =
            if let Some((spec_part, version_part)) = spec.split_once('/') {
                let version = SocksVersion::parse(version_part)
                    .with_context(|| format!("Invalid SOCKS version: {version_part}"))?;
                (spec_part, version)
            } else {
                (spec, SocksVersion::V5) // Default to SOCKS5
            };

        let bind_addr = parse_bind_spec(bind_spec)
            .with_context(|| format!("Invalid dynamic forwarding specification: {spec}"))?;

        Ok(ForwardingType::Dynamic {
            bind_addr: bind_addr.ip(),
            bind_port: bind_addr.port(),
            socks_version,
        })
    }

    /// Parse forwarding specification based on type
    pub fn parse(forward_type: &str, spec: &str) -> Result<ForwardingType> {
        match forward_type.to_lowercase().as_str() {
            "local" | "l" | "-l" => Self::parse_local(spec),
            "remote" | "r" | "-r" => Self::parse_remote(spec),
            "dynamic" | "d" | "-d" => Self::parse_dynamic(spec),
            _ => Err(anyhow::anyhow!(
                "Unknown forwarding type: '{forward_type}'. Expected: local, remote, or dynamic"
            )),
        }
    }

    /// Validate that a forwarding specification is well-formed
    pub fn validate(forwarding: &ForwardingType) -> Result<()> {
        match forwarding {
            ForwardingType::Local {
                bind_port,
                remote_port,
                remote_host,
                ..
            } => {
                if *bind_port == 0 {
                    return Err(anyhow::anyhow!("Local bind port cannot be 0"));
                }
                if *remote_port == 0 {
                    return Err(anyhow::anyhow!("Remote port cannot be 0"));
                }
                if remote_host.is_empty() {
                    return Err(anyhow::anyhow!("Remote host cannot be empty"));
                }
            }
            ForwardingType::Remote {
                bind_port,
                local_port,
                local_host,
                ..
            } => {
                if *bind_port == 0 {
                    return Err(anyhow::anyhow!("Remote bind port cannot be 0"));
                }
                if *local_port == 0 {
                    return Err(anyhow::anyhow!("Local port cannot be 0"));
                }
                if local_host.is_empty() {
                    return Err(anyhow::anyhow!("Local host cannot be empty"));
                }
            }
            ForwardingType::Dynamic { bind_port, .. } => {
                if *bind_port == 0 {
                    return Err(anyhow::anyhow!("Dynamic bind port cannot be 0"));
                }
            }
        }
        Ok(())
    }

    /// Check if a bind port requires elevated privileges (< 1024)
    pub fn requires_root(forwarding: &ForwardingType) -> bool {
        let bind_port = match forwarding {
            ForwardingType::Local { bind_port, .. } => *bind_port,
            ForwardingType::Remote { bind_port, .. } => *bind_port,
            ForwardingType::Dynamic { bind_port, .. } => *bind_port,
        };

        bind_port < 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_local_forwarding() {
        // Test simple format: port:host:hostport
        let spec = ForwardingSpec::parse_local("8080:example.com:80").unwrap();
        match spec {
            ForwardingType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(bind_port, 8080);
                assert_eq!(remote_host, "example.com");
                assert_eq!(remote_port, 80);
            }
            _ => panic!("Expected Local forwarding type"),
        }

        // Test with bind address: bind_address:port:host:hostport
        let spec = ForwardingSpec::parse_local("192.168.1.1:8080:example.com:80").unwrap();
        match spec {
            ForwardingType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(bind_port, 8080);
                assert_eq!(remote_host, "example.com");
                assert_eq!(remote_port, 80);
            }
            _ => panic!("Expected Local forwarding type"),
        }

        // Test wildcard binding
        let spec = ForwardingSpec::parse_local("*:8080:example.com:80").unwrap();
        match spec {
            ForwardingType::Local {
                bind_addr,
                bind_port,
                ..
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_eq!(bind_port, 8080);
            }
            _ => panic!("Expected Local forwarding type"),
        }
    }

    #[test]
    fn test_parse_remote_forwarding() {
        let spec = ForwardingSpec::parse_remote("8080:localhost:80").unwrap();
        match spec {
            ForwardingType::Remote {
                bind_addr,
                bind_port,
                local_host,
                local_port,
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(bind_port, 8080);
                assert_eq!(local_host, "localhost");
                assert_eq!(local_port, 80);
            }
            _ => panic!("Expected Remote forwarding type"),
        }
    }

    #[test]
    fn test_parse_dynamic_forwarding() {
        // Test default SOCKS5
        let spec = ForwardingSpec::parse_dynamic("1080").unwrap();
        match spec {
            ForwardingType::Dynamic {
                bind_addr,
                bind_port,
                socks_version,
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(bind_port, 1080);
                assert_eq!(socks_version, SocksVersion::V5);
            }
            _ => panic!("Expected Dynamic forwarding type"),
        }

        // Test explicit SOCKS4
        let spec = ForwardingSpec::parse_dynamic("1080/4").unwrap();
        match spec {
            ForwardingType::Dynamic { socks_version, .. } => {
                assert_eq!(socks_version, SocksVersion::V4);
            }
            _ => panic!("Expected Dynamic forwarding type"),
        }

        // Test with bind address
        let spec = ForwardingSpec::parse_dynamic("*:1080/5").unwrap();
        match spec {
            ForwardingType::Dynamic {
                bind_addr,
                bind_port,
                socks_version,
            } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_eq!(bind_port, 1080);
                assert_eq!(socks_version, SocksVersion::V5);
            }
            _ => panic!("Expected Dynamic forwarding type"),
        }
    }

    #[test]
    fn test_parse_generic() {
        let spec = ForwardingSpec::parse("local", "8080:example.com:80").unwrap();
        match spec {
            ForwardingType::Local { .. } => {}
            _ => panic!("Expected Local forwarding type"),
        }

        let spec = ForwardingSpec::parse("-R", "8080:localhost:80").unwrap();
        match spec {
            ForwardingType::Remote { .. } => {}
            _ => panic!("Expected Remote forwarding type"),
        }

        let spec = ForwardingSpec::parse("dynamic", "1080").unwrap();
        match spec {
            ForwardingType::Dynamic { .. } => {}
            _ => panic!("Expected Dynamic forwarding type"),
        }
    }

    #[test]
    fn test_validation() {
        let valid_local = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };
        assert!(ForwardingSpec::validate(&valid_local).is_ok());

        let invalid_local = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 0, // Invalid port
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };
        assert!(ForwardingSpec::validate(&invalid_local).is_err());

        let empty_host = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: String::new(), // Empty host
            remote_port: 80,
        };
        assert!(ForwardingSpec::validate(&empty_host).is_err());
    }

    #[test]
    fn test_requires_root() {
        let privileged = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 80, // Privileged port
            remote_host: "example.com".to_string(),
            remote_port: 8080,
        };
        assert!(ForwardingSpec::requires_root(&privileged));

        let unprivileged = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080, // Unprivileged port
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };
        assert!(!ForwardingSpec::requires_root(&unprivileged));
    }

    #[test]
    fn test_invalid_specifications() {
        // Invalid local forwarding formats
        assert!(ForwardingSpec::parse_local("invalid").is_err());
        assert!(ForwardingSpec::parse_local("8080:example.com").is_err()); // Missing port
        assert!(ForwardingSpec::parse_local("8080:example.com:80:extra").is_err()); // Too many parts
        assert!(ForwardingSpec::parse_local("invalid:example.com:80").is_err()); // Invalid port

        // Invalid remote forwarding formats
        assert!(ForwardingSpec::parse_remote("invalid").is_err());

        // Invalid dynamic forwarding formats
        assert!(ForwardingSpec::parse_dynamic("invalid:port").is_err());
        assert!(ForwardingSpec::parse_dynamic("1080/invalid").is_err()); // Invalid SOCKS version
    }
}
