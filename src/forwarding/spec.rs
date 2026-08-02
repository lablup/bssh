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
//! use bssh::ssh::tokio_client::AddressFamily;
//!
//! // Local forwarding: localhost:8080 -> remote:80 via SSH
//! let spec = ForwardingSpec::parse_local("8080:example.com:80", AddressFamily::Any).unwrap();
//!
//! // Remote forwarding: remote:8080 -> localhost:80
//! let spec = ForwardingSpec::parse_remote("8080:localhost:80").unwrap();
//!
//! // Dynamic SOCKS proxy on ::1:1080
//! let spec = ForwardingSpec::parse_dynamic("1080", AddressFamily::V6).unwrap();
//! ```

use super::{ForwardingType, SocksVersion, parse_bind_spec_with_family};
use crate::ssh::tokio_client::AddressFamily;
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
    ///
    /// `address_family` selects the implicit bind address when the spec does
    /// not name one: `-6` listens on `::1` instead of `127.0.0.1`. A spec that
    /// names a bind address explicitly overrides the flag.
    pub fn parse_local(spec: &str, address_family: AddressFamily) -> Result<ForwardingType> {
        let parts: Vec<&str> = spec.split(':').collect();

        match parts.len() {
            3 => {
                // Format: port:host:hostport
                let bind_port = parts[0]
                    .parse::<u16>()
                    .with_context(|| format!("Invalid local port: {}", parts[0]))?;
                let remote_host = parts[1].to_string();
                let remote_port = parts[2]
                    .parse::<u16>()
                    .with_context(|| format!("Invalid remote port: {}", parts[2]))?;

                Ok(ForwardingType::Local {
                    bind_addr: address_family.loopback(),
                    bind_port,
                    remote_host,
                    remote_port,
                })
            }
            4 => {
                // Format: bind_address:port:host:hostport
                let bind_spec = format!("{}:{}", parts[0], parts[1]);
                let bind_addr = parse_bind_spec_with_family(&bind_spec, address_family)?;
                let remote_host = parts[2].to_string();
                let remote_port = parts[3]
                    .parse::<u16>()
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
    ///
    /// Unlike `-L` and `-D`, the bind address here names a listener on the
    /// *remote* side, which the server creates and which the local `-4`/`-6`
    /// flags therefore do not govern. The implicit default stays IPv4
    /// loopback; see issue #246 for the decision.
    pub fn parse_remote(spec: &str) -> Result<ForwardingType> {
        let parts: Vec<&str> = spec.split(':').collect();

        match parts.len() {
            3 => {
                // Format: port:host:hostport
                let bind_port = parts[0]
                    .parse::<u16>()
                    .with_context(|| format!("Invalid remote port: {}", parts[0]))?;
                let local_host = parts[1].to_string();
                let local_port = parts[2]
                    .parse::<u16>()
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
                let bind_addr = parse_bind_spec_with_family(&bind_spec, AddressFamily::Any)?;
                let local_host = parts[2].to_string();
                let local_port = parts[3]
                    .parse::<u16>()
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
    ///
    /// `address_family` selects the implicit bind address the same way it does
    /// for [`parse_local`].
    pub fn parse_dynamic(spec: &str, address_family: AddressFamily) -> Result<ForwardingType> {
        // Check for SOCKS version specification
        let (bind_spec, socks_version) =
            if let Some((spec_part, version_part)) = spec.split_once('/') {
                let version = SocksVersion::parse(version_part)
                    .with_context(|| format!("Invalid SOCKS version: {version_part}"))?;
                (spec_part, version)
            } else {
                (spec, SocksVersion::V5) // Default to SOCKS5
            };

        let bind_addr = parse_bind_spec_with_family(bind_spec, address_family)
            .with_context(|| format!("Invalid dynamic forwarding specification: {spec}"))?;

        Ok(ForwardingType::Dynamic {
            bind_addr: bind_addr.ip(),
            bind_port: bind_addr.port(),
            socks_version,
        })
    }

    /// Parse forwarding specification based on type
    pub fn parse(
        forward_type: &str,
        spec: &str,
        address_family: AddressFamily,
    ) -> Result<ForwardingType> {
        match forward_type.to_lowercase().as_str() {
            "local" | "l" | "-l" => Self::parse_local(spec, address_family),
            // `address_family` is deliberately not forwarded here; see
            // `parse_remote`.
            "remote" | "r" | "-r" => Self::parse_remote(spec),
            "dynamic" | "d" | "-d" => Self::parse_dynamic(spec, address_family),
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn local_bind_addr(spec: &str, family: AddressFamily) -> IpAddr {
        match ForwardingSpec::parse_local(spec, family).unwrap() {
            ForwardingType::Local { bind_addr, .. } => bind_addr,
            other => panic!("expected Local forwarding type, got {other:?}"),
        }
    }

    fn dynamic_bind_addr(spec: &str, family: AddressFamily) -> IpAddr {
        match ForwardingSpec::parse_dynamic(spec, family).unwrap() {
            ForwardingType::Dynamic { bind_addr, .. } => bind_addr,
            other => panic!("expected Dynamic forwarding type, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_flag_moves_the_implicit_listener_to_ipv6_loopback() {
        assert_eq!(
            local_bind_addr("8080:example.com:80", AddressFamily::V6),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            dynamic_bind_addr("1080", AddressFamily::V6),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            local_bind_addr("*:8080:example.com:80", AddressFamily::V6),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn ipv4_flag_and_no_flag_keep_the_ipv4_listener_default() {
        for family in [AddressFamily::V4, AddressFamily::Any] {
            assert_eq!(
                local_bind_addr("8080:example.com:80", family),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            );
            assert_eq!(
                dynamic_bind_addr("1080", family),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            );
        }
    }

    #[test]
    fn explicit_bind_address_overrides_the_address_family_flag() {
        assert_eq!(
            local_bind_addr("192.168.1.1:8080:example.com:80", AddressFamily::V6),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            dynamic_bind_addr("[::1]:1080", AddressFamily::V4),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn remote_forwarding_listener_is_not_governed_by_the_local_flag() {
        // The `-R` listener lives on the server, so `-6` must not silently
        // rewrite what bssh asks the server to bind.
        match ForwardingSpec::parse_remote("8080:localhost:80").unwrap() {
            ForwardingType::Remote { bind_addr, .. } => {
                assert_eq!(bind_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            other => panic!("expected Remote forwarding type, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_local_forwarding() {
        // Test simple format: port:host:hostport
        let spec = ForwardingSpec::parse_local("8080:example.com:80", AddressFamily::Any).unwrap();
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
        let spec =
            ForwardingSpec::parse_local("192.168.1.1:8080:example.com:80", AddressFamily::Any)
                .unwrap();
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
        let spec =
            ForwardingSpec::parse_local("*:8080:example.com:80", AddressFamily::Any).unwrap();
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
        let spec = ForwardingSpec::parse_dynamic("1080", AddressFamily::Any).unwrap();
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
        let spec = ForwardingSpec::parse_dynamic("1080/4", AddressFamily::Any).unwrap();
        match spec {
            ForwardingType::Dynamic { socks_version, .. } => {
                assert_eq!(socks_version, SocksVersion::V4);
            }
            _ => panic!("Expected Dynamic forwarding type"),
        }

        // Test with bind address
        let spec = ForwardingSpec::parse_dynamic("*:1080/5", AddressFamily::Any).unwrap();
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
        let spec =
            ForwardingSpec::parse("local", "8080:example.com:80", AddressFamily::Any).unwrap();
        match spec {
            ForwardingType::Local { .. } => {}
            _ => panic!("Expected Local forwarding type"),
        }

        let spec = ForwardingSpec::parse("-R", "8080:localhost:80", AddressFamily::Any).unwrap();
        match spec {
            ForwardingType::Remote { .. } => {}
            _ => panic!("Expected Remote forwarding type"),
        }

        let spec = ForwardingSpec::parse("dynamic", "1080", AddressFamily::Any).unwrap();
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
        assert!(ForwardingSpec::parse_local("invalid", AddressFamily::Any).is_err());
        assert!(ForwardingSpec::parse_local("8080:example.com", AddressFamily::Any).is_err()); // Missing port
        assert!(
            ForwardingSpec::parse_local("8080:example.com:80:extra", AddressFamily::Any).is_err()
        ); // Too many parts
        assert!(ForwardingSpec::parse_local("invalid:example.com:80", AddressFamily::Any).is_err()); // Invalid port

        // Invalid remote forwarding formats
        assert!(ForwardingSpec::parse_remote("invalid").is_err());

        // Invalid dynamic forwarding formats
        assert!(ForwardingSpec::parse_dynamic("invalid:port", AddressFamily::Any).is_err());
        assert!(ForwardingSpec::parse_dynamic("1080/invalid", AddressFamily::Any).is_err()); // Invalid SOCKS version
    }
}
