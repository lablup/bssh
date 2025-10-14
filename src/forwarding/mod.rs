//! Port forwarding implementation for bssh
//!
//! This module provides comprehensive SSH port forwarding capabilities including:
//! - Local port forwarding (-L): Forward local port to remote destination via SSH
//! - Remote port forwarding (-R): Forward remote port to local destination via SSH  
//! - Dynamic port forwarding (-D): SOCKS proxy for dynamic destination forwarding
//!
//! # Architecture
//!
//! The forwarding system is built around three core components:
//! - **ForwardingSpec**: Parsing and validation of forwarding specifications
//! - **ForwardingManager**: Lifecycle management and coordination of forwards
//! - **Forwarder**: Individual forwarding implementations (local, remote, dynamic)
//!
//! # Design Principles
//!
//! - **Async-first**: Built on Tokio for maximum concurrency and performance
//! - **Resource-managed**: Proper cleanup and error handling with RAII patterns
//! - **Multiplexed**: Multiple forwards over single SSH connection when possible
//! - **Resilient**: Automatic reconnection with exponential backoff
//! - **Observable**: Comprehensive status reporting and monitoring

pub mod dynamic;
pub mod local;
pub mod manager;
pub mod remote;
pub mod spec;
pub mod tunnel;

// Re-export key types for convenience
pub use manager::{ForwardingId, ForwardingManager, ForwardingMessage};
pub use spec::ForwardingSpec;

use anyhow::{Context, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Port forwarding specification types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardingType {
    /// Local port forwarding (-L)
    /// Format: [bind_address:]port:host:hostport
    Local {
        bind_addr: IpAddr,
        bind_port: u16,
        remote_host: String,
        remote_port: u16,
    },
    /// Remote port forwarding (-R)  
    /// Format: [bind_address:]port:host:hostport
    Remote {
        bind_addr: IpAddr,
        bind_port: u16,
        local_host: String,
        local_port: u16,
    },
    /// Dynamic port forwarding (-D)
    /// Format: [bind_address:]port
    Dynamic {
        bind_addr: IpAddr,
        bind_port: u16,
        /// SOCKS protocol version (4 or 5)
        socks_version: SocksVersion,
    },
}

/// SOCKS protocol version for dynamic forwarding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V4,
    V5,
}

/// Status of a port forwarding session
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardingStatus {
    /// Forwarding is initializing
    Initializing,
    /// Forwarding is active and ready
    Active,
    /// Forwarding is temporarily disconnected, attempting reconnect
    Reconnecting,
    /// Forwarding failed and stopped
    Failed(String),
    /// Forwarding was stopped intentionally
    Stopped,
}

/// Statistics for a forwarding session
#[derive(Debug, Default, Clone)]
pub struct ForwardingStats {
    /// Number of active connections
    pub active_connections: usize,
    /// Total connections handled
    pub total_connections: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Number of failed connections
    pub failed_connections: u64,
    /// Last error message if any
    pub last_error: Option<String>,
}

/// Configuration for port forwarding behavior
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Maximum number of concurrent connections per forward
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Enable automatic reconnection on failure
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts (0 = unlimited)
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay in milliseconds
    pub reconnect_delay_ms: u64,
    /// Maximum reconnection delay in milliseconds (for exponential backoff)
    pub max_reconnect_delay_ms: u64,
    /// Buffer size for data transfer operations
    pub buffer_size: usize,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connect_timeout_secs: 30,
            auto_reconnect: true,
            max_reconnect_attempts: 10,
            reconnect_delay_ms: 1000,
            max_reconnect_delay_ms: 30000,
            buffer_size: 8192,
        }
    }
}

impl fmt::Display for ForwardingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardingType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => {
                write!(f, "{bind_addr}:{bind_port}→{remote_host}:{remote_port}")
            }
            ForwardingType::Remote {
                bind_addr,
                bind_port,
                local_host,
                local_port,
            } => {
                write!(f, "{bind_addr}:{bind_port}←{local_host}:{local_port}")
            }
            ForwardingType::Dynamic {
                bind_addr,
                bind_port,
                socks_version,
            } => {
                write!(f, "SOCKS{socks_version:?} proxy on {bind_addr}:{bind_port}")
            }
        }
    }
}

impl fmt::Display for ForwardingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardingStatus::Initializing => write!(f, "initializing"),
            ForwardingStatus::Active => write!(f, "active"),
            ForwardingStatus::Reconnecting => write!(f, "reconnecting"),
            ForwardingStatus::Failed(err) => write!(f, "failed: {err}"),
            ForwardingStatus::Stopped => write!(f, "stopped"),
        }
    }
}

impl SocksVersion {
    /// Parse SOCKS version from string
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "4" | "v4" | "socks4" => Ok(SocksVersion::V4),
            "5" | "v5" | "socks5" => Ok(SocksVersion::V5),
            _ => Err(anyhow::anyhow!(
                "Invalid SOCKS version: {s}. Expected 4 or 5"
            )),
        }
    }
}

/// Parse a bind address specification
///
/// Formats supported:
/// - `port` -> 127.0.0.1:port
/// - `address:port` -> address:port
/// - `*:port` -> 0.0.0.0:port (bind to all interfaces)
pub fn parse_bind_spec(spec: &str) -> Result<SocketAddr> {
    // Handle different bind specification formats
    if let Ok(port) = spec.parse::<u16>() {
        // Just a port number, bind to localhost
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }

    // Check for wildcard binding
    if let Some(port_str) = spec.strip_prefix("*:") {
        let port = port_str
            .parse::<u16>()
            .with_context(|| format!("Invalid port in bind specification: {spec}"))?;
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }

    // Parse as full socket address
    spec.parse::<SocketAddr>()
        .with_context(|| format!("Invalid bind specification: {spec}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bind_spec() {
        // Test port-only specification
        let addr = parse_bind_spec("8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);

        // Test wildcard binding
        let addr = parse_bind_spec("*:8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 8080);

        // Test explicit IP binding
        let addr = parse_bind_spec("192.168.1.1:8080").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port(), 8080);

        // Test IPv6
        let addr = parse_bind_spec("[::1]:8080").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_socks_version_parse() {
        assert_eq!(SocksVersion::parse("4").unwrap(), SocksVersion::V4);
        assert_eq!(SocksVersion::parse("v5").unwrap(), SocksVersion::V5);
        assert_eq!(SocksVersion::parse("socks4").unwrap(), SocksVersion::V4);
        assert!(SocksVersion::parse("invalid").is_err());
    }

    #[test]
    fn test_forwarding_type_display() {
        let local = ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 8080,
            remote_host: "example.com".to_string(),
            remote_port: 80,
        };
        assert_eq!(format!("{local}"), "127.0.0.1:8080→example.com:80");

        let dynamic = ForwardingType::Dynamic {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 1080,
            socks_version: SocksVersion::V5,
        };
        assert!(format!("{dynamic}").contains("SOCKS"));
    }
}
