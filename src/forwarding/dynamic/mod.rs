//! Dynamic port forwarding implementation (-D option)
//!
//! Dynamic port forwarding creates a local SOCKS proxy that accepts connections
//! and dynamically forwards them to destinations via SSH tunneling based on
//! SOCKS protocol requests. This is equivalent to the OpenSSH `-D [bind_address:]port` option.
//!
//! # Architecture
//!
//! ```text
//! [Client] → [SOCKS Proxy] → [SSH Channel] → [Dynamic Destination]
//!              ↑ bind_addr:bind_port          ↑ Per-request destination
//! ```
//!
//! # Example Usage
//!
//! Create SOCKS proxy on localhost:1080:
//! ```bash
//! bssh -D 1080 user@ssh-server
//! ```
//!
//! Configure applications to use 127.0.0.1:1080 as SOCKS proxy.
//! All traffic will be forwarded through the SSH connection with
//! destinations determined by SOCKS requests.
//!
//! # Implementation Status
//!
//! **Phase 2 - Placeholder Implementation**
//! This is a placeholder implementation that provides the basic structure.
//! The full SOCKS protocol implementation will be completed in Phase 2.
//!
//! # SOCKS Protocol Support
//!
//! **Phase 2 Features:**
//! - SOCKS4 protocol support
//! - SOCKS5 protocol support with authentication
//! - DNS resolution through remote connection
//! - IPv4 and IPv6 destination support

mod connection;
mod forwarder;
mod socks;
mod stats;

pub use forwarder::DynamicForwarder;
pub use stats::DynamicForwarderStats;

// Re-export SOCKS protocol handlers for tests
#[cfg(test)]
pub use socks::{handle_socks4_connection, handle_socks5_connection};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        forwarding::{ForwardingConfig, ForwardingType, SocksVersion},
        ssh::tokio_client::{AuthMethod, Client, ServerCheckMethod},
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_dynamic_forwarder_creation() {
        let spec = ForwardingType::Dynamic {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port: 1080,
            socks_version: SocksVersion::V5,
        };

        let ssh_client = Arc::new(
            Client::connect(
                ("127.0.0.1", 22),
                "test_user",
                AuthMethod::with_password("test"),
                ServerCheckMethod::NoCheck,
            )
            .await
            .unwrap(),
        );

        let config = ForwardingConfig::default();
        let cancel_token = CancellationToken::new();
        let (message_tx, _message_rx) = mpsc::unbounded_channel();
        let session_id = Uuid::new_v4();

        let forwarder = DynamicForwarder::new(
            session_id,
            spec,
            ssh_client,
            config,
            cancel_token,
            message_tx,
        );

        assert!(forwarder.is_ok());

        let forwarder = forwarder.unwrap();
        assert_eq!(forwarder.session_id, session_id);
        assert_eq!(forwarder.socks_version, SocksVersion::V5);
    }

    #[test]
    fn test_dynamic_forwarder_stats() {
        let stats = DynamicForwarderStats::default();

        stats.inc_accepted();
        stats.inc_accepted();
        stats.inc_accepted();
        stats.inc_socks4();
        stats.inc_socks5();
        stats.inc_socks5();
        stats.add_bytes(1024);
        stats.add_bytes(2048);

        assert_eq!(stats.total_accepted(), 3);
        assert_eq!(
            stats
                .socks4_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .socks5_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(stats.bytes_transferred(), 3072);
    }

    #[tokio::test]
    #[ignore = "Requires SSH server connection"]
    async fn test_socks_version_handling() {
        for socks_version in [SocksVersion::V4, SocksVersion::V5] {
            let spec = ForwardingType::Dynamic {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                bind_port: 1080,
                socks_version,
            };

            let ssh_client = Arc::new(
                Client::connect(
                    ("127.0.0.1", 22),
                    "test_user",
                    AuthMethod::with_password("test"),
                    ServerCheckMethod::NoCheck,
                )
                .await
                .unwrap(),
            );

            let config = ForwardingConfig::default();
            let cancel_token = CancellationToken::new();
            let (message_tx, _message_rx) = mpsc::unbounded_channel();
            let session_id = Uuid::new_v4();

            let forwarder = DynamicForwarder::new(
                session_id,
                spec,
                ssh_client,
                config,
                cancel_token,
                message_tx,
            )
            .unwrap();

            assert_eq!(forwarder.socks_version, socks_version);
        }
    }
}
