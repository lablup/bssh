//! Statistics tracking for dynamic port forwarding

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics specific to dynamic forwarding
#[derive(Debug, Default)]
#[allow(dead_code)] // Future implementation fields
pub struct DynamicForwarderStats {
    /// Total SOCKS connections accepted
    pub(crate) socks_connections_accepted: AtomicU64,
    /// Currently active SOCKS connections
    pub(crate) active_connections: AtomicU64,
    /// Total SOCKS connections failed
    pub(crate) socks_connections_failed: AtomicU64,
    /// Total bytes transferred across all connections
    pub(crate) total_bytes_transferred: AtomicU64,
    /// SOCKS4 protocol requests
    pub(crate) socks4_requests: AtomicU64,
    /// SOCKS5 protocol requests
    pub(crate) socks5_requests: AtomicU64,
    /// DNS resolution requests
    pub(crate) dns_resolutions: AtomicU64,
    /// Failed DNS resolutions
    pub(crate) dns_failures: AtomicU64,
}

impl DynamicForwarderStats {
    /// Get the number of active connections
    #[allow(dead_code)]
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total connections accepted
    #[allow(dead_code)]
    pub fn total_accepted(&self) -> u64 {
        self.socks_connections_accepted.load(Ordering::Relaxed)
    }

    /// Get total bytes transferred
    #[allow(dead_code)]
    pub fn bytes_transferred(&self) -> u64 {
        self.total_bytes_transferred.load(Ordering::Relaxed)
    }

    /// Increment active connections
    pub(crate) fn inc_active(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub(crate) fn dec_active(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment accepted connections
    pub(crate) fn inc_accepted(&self) {
        self.socks_connections_accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed connections
    pub(crate) fn inc_failed(&self) {
        self.socks_connections_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Add bytes transferred
    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.total_bytes_transferred
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment SOCKS4 requests
    pub(crate) fn inc_socks4(&self) {
        self.socks4_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment SOCKS5 requests
    pub(crate) fn inc_socks5(&self) {
        self.socks5_requests.fetch_add(1, Ordering::Relaxed);
    }
}
