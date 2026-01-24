// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! IP-based access control for the SSH server.
//!
//! This module provides functionality to allow or deny connections from
//! specific IP addresses or CIDR ranges.
//!
//! # Features
//!
//! - **Whitelist mode**: Only allow connections from specified IP ranges
//! - **Blacklist mode**: Block specific IP ranges
//! - **Priority**: Blocked IPs take priority over allowed IPs
//! - **Dynamic updates**: Add or remove rules at runtime
//!
//! # Example
//!
//! ```
//! use bssh::server::security::{IpAccessControl, AccessPolicy};
//!
//! let mut access = IpAccessControl::new();
//!
//! // Allow private networks
//! access.allow_cidr("10.0.0.0/8").unwrap();
//! access.allow_cidr("192.168.0.0/16").unwrap();
//!
//! // Block a specific range
//! access.block_cidr("192.168.100.0/24").unwrap();
//!
//! let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
//! assert_eq!(access.check(&ip), AccessPolicy::Allow);
//!
//! let blocked_ip: std::net::IpAddr = "192.168.100.50".parse().unwrap();
//! assert_eq!(access.check(&blocked_ip), AccessPolicy::Deny);
//! ```

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Access policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPolicy {
    /// Allow the connection.
    Allow,
    /// Deny the connection.
    Deny,
}

/// IP-based access control.
///
/// This struct manages allowed and blocked IP ranges for connection filtering.
/// Rules are evaluated in the following order:
///
/// 1. Check if IP is in blocked list → Deny
/// 2. If allowed list is non-empty, check if IP is in allowed list → Allow/Deny
/// 3. Use default policy (Allow if no allowed list specified)
#[derive(Debug, Clone)]
pub struct IpAccessControl {
    /// Allowed IP ranges (whitelist mode).
    allowed: Vec<IpNetwork>,
    /// Blocked IP ranges (blacklist).
    blocked: Vec<IpNetwork>,
    /// Default policy when no rules match.
    default_policy: AccessPolicy,
}

impl Default for IpAccessControl {
    fn default() -> Self {
        Self::new()
    }
}

impl IpAccessControl {
    /// Create a new access control with default allow policy.
    pub fn new() -> Self {
        Self {
            allowed: Vec::new(),
            blocked: Vec::new(),
            default_policy: AccessPolicy::Allow,
        }
    }

    /// Create access control from allowed and blocked IP lists.
    ///
    /// # Arguments
    ///
    /// * `allowed_ips` - List of allowed IP ranges in CIDR notation
    /// * `blocked_ips` - List of blocked IP ranges in CIDR notation
    ///
    /// # Returns
    ///
    /// Returns an error if any CIDR string is invalid.
    pub fn from_config(allowed_ips: &[String], blocked_ips: &[String]) -> Result<Self> {
        let mut ctrl = Self::new();

        for cidr in allowed_ips {
            let network: IpNetwork = cidr
                .parse()
                .with_context(|| format!("Invalid allowed_ips CIDR: {}", cidr))?;
            ctrl.allowed.push(network);
        }

        for cidr in blocked_ips {
            let network: IpNetwork = cidr
                .parse()
                .with_context(|| format!("Invalid blocked_ips CIDR: {}", cidr))?;
            ctrl.blocked.push(network);
        }

        // If allowed list is specified, default to deny
        if !ctrl.allowed.is_empty() {
            ctrl.default_policy = AccessPolicy::Deny;
        }

        tracing::info!(
            allowed_count = ctrl.allowed.len(),
            blocked_count = ctrl.blocked.len(),
            default_policy = ?ctrl.default_policy,
            "IP access control configured"
        );

        Ok(ctrl)
    }

    /// Check if an IP address is allowed to connect.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    ///
    /// Returns `AccessPolicy::Allow` if the IP is allowed, `AccessPolicy::Deny` otherwise.
    pub fn check(&self, ip: &IpAddr) -> AccessPolicy {
        // Check blocked list first (blacklist takes priority)
        for network in &self.blocked {
            if network.contains(*ip) {
                tracing::debug!(
                    ip = %ip,
                    network = %network,
                    "IP blocked by rule"
                );
                return AccessPolicy::Deny;
            }
        }

        // Check allowed list (whitelist)
        if !self.allowed.is_empty() {
            for network in &self.allowed {
                if network.contains(*ip) {
                    tracing::trace!(
                        ip = %ip,
                        network = %network,
                        "IP allowed by rule"
                    );
                    return AccessPolicy::Allow;
                }
            }
            // Not in whitelist
            tracing::debug!(
                ip = %ip,
                "IP not in allowed list"
            );
            return AccessPolicy::Deny;
        }

        self.default_policy
    }

    /// Add an allowed CIDR range.
    ///
    /// # Arguments
    ///
    /// * `cidr` - CIDR notation string (e.g., "192.168.0.0/16")
    pub fn allow_cidr(&mut self, cidr: &str) -> Result<()> {
        let network: IpNetwork = cidr
            .parse()
            .with_context(|| format!("Invalid CIDR: {}", cidr))?;
        self.allow(network);
        Ok(())
    }

    /// Add an allowed network.
    pub fn allow(&mut self, network: IpNetwork) {
        if !self.allowed.contains(&network) {
            self.allowed.push(network);
            // Update default policy when whitelist is non-empty
            if self.default_policy == AccessPolicy::Allow {
                self.default_policy = AccessPolicy::Deny;
            }
            tracing::info!(network = %network, "Added to allowed list");
        }
    }

    /// Add a blocked CIDR range.
    ///
    /// # Arguments
    ///
    /// * `cidr` - CIDR notation string (e.g., "10.10.10.10/32")
    pub fn block_cidr(&mut self, cidr: &str) -> Result<()> {
        let network: IpNetwork = cidr
            .parse()
            .with_context(|| format!("Invalid CIDR: {}", cidr))?;
        self.block(network);
        Ok(())
    }

    /// Add a blocked network.
    pub fn block(&mut self, network: IpNetwork) {
        if !self.blocked.contains(&network) {
            self.blocked.push(network);
            tracing::info!(network = %network, "Added to blocked list");
        }
    }

    /// Block a single IP address.
    ///
    /// This creates a /32 (IPv4) or /128 (IPv6) rule.
    pub fn block_ip(&mut self, ip: IpAddr) {
        let network = IpNetwork::from(ip);
        self.block(network);
    }

    /// Unblock a single IP address.
    ///
    /// Removes the /32 (IPv4) or /128 (IPv6) rule for this IP.
    pub fn unblock_ip(&mut self, ip: IpAddr) {
        let network = IpNetwork::from(ip);
        let before = self.blocked.len();
        self.blocked.retain(|n| n != &network);
        if self.blocked.len() < before {
            tracing::info!(ip = %ip, "Removed from blocked list");
        }
    }

    /// Remove an allowed network.
    pub fn remove_allowed(&mut self, network: &IpNetwork) {
        let before = self.allowed.len();
        self.allowed.retain(|n| n != network);
        if self.allowed.len() < before {
            tracing::info!(network = %network, "Removed from allowed list");
        }
        // Reset default policy if allowed list is now empty
        if self.allowed.is_empty() {
            self.default_policy = AccessPolicy::Allow;
        }
    }

    /// Remove a blocked network.
    pub fn remove_blocked(&mut self, network: &IpNetwork) {
        let before = self.blocked.len();
        self.blocked.retain(|n| n != network);
        if self.blocked.len() < before {
            tracing::info!(network = %network, "Removed from blocked list");
        }
    }

    /// Reload configuration from allowed and blocked IP lists.
    pub fn reload(&mut self, allowed_ips: &[String], blocked_ips: &[String]) -> Result<()> {
        let new_config = Self::from_config(allowed_ips, blocked_ips)?;
        *self = new_config;
        tracing::info!("IP access control reloaded");
        Ok(())
    }

    /// Get the number of allowed networks.
    pub fn allowed_count(&self) -> usize {
        self.allowed.len()
    }

    /// Get the number of blocked networks.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Get the default policy.
    pub fn default_policy(&self) -> AccessPolicy {
        self.default_policy
    }

    /// Check if the access control is in whitelist mode.
    ///
    /// Returns `true` if there are allowed networks configured,
    /// meaning only those networks are allowed.
    pub fn is_whitelist_mode(&self) -> bool {
        !self.allowed.is_empty()
    }

    /// Get a copy of the allowed networks.
    pub fn allowed_networks(&self) -> Vec<IpNetwork> {
        self.allowed.clone()
    }

    /// Get a copy of the blocked networks.
    pub fn blocked_networks(&self) -> Vec<IpNetwork> {
        self.blocked.clone()
    }
}

/// Thread-safe wrapper for IP access control.
///
/// This allows sharing the access control across multiple handlers
/// and updating rules at runtime.
#[derive(Clone)]
pub struct SharedIpAccessControl {
    inner: Arc<RwLock<IpAccessControl>>,
}

impl SharedIpAccessControl {
    /// Create a new shared access control.
    pub fn new(access: IpAccessControl) -> Self {
        Self {
            inner: Arc::new(RwLock::new(access)),
        }
    }

    /// Check if an IP address is allowed.
    pub async fn check(&self, ip: &IpAddr) -> AccessPolicy {
        self.inner.read().await.check(ip)
    }

    /// Check if an IP address is allowed (blocking version).
    ///
    /// This is useful when you need to check access in a synchronous context.
    /// On lock contention, defaults to DENY for security (fail-closed).
    pub fn check_sync(&self, ip: &IpAddr) -> AccessPolicy {
        // Try to acquire read lock without blocking
        if let Ok(guard) = self.inner.try_read() {
            return guard.check(ip);
        }
        // Fail-closed: deny on lock contention to prevent security bypass
        tracing::warn!(
            ip = %ip,
            "Access control lock contended, denying for security"
        );
        AccessPolicy::Deny
    }

    /// Block an IP address at runtime.
    pub async fn block_ip(&self, ip: IpAddr) {
        self.inner.write().await.block_ip(ip);
    }

    /// Unblock an IP address at runtime.
    pub async fn unblock_ip(&self, ip: IpAddr) {
        self.inner.write().await.unblock_ip(ip);
    }

    /// Reload configuration.
    pub async fn reload(&self, allowed_ips: &[String], blocked_ips: &[String]) -> Result<()> {
        self.inner.write().await.reload(allowed_ips, blocked_ips)
    }

    /// Get statistics about the access control.
    pub async fn stats(&self) -> (usize, usize, AccessPolicy) {
        let guard = self.inner.read().await;
        (
            guard.allowed_count(),
            guard.blocked_count(),
            guard.default_policy(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_default_allow() {
        let access = IpAccessControl::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(access.check(&ip), AccessPolicy::Allow);
    }

    #[test]
    fn test_cidr_matching() {
        let mut access = IpAccessControl::new();
        access.allow_cidr("192.168.0.0/16").unwrap();

        // IP in range should be allowed
        let ip_in: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(access.check(&ip_in), AccessPolicy::Allow);

        // IP outside range should be denied (whitelist mode)
        let ip_out: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(access.check(&ip_out), AccessPolicy::Deny);
    }

    #[test]
    fn test_whitelist_mode() {
        let access = IpAccessControl::from_config(
            &["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
            &[],
        )
        .unwrap();

        assert!(access.is_whitelist_mode());
        assert_eq!(access.default_policy(), AccessPolicy::Deny);

        // Allowed IPs
        assert_eq!(
            access.check(&"10.1.2.3".parse().unwrap()),
            AccessPolicy::Allow
        );
        assert_eq!(
            access.check(&"192.168.100.1".parse().unwrap()),
            AccessPolicy::Allow
        );

        // Denied IPs
        assert_eq!(
            access.check(&"8.8.8.8".parse().unwrap()),
            AccessPolicy::Deny
        );
    }

    #[test]
    fn test_blacklist_priority() {
        // Blacklist should take priority over whitelist
        let access = IpAccessControl::from_config(
            &["192.168.0.0/16".to_string()],
            &["192.168.100.0/24".to_string()],
        )
        .unwrap();

        // IP in allowed range but not in blocked
        assert_eq!(
            access.check(&"192.168.1.1".parse().unwrap()),
            AccessPolicy::Allow
        );

        // IP in both allowed and blocked - blocked wins
        assert_eq!(
            access.check(&"192.168.100.50".parse().unwrap()),
            AccessPolicy::Deny
        );
    }

    #[test]
    fn test_single_ip_blocking() {
        let mut access = IpAccessControl::new();

        let ip: IpAddr = "10.10.10.10".parse().unwrap();
        assert_eq!(access.check(&ip), AccessPolicy::Allow);

        access.block_ip(ip);
        assert_eq!(access.check(&ip), AccessPolicy::Deny);

        // Other IPs still allowed
        assert_eq!(
            access.check(&"10.10.10.11".parse().unwrap()),
            AccessPolicy::Allow
        );

        access.unblock_ip(ip);
        assert_eq!(access.check(&ip), AccessPolicy::Allow);
    }

    #[test]
    fn test_ipv6_support() {
        let mut access = IpAccessControl::new();
        access.allow_cidr("2001:db8::/32").unwrap();

        // IPv6 in range
        let ip_in: IpAddr = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(access.check(&ip_in), AccessPolicy::Allow);

        // IPv6 outside range
        let ip_out: IpAddr = IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(access.check(&ip_out), AccessPolicy::Deny);
    }

    #[test]
    fn test_mixed_ipv4_ipv6() {
        let access = IpAccessControl::from_config(
            &["192.168.0.0/16".to_string(), "2001:db8::/32".to_string()],
            &[],
        )
        .unwrap();

        // IPv4 allowed
        assert_eq!(
            access.check(&"192.168.1.1".parse().unwrap()),
            AccessPolicy::Allow
        );

        // IPv6 allowed
        let ipv6: IpAddr = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(access.check(&ipv6), AccessPolicy::Allow);

        // IPv4 denied
        assert_eq!(
            access.check(&"10.0.0.1".parse().unwrap()),
            AccessPolicy::Deny
        );
    }

    #[test]
    fn test_invalid_cidr() {
        let result = IpAccessControl::from_config(&["not-a-cidr".to_string()], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_reload() {
        let mut access = IpAccessControl::from_config(&["10.0.0.0/8".to_string()], &[]).unwrap();

        // Initially only 10.x.x.x allowed
        assert_eq!(
            access.check(&"192.168.1.1".parse().unwrap()),
            AccessPolicy::Deny
        );

        // Reload with different config
        access
            .reload(&["192.168.0.0/16".to_string()], &[])
            .unwrap();

        // Now 192.168.x.x allowed
        assert_eq!(
            access.check(&"192.168.1.1".parse().unwrap()),
            AccessPolicy::Allow
        );

        // And 10.x.x.x denied
        assert_eq!(
            access.check(&"10.1.1.1".parse().unwrap()),
            AccessPolicy::Deny
        );
    }

    #[test]
    fn test_remove_networks() {
        let mut access = IpAccessControl::new();
        access.allow_cidr("10.0.0.0/8").unwrap();
        access.block_cidr("192.168.0.0/16").unwrap();

        assert_eq!(access.allowed_count(), 1);
        assert_eq!(access.blocked_count(), 1);

        let allowed_net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        access.remove_allowed(&allowed_net);
        assert_eq!(access.allowed_count(), 0);
        assert_eq!(access.default_policy(), AccessPolicy::Allow); // Reset when empty

        let blocked_net: IpNetwork = "192.168.0.0/16".parse().unwrap();
        access.remove_blocked(&blocked_net);
        assert_eq!(access.blocked_count(), 0);
    }

    #[test]
    fn test_localhost_allowed_by_default() {
        let access = IpAccessControl::new();

        // IPv4 localhost
        let localhost_v4: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(access.check(&localhost_v4), AccessPolicy::Allow);

        // IPv6 localhost
        let localhost_v6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(access.check(&localhost_v6), AccessPolicy::Allow);
    }

    #[test]
    fn test_empty_config() {
        let access = IpAccessControl::from_config(&[], &[]).unwrap();

        assert!(!access.is_whitelist_mode());
        assert_eq!(access.default_policy(), AccessPolicy::Allow);
        assert_eq!(access.allowed_count(), 0);
        assert_eq!(access.blocked_count(), 0);

        // All IPs allowed
        assert_eq!(
            access.check(&"8.8.8.8".parse().unwrap()),
            AccessPolicy::Allow
        );
    }

    #[test]
    fn test_get_networks() {
        let access = IpAccessControl::from_config(
            &["10.0.0.0/8".to_string()],
            &["192.168.0.0/16".to_string()],
        )
        .unwrap();

        let allowed = access.allowed_networks();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].to_string(), "10.0.0.0/8");

        let blocked = access.blocked_networks();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].to_string(), "192.168.0.0/16");
    }

    #[tokio::test]
    async fn test_shared_access_control() {
        let access = IpAccessControl::from_config(&["10.0.0.0/8".to_string()], &[]).unwrap();

        let shared = SharedIpAccessControl::new(access);

        // Check allowed
        assert_eq!(
            shared.check(&"10.1.2.3".parse().unwrap()).await,
            AccessPolicy::Allow
        );

        // Check denied
        assert_eq!(
            shared.check(&"192.168.1.1".parse().unwrap()).await,
            AccessPolicy::Deny
        );

        // Block at runtime
        let ip: IpAddr = "10.100.100.100".parse().unwrap();
        assert_eq!(shared.check(&ip).await, AccessPolicy::Allow);
        shared.block_ip(ip).await;
        assert_eq!(shared.check(&ip).await, AccessPolicy::Deny);
        shared.unblock_ip(ip).await;
        assert_eq!(shared.check(&ip).await, AccessPolicy::Allow);

        // Stats
        let (allowed, blocked, policy) = shared.stats().await;
        assert_eq!(allowed, 1);
        assert_eq!(blocked, 0);
        assert_eq!(policy, AccessPolicy::Deny);
    }
}
