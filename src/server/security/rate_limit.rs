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

//! Authentication rate limiter with ban support.
//!
//! This module provides fail2ban-like functionality for protecting the SSH server
//! against brute-force attacks. It tracks failed authentication attempts per IP
//! and automatically bans IPs that exceed the configured threshold.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for authentication rate limiting.
///
/// This struct defines the parameters for the fail2ban-like functionality:
/// - `max_attempts`: Maximum failed attempts before ban
/// - `window`: Time window for counting attempts
/// - `ban_duration`: How long to ban an IP
/// - `whitelist`: IPs that are never banned
#[derive(Debug, Clone)]
pub struct AuthRateLimitConfig {
    /// Maximum failed attempts before ban.
    pub max_attempts: u32,
    /// Time window for counting attempts.
    pub window: Duration,
    /// Ban duration after exceeding max attempts.
    pub ban_duration: Duration,
    /// Whitelist IPs (never banned).
    pub whitelist: Vec<IpAddr>,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window: Duration::from_secs(300),      // 5 minutes
            ban_duration: Duration::from_secs(300), // 5 minutes
            whitelist: vec![],
        }
    }
}

impl AuthRateLimitConfig {
    /// Create a new configuration with specified parameters.
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - Maximum failed attempts before ban
    /// * `window_secs` - Time window in seconds for counting attempts
    /// * `ban_duration_secs` - Ban duration in seconds
    pub fn new(max_attempts: u32, window_secs: u64, ban_duration_secs: u64) -> Self {
        Self {
            max_attempts,
            window: Duration::from_secs(window_secs),
            ban_duration: Duration::from_secs(ban_duration_secs),
            whitelist: vec![],
        }
    }

    /// Add an IP to the whitelist.
    pub fn add_whitelist(&mut self, ip: IpAddr) {
        if !self.whitelist.contains(&ip) {
            self.whitelist.push(ip);
        }
    }

    /// Set the whitelist from a list of IPs.
    pub fn with_whitelist(mut self, whitelist: Vec<IpAddr>) -> Self {
        self.whitelist = whitelist;
        self
    }
}

/// Record of failed authentication attempts for an IP.
#[derive(Debug)]
struct FailureRecord {
    /// Number of failed attempts.
    count: u32,
    /// Timestamp of the first failure in the current window.
    first_failure: Instant,
    /// Timestamp of the most recent failure.
    last_failure: Instant,
}

/// Authentication rate limiter with ban support.
///
/// This struct provides fail2ban-like functionality for the SSH server.
/// It tracks failed authentication attempts per IP address and automatically
/// bans IPs that exceed the configured maximum attempts within the time window.
///
/// # Features
///
/// - **Failure tracking**: Counts failed authentication attempts per IP
/// - **Automatic banning**: Bans IPs that exceed the threshold
/// - **Time-based window**: Failures outside the window are not counted
/// - **Configurable ban duration**: Bans expire after the configured time
/// - **IP whitelist**: Whitelisted IPs are never banned
/// - **Automatic cleanup**: Expired records are cleaned up periodically
///
/// # Thread Safety
///
/// The rate limiter is thread-safe and can be shared across async tasks.
#[derive(Debug)]
pub struct AuthRateLimiter {
    /// Failed attempt records per IP.
    failures: Arc<RwLock<HashMap<IpAddr, FailureRecord>>>,
    /// Banned IPs with expiration time.
    bans: Arc<RwLock<HashMap<IpAddr, Instant>>>,
    /// Configuration.
    config: AuthRateLimitConfig,
}

impl AuthRateLimiter {
    /// Create a new authentication rate limiter with the given configuration.
    pub fn new(config: AuthRateLimitConfig) -> Self {
        Self {
            failures: Arc::new(RwLock::new(HashMap::new())),
            bans: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if an IP address is currently banned.
    ///
    /// Returns `true` if the IP is banned and the ban has not expired.
    /// Whitelisted IPs always return `false`.
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        // Whitelisted IPs are never banned
        if self.config.whitelist.contains(ip) {
            return false;
        }

        let bans = self.bans.read().await;
        if let Some(expiry) = bans.get(ip) {
            if Instant::now() < *expiry {
                return true;
            }
        }
        false
    }

    /// Record a failed authentication attempt.
    ///
    /// Increments the failure count for the IP. If the IP exceeds the maximum
    /// allowed attempts within the time window, it will be banned.
    ///
    /// # Returns
    ///
    /// Returns `true` if the IP was banned as a result of this failure,
    /// `false` otherwise.
    pub async fn record_failure(&self, ip: IpAddr) -> bool {
        // Skip whitelisted IPs
        if self.config.whitelist.contains(&ip) {
            return false;
        }

        let mut failures = self.failures.write().await;
        let now = Instant::now();

        let record = failures.entry(ip).or_insert_with(|| FailureRecord {
            count: 0,
            first_failure: now,
            last_failure: now,
        });

        // Reset if window expired
        if now.duration_since(record.first_failure) > self.config.window {
            record.count = 1;
            record.first_failure = now;
        } else {
            record.count += 1;
        }
        record.last_failure = now;

        // Check if should ban
        if record.count >= self.config.max_attempts {
            drop(failures); // Release lock before acquiring ban lock
            self.ban(ip).await;
            return true;
        }

        false
    }

    /// Record a successful authentication.
    ///
    /// Clears the failure record for the IP, allowing a fresh start.
    pub async fn record_success(&self, ip: &IpAddr) {
        let mut failures = self.failures.write().await;
        failures.remove(ip);
    }

    /// Ban an IP address.
    ///
    /// The IP will be banned for the configured ban duration.
    /// Also clears the failure record for the IP.
    pub async fn ban(&self, ip: IpAddr) {
        tracing::warn!(
            ip = %ip,
            duration_secs = self.config.ban_duration.as_secs(),
            "Banning IP due to too many failed auth attempts"
        );

        let mut bans = self.bans.write().await;
        let expiry = Instant::now() + self.config.ban_duration;
        bans.insert(ip, expiry);

        // Clean up failure record
        drop(bans);
        let mut failures = self.failures.write().await;
        failures.remove(&ip);
    }

    /// Manually unban an IP address.
    pub async fn unban(&self, ip: &IpAddr) {
        let mut bans = self.bans.write().await;
        if bans.remove(ip).is_some() {
            tracing::info!(ip = %ip, "Manually unbanned IP");
        }
    }

    /// Get the remaining attempts before ban for an IP.
    ///
    /// Returns the maximum attempts if the IP has no failure record.
    pub async fn remaining_attempts(&self, ip: &IpAddr) -> u32 {
        let failures = self.failures.read().await;
        if let Some(record) = failures.get(ip) {
            let now = Instant::now();
            // If window expired, return max attempts
            if now.duration_since(record.first_failure) > self.config.window {
                return self.config.max_attempts;
            }
            self.config.max_attempts.saturating_sub(record.count)
        } else {
            self.config.max_attempts
        }
    }

    /// Clean up expired records.
    ///
    /// This should be called periodically to prevent unbounded memory growth.
    /// It removes:
    /// - Expired bans
    /// - Failure records outside the time window
    pub async fn cleanup(&self) {
        let now = Instant::now();

        // Clean expired bans
        {
            let mut bans = self.bans.write().await;
            let before = bans.len();
            bans.retain(|_, expiry| now < *expiry);
            let after = bans.len();
            if before > after {
                tracing::debug!(
                    removed = before - after,
                    remaining = after,
                    "Cleaned up expired bans"
                );
            }
        }

        // Clean old failure records
        {
            let mut failures = self.failures.write().await;
            let before = failures.len();
            failures.retain(|_, record| {
                now.duration_since(record.last_failure) < self.config.window
            });
            let after = failures.len();
            if before > after {
                tracing::debug!(
                    removed = before - after,
                    remaining = after,
                    "Cleaned up expired failure records"
                );
            }
        }
    }

    /// Get the current list of banned IPs with remaining ban duration.
    pub async fn get_bans(&self) -> Vec<(IpAddr, Duration)> {
        let now = Instant::now();
        let bans = self.bans.read().await;
        bans.iter()
            .filter_map(|(ip, expiry)| {
                if now < *expiry {
                    Some((*ip, *expiry - now))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get the number of currently banned IPs.
    pub async fn banned_count(&self) -> usize {
        let now = Instant::now();
        let bans = self.bans.read().await;
        bans.values().filter(|expiry| now < **expiry).count()
    }

    /// Get the number of IPs with failure records.
    pub async fn tracked_count(&self) -> usize {
        self.failures.read().await.len()
    }

    /// Get the configuration.
    pub fn config(&self) -> &AuthRateLimitConfig {
        &self.config
    }

    /// Check if an IP is whitelisted.
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.config.whitelist.contains(ip)
    }
}

impl Clone for AuthRateLimiter {
    fn clone(&self) -> Self {
        Self {
            failures: Arc::clone(&self.failures),
            bans: Arc::clone(&self.bans),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    fn test_ip2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[tokio::test]
    async fn test_failure_counting() {
        let config = AuthRateLimitConfig::new(5, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // Record failures without triggering ban
        for i in 1..5 {
            let banned = limiter.record_failure(ip).await;
            assert!(!banned, "Should not be banned after {i} failures");
            assert_eq!(
                limiter.remaining_attempts(&ip).await,
                5 - i,
                "Should have {} remaining attempts",
                5 - i
            );
        }
    }

    #[tokio::test]
    async fn test_ban_after_max_attempts() {
        let config = AuthRateLimitConfig::new(3, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // First two failures
        assert!(!limiter.record_failure(ip).await);
        assert!(!limiter.record_failure(ip).await);
        assert!(!limiter.is_banned(&ip).await);

        // Third failure should trigger ban
        assert!(limiter.record_failure(ip).await);
        assert!(limiter.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_ban_expiration() {
        let config = AuthRateLimitConfig::new(2, 300, 0); // 0 second ban
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // Trigger ban
        limiter.record_failure(ip).await;
        assert!(limiter.record_failure(ip).await);

        // Ban should have expired immediately (or very quickly)
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!limiter.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_whitelist_ips() {
        let config = AuthRateLimitConfig::new(1, 300, 300)
            .with_whitelist(vec![localhost()]);
        let limiter = AuthRateLimiter::new(config);

        let whitelisted = localhost();
        let not_whitelisted = test_ip();

        // Whitelisted IP should never be banned
        assert!(!limiter.record_failure(whitelisted).await);
        assert!(!limiter.is_banned(&whitelisted).await);

        // Non-whitelisted should be banned after 1 failure
        assert!(limiter.record_failure(not_whitelisted).await);
        assert!(limiter.is_banned(&not_whitelisted).await);

        assert!(limiter.is_whitelisted(&whitelisted));
        assert!(!limiter.is_whitelisted(&not_whitelisted));
    }

    #[tokio::test]
    async fn test_success_resets_failures() {
        let config = AuthRateLimitConfig::new(3, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // Record 2 failures
        limiter.record_failure(ip).await;
        limiter.record_failure(ip).await;
        assert_eq!(limiter.remaining_attempts(&ip).await, 1);

        // Successful auth resets failures
        limiter.record_success(&ip).await;
        assert_eq!(limiter.remaining_attempts(&ip).await, 3);

        // Should need 3 more failures to ban
        limiter.record_failure(ip).await;
        limiter.record_failure(ip).await;
        assert!(!limiter.is_banned(&ip).await);
        limiter.record_failure(ip).await;
        assert!(limiter.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_window_expiration() {
        // Use a very short window for testing
        let config = AuthRateLimitConfig {
            max_attempts: 3,
            window: Duration::from_millis(50),
            ban_duration: Duration::from_secs(300),
            whitelist: vec![],
        };
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // Record 2 failures
        limiter.record_failure(ip).await;
        limiter.record_failure(ip).await;
        assert_eq!(limiter.remaining_attempts(&ip).await, 1);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Window expired, should have full attempts again
        assert_eq!(limiter.remaining_attempts(&ip).await, 3);

        // New failure should start fresh count
        assert!(!limiter.record_failure(ip).await);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let config = AuthRateLimitConfig {
            max_attempts: 2,
            window: Duration::from_millis(10),
            ban_duration: Duration::from_millis(10),
            whitelist: vec![],
        };
        let limiter = AuthRateLimiter::new(config);

        let ip1 = test_ip();
        let ip2 = test_ip2();

        // Create some records
        limiter.record_failure(ip1).await;
        limiter.record_failure(ip2).await;
        limiter.record_failure(ip2).await; // This triggers ban

        assert_eq!(limiter.tracked_count().await, 1); // ip1 still tracked
        assert_eq!(limiter.banned_count().await, 1);  // ip2 banned

        // Wait for records to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cleanup
        limiter.cleanup().await;

        assert_eq!(limiter.tracked_count().await, 0);
        assert_eq!(limiter.banned_count().await, 0);
    }

    #[tokio::test]
    async fn test_manual_ban_unban() {
        let config = AuthRateLimitConfig::new(5, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip = test_ip();

        // Manual ban
        limiter.ban(ip).await;
        assert!(limiter.is_banned(&ip).await);

        // Manual unban
        limiter.unban(&ip).await;
        assert!(!limiter.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_get_bans() {
        let config = AuthRateLimitConfig::new(1, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip1 = test_ip();
        let ip2 = test_ip2();

        // Ban two IPs
        limiter.record_failure(ip1).await;
        limiter.record_failure(ip2).await;

        let bans = limiter.get_bans().await;
        assert_eq!(bans.len(), 2);

        // Check that both IPs are in the list
        let ips: Vec<IpAddr> = bans.iter().map(|(ip, _)| *ip).collect();
        assert!(ips.contains(&ip1));
        assert!(ips.contains(&ip2));

        // Check that remaining durations are positive
        for (_, duration) in &bans {
            assert!(duration.as_secs() > 0);
        }
    }

    #[tokio::test]
    async fn test_clone_shares_state() {
        let config = AuthRateLimitConfig::new(3, 300, 300);
        let limiter1 = AuthRateLimiter::new(config);
        let limiter2 = limiter1.clone();

        let ip = test_ip();

        // Record failures on limiter1
        limiter1.record_failure(ip).await;
        limiter1.record_failure(ip).await;

        // limiter2 should see the same state
        assert_eq!(limiter2.remaining_attempts(&ip).await, 1);

        // Ban via limiter2
        limiter2.record_failure(ip).await;

        // limiter1 should see the ban
        assert!(limiter1.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_per_ip_isolation() {
        let config = AuthRateLimitConfig::new(2, 300, 300);
        let limiter = AuthRateLimiter::new(config);

        let ip1 = test_ip();
        let ip2 = test_ip2();

        // Record failure for ip1
        limiter.record_failure(ip1).await;

        // ip2 should be unaffected
        assert_eq!(limiter.remaining_attempts(&ip2).await, 2);
        assert!(!limiter.is_banned(&ip2).await);

        // Ban ip1
        limiter.record_failure(ip1).await;
        assert!(limiter.is_banned(&ip1).await);

        // ip2 still unaffected
        assert!(!limiter.is_banned(&ip2).await);
    }

    #[tokio::test]
    async fn test_config_accessors() {
        let config = AuthRateLimitConfig::new(10, 600, 1800);
        let limiter = AuthRateLimiter::new(config);

        assert_eq!(limiter.config().max_attempts, 10);
        assert_eq!(limiter.config().window.as_secs(), 600);
        assert_eq!(limiter.config().ban_duration.as_secs(), 1800);
    }
}
