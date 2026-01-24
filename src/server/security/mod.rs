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

//! Security module for bssh-server.
//!
//! This module provides security features including:
//!
//! - [`AuthRateLimiter`]: Authentication rate limiting with ban support (fail2ban-like)
//! - [`IpAccessControl`]: IP-based access control (whitelist/blacklist)
//!
//! # Authentication Rate Limiting
//!
//! The `AuthRateLimiter` tracks failed authentication attempts per IP address
//! and automatically bans IPs that exceed the configured threshold.
//!
//! ## Example
//!
//! ```
//! use bssh::server::security::{AuthRateLimiter, AuthRateLimitConfig};
//! use std::net::IpAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = AuthRateLimitConfig::default();
//!     let limiter = AuthRateLimiter::new(config);
//!
//!     let ip: IpAddr = "192.168.1.100".parse().unwrap();
//!
//!     // Check if banned before auth
//!     if limiter.is_banned(&ip).await {
//!         println!("IP is banned");
//!         return;
//!     }
//!
//!     // On auth failure
//!     if limiter.record_failure(ip).await {
//!         println!("IP has been banned after too many failures");
//!     }
//!
//!     // On auth success
//!     limiter.record_success(&ip).await;
//! }
//! ```
//!
//! # IP-based Access Control
//!
//! The `IpAccessControl` provides whitelist and blacklist functionality
//! for controlling which IP addresses can connect to the server.
//!
//! ## Example
//!
//! ```
//! use bssh::server::security::{IpAccessControl, AccessPolicy};
//!
//! let mut access = IpAccessControl::new();
//!
//! // Allow only private networks
//! access.allow_cidr("10.0.0.0/8").unwrap();
//! access.allow_cidr("192.168.0.0/16").unwrap();
//!
//! // Block a specific subnet
//! access.block_cidr("192.168.100.0/24").unwrap();
//!
//! let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
//! assert_eq!(access.check(&ip), AccessPolicy::Allow);
//! ```

mod access;
mod rate_limit;

pub use access::{AccessPolicy, IpAccessControl, SharedIpAccessControl};
pub use rate_limit::{AuthRateLimitConfig, AuthRateLimiter};
