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

//! Server configuration types.
//!
//! This module defines configuration options for the SSH server.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for the SSH server.
///
/// Contains all settings needed to initialize and run the SSH server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Paths to host key files (e.g., SSH private keys).
    #[serde(default)]
    pub host_keys: Vec<PathBuf>,

    /// Address to listen on (e.g., "0.0.0.0:2222").
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Maximum number of concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum number of authentication attempts per connection.
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,

    /// Timeout for authentication in seconds.
    #[serde(default = "default_auth_timeout_secs")]
    pub auth_timeout_secs: u64,

    /// Connection idle timeout in seconds.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Enable password authentication.
    #[serde(default)]
    pub allow_password_auth: bool,

    /// Enable public key authentication.
    #[serde(default = "default_true")]
    pub allow_publickey_auth: bool,

    /// Enable keyboard-interactive authentication.
    #[serde(default)]
    pub allow_keyboard_interactive: bool,

    /// Banner message displayed to clients before authentication.
    #[serde(default)]
    pub banner: Option<String>,
}

fn default_listen_address() -> String {
    "0.0.0.0:2222".to_string()
}

fn default_max_connections() -> usize {
    100
}

fn default_max_auth_attempts() -> u32 {
    6
}

fn default_auth_timeout_secs() -> u64 {
    120
}

fn default_idle_timeout_secs() -> u64 {
    0 // 0 means no timeout
}

fn default_true() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host_keys: Vec::new(),
            listen_address: default_listen_address(),
            max_connections: default_max_connections(),
            max_auth_attempts: default_max_auth_attempts(),
            auth_timeout_secs: default_auth_timeout_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
            allow_password_auth: false,
            allow_publickey_auth: true,
            allow_keyboard_interactive: false,
            banner: None,
        }
    }
}

impl ServerConfig {
    /// Create a new server configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing server configuration.
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }

    /// Get the authentication timeout as a Duration.
    pub fn auth_timeout(&self) -> Duration {
        Duration::from_secs(self.auth_timeout_secs)
    }

    /// Get the idle timeout as a Duration.
    ///
    /// Returns `None` if idle timeout is disabled (set to 0).
    pub fn idle_timeout(&self) -> Option<Duration> {
        if self.idle_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.idle_timeout_secs))
        }
    }

    /// Check if any host keys are configured.
    pub fn has_host_keys(&self) -> bool {
        !self.host_keys.is_empty()
    }

    /// Add a host key path.
    pub fn add_host_key(&mut self, path: impl Into<PathBuf>) {
        self.host_keys.push(path.into());
    }
}

/// Builder for constructing ServerConfig.
#[derive(Debug, Default)]
pub struct ServerConfigBuilder {
    config: ServerConfig,
}

impl ServerConfigBuilder {
    /// Set the host key paths.
    pub fn host_keys(mut self, keys: Vec<PathBuf>) -> Self {
        self.config.host_keys = keys;
        self
    }

    /// Add a host key path.
    pub fn host_key(mut self, key: impl Into<PathBuf>) -> Self {
        self.config.host_keys.push(key.into());
        self
    }

    /// Set the listen address.
    pub fn listen_address(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_address = addr.into();
        self
    }

    /// Set the maximum number of connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Set the maximum authentication attempts.
    pub fn max_auth_attempts(mut self, max: u32) -> Self {
        self.config.max_auth_attempts = max;
        self
    }

    /// Set the authentication timeout in seconds.
    pub fn auth_timeout_secs(mut self, secs: u64) -> Self {
        self.config.auth_timeout_secs = secs;
        self
    }

    /// Set the idle timeout in seconds.
    pub fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.config.idle_timeout_secs = secs;
        self
    }

    /// Enable or disable password authentication.
    pub fn allow_password_auth(mut self, allow: bool) -> Self {
        self.config.allow_password_auth = allow;
        self
    }

    /// Enable or disable public key authentication.
    pub fn allow_publickey_auth(mut self, allow: bool) -> Self {
        self.config.allow_publickey_auth = allow;
        self
    }

    /// Enable or disable keyboard-interactive authentication.
    pub fn allow_keyboard_interactive(mut self, allow: bool) -> Self {
        self.config.allow_keyboard_interactive = allow;
        self
    }

    /// Set the banner message.
    pub fn banner(mut self, banner: impl Into<String>) -> Self {
        self.config.banner = Some(banner.into());
        self
    }

    /// Build the ServerConfig.
    pub fn build(self) -> ServerConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert!(config.host_keys.is_empty());
        assert_eq!(config.listen_address, "0.0.0.0:2222");
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.max_auth_attempts, 6);
        assert!(!config.allow_password_auth);
        assert!(config.allow_publickey_auth);
    }

    #[test]
    fn test_config_builder() {
        let config = ServerConfig::builder()
            .host_key("/etc/ssh/ssh_host_ed25519_key")
            .listen_address("127.0.0.1:22")
            .max_connections(50)
            .max_auth_attempts(3)
            .allow_password_auth(true)
            .banner("Welcome to bssh server!")
            .build();

        assert_eq!(config.host_keys.len(), 1);
        assert_eq!(config.listen_address, "127.0.0.1:22");
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.max_auth_attempts, 3);
        assert!(config.allow_password_auth);
        assert_eq!(config.banner, Some("Welcome to bssh server!".to_string()));
    }

    #[test]
    fn test_auth_timeout() {
        let config = ServerConfig::default();
        assert_eq!(config.auth_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn test_idle_timeout() {
        let mut config = ServerConfig::default();
        assert!(config.idle_timeout().is_none());

        config.idle_timeout_secs = 300;
        assert_eq!(config.idle_timeout(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_has_host_keys() {
        let mut config = ServerConfig::default();
        assert!(!config.has_host_keys());

        config.add_host_key("/path/to/key");
        assert!(config.has_host_keys());
    }

    #[test]
    fn test_config_new() {
        let config = ServerConfig::new();
        assert!(config.host_keys.is_empty());
        assert_eq!(config.listen_address, "0.0.0.0:2222");
    }

    #[test]
    fn test_builder_host_keys_vec() {
        let config = ServerConfig::builder()
            .host_keys(vec!["/path/to/key1".into(), "/path/to/key2".into()])
            .build();

        assert_eq!(config.host_keys.len(), 2);
    }

    #[test]
    fn test_builder_auth_timeout() {
        let config = ServerConfig::builder().auth_timeout_secs(60).build();

        assert_eq!(config.auth_timeout_secs, 60);
        assert_eq!(config.auth_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_builder_idle_timeout() {
        let config = ServerConfig::builder().idle_timeout_secs(600).build();

        assert_eq!(config.idle_timeout_secs, 600);
        assert_eq!(config.idle_timeout(), Some(Duration::from_secs(600)));
    }
}
