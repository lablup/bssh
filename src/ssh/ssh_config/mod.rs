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

//! SSH configuration parsing and management
//!
//! This module provides functionality to parse SSH configuration files, resolve host-specific
//! configurations, and provide a clean API for SSH connection setup.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// Internal modules
mod env_cache;
#[cfg(test)]
mod integration_tests;
mod parser;
mod path;
mod pattern;
mod resolver;
mod security;
mod types;

// Re-export public types
pub use types::SshHostConfig;

/// SSH configuration parser and resolver
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    pub hosts: Vec<SshHostConfig>,
}

impl SshConfig {
    /// Create a new empty SSH configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Load SSH configuration from a file
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read SSH config file: {}", path.display()))?;

        Self::parse(&content)
            .with_context(|| format!("Failed to parse SSH config file: {}", path.display()))
    }

    /// Load SSH configuration from a file with caching
    /// Uses the global cache to improve performance for repeated access
    pub async fn load_from_file_cached<P: AsRef<Path>>(path: P) -> Result<Self> {
        crate::ssh::GLOBAL_CACHE.get_or_load(path).await
    }

    /// Load SSH configuration from the default locations
    pub async fn load_default() -> Result<Self> {
        // Try user-specific SSH config first
        if let Some(home_dir) = dirs::home_dir() {
            let user_config = home_dir.join(".ssh").join("config");
            if tokio::fs::try_exists(&user_config).await.unwrap_or(false) {
                return Self::load_from_file(&user_config).await;
            }
        }

        // Try system-wide SSH config
        let system_config = Path::new("/etc/ssh/ssh_config");
        if tokio::fs::try_exists(system_config).await.unwrap_or(false) {
            return Self::load_from_file(system_config).await;
        }

        // Return empty config if no files found
        Ok(Self::new())
    }

    /// Load SSH configuration from the default locations with caching
    /// Uses the global cache to improve performance for repeated access
    pub async fn load_default_cached() -> Result<Self> {
        crate::ssh::GLOBAL_CACHE.load_default().await
    }

    /// Parse SSH configuration from a string
    pub fn parse(content: &str) -> Result<Self> {
        let hosts = parser::parse(content)?;
        Ok(Self { hosts })
    }

    /// Find configuration for a specific hostname
    pub fn find_host_config(&self, hostname: &str) -> SshHostConfig {
        resolver::find_host_config(&self.hosts, hostname)
    }

    /// Get the effective hostname (resolves HostName directive)
    pub fn get_effective_hostname(&self, hostname: &str) -> String {
        resolver::get_effective_hostname(&self.hosts, hostname)
    }

    /// Get the effective username
    pub fn get_effective_user(&self, hostname: &str, cli_user: Option<&str>) -> Option<String> {
        resolver::get_effective_user(&self.hosts, hostname, cli_user)
    }

    /// Get the effective port
    pub fn get_effective_port(&self, hostname: &str, cli_port: Option<u16>) -> u16 {
        resolver::get_effective_port(&self.hosts, hostname, cli_port)
    }

    /// Get identity files for a hostname
    pub fn get_identity_files(&self, hostname: &str) -> Vec<PathBuf> {
        resolver::get_identity_files(&self.hosts, hostname)
    }

    /// Get the effective StrictHostKeyChecking value
    pub fn get_strict_host_key_checking(&self, hostname: &str) -> Option<String> {
        resolver::get_strict_host_key_checking(&self.hosts, hostname)
    }

    /// Get ProxyJump configuration
    pub fn get_proxy_jump(&self, hostname: &str) -> Option<String> {
        resolver::get_proxy_jump(&self.hosts, hostname)
    }

    /// Get all host configurations (for debugging)
    pub fn get_all_configs(&self) -> &[SshHostConfig] {
        &self.hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_basic_host_config() {
        let config_content = r#"
Host example.com
    User testuser
    Port 2222
    IdentityFile ~/.ssh/test_key
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 1);

        let host = &config.hosts[0];
        assert_eq!(host.host_patterns, vec!["example.com"]);
        assert_eq!(host.user, Some("testuser".to_string()));
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.identity_files.len(), 1);
    }

    #[test]
    fn test_parse_multiple_hosts() {
        let config_content = r#"
Host web*.example.com
    User webuser
    Port 22

Host db*.example.com
    User dbuser
    Port 5432
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 2);

        let web_host = &config.hosts[0];
        assert_eq!(web_host.host_patterns, vec!["web*.example.com"]);
        assert_eq!(web_host.user, Some("webuser".to_string()));
        assert_eq!(web_host.port, Some(22));

        let db_host = &config.hosts[1];
        assert_eq!(db_host.host_patterns, vec!["db*.example.com"]);
        assert_eq!(db_host.user, Some("dbuser".to_string()));
        assert_eq!(db_host.port, Some(5432));
    }

    #[test]
    fn test_find_host_config() {
        let config_content = r#"
Host *.example.com
    User defaultuser
    Port 22

Host web*.example.com
    User webuser
    Port 8080

Host web1.example.com
    Port 9090
"#;

        let config = SshConfig::parse(config_content).unwrap();

        // Test that most specific match wins
        let host_config = config.find_host_config("web1.example.com");
        assert_eq!(host_config.user, Some("webuser".to_string())); // From web*.example.com
        assert_eq!(host_config.port, Some(9090)); // From web1.example.com (most specific)

        // Test that patterns are applied in order
        let host_config = config.find_host_config("web2.example.com");
        assert_eq!(host_config.user, Some("webuser".to_string())); // From web*.example.com
        assert_eq!(host_config.port, Some(8080)); // From web*.example.com

        let host_config = config.find_host_config("db1.example.com");
        assert_eq!(host_config.user, Some("defaultuser".to_string())); // From *.example.com
        assert_eq!(host_config.port, Some(22)); // From *.example.com
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("ssh_config");

        let config_content = r#"
Host test.example.com
    User testuser
    Port 2222
"#;

        std::fs::write(&config_file, config_content).unwrap();

        let config = tokio_test::block_on(SshConfig::load_from_file(&config_file)).unwrap();
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.hosts[0].host_patterns, vec!["test.example.com"]);
        assert_eq!(config.hosts[0].user, Some("testuser".to_string()));
        assert_eq!(config.hosts[0].port, Some(2222));
    }
}
