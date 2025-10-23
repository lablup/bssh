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
mod include;
#[cfg(test)]
mod integration_tests;
mod match_directive;
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

    /// Load SSH configuration from a file with Include support
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read SSH config file: {}", path.display()))?;

        Self::parse_from_file_with_content(path, &content)
            .await
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

    /// Parse SSH configuration from a string (without Include support)
    pub fn parse(content: &str) -> Result<Self> {
        let hosts = parser::parse(content)?;
        Ok(Self { hosts })
    }

    /// Parse SSH configuration from a file with Include support
    pub async fn parse_from_file_with_content(path: &Path, content: &str) -> Result<Self> {
        let hosts = parser::parse_from_file(path, content).await?;
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

    #[test]
    fn test_parse_phase2_certificate_and_forwarding_options() {
        // Test parsing of Phase 2 options: certificate authentication and advanced port forwarding
        let config_content = r#"
Host *.secure.example.com
    CertificateFile ~/.ssh/id_rsa-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    GatewayPorts yes
    ExitOnForwardFailure yes
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512

Host web1.secure.example.com
    CertificateFile /etc/ssh/host-cert.pub
    PermitRemoteOpen localhost:8080 db.internal:5432
    GatewayPorts clientspecified
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 2);

        // Verify first host (*.secure.example.com)
        let host1 = &config.hosts[0];
        assert_eq!(host1.certificate_files.len(), 1);
        assert!(host1.certificate_files[0]
            .to_string_lossy()
            .contains("id_rsa-cert.pub"));
        assert_eq!(host1.ca_signature_algorithms.len(), 2);
        assert_eq!(host1.ca_signature_algorithms[0], "ssh-ed25519");
        assert_eq!(host1.ca_signature_algorithms[1], "rsa-sha2-512");
        assert_eq!(host1.gateway_ports, Some("yes".to_string()));
        assert_eq!(host1.exit_on_forward_failure, Some(true));
        assert_eq!(host1.hostbased_authentication, Some(true));
        assert_eq!(host1.hostbased_accepted_algorithms.len(), 2);

        // Verify second host (web1.secure.example.com)
        let host2 = &config.hosts[1];
        assert_eq!(host2.certificate_files.len(), 1);
        assert!(host2.certificate_files[0]
            .to_string_lossy()
            .contains("host-cert.pub"));
        assert_eq!(host2.permit_remote_open.len(), 2);
        assert_eq!(host2.permit_remote_open[0], "localhost:8080");
        assert_eq!(host2.permit_remote_open[1], "db.internal:5432");
        assert_eq!(host2.gateway_ports, Some("clientspecified".to_string()));
    }

    #[test]
    fn test_merge_phase2_options() {
        // Test that Phase 2 options are properly merged according to SSH config precedence
        let config_content = r#"
Host *.example.com
    CertificateFile ~/.ssh/default-cert.pub
    CASignatureAlgorithms ssh-ed25519
    GatewayPorts no
    HostbasedAuthentication no

Host web*.example.com
    CertificateFile ~/.ssh/web-cert.pub
    GatewayPorts yes
    PermitRemoteOpen localhost:8080

Host web1.example.com
    CASignatureAlgorithms rsa-sha2-512,rsa-sha2-256
    ExitOnForwardFailure yes
"#;

        let config = SshConfig::parse(config_content).unwrap();

        // Test merging for web1.example.com (should get configs from all three blocks)
        let host_config = config.find_host_config("web1.example.com");

        // Should have certificate files from both *.example.com and web*.example.com (appended)
        assert_eq!(host_config.certificate_files.len(), 2);

        // CASignatureAlgorithms should be from web1.example.com (most specific)
        assert_eq!(host_config.ca_signature_algorithms.len(), 2);
        assert_eq!(host_config.ca_signature_algorithms[0], "rsa-sha2-512");
        assert_eq!(host_config.ca_signature_algorithms[1], "rsa-sha2-256");

        // GatewayPorts should be from web*.example.com
        assert_eq!(host_config.gateway_ports, Some("yes".to_string()));

        // ExitOnForwardFailure should be from web1.example.com
        assert_eq!(host_config.exit_on_forward_failure, Some(true));

        // PermitRemoteOpen should be from web*.example.com
        assert_eq!(host_config.permit_remote_open.len(), 1);
        assert_eq!(host_config.permit_remote_open[0], "localhost:8080");

        // HostbasedAuthentication should be from *.example.com
        assert_eq!(host_config.hostbased_authentication, Some(false));
    }
}
