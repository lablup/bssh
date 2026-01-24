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

//! Configuration types for bssh-server.
//!
//! This module defines the complete configuration schema for YAML file-based
//! server configuration. All types support serde serialization/deserialization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main server configuration loaded from YAML files.
///
/// This is the root configuration structure that encompasses all server settings.
/// It supports hierarchical configuration from multiple sources:
/// - YAML configuration files
/// - Environment variables
/// - CLI arguments
///
/// # Example YAML
///
/// ```yaml
/// server:
///   bind_address: "0.0.0.0"
///   port: 2222
///   host_keys:
///     - /etc/bssh/ssh_host_ed25519_key
///   max_connections: 100
///
/// auth:
///   methods:
///     - publickey
///   publickey:
///     authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct ServerFileConfig {
    /// Server network and connection settings.
    pub server: ServerSettings,

    /// Authentication configuration.
    pub auth: AuthConfig,

    /// Shell execution configuration.
    pub shell: ShellConfig,

    /// SFTP subsystem configuration.
    pub sftp: SftpConfig,

    /// SCP protocol configuration.
    pub scp: ScpConfig,

    /// File transfer filtering rules.
    pub filter: FilterConfig,

    /// Audit logging configuration.
    pub audit: AuditConfig,

    /// Security and access control settings.
    pub security: SecurityConfig,
}

/// Server network and connection settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerSettings {
    /// Address to bind to (e.g., "0.0.0.0" or "127.0.0.1").
    ///
    /// Default: "0.0.0.0"
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Port to listen on.
    ///
    /// Default: 2222 (to avoid conflicts with system SSH on port 22)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Paths to SSH host private key files.
    ///
    /// At least one host key must be configured. Supports multiple key types:
    /// - Ed25519 (recommended)
    /// - RSA
    /// - ECDSA
    #[serde(default)]
    pub host_keys: Vec<PathBuf>,

    /// Maximum number of concurrent connections.
    ///
    /// Default: 100
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Connection timeout in seconds.
    ///
    /// Connections idle for longer than this will be closed.
    /// Set to 0 to disable timeout.
    ///
    /// Default: 300 (5 minutes)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// SSH keepalive interval in seconds.
    ///
    /// Send keepalive messages at this interval to detect broken connections.
    /// Set to 0 to disable keepalives.
    ///
    /// Default: 60 (1 minute)
    #[serde(default = "default_keepalive")]
    pub keepalive_interval: u64,
}

/// Authentication configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    /// List of enabled authentication methods.
    ///
    /// Default: ["publickey"]
    #[serde(default = "default_auth_methods")]
    pub methods: Vec<AuthMethod>,

    /// Public key authentication settings.
    #[serde(default)]
    pub publickey: PublicKeyAuthSettings,

    /// Password authentication settings.
    #[serde(default)]
    pub password: PasswordAuthSettings,
}

/// Authentication method types.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Public key authentication (recommended).
    PublicKey,

    /// Password authentication.
    Password,
}

/// Public key authentication settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PublicKeyAuthSettings {
    /// Directory containing per-user authorized_keys files.
    ///
    /// Structure: `{dir}/{username}/authorized_keys`
    ///
    /// Example: `/etc/bssh/authorized_keys`
    /// would look for `/etc/bssh/alice/authorized_keys` for user "alice"
    pub authorized_keys_dir: Option<PathBuf>,

    /// Pattern for authorized_keys file path.
    ///
    /// Supports `{user}` placeholder which will be replaced with username.
    ///
    /// Example: `/home/{user}/.ssh/authorized_keys`
    pub authorized_keys_pattern: Option<String>,
}

/// Password authentication settings.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PasswordAuthSettings {
    /// Path to YAML file containing user definitions.
    ///
    /// The file should contain a list of UserDefinition entries.
    pub users_file: Option<PathBuf>,

    /// Inline user definitions.
    ///
    /// Users can be defined directly in the configuration file.
    #[serde(default)]
    pub users: Vec<UserDefinition>,
}

/// User definition for password authentication.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserDefinition {
    /// Username.
    pub name: String,

    /// Password hash (bcrypt or similar).
    ///
    /// Generate with: `openssl passwd -6`
    pub password_hash: String,

    /// Override shell for this user.
    #[serde(default)]
    pub shell: Option<PathBuf>,

    /// Override home directory for this user.
    #[serde(default)]
    pub home: Option<PathBuf>,

    /// Additional environment variables for this user.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Shell execution configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ShellConfig {
    /// Default shell for command execution.
    ///
    /// Default: "/bin/sh"
    #[serde(default = "default_shell")]
    pub default: PathBuf,

    /// Global environment variables to set for all sessions.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Command execution timeout in seconds.
    ///
    /// Commands running longer than this will be terminated.
    /// Set to 0 for no timeout.
    ///
    /// Default: 3600 (1 hour)
    #[serde(default = "default_command_timeout")]
    pub command_timeout: u64,
}

/// SFTP subsystem configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SftpConfig {
    /// Enable SFTP subsystem.
    ///
    /// Default: true
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Root directory for SFTP operations.
    ///
    /// If set, SFTP clients will be chrooted to this directory.
    /// If None, users have access to the entire filesystem (subject to permissions).
    pub root: Option<PathBuf>,
}

/// SCP protocol configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ScpConfig {
    /// Enable SCP protocol support.
    ///
    /// Default: true
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// File transfer filtering configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct FilterConfig {
    /// Enable file transfer filtering.
    ///
    /// Default: false
    #[serde(default)]
    pub enabled: bool,

    /// Default action when no rules match.
    ///
    /// Default: allow
    #[serde(default)]
    pub default_action: Option<FilterAction>,

    /// Filter rules to apply.
    ///
    /// Rules are evaluated in order. First matching rule determines action.
    #[serde(default)]
    pub rules: Vec<FilterRule>,
}

/// A single file transfer filter rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterRule {
    /// Rule name (for logging and debugging).
    ///
    /// Example: "block-keys"
    #[serde(default)]
    pub name: Option<String>,

    /// Glob pattern to match against file paths.
    ///
    /// Example: "*.exe" matches all executable files
    #[serde(default)]
    pub pattern: Option<String>,

    /// Path prefix to match.
    ///
    /// Example: "/tmp/" matches all files in /tmp
    #[serde(default)]
    pub path_prefix: Option<String>,

    /// Action to take when rule matches.
    pub action: FilterAction,

    /// Operations this rule applies to.
    ///
    /// If not specified, the rule applies to all operations.
    /// Valid values: upload, download, delete, rename, createdir, listdir
    #[serde(default)]
    pub operations: Option<Vec<String>>,

    /// Users this rule applies to.
    ///
    /// If not specified, the rule applies to all users.
    #[serde(default)]
    pub users: Option<Vec<String>>,
}

/// Action to take when a filter rule matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    /// Allow the file transfer.
    #[default]
    Allow,

    /// Deny the file transfer.
    Deny,

    /// Log the file transfer but allow it.
    Log,
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging.
    ///
    /// Default: false
    #[serde(default)]
    pub enabled: bool,

    /// Audit log exporters.
    ///
    /// Multiple exporters can be configured to send logs to different destinations.
    #[serde(default)]
    pub exporters: Vec<AuditExporterConfig>,
}

/// Audit log exporter configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum AuditExporterConfig {
    /// Export audit logs to a file.
    #[serde(rename = "file")]
    File {
        /// Path to the audit log file.
        path: PathBuf,
    },

    /// Export audit logs to OpenTelemetry.
    #[serde(rename = "otel")]
    Otel {
        /// OpenTelemetry collector endpoint.
        endpoint: String,
    },

    /// Export audit logs to Logstash.
    #[serde(rename = "logstash")]
    Logstash {
        /// Logstash host.
        host: String,
        /// Logstash port.
        port: u16,
    },
}

/// Security and access control configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Maximum authentication attempts before banning IP.
    ///
    /// Default: 5
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,

    /// Time window in seconds for counting authentication attempts.
    ///
    /// Failed attempts outside this window are not counted toward the ban threshold.
    ///
    /// Default: 300 (5 minutes)
    #[serde(default = "default_auth_window")]
    pub auth_window: u64,

    /// Ban duration in seconds after exceeding max auth attempts.
    ///
    /// Default: 300 (5 minutes)
    #[serde(default = "default_ban_time")]
    pub ban_time: u64,

    /// IP addresses that are never banned (whitelist).
    ///
    /// These IPs are exempt from rate limiting and banning.
    ///
    /// Example: ["127.0.0.1", "::1"]
    #[serde(default)]
    pub whitelist_ips: Vec<String>,

    /// Maximum number of concurrent sessions per user.
    ///
    /// Default: 10
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,

    /// Idle session timeout in seconds.
    ///
    /// Sessions idle for longer than this will be terminated.
    /// Set to 0 to disable.
    ///
    /// Default: 3600 (1 hour)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,

    /// Maximum session duration in seconds (optional).
    ///
    /// If set, sessions are terminated after this duration regardless of activity.
    /// Set to 0 to disable.
    ///
    /// Default: 0 (disabled)
    #[serde(default)]
    pub session_timeout: u64,

    /// Allowed IP ranges in CIDR notation.
    ///
    /// If non-empty, only connections from these ranges are allowed.
    /// Empty list means all IPs are allowed (subject to blocked_ips).
    ///
    /// Example: ["192.168.1.0/24", "10.0.0.0/8"]
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Blocked IP ranges in CIDR notation.
    ///
    /// Connections from these ranges are always denied.
    ///
    /// Example: ["203.0.113.0/24"]
    #[serde(default)]
    pub blocked_ips: Vec<String>,
}

// Default value functions

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    2222
}

fn default_max_connections() -> usize {
    100
}

fn default_timeout() -> u64 {
    300
}

fn default_keepalive() -> u64 {
    60
}

fn default_auth_methods() -> Vec<AuthMethod> {
    vec![AuthMethod::PublicKey]
}

fn default_shell() -> PathBuf {
    PathBuf::from("/bin/sh")
}

fn default_command_timeout() -> u64 {
    3600
}

fn default_true() -> bool {
    true
}

fn default_max_auth_attempts() -> u32 {
    5
}

fn default_auth_window() -> u64 {
    300
}

fn default_ban_time() -> u64 {
    300
}

fn default_max_sessions_per_user() -> usize {
    10
}

fn default_idle_timeout() -> u64 {
    3600
}

// Default implementations

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_port(),
            host_keys: Vec::new(),
            max_connections: default_max_connections(),
            timeout: default_timeout(),
            keepalive_interval: default_keepalive(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            methods: default_auth_methods(),
            publickey: PublicKeyAuthSettings::default(),
            password: PasswordAuthSettings::default(),
        }
    }
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            default: default_shell(),
            env: HashMap::new(),
            command_timeout: default_command_timeout(),
        }
    }
}

impl Default for SftpConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            root: None,
        }
    }
}

impl Default for ScpConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_auth_attempts: default_max_auth_attempts(),
            auth_window: default_auth_window(),
            ban_time: default_ban_time(),
            whitelist_ips: Vec::new(),
            max_sessions_per_user: default_max_sessions_per_user(),
            idle_timeout: default_idle_timeout(),
            session_timeout: 0,
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerFileConfig::default();
        assert_eq!(config.server.bind_address, "0.0.0.0");
        assert_eq!(config.server.port, 2222);
        assert_eq!(config.server.max_connections, 100);
        assert!(config.sftp.enabled);
        assert!(config.scp.enabled);
        assert!(!config.filter.enabled);
        assert!(!config.audit.enabled);
    }

    #[test]
    fn test_auth_method_serialization() {
        let yaml = "publickey";
        let method: AuthMethod = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(method, AuthMethod::PublicKey);

        let yaml = "password";
        let method: AuthMethod = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(method, AuthMethod::Password);
    }

    #[test]
    fn test_filter_action_serialization() {
        let yaml = "allow";
        let action: FilterAction = serde_yaml::from_str(yaml).unwrap();
        matches!(action, FilterAction::Allow);

        let yaml = "deny";
        let action: FilterAction = serde_yaml::from_str(yaml).unwrap();
        matches!(action, FilterAction::Deny);

        let yaml = "log";
        let action: FilterAction = serde_yaml::from_str(yaml).unwrap();
        matches!(action, FilterAction::Log);
    }

    #[test]
    fn test_yaml_parsing_minimal() {
        let yaml = r#"
server:
  port: 2222
  host_keys:
    - /etc/bssh/host_key
"#;
        let config: ServerFileConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.port, 2222);
        assert_eq!(config.server.host_keys.len(), 1);
    }

    #[test]
    fn test_yaml_parsing_comprehensive() {
        let yaml = r#"
server:
  bind_address: "127.0.0.1"
  port: 2223
  host_keys:
    - /etc/bssh/ssh_host_ed25519_key
    - /etc/bssh/ssh_host_rsa_key
  max_connections: 50
  timeout: 600
  keepalive_interval: 30

auth:
  methods:
    - publickey
    - password
  publickey:
    authorized_keys_pattern: "/home/{user}/.ssh/authorized_keys"
  password:
    users:
      - name: testuser
        password_hash: "$6$rounds=656000$..."
        shell: /bin/bash

shell:
  default: /bin/bash
  command_timeout: 7200
  env:
    LANG: en_US.UTF-8

security:
  max_auth_attempts: 3
  ban_time: 600
  allowed_ips:
    - "192.168.1.0/24"
"#;
        let config: ServerFileConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.port, 2223);
        assert_eq!(config.server.host_keys.len(), 2);
        assert_eq!(config.auth.methods.len(), 2);
        assert_eq!(config.shell.default, PathBuf::from("/bin/bash"));
        assert_eq!(config.security.max_auth_attempts, 3);
        assert_eq!(config.security.allowed_ips.len(), 1);
    }
}
