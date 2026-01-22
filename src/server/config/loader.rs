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

//! Configuration loader for bssh-server.
//!
//! This module handles loading configuration from multiple sources with
//! the following precedence (highest to lowest):
//! 1. CLI arguments
//! 2. Environment variables
//! 3. Configuration file (YAML)
//! 4. Default values

use super::types::ServerFileConfig;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Load configuration from file, environment, and CLI arguments.
///
/// # Configuration Precedence
///
/// Configuration is loaded with the following precedence (highest to lowest):
/// 1. CLI arguments (when supported)
/// 2. Environment variables (BSSH_* prefix)
/// 3. Configuration file (YAML)
/// 4. Default values
///
/// # Arguments
///
/// * `config_path` - Optional path to configuration file. If None, searches default locations.
///
/// # Default Locations
///
/// If no config path is specified, searches in order:
/// 1. `./bssh-server.yaml` (current directory)
/// 2. `/etc/bssh/server.yaml` (system-wide)
/// 3. `$XDG_CONFIG_HOME/bssh/server.yaml` or `~/.config/bssh/server.yaml` (user-specific)
///
/// # Environment Variables
///
/// The following environment variables can override config file settings:
///
/// - `BSSH_PORT` - Server port (e.g., "2222")
/// - `BSSH_BIND_ADDRESS` - Bind address (e.g., "0.0.0.0")
/// - `BSSH_HOST_KEY` - Comma-separated host key paths
/// - `BSSH_MAX_CONNECTIONS` - Maximum concurrent connections
/// - `BSSH_KEEPALIVE_INTERVAL` - Keepalive interval in seconds
/// - `BSSH_AUTH_METHODS` - Comma-separated auth methods (e.g., "publickey,password")
/// - `BSSH_AUTHORIZED_KEYS_DIR` - Directory for authorized_keys files
/// - `BSSH_AUTHORIZED_KEYS_PATTERN` - Pattern for authorized_keys paths
/// - `BSSH_SHELL` - Default shell path
/// - `BSSH_COMMAND_TIMEOUT` - Command timeout in seconds
///
/// # Example
///
/// ```no_run
/// use bssh::server::config::load_config;
///
/// # fn main() -> anyhow::Result<()> {
/// // Load from default locations
/// let config = load_config(None)?;
///
/// // Load from specific file
/// let config = load_config(Some("/etc/bssh/custom.yaml".as_ref()))?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Configuration file cannot be read or parsed
/// - Environment variables have invalid values
/// - Configuration validation fails
pub fn load_config(config_path: Option<&Path>) -> Result<ServerFileConfig> {
    // Start with defaults
    let mut config = ServerFileConfig::default();

    // Load from file if specified or found in default locations
    if let Some(path) = config_path {
        config = load_config_file(path).context("Failed to load configuration file")?;
        tracing::info!(path = %path.display(), "Loaded configuration from file");
    } else {
        // Try default locations
        for path in default_config_paths() {
            if path.exists() {
                config = load_config_file(&path).context("Failed to load configuration file")?;
                tracing::info!(path = %path.display(), "Loaded configuration from file");
                break;
            }
        }
    }

    // Apply environment variable overrides
    config = apply_env_overrides(config)?;

    // Validate configuration
    validate_config(&config)?;

    Ok(config)
}

/// Generate a configuration template as YAML string.
///
/// This generates a fully documented configuration file template with
/// all available options and their default values.
///
/// # Example
///
/// ```
/// use bssh::server::config::generate_config_template;
///
/// let template = generate_config_template();
/// std::fs::write("bssh-server.yaml", template).unwrap();
/// ```
pub fn generate_config_template() -> String {
    let config = ServerFileConfig::default();
    let mut yaml = String::new();

    // Add header comment
    yaml.push_str("# bssh-server configuration file\n");
    yaml.push_str("#\n");
    yaml.push_str(
        "# This is a comprehensive configuration template showing all available options.\n",
    );
    yaml.push_str("# Uncomment and modify options as needed.\n");
    yaml.push_str("#\n");
    yaml.push_str("# Configuration hierarchy (highest to lowest precedence):\n");
    yaml.push_str("# 1. CLI arguments\n");
    yaml.push_str("# 2. Environment variables (BSSH_* prefix)\n");
    yaml.push_str("# 3. This configuration file\n");
    yaml.push_str("# 4. Default values\n\n");

    // Serialize config with defaults
    yaml.push_str(&serde_yaml::to_string(&config).unwrap_or_default());

    yaml
}

/// Load configuration from a YAML file.
fn load_config_file(path: &Path) -> Result<ServerFileConfig> {
    let content =
        std::fs::read_to_string(path).context(format!("Failed to read {}", path.display()))?;

    serde_yaml::from_str(&content).context(format!("Failed to parse {}", path.display()))
}

/// Get default configuration file search paths.
fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Current directory
    paths.push(PathBuf::from("./bssh-server.yaml"));

    // System-wide config
    paths.push(PathBuf::from("/etc/bssh/server.yaml"));

    // User config directory
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("bssh/server.yaml"));
    }

    paths
}

/// Apply environment variable overrides to configuration.
fn apply_env_overrides(mut config: ServerFileConfig) -> Result<ServerFileConfig> {
    // BSSH_PORT
    if let Ok(port_str) = std::env::var("BSSH_PORT") {
        config.server.port = port_str
            .parse()
            .context(format!("Invalid BSSH_PORT value: {port_str}"))?;
        tracing::debug!(port = config.server.port, "Applied BSSH_PORT override");
    }

    // BSSH_BIND_ADDRESS
    if let Ok(addr) = std::env::var("BSSH_BIND_ADDRESS") {
        config.server.bind_address = addr.clone();
        tracing::debug!(address = %addr, "Applied BSSH_BIND_ADDRESS override");
    }

    // BSSH_HOST_KEY (comma-separated list)
    if let Ok(keys) = std::env::var("BSSH_HOST_KEY") {
        config.server.host_keys = keys.split(',').map(|s| PathBuf::from(s.trim())).collect();
        tracing::debug!(
            key_count = config.server.host_keys.len(),
            "Applied BSSH_HOST_KEY override"
        );
    }

    // BSSH_MAX_CONNECTIONS
    if let Ok(max_str) = std::env::var("BSSH_MAX_CONNECTIONS") {
        config.server.max_connections = max_str
            .parse()
            .context(format!("Invalid BSSH_MAX_CONNECTIONS value: {max_str}"))?;
        tracing::debug!(
            max = config.server.max_connections,
            "Applied BSSH_MAX_CONNECTIONS override"
        );
    }

    // BSSH_KEEPALIVE_INTERVAL
    if let Ok(interval_str) = std::env::var("BSSH_KEEPALIVE_INTERVAL") {
        config.server.keepalive_interval = interval_str.parse().context(format!(
            "Invalid BSSH_KEEPALIVE_INTERVAL value: {interval_str}"
        ))?;
        tracing::debug!(
            interval = config.server.keepalive_interval,
            "Applied BSSH_KEEPALIVE_INTERVAL override"
        );
    }

    // BSSH_AUTH_METHODS (comma-separated: "publickey,password")
    if let Ok(methods_str) = std::env::var("BSSH_AUTH_METHODS") {
        use super::types::AuthMethod;
        let mut methods = Vec::new();
        for method in methods_str.split(',') {
            let method = method.trim().to_lowercase();
            match method.as_str() {
                "publickey" => methods.push(AuthMethod::PublicKey),
                "password" => methods.push(AuthMethod::Password),
                _ => {
                    anyhow::bail!("Unknown auth method in BSSH_AUTH_METHODS: {}", method);
                }
            }
        }
        config.auth.methods = methods;
        tracing::debug!(
            methods = ?config.auth.methods,
            "Applied BSSH_AUTH_METHODS override"
        );
    }

    // BSSH_AUTHORIZED_KEYS_DIR
    if let Ok(dir) = std::env::var("BSSH_AUTHORIZED_KEYS_DIR") {
        config.auth.publickey.authorized_keys_dir = Some(PathBuf::from(dir.clone()));
        config.auth.publickey.authorized_keys_pattern = None;
        tracing::debug!(dir = %dir, "Applied BSSH_AUTHORIZED_KEYS_DIR override");
    }

    // BSSH_AUTHORIZED_KEYS_PATTERN
    if let Ok(pattern) = std::env::var("BSSH_AUTHORIZED_KEYS_PATTERN") {
        config.auth.publickey.authorized_keys_pattern = Some(pattern.clone());
        config.auth.publickey.authorized_keys_dir = None;
        tracing::debug!(
            pattern = %pattern,
            "Applied BSSH_AUTHORIZED_KEYS_PATTERN override"
        );
    }

    // BSSH_SHELL
    if let Ok(shell) = std::env::var("BSSH_SHELL") {
        config.shell.default = PathBuf::from(shell.clone());
        tracing::debug!(shell = %shell, "Applied BSSH_SHELL override");
    }

    // BSSH_COMMAND_TIMEOUT
    if let Ok(timeout_str) = std::env::var("BSSH_COMMAND_TIMEOUT") {
        config.shell.command_timeout = timeout_str
            .parse()
            .context(format!("Invalid BSSH_COMMAND_TIMEOUT value: {timeout_str}"))?;
        tracing::debug!(
            timeout = config.shell.command_timeout,
            "Applied BSSH_COMMAND_TIMEOUT override"
        );
    }

    Ok(config)
}

/// Validate configuration for correctness.
fn validate_config(config: &ServerFileConfig) -> Result<()> {
    // Validate host keys exist
    if config.server.host_keys.is_empty() {
        anyhow::bail!(
            "At least one host key must be configured (server.host_keys or BSSH_HOST_KEY)"
        );
    }

    for key_path in &config.server.host_keys {
        if !key_path.exists() {
            anyhow::bail!("Host key file not found: {}", key_path.display());
        }
    }

    // Validate authentication configuration
    if config.auth.methods.is_empty() {
        anyhow::bail!("At least one authentication method must be enabled (auth.methods)");
    }

    // Validate IP ranges (CIDR notation)
    for cidr in &config.security.allowed_ips {
        cidr.parse::<ipnetwork::IpNetwork>()
            .context(format!("Invalid CIDR notation in allowed_ips: {cidr}"))?;
    }

    for cidr in &config.security.blocked_ips {
        cidr.parse::<ipnetwork::IpNetwork>()
            .context(format!("Invalid CIDR notation in blocked_ips: {cidr}"))?;
    }

    // Validate port number
    if config.server.port == 0 {
        anyhow::bail!("Server port cannot be 0");
    }

    // Validate max connections
    if config.server.max_connections == 0 {
        anyhow::bail!("max_connections must be greater than 0");
    }

    tracing::info!("Configuration validation passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_config_template() {
        let template = generate_config_template();
        assert!(template.contains("bssh-server configuration"));
        assert!(template.contains("server:"));
        assert!(template.contains("auth:"));
        assert!(template.contains("shell:"));

        // Template should be valid YAML
        let parsed: Result<ServerFileConfig, _> = serde_yaml::from_str(&template);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_load_config_from_file() {
        let yaml_content = r#"
server:
  port: 2223
  bind_address: "127.0.0.1"
  host_keys:
    - /tmp/test_key
auth:
  methods:
    - publickey
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(yaml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = load_config_file(temp_file.path()).unwrap();
        assert_eq!(config.server.port, 2223);
        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.host_keys.len(), 1);
    }

    #[test]
    #[serial_test::serial]
    fn test_env_override_port() {
        // Clear any existing env vars
        std::env::remove_var("BSSH_PORT");

        std::env::set_var("BSSH_PORT", "3333");
        let config = apply_env_overrides(ServerFileConfig::default()).unwrap();
        assert_eq!(config.server.port, 3333);
        std::env::remove_var("BSSH_PORT");
    }

    #[test]
    #[serial_test::serial]
    fn test_env_override_bind_address() {
        // Clear any existing env vars
        std::env::remove_var("BSSH_PORT");

        std::env::set_var("BSSH_BIND_ADDRESS", "192.168.1.1");
        let config = apply_env_overrides(ServerFileConfig::default()).unwrap();
        assert_eq!(config.server.bind_address, "192.168.1.1");
        std::env::remove_var("BSSH_BIND_ADDRESS");
    }

    #[test]
    #[serial_test::serial]
    fn test_env_override_host_keys() {
        // Clear any existing env vars
        std::env::remove_var("BSSH_PORT");

        std::env::set_var("BSSH_HOST_KEY", "/key1,/key2,/key3");
        let config = apply_env_overrides(ServerFileConfig::default()).unwrap();
        assert_eq!(config.server.host_keys.len(), 3);
        assert_eq!(config.server.host_keys[0], PathBuf::from("/key1"));
        std::env::remove_var("BSSH_HOST_KEY");
    }

    #[test]
    #[serial_test::serial]
    fn test_env_override_auth_methods() {
        // Clear any existing env vars
        std::env::remove_var("BSSH_PORT");

        std::env::set_var("BSSH_AUTH_METHODS", "publickey,password");
        let config = apply_env_overrides(ServerFileConfig::default()).unwrap();
        assert_eq!(config.auth.methods.len(), 2);
        std::env::remove_var("BSSH_AUTH_METHODS");
    }

    #[test]
    #[serial_test::serial]
    fn test_env_override_invalid_port() {
        // Clear any existing env vars first
        std::env::remove_var("BSSH_PORT");

        std::env::set_var("BSSH_PORT", "invalid");
        let result = apply_env_overrides(ServerFileConfig::default());
        assert!(result.is_err());
        std::env::remove_var("BSSH_PORT");
    }

    #[test]
    fn test_validate_config_no_host_keys() {
        let mut config = ServerFileConfig::default();
        config.server.host_keys.clear();

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("At least one host key"));
    }

    #[test]
    fn test_validate_config_no_auth_methods() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"fake host key").unwrap();
        temp_file.flush().unwrap();

        let mut config = ServerFileConfig::default();
        config.server.host_keys.push(temp_file.path().to_path_buf());
        config.auth.methods.clear();

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication method"));
    }

    #[test]
    fn test_validate_config_invalid_cidr() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"fake host key").unwrap();
        temp_file.flush().unwrap();

        let mut config = ServerFileConfig::default();
        config.server.host_keys.push(temp_file.path().to_path_buf());
        config.security.allowed_ips.push("invalid-cidr".to_string());

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CIDR"));
    }

    #[test]
    fn test_validate_config_valid_cidr() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"fake host key").unwrap();
        temp_file.flush().unwrap();

        let mut config = ServerFileConfig::default();
        config.server.host_keys.push(temp_file.path().to_path_buf());
        config
            .security
            .allowed_ips
            .push("192.168.1.0/24".to_string());
        config.security.blocked_ips.push("10.0.0.0/8".to_string());

        // Should pass validation with valid CIDR
        let result = validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_zero_port() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"fake host key").unwrap();
        temp_file.flush().unwrap();

        let mut config = ServerFileConfig::default();
        config.server.host_keys.push(temp_file.path().to_path_buf());
        config.server.port = 0;

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("port cannot be 0"));
    }

    #[test]
    fn test_validate_config_zero_max_connections() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"fake host key").unwrap();
        temp_file.flush().unwrap();

        let mut config = ServerFileConfig::default();
        config.server.host_keys.push(temp_file.path().to_path_buf());
        config.server.max_connections = 0;

        let result = validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_connections must be greater than 0"));
    }
}
