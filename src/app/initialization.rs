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

//! Application initialization and configuration loading

use anyhow::{Context, Result};
use bssh::{
    cli::Cli,
    config::Config,
    jump::parse_jump_hosts,
    node::Node,
    ssh::{known_hosts::StrictHostKeyChecking, SshConfig},
    utils::init_logging,
};
use std::path::PathBuf;

/// Application context after initialization
pub struct AppContext {
    pub config: Config,
    pub ssh_config: SshConfig,
    pub nodes: Vec<Node>,
    pub cluster_name: Option<String>,
    pub strict_mode: StrictHostKeyChecking,
    #[allow(dead_code)] // Will be used when jump hosts are fully integrated
    pub jump_hosts: Option<Vec<bssh::jump::JumpHost>>,
    pub max_parallel: usize,
}

/// Check if a string is a valid IPv4 address.
///
/// Validates that the string has exactly 4 octets separated by dots,
/// and each octet is a valid u8 (0-255).
///
/// # Examples
/// ```
/// use bssh::app::initialization::is_ipv4_address;
///
/// assert!(is_ipv4_address("127.0.0.1"));
/// assert!(is_ipv4_address("192.168.1.1"));
/// assert!(is_ipv4_address("0.0.0.0"));
/// assert!(is_ipv4_address("255.255.255.255"));
/// assert!(!is_ipv4_address("999.999.999.999"));
/// assert!(!is_ipv4_address("1.2.3"));
/// assert!(!is_ipv4_address("1.2.3.4.5"));
/// ```
pub fn is_ipv4_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();

    // Must have exactly 4 octets
    if parts.len() != 4 {
        return false;
    }

    // Each octet must be a valid u8 (0-255)
    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

/// Check if a string looks like a host specification rather than a command.
///
/// This heuristic detects explicit host patterns to avoid misinterpreting them as commands
/// in Backend.AI auto-detection scenarios.
///
/// Detected patterns:
/// - Special hostnames (`localhost`, `localhost.localdomain`)
/// - IPv4 addresses (e.g., `127.0.0.1`, `192.168.1.1`)
/// - `user@host` format (contains `@`)
/// - `host:port` format (contains `:`)
/// - SSH URI format (starts with `ssh://`)
/// - FQDN format (multiple `.` and no spaces)
/// - IPv6 format (starts with `[`)
///
/// # Examples
/// ```
/// use bssh::app::initialization::looks_like_host_specification;
///
/// assert!(looks_like_host_specification("localhost"));
/// assert!(looks_like_host_specification("localhost.localdomain"));
/// assert!(looks_like_host_specification("127.0.0.1"));
/// assert!(looks_like_host_specification("192.168.1.1"));
/// assert!(looks_like_host_specification("user@localhost"));
/// assert!(looks_like_host_specification("localhost:22"));
/// assert!(looks_like_host_specification("server.example.com"));
/// assert!(looks_like_host_specification("ssh://host"));
/// assert!(looks_like_host_specification("[::1]:22"));
/// assert!(!looks_like_host_specification("whoami"));
/// assert!(!looks_like_host_specification("echo hello"));
/// ```
pub fn looks_like_host_specification(s: &str) -> bool {
    const MIN_FQDN_PARTS: usize = 2;

    // Special hostnames (checked early for performance)
    if s == "localhost" || s == "localhost.localdomain" {
        return true;
    }

    // IPv4 address detection
    if is_ipv4_address(s) {
        return true;
    }

    // Early returns for most common patterns (performance optimization)
    if s.contains('@') {
        return true; // user@host format
    }
    if s.starts_with('[') {
        return true; // IPv6 format like [::1]:22
    }
    if s.starts_with("ssh://") {
        return true; // SSH URI format
    }
    if s.contains(':') {
        return true; // host:port format
    }

    // FQDN format: multiple dots and no spaces (e.g., server.example.com)
    // Also ensure it's not just dots or starts/ends with dot
    s.contains('.')
        && s.split('.').count() >= MIN_FQDN_PARTS
        && !s.contains(' ')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.split('.').any(|part| !part.is_empty())
}

/// Initialize the application, load configs, and resolve nodes
pub async fn initialize_app(cli: &mut Cli, args: &[String]) -> Result<AppContext> {
    // Initialize logging
    init_logging(cli.verbose);

    // Early Backend.AI environment detection
    // Auto-set cluster if Backend.AI environment is detected and no explicit cluster/hosts specified
    // Skip auto-detection if destination looks like a host specification (user@host, host:port, FQDN, etc.)
    let destination_looks_like_host = cli
        .destination
        .as_ref()
        .is_some_and(|dest| looks_like_host_specification(dest));

    if Config::from_backendai_env().is_some()
        && cli.cluster.is_none()
        && cli.hosts.is_none()
        && !destination_looks_like_host
    {
        cli.cluster = Some("bai_auto".to_string());
        tracing::debug!("Auto-detected Backend.AI environment, setting cluster to 'bai_auto'");
    }

    // Check if user explicitly specified options
    let has_explicit_config = args.iter().any(|arg| arg == "--config");
    let has_explicit_parallel = args
        .iter()
        .any(|arg| arg == "--parallel" || arg.starts_with("--parallel="));

    // If user explicitly specified --config, ensure the file exists
    if has_explicit_config {
        let expanded_path = if cli.config.starts_with("~") {
            let path_str = cli.config.to_string_lossy();
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(path_str.replacen("~", &home, 1))
            } else {
                cli.config.clone()
            }
        } else {
            cli.config.clone()
        };

        if !expanded_path.exists() {
            anyhow::bail!("Config file not found: {expanded_path:?}");
        }
    }

    // Load configuration with priority
    let config = Config::load_with_priority(&cli.config).await?;

    // Load SSH configuration with caching for improved performance
    let ssh_config = if let Some(ref ssh_config_path) = cli.ssh_config {
        SshConfig::load_from_file_cached(ssh_config_path)
            .await
            .with_context(|| format!("Failed to load SSH config from {ssh_config_path:?}"))?
    } else {
        SshConfig::load_default_cached().await.unwrap_or_else(|_| {
            tracing::debug!("No SSH config found or failed to load, using empty config");
            SshConfig::new()
        })
    };

    // Determine nodes to execute on
    let (nodes, actual_cluster_name) =
        super::nodes::resolve_nodes(cli, &config, &ssh_config).await?;

    if nodes.is_empty() {
        anyhow::bail!(
            "No hosts specified. Please use one of the following options:\n  \
             -H <hosts>    Specify comma-separated hosts (e.g., -H user@host1,user@host2)\n  \
             -c <cluster>  Use a cluster from your configuration file"
        );
    }

    // Parse jump hosts if specified
    let jump_hosts = if let Some(ref jump_spec) = cli.jump_hosts {
        Some(
            parse_jump_hosts(jump_spec)
                .with_context(|| format!("Invalid jump host specification: '{jump_spec}'"))?,
        )
    } else {
        None
    };

    // Display jump host information if present
    if let Some(ref jumps) = jump_hosts {
        if jumps.len() == 1 {
            tracing::info!("Using jump host: {}", jumps[0]);
        } else {
            tracing::info!(
                "Using jump host chain: {}",
                jumps
                    .iter()
                    .map(|j| j.to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
        }
    }

    // Parse strict host key checking mode with SSH config integration
    let hostname = if cli.is_ssh_mode() {
        cli.parse_destination().map(|(_, host, _)| host)
    } else {
        None
    };
    let strict_mode = determine_strict_host_key_checking(cli, &ssh_config, hostname.as_deref());

    // Determine max_parallel: CLI argument takes precedence over config
    // For SSH mode (single host), parallel is always 1
    let max_parallel = if cli.is_ssh_mode() {
        1
    } else if has_explicit_parallel {
        cli.parallel
    } else {
        config
            .get_parallel(actual_cluster_name.as_deref().or(cli.cluster.as_deref()))
            .unwrap_or(cli.parallel) // Fall back to CLI default (10)
    };

    Ok(AppContext {
        config,
        ssh_config,
        nodes,
        cluster_name: actual_cluster_name,
        strict_mode,
        jump_hosts,
        max_parallel,
    })
}

/// Determine strict host key checking mode with SSH config integration
pub fn determine_strict_host_key_checking(
    cli: &Cli,
    ssh_config: &SshConfig,
    hostname: Option<&str>,
) -> StrictHostKeyChecking {
    // CLI argument takes precedence
    if cli.strict_host_key_checking != "accept-new" {
        return cli.strict_host_key_checking.parse().unwrap_or_default();
    }

    // SSH config value for specific hostname
    if let Some(host) = hostname {
        if let Some(ssh_config_value) = ssh_config.get_strict_host_key_checking(host) {
            return match ssh_config_value.to_lowercase().as_str() {
                "yes" => StrictHostKeyChecking::Yes,
                "no" => StrictHostKeyChecking::No,
                "ask" | "accept-new" => StrictHostKeyChecking::AcceptNew,
                _ => StrictHostKeyChecking::AcceptNew,
            };
        }
    }

    // Default from CLI (already parsed)
    cli.strict_host_key_checking.parse().unwrap_or_default()
}

/// Determine SSH key path with integration of SSH config
pub fn determine_ssh_key_path(
    cli: &Cli,
    config: &Config,
    ssh_config: &SshConfig,
    hostname: Option<&str>,
    cluster_name: Option<&str>,
) -> Option<PathBuf> {
    // CLI identity file takes highest precedence
    if let Some(identity) = &cli.identity {
        return Some(identity.clone());
    }

    // SSH config identity files (for specific hostname if available)
    if let Some(host) = hostname {
        let identity_files = ssh_config.get_identity_files(host);
        if !identity_files.is_empty() {
            // Return the first identity file from SSH config
            return Some(identity_files[0].clone());
        }
    }

    // Cluster configuration SSH key
    config
        .get_ssh_key(cluster_name)
        .map(|ssh_key| bssh::config::expand_tilde(std::path::Path::new(&ssh_key)))
}

/// Determine whether to use macOS Keychain for SSH key passphrases
///
/// This checks the SSH config for the UseKeychain option for a specific hostname.
/// The option is only available on macOS.
///
/// # Arguments
/// * `ssh_config` - The loaded SSH configuration
/// * `hostname` - The target hostname to check (optional)
///
/// # Returns
/// `true` if UseKeychain is enabled in SSH config, `false` otherwise
#[cfg(target_os = "macos")]
pub fn determine_use_keychain(ssh_config: &SshConfig, hostname: Option<&str>) -> bool {
    if let Some(host) = hostname {
        let host_config = ssh_config.find_host_config(host);
        host_config.use_keychain.unwrap_or(false)
    } else {
        false
    }
}

/// Non-macOS version of determine_use_keychain (always returns false)
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub fn determine_use_keychain(_ssh_config: &SshConfig, _hostname: Option<&str>) -> bool {
    false
}

/// Determine the effective jump hosts for a connection.
///
/// Priority order:
/// 1. CLI `-J` option (highest priority)
/// 2. SSH config `ProxyJump` directive for the hostname
/// 3. None (direct connection)
///
/// # Arguments
/// * `cli_jump_hosts` - Jump hosts specified via CLI `-J` option
/// * `ssh_config` - The loaded SSH configuration
/// * `hostname` - The target hostname to check for ProxyJump config
///
/// # Returns
/// The effective jump host specification, or None for direct connection
#[allow(dead_code)] // Used for documentation and potential future use
pub fn determine_effective_jump_hosts(
    cli_jump_hosts: Option<&str>,
    ssh_config: &SshConfig,
    hostname: &str,
) -> Option<String> {
    // CLI takes precedence
    if let Some(jump) = cli_jump_hosts {
        return Some(jump.to_string());
    }

    // Fall back to SSH config ProxyJump
    ssh_config.get_proxy_jump(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_effective_jump_hosts_cli_takes_precedence() {
        let ssh_config_content = r#"
Host example.com
    ProxyJump bastion.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // CLI jump host should take precedence over SSH config
        let result = determine_effective_jump_hosts(
            Some("cli-jump.example.com"),
            &ssh_config,
            "example.com",
        );
        assert_eq!(result, Some("cli-jump.example.com".to_string()));
    }

    #[test]
    fn test_determine_effective_jump_hosts_falls_back_to_ssh_config() {
        let ssh_config_content = r#"
Host example.com
    ProxyJump bastion.example.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // Should use SSH config when CLI jump host is not specified
        let result = determine_effective_jump_hosts(None, &ssh_config, "example.com");
        assert_eq!(result, Some("bastion.example.com".to_string()));
    }

    #[test]
    fn test_determine_effective_jump_hosts_no_jump_host() {
        let ssh_config = SshConfig::new();

        // Should return None when no jump host is configured
        let result = determine_effective_jump_hosts(None, &ssh_config, "example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_determine_effective_jump_hosts_wildcard_pattern() {
        let ssh_config_content = r#"
Host *.internal
    ProxyJump gateway.company.com

Host db.internal
    ProxyJump db-gateway.company.com
"#;
        let ssh_config = SshConfig::parse(ssh_config_content).unwrap();

        // Should match the most specific pattern
        let result = determine_effective_jump_hosts(None, &ssh_config, "db.internal");
        assert_eq!(result, Some("db-gateway.company.com".to_string()));

        // Should match wildcard pattern
        let result = determine_effective_jump_hosts(None, &ssh_config, "web.internal");
        assert_eq!(result, Some("gateway.company.com".to_string()));
    }
}
