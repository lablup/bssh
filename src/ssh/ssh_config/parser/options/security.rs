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

//! SSH security options parsing
//!
//! Handles security-related configuration options including host key
//! verification, known hosts files, and cryptographic algorithms.

use crate::ssh::ssh_config::parser::helpers::parse_yes_no;
use crate::ssh::ssh_config::security::secure_validate_path;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse security-related SSH configuration options
pub(super) fn parse_security_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "stricthostkeychecking" => {
            if args.is_empty() {
                anyhow::bail!("StrictHostKeyChecking requires a value at line {line_number}");
            }
            let value = &args[0];
            tracing::debug!(
                "Setting StrictHostKeyChecking to '{}' at line {} (security-sensitive)",
                value,
                line_number
            );
            host.strict_host_key_checking = Some(value.clone());
        }
        "userknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("UserKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(&args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid UserKnownHostsFile path at line {line_number}")
                })?;
            host.user_known_hosts_file = Some(path);
        }
        "globalknownhostsfile" => {
            if args.is_empty() {
                anyhow::bail!("GlobalKnownHostsFile requires a value at line {line_number}");
            }
            let path =
                secure_validate_path(&args[0], "known_hosts", line_number).with_context(|| {
                    format!("Invalid GlobalKnownHostsFile path at line {line_number}")
                })?;
            host.global_known_hosts_file = Some(path);
        }
        "hostkeyalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("HostKeyAlgorithms requires a value at line {line_number}");
            }
            host.host_key_algorithms = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "kexalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("KexAlgorithms requires a value at line {line_number}");
            }
            host.kex_algorithms = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "ciphers" => {
            if args.is_empty() {
                anyhow::bail!("Ciphers requires a value at line {line_number}");
            }
            host.ciphers = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "macs" => {
            if args.is_empty() {
                anyhow::bail!("MACs requires a value at line {line_number}");
            }
            host.macs = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "casignaturealgorithms" => {
            if args.is_empty() {
                anyhow::bail!("CASignatureAlgorithms requires a value at line {line_number}");
            }
            // Security: Limit the number of algorithms to prevent memory exhaustion
            const MAX_ALGORITHMS: usize = 50;
            let algorithms: Vec<String> = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()) // Skip empty strings from malformed input
                .take(MAX_ALGORITHMS)
                .collect();

            if args.join(",").split(',').count() > MAX_ALGORITHMS {
                tracing::warn!(
                    "CASignatureAlgorithms at line {} contains more than {} algorithms, truncated to first {}",
                    line_number, MAX_ALGORITHMS, MAX_ALGORITHMS
                );
            }

            host.ca_signature_algorithms = algorithms;
        }
        "nohostauthenticationforlocalhost" => {
            if args.is_empty() {
                anyhow::bail!(
                    "NoHostAuthenticationForLocalhost requires a value at line {line_number}"
                );
            }
            let value = parse_yes_no(&args[0], line_number)?;
            if value {
                tracing::debug!(
                    "NoHostAuthenticationForLocalhost enabled at line {} - skipping host verification for localhost (security-sensitive)",
                    line_number
                );
            }
            host.no_host_authentication_for_localhost = Some(value);
        }
        "hashknownhosts" => {
            if args.is_empty() {
                anyhow::bail!("HashKnownHosts requires a value at line {line_number}");
            }
            host.hash_known_hosts = Some(parse_yes_no(&args[0], line_number)?);
        }
        "checkhostip" => {
            if args.is_empty() {
                anyhow::bail!("CheckHostIP requires a value at line {line_number}");
            }
            host.check_host_ip = Some(parse_yes_no(&args[0], line_number)?);
            // Note: CheckHostIP is deprecated in OpenSSH 8.5+ (2021)
            tracing::warn!(
                "CheckHostIP at line {} is deprecated in OpenSSH 8.5+ and may not have effect",
                line_number
            );
        }
        "visualhostkey" => {
            if args.is_empty() {
                anyhow::bail!("VisualHostKey requires a value at line {line_number}");
            }
            host.visual_host_key = Some(parse_yes_no(&args[0], line_number)?);
        }
        "hostkeyalias" => {
            if args.is_empty() {
                anyhow::bail!("HostKeyAlias requires a value at line {line_number}");
            }
            // Security: Validate HostKeyAlias to prevent injection attacks
            // Only allow alphanumeric, dots, hyphens, and underscores (valid hostname characters)
            let alias = &args[0];
            if alias.is_empty() {
                anyhow::bail!("HostKeyAlias cannot be empty at line {line_number}");
            }
            if alias.len() > 255 {
                anyhow::bail!(
                    "HostKeyAlias at line {line_number} exceeds maximum length of 255 characters"
                );
            }
            // Check for dangerous characters that could be used in injection attacks
            if !alias
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                anyhow::bail!(
                    "HostKeyAlias at line {} contains invalid characters. Only alphanumeric, dots, hyphens, and underscores are allowed",
                    line_number
                );
            }
            // Prevent directory traversal
            if alias.contains("..") {
                anyhow::bail!(
                    "HostKeyAlias at line {} contains '..' which could be used for path traversal attacks",
                    line_number
                );
            }
            tracing::debug!(
                "Setting HostKeyAlias to '{}' at line {} (security-sensitive: affects host key verification)",
                alias, line_number
            );
            host.host_key_alias = Some(alias.clone());
        }
        "verifyhostkeydns" => {
            if args.is_empty() {
                anyhow::bail!("VerifyHostKeyDNS requires a value at line {line_number}");
            }
            // Accepts yes/no/ask
            let value = args[0].to_lowercase();
            if !["yes", "no", "ask"].contains(&value.as_str()) {
                anyhow::bail!(
                    "VerifyHostKeyDNS at line {} must be yes, no, or ask, got '{}'",
                    line_number,
                    args[0]
                );
            }
            host.verify_host_key_dns = Some(value);
        }
        "updatehostkeys" => {
            if args.is_empty() {
                anyhow::bail!("UpdateHostKeys requires a value at line {line_number}");
            }
            // Accepts yes/no/ask
            let value = args[0].to_lowercase();
            if !["yes", "no", "ask"].contains(&value.as_str()) {
                anyhow::bail!(
                    "UpdateHostKeys at line {} must be yes, no, or ask, got '{}'",
                    line_number,
                    args[0]
                );
            }
            host.update_host_keys = Some(value);
        }
        "requiredrsasize" => {
            if args.is_empty() {
                anyhow::bail!("RequiredRSASize requires a value at line {line_number}");
            }
            let size: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid RequiredRSASize value '{}' at line {}",
                    args[0], line_number
                )
            })?;

            // Security: Enforce reasonable limits to prevent issues
            // OpenSSH minimum is 1024, maximum practical is 16384
            const MIN_RSA_SIZE: u32 = 1024;
            const MAX_RSA_SIZE: u32 = 16384;
            const RECOMMENDED_MIN: u32 = 2048;

            if size < MIN_RSA_SIZE {
                anyhow::bail!(
                    "RequiredRSASize {} at line {} is below minimum allowed value of {}",
                    size,
                    line_number,
                    MIN_RSA_SIZE
                );
            }

            if size > MAX_RSA_SIZE {
                anyhow::bail!(
                    "RequiredRSASize {} at line {} exceeds maximum allowed value of {}",
                    size,
                    line_number,
                    MAX_RSA_SIZE
                );
            }

            // Warn if below recommended minimum (OpenSSH 9.0+ default is 2048)
            if size < RECOMMENDED_MIN {
                tracing::warn!(
                    "RequiredRSASize {} at line {} is below recommended minimum {} (OpenSSH 9.0+ default). \
                     RSA keys smaller than {} bits are considered weak and may be vulnerable to attacks",
                    size,
                    line_number,
                    RECOMMENDED_MIN,
                    RECOMMENDED_MIN
                );
            }

            host.required_rsa_size = Some(size);
        }
        "fingerprinthash" => {
            if args.is_empty() {
                anyhow::bail!("FingerprintHash requires a value at line {line_number}");
            }
            let value = args[0].to_lowercase();
            if !["md5", "sha256"].contains(&value.as_str()) {
                anyhow::bail!(
                    "Invalid FingerprintHash value '{}' at line {} (must be md5 or sha256)",
                    args[0],
                    line_number
                );
            }

            // Warn about MD5 usage (deprecated in OpenSSH 6.8+, default is sha256)
            if value == "md5" {
                tracing::warn!(
                    "FingerprintHash md5 at line {} is deprecated. \
                     OpenSSH 6.8+ (2015) uses sha256 by default. \
                     MD5 should only be used for compatibility with legacy systems",
                    line_number
                );
            }

            host.fingerprint_hash = Some(value);
        }
        _ => unreachable!("Unexpected keyword in parse_security_option: {}", keyword),
    }

    Ok(())
}
