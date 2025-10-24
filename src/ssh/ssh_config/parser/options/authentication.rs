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

//! SSH authentication options parsing
//!
//! Handles authentication-related configuration options including
//! identity files, authentication methods, and algorithm preferences.

use crate::ssh::ssh_config::parser::helpers::parse_yes_no;
use crate::ssh::ssh_config::security::secure_validate_path;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse authentication-related SSH configuration options
pub(super) fn parse_authentication_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "identityfile" => {
            if args.is_empty() {
                anyhow::bail!("IdentityFile requires a value at line {line_number}");
            }
            let path = secure_validate_path(&args[0], "identity", line_number)
                .with_context(|| format!("Invalid IdentityFile path at line {line_number}"))?;
            host.identity_files.push(path);
        }
        "identitiesonly" => {
            if args.is_empty() {
                anyhow::bail!("IdentitiesOnly requires a value at line {line_number}");
            }
            host.identities_only = Some(parse_yes_no(&args[0], line_number)?);
        }
        "addkeystoagent" => {
            if args.is_empty() {
                anyhow::bail!("AddKeysToAgent requires a value at line {line_number}");
            }
            let value = args[0].to_lowercase();
            if !["yes", "no", "ask", "confirm"].contains(&value.as_str()) {
                anyhow::bail!(
                    "Invalid AddKeysToAgent value '{}' at line {} (must be yes/no/ask/confirm)",
                    args[0],
                    line_number
                );
            }
            host.add_keys_to_agent = Some(value);
        }
        "identityagent" => {
            if args.is_empty() {
                anyhow::bail!("IdentityAgent requires a value at line {line_number}");
            }
            // IdentityAgent can be a socket path or special value "none" or "SSH_AUTH_SOCK"
            let value = &args[0];

            // Security: Validate special values first
            if value.to_lowercase() == "none" || value == "SSH_AUTH_SOCK" {
                host.identity_agent = Some(value.to_string());
            } else {
                // Security: Check for path traversal attempts without expanding the path
                if value.contains("../") || value.contains("..\\") {
                    anyhow::bail!(
                        "Security violation: IdentityAgent path contains directory traversal sequence '..' at line {}. \
                         Path traversal attacks are not allowed.",
                        line_number
                    );
                }

                // Check for null bytes and other dangerous characters
                if value.contains('\0') {
                    anyhow::bail!(
                        "Security violation: IdentityAgent path contains null byte at line {}. \
                         This could be used for path truncation attacks.",
                        line_number
                    );
                }

                // Validate it looks like a path (contains / or starts with ~)
                if !value.contains('/') && !value.starts_with('~') {
                    tracing::warn!(
                        "IdentityAgent '{}' at line {} does not look like a valid socket path",
                        value,
                        line_number
                    );
                }

                // Store the original path format (validation happens at usage time)
                host.identity_agent = Some(value.to_string());
            }
        }
        "pubkeyacceptedalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("PubkeyAcceptedAlgorithms requires a value at line {line_number}");
            }
            // Security: Limit the number of algorithms to prevent memory exhaustion
            const MAX_ALGORITHMS: usize = 50;
            const MAX_ALGORITHM_NAME_LENGTH: usize = 256;

            let mut algorithms = Vec::with_capacity(MAX_ALGORITHMS.min(args.len() * 2));
            let mut total_count = 0;
            let mut truncated = false;

            // Efficiently parse algorithms without creating unnecessary intermediate strings
            for arg in args {
                // Split each arg by comma and process
                for algorithm in arg.split(',') {
                    total_count += 1;

                    // Stop processing if we've hit the limit
                    if algorithms.len() >= MAX_ALGORITHMS {
                        truncated = true;
                        break;
                    }

                    let trimmed = algorithm.trim();

                    // Skip empty strings from malformed input
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Security: Limit individual algorithm name length
                    if trimmed.len() > MAX_ALGORITHM_NAME_LENGTH {
                        tracing::warn!(
                            "Algorithm name at line {} exceeds maximum length of {} characters, skipping",
                            line_number, MAX_ALGORITHM_NAME_LENGTH
                        );
                        continue;
                    }

                    // Security: Validate algorithm name contains only safe characters
                    // Allow alphanumeric, hyphens, dots, underscores, @ and +
                    if !trimmed.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || c == '-'
                            || c == '.'
                            || c == '_'
                            || c == '@'
                            || c == '+'
                    }) {
                        anyhow::bail!(
                            "PubkeyAcceptedAlgorithms at line {} contains invalid characters in algorithm name '{}'. \
                             Only alphanumeric characters, hyphens, dots, underscores, @ and + are allowed",
                            line_number, trimmed
                        );
                    }

                    algorithms.push(trimmed.to_string());
                }

                if truncated {
                    break;
                }
            }

            if truncated {
                tracing::warn!(
                    "PubkeyAcceptedAlgorithms at line {} contains {} algorithms, truncated to first {}",
                    line_number, total_count, MAX_ALGORITHMS
                );
            }

            // Ensure we have at least one algorithm
            if algorithms.is_empty() {
                anyhow::bail!(
                    "PubkeyAcceptedAlgorithms at line {} must contain at least one valid algorithm",
                    line_number
                );
            }

            host.pubkey_accepted_algorithms = algorithms;
        }
        "certificatefile" => {
            if args.is_empty() {
                anyhow::bail!("CertificateFile requires a value at line {line_number}");
            }
            let path = secure_validate_path(&args[0], "certificate", line_number)
                .with_context(|| format!("Invalid CertificateFile path at line {line_number}"))?;
            host.certificate_files.push(path);
        }
        "pubkeyauthentication" => {
            if args.is_empty() {
                anyhow::bail!("PubkeyAuthentication requires a value at line {line_number}");
            }
            host.pubkey_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "passwordauthentication" => {
            if args.is_empty() {
                anyhow::bail!("PasswordAuthentication requires a value at line {line_number}");
            }
            host.password_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "kbdinteractiveauthentication" => {
            if args.is_empty() {
                anyhow::bail!(
                    "KbdInteractiveAuthentication requires a value at line {line_number}"
                );
            }
            host.keyboard_interactive_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "gssapiauthentication" => {
            if args.is_empty() {
                anyhow::bail!("GSSAPIAuthentication requires a value at line {line_number}");
            }
            host.gssapi_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "preferredauthentications" => {
            if args.is_empty() {
                anyhow::bail!("PreferredAuthentications requires a value at line {line_number}");
            }
            host.preferred_authentications = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        "hostbasedauthentication" => {
            if args.is_empty() {
                anyhow::bail!("HostbasedAuthentication requires a value at line {line_number}");
            }
            host.hostbased_authentication = Some(parse_yes_no(&args[0], line_number)?);
        }
        "hostbasedacceptedalgorithms" => {
            if args.is_empty() {
                anyhow::bail!("HostbasedAcceptedAlgorithms requires a value at line {line_number}");
            }
            // Security: Limit the number of algorithms to prevent memory exhaustion
            const MAX_ALGORITHMS: usize = 50;
            const MAX_ALGORITHM_NAME_LENGTH: usize = 256;

            let mut algorithms = Vec::with_capacity(MAX_ALGORITHMS.min(args.len() * 2));
            let mut total_count = 0;
            let mut truncated = false;

            // Efficiently parse algorithms without creating unnecessary intermediate strings
            for arg in args {
                // Split each arg by comma and process
                for algorithm in arg.split(',') {
                    total_count += 1;

                    // Stop processing if we've hit the limit
                    if algorithms.len() >= MAX_ALGORITHMS {
                        truncated = true;
                        break;
                    }

                    let trimmed = algorithm.trim();

                    // Skip empty strings from malformed input
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Security: Limit individual algorithm name length
                    if trimmed.len() > MAX_ALGORITHM_NAME_LENGTH {
                        tracing::warn!(
                            "Algorithm name at line {} exceeds maximum length of {} characters, skipping",
                            line_number, MAX_ALGORITHM_NAME_LENGTH
                        );
                        continue;
                    }

                    // Security: Validate algorithm name contains only safe characters
                    // Allow alphanumeric, hyphens, dots, underscores, @ and +
                    if !trimmed.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || c == '-'
                            || c == '.'
                            || c == '_'
                            || c == '@'
                            || c == '+'
                    }) {
                        anyhow::bail!(
                            "HostbasedAcceptedAlgorithms at line {} contains invalid characters in algorithm name '{}'. \
                             Only alphanumeric characters, hyphens, dots, underscores, @ and + are allowed",
                            line_number, trimmed
                        );
                    }

                    algorithms.push(trimmed.to_string());
                }

                if truncated {
                    break;
                }
            }

            if truncated {
                tracing::warn!(
                    "HostbasedAcceptedAlgorithms at line {} contains {} algorithms, truncated to first {}",
                    line_number, total_count, MAX_ALGORITHMS
                );
            }

            // Ensure we have at least one algorithm
            if algorithms.is_empty() {
                anyhow::bail!(
                    "HostbasedAcceptedAlgorithms at line {} must contain at least one valid algorithm",
                    line_number
                );
            }

            host.hostbased_accepted_algorithms = algorithms;
        }
        "numberofpasswordprompts" => {
            if args.is_empty() {
                anyhow::bail!("NumberOfPasswordPrompts requires a value at line {line_number}");
            }
            let num: u32 = args[0].parse().with_context(|| {
                format!(
                    "Invalid NumberOfPasswordPrompts value '{}' at line {}",
                    args[0], line_number
                )
            })?;

            // Security: Enforce reasonable limits to prevent DoS attacks
            // OpenSSH default is 3, typical max is 10
            const MAX_PASSWORD_PROMPTS: u32 = 100;

            if num == 0 {
                anyhow::bail!(
                    "NumberOfPasswordPrompts at line {} must be at least 1",
                    line_number
                );
            }

            if num > MAX_PASSWORD_PROMPTS {
                anyhow::bail!(
                    "NumberOfPasswordPrompts {} at line {} exceeds maximum allowed value of {}",
                    num,
                    line_number,
                    MAX_PASSWORD_PROMPTS
                );
            }

            // Warn if outside typical range but still within limits
            if !(1..=10).contains(&num) {
                tracing::warn!(
                    "NumberOfPasswordPrompts {} at line {} is outside typical range 1-10. \
                     This may cause security issues or poor user experience",
                    num,
                    line_number
                );
            }

            host.number_of_password_prompts = Some(num);
        }
        "enablesshkeysign" => {
            if args.is_empty() {
                anyhow::bail!("EnableSSHKeysign requires a value at line {line_number}");
            }
            let value = parse_yes_no(&args[0], line_number)?;
            if value {
                tracing::debug!(
                    "EnableSSHKeysign enabled at line {} (security-sensitive: allows ssh-keysign for HostbasedAuthentication)",
                    line_number
                );
            }
            host.enable_ssh_keysign = Some(value);
        }
        _ => unreachable!(
            "Unexpected keyword in parse_authentication_option: {}",
            keyword
        ),
    }

    Ok(())
}
