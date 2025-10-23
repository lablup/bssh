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
            // Parse yes/no and store in identity_files behavior (implicit)
            let value = parse_yes_no(&args[0], line_number)?;
            if value {
                // When IdentitiesOnly is yes, clear default identity files
                // This is handled during resolution
            }
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
            let algorithms: Vec<String> = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()) // Skip empty strings from malformed input
                .take(MAX_ALGORITHMS)
                .collect();

            if args.join(",").split(',').count() > MAX_ALGORITHMS {
                tracing::warn!(
                    "HostbasedAcceptedAlgorithms at line {} contains more than {} algorithms, truncated to first {}",
                    line_number, MAX_ALGORITHMS, MAX_ALGORITHMS
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
            if !(1..=10).contains(&num) {
                tracing::warn!(
                    "NumberOfPasswordPrompts {} at line {} is outside typical range 1-10",
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
            host.enable_ssh_keysign = Some(parse_yes_no(&args[0], line_number)?);
        }
        _ => unreachable!(
            "Unexpected keyword in parse_authentication_option: {}",
            keyword
        ),
    }

    Ok(())
}
