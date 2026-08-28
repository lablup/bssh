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

//! SSH environment options parsing
//!
//! Handles environment-related configuration options including SendEnv
//! and SetEnv settings for passing environment variables to remote hosts.

use super::command::validate_default_percent_tokens;
use crate::ssh::session_policy::{MAX_ENVIRONMENT_VALUE_BYTES, validate_environment};
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse environment-related SSH configuration options
pub(super) fn parse_environment_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "sendenv" => {
            if args.is_empty() {
                anyhow::bail!("SendEnv requires a value at line {line_number}");
            }
            host.send_env.extend(args.iter().map(|s| s.to_string()));
        }
        "setenv" => {
            if args.is_empty() {
                anyhow::bail!("SetEnv requires at least one name=value pair at line {line_number}");
            }
            // SetEnv can have multiple name=value pairs
            // If we have a single arg (from equals syntax), it might contain multiple pairs
            let pairs: Vec<&str> = if args.len() == 1 && args[0].contains('=') {
                // Single arg from equals syntax - might have multiple name=value pairs
                args[0].split_whitespace().collect()
            } else {
                // Multiple args from space syntax - convert to &str references
                args.iter().map(String::as_str).collect()
            };

            for pair in pairs {
                if let Some(eq_pos) = pair.find('=') {
                    let name = pair[..eq_pos].to_string();
                    let value = pair[eq_pos + 1..].to_string();
                    validate_environment(&name, &value)
                        .with_context(|| format!("Invalid SetEnv entry at line {line_number}"))?;
                    validate_default_percent_tokens(
                        &value,
                        "SetEnv value",
                        line_number,
                        MAX_ENVIRONMENT_VALUE_BYTES,
                    )?;
                    validate_dollar_expansions(&value, line_number)?;
                    host.set_env.entry(name).or_insert(value);
                } else {
                    anyhow::bail!(
                        "Invalid SetEnv format '{pair}' at line {line_number} (expected name=value)"
                    );
                }
            }
        }
        _ => unreachable!(
            "Unexpected keyword in parse_environment_option: {}",
            keyword
        ),
    }

    Ok(())
}

fn validate_dollar_expansions(value: &str, line_number: usize) -> Result<()> {
    let mut remaining = value;
    while let Some(start) = remaining.find("${") {
        let variable = &remaining[start + 2..];
        let Some(end) = variable.find('}') else {
            anyhow::bail!(
                "SetEnv environment variable expansion is missing closing '}}' at line {line_number}"
            );
        };
        if end == 0 {
            anyhow::bail!(
                "SetEnv environment variable expansion has an empty name at line {line_number}"
            );
        }
        remaining = &variable[end + 1..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setenv_accepts_default_tokens_and_dollar_expansion_syntax() {
        let mut config = SshHostConfig::default();
        let value = "VALUE=%%:%C:%d:%h:%i:%j:%k:%L:%l:%n:%p:%r:%u:${HOME}";
        parse_environment_option(&mut config, "setenv", &[value.into()], 7).unwrap();
        assert_eq!(
            config.set_env.get("VALUE").map(String::as_str),
            Some("%%:%C:%d:%h:%i:%j:%k:%L:%l:%n:%p:%r:%u:${HOME}")
        );

        parse_environment_option(&mut config, "setenv", &["EMPTY=".into()], 8).unwrap();
        assert_eq!(config.set_env.get("EMPTY").map(String::as_str), Some(""));
    }

    #[test]
    fn setenv_rejects_directive_foreign_tokens_and_malformed_dollar_syntax() {
        for value in [
            "VALUE=%H",
            "VALUE=%T",
            "VALUE=%x",
            "VALUE=${BROKEN",
            "VALUE=${}",
        ] {
            let mut config = SshHostConfig::default();
            assert!(
                parse_environment_option(&mut config, "setenv", &[value.into()], 9).is_err(),
                "{value} must be rejected"
            );
        }
    }
}
