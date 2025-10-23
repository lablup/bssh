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

//! SSH proxy options parsing
//!
//! Handles proxy-related configuration options including ProxyJump
//! and ProxyCommand settings.

use crate::ssh::ssh_config::security::validate_executable_string;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

/// Parse proxy-related SSH configuration options
pub(super) fn parse_proxy_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "proxyjump" => {
            if args.is_empty() {
                anyhow::bail!("ProxyJump requires a value at line {line_number}");
            }
            host.proxy_jump = Some(args.join(" "));
        }
        "proxycommand" => {
            if args.is_empty() {
                anyhow::bail!("ProxyCommand requires a value at line {line_number}");
            }
            let command = args.join(" ");
            validate_executable_string(&command, "ProxyCommand", line_number)?;
            host.proxy_command = Some(command);
        }
        _ => unreachable!("Unexpected keyword in parse_proxy_option: {}", keyword),
    }

    Ok(())
}
