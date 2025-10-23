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

//! SSH user interface options parsing
//!
//! Handles UI-related configuration options including TTY settings,
//! escape characters, logging levels, and protocol preferences.

use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

/// Parse UI-related SSH configuration options
pub(super) fn parse_ui_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "requesttty" => {
            if args.is_empty() {
                anyhow::bail!("RequestTTY requires a value at line {line_number}");
            }
            host.request_tty = Some(args[0].clone());
        }
        "escapechar" => {
            if args.is_empty() {
                anyhow::bail!("EscapeChar requires a value at line {line_number}");
            }
            host.escape_char = Some(args[0].clone());
        }
        "loglevel" => {
            if args.is_empty() {
                anyhow::bail!("LogLevel requires a value at line {line_number}");
            }
            host.log_level = Some(args[0].clone());
        }
        "syslogfacility" => {
            if args.is_empty() {
                anyhow::bail!("SyslogFacility requires a value at line {line_number}");
            }
            host.syslog_facility = Some(args[0].clone());
        }
        "protocol" => {
            if args.is_empty() {
                anyhow::bail!("Protocol requires a value at line {line_number}");
            }
            host.protocol = args
                .join(",")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        _ => unreachable!("Unexpected keyword in parse_ui_option: {}", keyword),
    }

    Ok(())
}
