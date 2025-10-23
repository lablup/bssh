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

//! Basic SSH configuration options parsing
//!
//! Handles fundamental connection options like hostname, user, and port.

use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::{Context, Result};

/// Parse basic SSH configuration options
pub(super) fn parse_basic_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "hostname" => {
            if args.is_empty() {
                anyhow::bail!("HostName requires a value at line {line_number}");
            }
            host.hostname = Some(args[0].clone());
        }
        "user" => {
            if args.is_empty() {
                anyhow::bail!("User requires a value at line {line_number}");
            }
            host.user = Some(args[0].clone());
        }
        "port" => {
            if args.is_empty() {
                anyhow::bail!("Port requires a value at line {line_number}");
            }
            let port: u16 = args[0].parse().with_context(|| {
                format!("Invalid port number '{}' at line {}", args[0], line_number)
            })?;
            host.port = Some(port);
        }
        _ => unreachable!("Unexpected keyword in parse_basic_option: {}", keyword),
    }

    Ok(())
}
