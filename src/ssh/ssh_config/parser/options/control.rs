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

//! SSH control socket options parsing
//!
//! Handles control socket configuration options for connection multiplexing
//! including ControlMaster, ControlPath, and ControlPersist settings.

use crate::ssh::ssh_config::security::validate_control_path;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

/// Parse control socket SSH configuration options
pub(super) fn parse_control_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "controlmaster" => {
            if args.is_empty() {
                anyhow::bail!("ControlMaster requires a value at line {line_number}");
            }
            host.control_master = Some(args[0].clone());
        }
        "controlpath" => {
            if args.is_empty() {
                anyhow::bail!("ControlPath requires a value at line {line_number}");
            }
            let path = args[0].clone();
            // ControlPath has different validation - it allows SSH substitution patterns
            validate_control_path(&path, line_number)?;
            host.control_path = Some(path);
        }
        "controlpersist" => {
            if args.is_empty() {
                anyhow::bail!("ControlPersist requires a value at line {line_number}");
            }
            host.control_persist = Some(args[0].clone());
        }
        _ => unreachable!("Unexpected keyword in parse_control_option: {}", keyword),
    }

    Ok(())
}
