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

//! SSH port forwarding options parsing
//!
//! Handles forwarding-related configuration options including agent
//! forwarding, X11 forwarding, and various port forwarding settings.

use crate::ssh::ssh_config::parser::helpers::parse_yes_no;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

/// Parse forwarding-related SSH configuration options
pub(super) fn parse_forwarding_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "forwardagent" => {
            if args.is_empty() {
                anyhow::bail!("ForwardAgent requires a value at line {line_number}");
            }
            host.forward_agent = Some(parse_yes_no(&args[0], line_number)?);
        }
        "forwardx11" => {
            if args.is_empty() {
                anyhow::bail!("ForwardX11 requires a value at line {line_number}");
            }
            host.forward_x11 = Some(parse_yes_no(&args[0], line_number)?);
        }
        "localforward" => {
            if args.is_empty() {
                anyhow::bail!("LocalForward requires a value at line {line_number}");
            }
            host.local_forward.push(args.join(" "));
        }
        "remoteforward" => {
            if args.is_empty() {
                anyhow::bail!("RemoteForward requires a value at line {line_number}");
            }
            host.remote_forward.push(args.join(" "));
        }
        "dynamicforward" => {
            if args.is_empty() {
                anyhow::bail!("DynamicForward requires a value at line {line_number}");
            }
            host.dynamic_forward.push(args.join(" "));
        }
        "gatewayports" => {
            if args.is_empty() {
                anyhow::bail!("GatewayPorts requires a value at line {line_number}");
            }
            // Validate GatewayPorts value (yes, no, or clientspecified)
            let value = args[0].to_lowercase();
            match value.as_str() {
                "yes" | "no" | "clientspecified" => {
                    host.gateway_ports = Some(value);
                }
                _ => {
                    anyhow::bail!(
                        "Invalid GatewayPorts value '{}' at line {} (expected yes, no, or clientspecified)",
                        args[0],
                        line_number
                    );
                }
            }
        }
        "exitonforwardfailure" => {
            if args.is_empty() {
                anyhow::bail!("ExitOnForwardFailure requires a value at line {line_number}");
            }
            host.exit_on_forward_failure = Some(parse_yes_no(&args[0], line_number)?);
        }
        "permitremoteopen" => {
            if args.is_empty() {
                anyhow::bail!("PermitRemoteOpen requires at least one value at line {line_number}");
            }
            // PermitRemoteOpen can have multiple host:port patterns or special values
            // Support both space-separated and single value
            host.permit_remote_open
                .extend(args.iter().map(|s| s.to_string()));
        }
        "clearallforwardings" => {
            if args.is_empty() {
                anyhow::bail!("ClearAllForwardings requires a value at line {line_number}");
            }
            host.clear_all_forwardings = Some(parse_yes_no(&args[0], line_number)?);
        }
        "forwardx11timeout" => {
            if args.is_empty() {
                anyhow::bail!("ForwardX11Timeout requires a value at line {line_number}");
            }
            // Store timeout value as string (can be "0" for unlimited or time spec like "1h")
            host.forward_x11_timeout = Some(args[0].clone());
        }
        "forwardx11trusted" => {
            if args.is_empty() {
                anyhow::bail!("ForwardX11Trusted requires a value at line {line_number}");
            }
            host.forward_x11_trusted = Some(parse_yes_no(&args[0], line_number)?);
        }
        _ => unreachable!("Unexpected keyword in parse_forwarding_option: {}", keyword),
    }

    Ok(())
}
