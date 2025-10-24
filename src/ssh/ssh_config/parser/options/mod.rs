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

//! SSH configuration option parsing
//!
//! This module provides a dispatcher that routes option parsing to
//! category-specific parsers for better code organization.

mod authentication;
mod basic;
mod command;
mod connection;
mod control;
mod environment;
mod forwarding;
mod proxy;
mod security;
mod ui;

use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

/// Parse a configuration option for a host
///
/// This function dispatches option parsing to the appropriate
/// category-specific parser based on the keyword.
pub fn parse_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        // Basic options
        "hostname" | "user" | "port" => basic::parse_basic_option(host, keyword, args, line_number),

        // Authentication options
        "identityfile"
        | "identitiesonly"
        | "addkeystoagent"
        | "identityagent"
        | "pubkeyacceptedalgorithms"
        | "certificatefile"
        | "pubkeyauthentication"
        | "passwordauthentication"
        | "kbdinteractiveauthentication"
        | "gssapiauthentication"
        | "preferredauthentications"
        | "hostbasedauthentication"
        | "hostbasedacceptedalgorithms"
        | "numberofpasswordprompts"
        | "enablesshkeysign" => {
            authentication::parse_authentication_option(host, keyword, args, line_number)
        }

        // Security options
        "stricthostkeychecking"
        | "userknownhostsfile"
        | "globalknownhostsfile"
        | "hostkeyalgorithms"
        | "kexalgorithms"
        | "ciphers"
        | "macs"
        | "casignaturealgorithms"
        | "nohostauthenticationforlocalhost"
        | "hashknownhosts"
        | "checkhostip"
        | "visualhostkey"
        | "hostkeyalias"
        | "verifyhostkeydns"
        | "updatehostkeys"
        | "requiredrsasize"
        | "fingerprinthash" => security::parse_security_option(host, keyword, args, line_number),

        // Forwarding options
        "forwardagent"
        | "forwardx11"
        | "localforward"
        | "remoteforward"
        | "dynamicforward"
        | "gatewayports"
        | "exitonforwardfailure"
        | "permitremoteopen"
        | "clearallforwardings"
        | "forwardx11timeout"
        | "forwardx11trusted" => {
            forwarding::parse_forwarding_option(host, keyword, args, line_number)
        }

        // Connection options
        "serveraliveinterval"
        | "serveralivecountmax"
        | "connecttimeout"
        | "connectionattempts"
        | "batchmode"
        | "compression"
        | "tcpkeepalive"
        | "addressfamily"
        | "bindaddress"
        | "bindinterface"
        | "ipqos"
        | "rekeylimit" => connection::parse_connection_option(host, keyword, args, line_number),

        // Proxy options
        "proxyjump" | "proxycommand" | "proxyusefdpass" => {
            proxy::parse_proxy_option(host, keyword, args, line_number)
        }

        // Control options
        "controlmaster" | "controlpath" | "controlpersist" => {
            control::parse_control_option(host, keyword, args, line_number)
        }

        // Environment options
        "sendenv" | "setenv" => {
            environment::parse_environment_option(host, keyword, args, line_number)
        }

        // UI options
        "requesttty" | "escapechar" | "loglevel" | "syslogfacility" | "protocol" => {
            ui::parse_ui_option(host, keyword, args, line_number)
        }

        // Command execution options
        "permitlocalcommand"
        | "localcommand"
        | "remotecommand"
        | "knownhostscommand"
        | "forkafterauthentication"
        | "sessiontype"
        | "stdinnull" => command::parse_command_option(host, keyword, args, line_number),

        _ => {
            // Unknown option - log a warning but continue
            tracing::warn!(
                "Unknown SSH config option '{}' at line {}",
                keyword,
                line_number
            );
            Ok(())
        }
    }
}
