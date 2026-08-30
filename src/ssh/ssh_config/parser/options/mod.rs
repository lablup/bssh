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
mod support;
mod ui;

use super::diagnostic::DiagnosticSource;
use crate::ssh::ssh_config::diagnostic::escape_field;
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;
use std::collections::HashSet;

/// Parse a configuration option for a host
///
/// This function dispatches option parsing to the appropriate
/// category-specific parser based on the keyword.
pub fn parse_option(
    host: &mut SshHostConfig,
    accepted_keyword: &str,
    args: &[String],
    source: DiagnosticSource<'_>,
    reported_diagnostics: &mut HashSet<String>,
) -> Result<()> {
    let line_number = source.number();
    let Some(spec) = support::keyword_spec(accepted_keyword) else {
        host.unknown_options
            .entry(accepted_keyword.to_string())
            .or_insert_with(|| args.to_vec());
        if reported_diagnostics.insert(format!("unknown:{accepted_keyword}")) {
            let keyword = escape_field(accepted_keyword);
            let location = source.location();
            crate::diagnosticln!("Unknown SSH config option '{keyword}' at {location}");
        }
        return Ok(());
    };
    let keyword = spec.canonical;

    if spec.support == support::KeywordSupport::Unimplemented {
        if !args.is_empty() {
            host.unimplemented_options
                .entry(keyword.to_string())
                .or_insert_with(|| args.to_vec());
        }
        if reported_diagnostics.insert(format!("unsupported:{keyword}")) {
            let location = source.location();
            crate::diagnosticln!(
                "Unsupported SSH config option '{keyword}' at {location}; bssh parses this value for inspection but does not implement its runtime behavior"
            );
        }
    }

    match keyword {
        // Basic options
        "hostname" | "user" | "port" => basic::parse_basic_option(host, keyword, args, line_number),

        // Authentication options
        "identityfile"
        | "identitiesonly"
        | "addkeystoagent"
        | "identityagent"
        | "pubkeyacceptedalgorithms"
        | "pubkeyacceptedkeytypes"
        | "certificatefile"
        | "pubkeyauthentication"
        | "passwordauthentication"
        | "kbdinteractiveauthentication"
        | "challengeresponseauthentication"
        | "gssapiauthentication"
        | "preferredauthentications"
        | "hostbasedauthentication"
        | "hostbasedacceptedalgorithms"
        | "hostbasedkeytypes"
        | "numberofpasswordprompts"
        | "enablesshkeysign"
        | "usekeychain" => {
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

        "cipher"
        | "fallbacktorsh"
        | "globalknownhostsfile2"
        | "rhostsauthentication"
        | "securitykeyprovider"
        | "userknownhostsfile2"
        | "useroaming"
        | "usersh"
        | "useprivilegedport"
        | "tunneldevice" => Ok(()),
        _ => unreachable!("accepted keyword is missing a parser: {keyword}"),
    }
}
