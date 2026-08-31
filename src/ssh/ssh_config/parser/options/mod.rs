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
            crate::warningln!("Unknown SSH config option '{keyword}' at {location}");
        }
        return Ok(());
    };
    let keyword = spec.canonical;

    let enforced_gssapi_disable = keyword == "gssapidelegatecredentials"
        && args
            .first()
            .is_some_and(|value| value.eq_ignore_ascii_case("no"));
    if spec.support == support::KeywordSupport::Unimplemented && !enforced_gssapi_disable {
        validate_retained_option(keyword, args, line_number)?;
        if !args.is_empty() {
            host.unimplemented_options
                .entry(keyword.to_string())
                .or_insert_with(|| args.to_vec());
        }
        if reported_diagnostics.insert(format!("unsupported:{keyword}")) {
            let location = source.location();
            crate::warningln!(
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
        | "gssapidelegatecredentials"
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
        | "tunneldevice"
        | "canonicalizefallbacklocal"
        | "canonicalizehostname"
        | "canonicalizemaxdots"
        | "canonicaldomains"
        | "canonicalizepermittedcnames"
        | "channeltimeout"
        | "enableescapecommandline"
        | "logverbose"
        | "obscurekeystroketiming"
        | "streamlocalbindunlink"
        | "streamlocalbindmask"
        | "tunnel"
        | "warnweakcrypto"
        | "xauthlocation"
        | "revokedhostkeys" => Ok(()),
        _ => unreachable!("accepted keyword is missing a parser: {keyword}"),
    }
}

fn validate_retained_option(keyword: &str, args: &[String], line_number: usize) -> Result<()> {
    let one = || {
        if args.len() != 1 || args[0].is_empty() {
            anyhow::bail!("{keyword} expects exactly one value at line {line_number}");
        }
        Ok(())
    };
    let boolean = || {
        one()?;
        if !matches!(
            args[0].to_ascii_lowercase().as_str(),
            "yes" | "no" | "true" | "false"
        ) {
            anyhow::bail!("Invalid boolean for {keyword} at line {line_number}");
        }
        Ok(())
    };
    match keyword {
        "canonicalizefallbacklocal" => {
            boolean()?;
        }
        "canonicalizehostname" => {
            one()?;
            if !matches!(
                args[0].to_ascii_lowercase().as_str(),
                "yes" | "no" | "always" | "true" | "false"
            ) {
                anyhow::bail!("Invalid canonicalizehostname at line {line_number}");
            }
        }
        "canonicalizemaxdots" => {
            one()?;
            args[0].parse::<u32>().map_err(|_| {
                anyhow::anyhow!("Invalid canonicalizemaxdots at line {line_number}")
            })?;
        }
        "canonicaldomains" | "canonicalizepermittedcnames" => {
            if args.is_empty() {
                anyhow::bail!("{keyword} requires at least one value at line {line_number}");
            }
        }
        "enableescapecommandline" | "streamlocalbindunlink" | "warnweakcrypto" => boolean()?,
        "tunnel" => {
            one()?;
            if !matches!(
                args[0].to_ascii_lowercase().as_str(),
                "yes" | "no" | "true" | "false" | "point-to-point" | "ethernet"
            ) {
                anyhow::bail!("Invalid tunnel value at line {line_number}");
            }
        }
        "streamlocalbindmask" => {
            one()?;
            let mode = u32::from_str_radix(&args[0], 8).map_err(|_| {
                anyhow::anyhow!("Invalid streamlocalbindmask at line {line_number}")
            })?;
            if mode > 0o777 {
                anyhow::bail!("Invalid streamlocalbindmask at line {line_number}");
            }
        }
        "tunneldevice" => {
            one()?;
            let component = |part: &str| part == "any" || part.parse::<u32>().is_ok();
            let valid = args[0].split_once(':').map_or_else(
                || component(&args[0]),
                |(local, remote)| component(local) && component(remote),
            );
            if !valid {
                anyhow::bail!("Invalid tunneldevice at line {line_number}");
            }
        }
        "obscurekeystroketiming" => {
            one()?;
            let value = args[0].to_ascii_lowercase();
            if !matches!(value.as_str(), "yes" | "no" | "true" | "false")
                && !value
                    .strip_prefix("interval:")
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_some_and(|value| (1..=1000).contains(&value))
            {
                anyhow::bail!("Invalid obscurekeystroketiming at line {line_number}");
            }
        }
        "securitykeyprovider" | "xauthlocation" | "revokedhostkeys" => one()?,
        "channeltimeout" | "logverbose" if args.is_empty() => {
            anyhow::bail!("{keyword} expects at least one value at line {line_number}");
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ssh::ssh_config::SshConfig;

    #[test]
    fn accepts_audited_retained_value_grammars() {
        let valid = r#"
Host *
    CanonicalizeFallbackLocal yes
    CanonicalizeHostname false
    CanonicalizeMaxDots 1
    CanonicalDomains none
    CanonicalizePermittedCNAMEs none
    ChannelTimeout none
    EnableEscapeCommandline no
    LogVerbose none
    ObscureKeystrokeTiming interval:1000
    StreamLocalBindUnlink yes
    StreamLocalBindMask 0000
    Tunnel point-to-point
    TunnelDevice any
    WarnWeakCrypto yes
    SecurityKeyProvider /tmp/provider
    XAuthLocation /usr/bin/xauth
    RevokedHostKeys none
"#;
        assert!(SshConfig::parse(valid).is_ok());
        assert!(SshConfig::parse("Host *\nStreamLocalBindMask 0777\n").is_ok());
        assert!(SshConfig::parse("Host *\nTunnelDevice 1:any\n").is_ok());
        assert!(SshConfig::parse("Host *\nObscureKeystrokeTiming interval:1\n").is_ok());
        assert!(SshConfig::parse("Host *\nCanonicalizeFallbackLocal no\n").is_ok());
        assert!(SshConfig::parse("Host *\nCanonicalizeHostname yes\n").is_ok());
        assert!(SshConfig::parse("Host *\nCanonicalizeMaxDots 2\n").is_ok());
        assert!(SshConfig::parse("Host *\nCanonicalDomains example.com\n").is_ok());
        assert!(SshConfig::parse("Host *\nCanonicalizePermittedCNAMEs *.a:*.b\n").is_ok());
    }

    #[test]
    fn rejects_invalid_retained_values() {
        for option in [
            "CanonicalizeFallbackLocal maybe",
            "CanonicalizeHostname maybe",
            "CanonicalizeMaxDots nope",
            "CanonicalDomains",
            "CanonicalizePermittedCNAMEs",
            "ChannelTimeout",
            "EnableEscapeCommandline maybe",
            "LogVerbose",
            "ObscureKeystrokeTiming interval:0",
            "ObscureKeystrokeTiming interval:1001",
            "StreamLocalBindUnlink maybe",
            "StreamLocalBindMask 1000",
            "Tunnel invalid",
            "TunnelDevice any:invalid",
            "WarnWeakCrypto maybe",
            "SecurityKeyProvider",
            "XAuthLocation",
            "RevokedHostKeys",
        ] {
            let config = format!("Host *\n    {option}\n");
            assert!(SshConfig::parse(&config).is_err(), "accepted {option}");
        }
    }

    #[test]
    fn existing_opaque_legacy_values_keep_their_previous_behavior() {
        assert!(SshConfig::parse("Host *\n    UseKeychain yes\n").is_ok());
        assert!(SshConfig::parse("Host *\n    UseKeychain arbitrary legacy value\n").is_err());
    }
}
