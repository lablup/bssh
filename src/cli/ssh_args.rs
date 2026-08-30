// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Order-preserving extraction of ssh_config command-line options.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Inputs needed by `ssh -G`, in the order OpenSSH obtains them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDumpInvocation {
    pub destination: String,
    pub config_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub overrides: Vec<String>,
}

impl SshDumpInvocation {
    /// Preserve OpenSSH's two-pass argv behavior: after capturing the first
    /// destination, another option group may follow. The next non-option is
    /// the remote command and ends option processing.
    pub fn requests_config_dump(args: &[String]) -> bool {
        scan_for_dump_flag(args)
    }

    /// Extract `-E` before fallible validation so every `-G` diagnostic uses
    /// the requested sink, including errors later in the second option pass.
    pub fn diagnostic_file(args: &[String]) -> Option<PathBuf> {
        scan_diagnostic_file(args)
    }

    pub fn from_argv(args: &[String]) -> Result<Self> {
        let mut overrides = Vec::new();
        let mut priority_overrides = Vec::new();
        let mut config_file = None;
        let mut log_file = None;
        let mut index = 1usize;
        let mut destination = None;
        let mut options_terminated = false;
        let mut stdio_forward = false;
        let mut saw_dump = false;

        while index < args.len() {
            let argument = &args[index];
            if argument == "--" {
                if destination.is_some() {
                    break;
                }
                options_terminated = true;
                index += 1;
                continue;
            }
            if !argument.starts_with('-') && destination.is_none() {
                add_destination_overrides(argument, &mut overrides)?;
                destination = Some(argument.clone());
                index += 1;
                if options_terminated {
                    break;
                }
                continue;
            }
            if destination.is_some() && !argument.starts_with('-') {
                break;
            }

            if let Some(long) = argument.strip_prefix("--") {
                let (name, attached) = long
                    .split_once('=')
                    .map_or((long, None), |(name, value)| (name, Some(value)));
                if let Some(value_name) = long_value_name(name) {
                    let (value, consumed) = value_for(args, index, attached, value_name)?;
                    apply_value(
                        value_name,
                        value,
                        &mut config_file,
                        &mut log_file,
                        &mut overrides,
                        &mut priority_overrides,
                    )?;
                    stdio_forward |= value_name == "stdio-forward";
                    index += consumed;
                } else {
                    match name {
                        "print-config" => saw_dump = true,
                        "ipv4" => set_priority(
                            &mut priority_overrides,
                            "addressfamily",
                            "AddressFamily=inet",
                        ),
                        "ipv6" => set_priority(
                            &mut priority_overrides,
                            "addressfamily",
                            "AddressFamily=inet6",
                        ),
                        "tty" => {
                            set_priority(&mut priority_overrides, "requesttty", "RequestTTY=yes")
                        }
                        "no-tty" => {
                            set_priority(&mut priority_overrides, "requesttty", "RequestTTY=no")
                        }
                        "no-x11" => {
                            set_priority(&mut priority_overrides, "forwardx11", "ForwardX11=no")
                        }
                        _ => anyhow::bail!("Unknown option '--{name}'"),
                    }
                }
                index += 1;
                continue;
            }

            if let Some(shorts) = argument.strip_prefix('-') {
                for (position, short) in shorts.char_indices() {
                    let value_name = match short {
                        'o' => Some("option"),
                        'l' => Some("login"),
                        'p' => Some("port"),
                        'i' => Some("identity"),
                        'J' => Some("jump-host"),
                        'c' => Some("cipher"),
                        'm' => Some("macs"),
                        'F' => Some("ssh-config"),
                        'L' => Some("local-forward"),
                        'R' => Some("remote-forward"),
                        'D' => Some("dynamic-forward"),
                        'W' => Some("stdio-forward"),
                        'E' => Some("diagnostic-file"),
                        'Q' => Some("query"),
                        'B' => Some("bind-interface"),
                        'b' => Some("bind-address"),
                        'e' => Some("escape-char"),
                        'I' => Some("pkcs11-provider"),
                        'O' => Some("control-command"),
                        'P' => Some("tag"),
                        'S' => Some("control-path"),
                        'w' => Some("tunnel-device"),
                        _ => None,
                    };
                    if let Some(name) = value_name {
                        let value_start = position + short.len_utf8();
                        let attached = shorts
                            .get(value_start..)
                            .filter(|remaining| !remaining.is_empty());
                        let (value, consumed) = value_for(args, index, attached, name)?;
                        apply_value(
                            name,
                            value,
                            &mut config_file,
                            &mut log_file,
                            &mut overrides,
                            &mut priority_overrides,
                        )?;
                        stdio_forward |= name == "stdio-forward";
                        index += consumed;
                        break;
                    }
                    match short {
                        'G' => saw_dump = true,
                        '4' => set_priority(
                            &mut priority_overrides,
                            "addressfamily",
                            "AddressFamily=inet",
                        ),
                        '6' => set_priority(
                            &mut priority_overrides,
                            "addressfamily",
                            "AddressFamily=inet6",
                        ),
                        'A' => set_priority(
                            &mut priority_overrides,
                            "forwardagent",
                            "ForwardAgent=yes",
                        ),
                        'a' => {
                            set_priority(&mut priority_overrides, "forwardagent", "ForwardAgent=no")
                        }
                        'X' => {
                            set_priority(&mut priority_overrides, "forwardx11", "ForwardX11=yes")
                        }
                        'x' => set_priority(&mut priority_overrides, "forwardx11", "ForwardX11=no"),
                        't' => {
                            set_priority(&mut priority_overrides, "requesttty", "RequestTTY=yes")
                        }
                        'T' => set_priority(&mut priority_overrides, "requesttty", "RequestTTY=no"),
                        'C' => {
                            set_priority(&mut priority_overrides, "compression", "Compression=yes")
                        }
                        'N' => {
                            set_priority(&mut priority_overrides, "sessiontype", "SessionType=none")
                        }
                        'n' => set_priority(&mut priority_overrides, "stdinnull", "StdinNull=yes"),
                        'f' => set_priority(
                            &mut priority_overrides,
                            "forkafterauthentication",
                            "ForkAfterAuthentication=yes",
                        ),
                        'g' => set_priority(
                            &mut priority_overrides,
                            "gatewayports",
                            "GatewayPorts=yes",
                        ),
                        'M' => set_priority(
                            &mut priority_overrides,
                            "controlmaster",
                            "ControlMaster=yes",
                        ),
                        's' => set_priority(
                            &mut priority_overrides,
                            "sessiontype",
                            "SessionType=subsystem",
                        ),
                        'Y' => {
                            set_priority(&mut priority_overrides, "forwardx11", "ForwardX11=yes");
                            set_priority(
                                &mut priority_overrides,
                                "forwardx11trusted",
                                "ForwardX11Trusted=yes",
                            );
                        }
                        'q' | 'v' | 'V' | 'y' => {}
                        _ => anyhow::bail!("Unknown option '-{short}'"),
                    }
                }
            }
            index += 1;
        }

        if !saw_dump {
            anyhow::bail!("Resolved configuration invocation is missing -G");
        }
        let destination = destination.context("-G requires a destination")?;
        let destination = destination.strip_prefix("ssh://").unwrap_or(&destination);
        let parsed = crate::node::parse_node_spec(destination)
            .context("Invalid destination for resolved configuration")?;
        if stdio_forward {
            for (keyword, implicit) in [
                ("clearallforwardings", "ClearAllForwardings=yes"),
                ("exitonforwardfailure", "ExitOnForwardFailure=yes"),
            ] {
                if !overrides.iter().any(|option| {
                    option
                        .split_once('=')
                        .is_some_and(|(key, _)| key.eq_ignore_ascii_case(keyword))
                }) {
                    overrides.push(implicit.to_string());
                }
            }
        }

        let mut all_overrides = priority_overrides
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        all_overrides.extend(overrides);

        Ok(Self {
            destination: parsed.host.to_string(),
            config_file,
            log_file,
            overrides: all_overrides,
        })
    }
}

fn add_destination_overrides(destination: &str, overrides: &mut Vec<String>) -> Result<()> {
    let destination = destination.strip_prefix("ssh://").unwrap_or(destination);
    let parsed = crate::node::parse_node_spec(destination)
        .context("Invalid destination for resolved configuration")?;
    if let Some(user) = parsed.user {
        overrides.push(format!("User={}", literal_user(user)?));
    }
    if let Some(port) = parsed.port {
        overrides.push(format!("Port={port}"));
    }
    Ok(())
}

fn value_for<'a>(
    args: &'a [String],
    index: usize,
    attached: Option<&'a str>,
    name: &str,
) -> Result<(&'a str, usize)> {
    if let Some(value) = attached {
        return Ok((value, 0));
    }
    args.get(index + 1)
        .map(|value| (value.as_str(), 1))
        .with_context(|| format!("-{name} requires an argument"))
}

fn apply_value(
    name: &str,
    value: &str,
    config_file: &mut Option<PathBuf>,
    log_file: &mut Option<PathBuf>,
    overrides: &mut Vec<String>,
    priority_overrides: &mut Vec<(&'static str, String)>,
) -> Result<()> {
    let option = match name {
        "option" => value.to_string(),
        "login" => format!("User={}", literal_user(value)?),
        "port" => {
            value
                .parse::<u16>()
                .with_context(|| format!("Invalid port '{value}'"))?;
            format!("Port={value}")
        }
        "identity" => format!("IdentityFile={value}"),
        "jump-host" => format!("ProxyJump={value}"),
        "cipher" => {
            set_priority(priority_overrides, "ciphers", format!("Ciphers={value}"));
            return Ok(());
        }
        "macs" => {
            set_priority(priority_overrides, "macs", format!("MACs={value}"));
            return Ok(());
        }
        "local-forward" => format!("LocalForward={value}"),
        "remote-forward" => format!("RemoteForward={value}"),
        "dynamic-forward" => format!("DynamicForward={value}"),
        "stdio-forward" => {
            validate_stdio_forward(value)?;
            return Ok(());
        }
        "diagnostic-file" => {
            *log_file = Some(PathBuf::from(value));
            return Ok(());
        }
        "query" => return Ok(()),
        "bind-interface" => format!("BindInterface={value}"),
        "bind-address" => format!("BindAddress={value}"),
        "escape-char" => format!("EscapeChar={value}"),
        "control-path" => format!("ControlPath={value}"),
        "tunnel-device" => format!("TunnelDevice={value}"),
        "pkcs11-provider" | "control-command" | "tag" => {
            anyhow::bail!("Option '-{name}' is not supported with -G")
        }
        "ssh-config" => {
            *config_file = Some(PathBuf::from(value));
            return Ok(());
        }
        _ => return Ok(()),
    };
    overrides.push(option);
    Ok(())
}

fn set_priority(
    overrides: &mut Vec<(&'static str, String)>,
    keyword: &'static str,
    value: impl Into<String>,
) {
    if let Some(existing) = overrides.iter_mut().find(|(key, _)| *key == keyword) {
        existing.1 = value.into();
    } else {
        overrides.push((keyword, value.into()));
    }
}

fn validate_stdio_forward(value: &str) -> Result<()> {
    let (host, port) = value.rsplit_once(':').context("-W requires host:port")?;
    let valid_host = !host.is_empty()
        && if host.starts_with('[') {
            host.ends_with(']') && host.len() > 2
        } else {
            !host.contains(':') && !host.ends_with(']')
        };
    let valid_port = match port.parse::<u16>() {
        Ok(port) => port > 0,
        Err(_) => service_exists(port),
    };
    if !valid_host || !valid_port {
        anyhow::bail!("Invalid -W target '{value}'; expected host:port");
    }
    Ok(())
}

#[cfg(unix)]
fn service_exists(name: &str) -> bool {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return false;
    }
    std::fs::read_to_string("/etc/services")
        .ok()
        .is_some_and(|services| {
            services.lines().any(|line| {
                let fields = line
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                fields.get(1).is_some_and(|port| port.ends_with("/tcp"))
                    && fields
                        .iter()
                        .enumerate()
                        .any(|(index, field)| index != 1 && *field == name)
            })
        })
}

#[cfg(not(unix))]
fn service_exists(_name: &str) -> bool {
    false
}

fn scan_for_dump_flag(args: &[String]) -> bool {
    let mut index = 1usize;
    let mut destination_seen = false;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            if destination_seen {
                break;
            }
            index += 1;
            if index < args.len() {
                destination_seen = true;
            }
            index += 1;
            continue;
        }
        if !argument.starts_with('-') || argument == "-" {
            if destination_seen {
                break;
            }
            destination_seen = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            if name == "print-config" {
                return true;
            }
            if long_takes_value(name) && !attached {
                index += 1;
            }
        } else if let Some(shorts) = argument.strip_prefix('-') {
            for (position, short) in shorts.char_indices() {
                if short == 'G' {
                    return true;
                }
                if short_takes_value(short) {
                    if position + short.len_utf8() == shorts.len() {
                        index += 1;
                    }
                    break;
                }
            }
        }
        index += 1;
    }
    false
}

fn scan_diagnostic_file(args: &[String]) -> Option<PathBuf> {
    let mut result = None;
    let mut index = 1usize;
    let mut destination_seen = false;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            if destination_seen {
                break;
            }
            index += 2;
            destination_seen = true;
            continue;
        }
        if !argument.starts_with('-') || argument == "-" {
            if destination_seen {
                break;
            }
            destination_seen = true;
            index += 1;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if long_takes_value(name) {
                let value = attached.or_else(|| args.get(index + 1).map(String::as_str));
                if name == "diagnostic-file" {
                    result = value.map(PathBuf::from);
                }
                if attached.is_none() {
                    index += 1;
                }
            }
        } else if let Some(shorts) = argument.strip_prefix('-') {
            for (position, short) in shorts.char_indices() {
                if !short_takes_value(short) {
                    continue;
                }
                let value_start = position + short.len_utf8();
                let attached = shorts
                    .get(value_start..)
                    .filter(|remaining| !remaining.is_empty());
                let value = attached.or_else(|| args.get(index + 1).map(String::as_str));
                if short == 'E' {
                    result = value.map(PathBuf::from);
                }
                if attached.is_none() {
                    index += 1;
                }
                break;
            }
        }
        index += 1;
    }
    result
}

fn short_takes_value(short: char) -> bool {
    matches!(
        short,
        'B' | 'b'
            | 'c'
            | 'D'
            | 'E'
            | 'e'
            | 'F'
            | 'I'
            | 'i'
            | 'J'
            | 'L'
            | 'l'
            | 'm'
            | 'O'
            | 'o'
            | 'P'
            | 'p'
            | 'Q'
            | 'R'
            | 'S'
            | 'W'
            | 'w'
    )
}

fn long_takes_value(name: &str) -> bool {
    long_value_name(name).is_some()
}

fn long_value_name(name: &str) -> Option<&str> {
    matches!(
        name,
        "option"
            | "login"
            | "port"
            | "identity"
            | "jump-host"
            | "cipher"
            | "macs"
            | "ssh-config"
            | "local-forward"
            | "remote-forward"
            | "dynamic-forward"
            | "stdio-forward"
            | "diagnostic-file"
            | "bind-interface"
            | "bind-address"
            | "escape-char"
            | "pkcs11-provider"
            | "control-command"
            | "tag"
            | "control-path"
            | "tunnel-device"
    )
    .then_some(name)
}

fn literal_user(value: &str) -> Result<String> {
    let chars = value.chars().collect::<Vec<_>>();
    let forbidden = "'`\";&<>|(){}";
    if value.starts_with('-')
        || chars
            .iter()
            .any(|ch| ch.is_control() || forbidden.contains(*ch))
        || chars
            .windows(2)
            .any(|pair| pair[0].is_whitespace() && pair[1] == '-')
        || value.ends_with('\\')
    {
        anyhow::bail!("Remote username contains invalid characters");
    }
    Ok(value.replace('$', "$$").replace('%', "%%"))
}

#[cfg(test)]
mod tests {
    use super::SshDumpInvocation;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn preserves_order_across_second_option_pass() {
        let argv = args(&[
            "bssh",
            "-G6",
            "-oUser=first",
            "-lsecond",
            "host",
            "-o",
            "Port=9",
        ]);
        let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
        assert_eq!(
            parsed.overrides,
            ["AddressFamily=inet6", "User=first", "User=second", "Port=9"]
        );
    }

    #[test]
    fn destination_values_are_last_and_ipv6_is_unwrapped() {
        let argv = args(&["bssh", "-Gp2200", "user@[::1]:2300"]);
        let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
        assert_eq!(parsed.destination, "::1");
        assert_eq!(parsed.overrides, ["Port=2200", "User=user", "Port=2300"]);
    }

    #[test]
    fn stdio_forward_implicit_clear_is_overridden_by_explicit_option() {
        let implicit = args(&["bssh", "-GF", "none", "-W", "a:1", "host"]);
        let parsed = SshDumpInvocation::from_argv(&implicit).unwrap();
        assert!(
            parsed
                .overrides
                .contains(&"ClearAllForwardings=yes".to_string())
        );
        assert!(
            parsed
                .overrides
                .contains(&"ExitOnForwardFailure=yes".to_string())
        );

        let explicit = args(&[
            "bssh",
            "-GF",
            "none",
            "-W",
            "a:1",
            "-o",
            "ClearAllForwardings=no",
            "host",
        ]);
        let parsed = SshDumpInvocation::from_argv(&explicit).unwrap();
        assert!(
            !parsed
                .overrides
                .contains(&"ClearAllForwardings=yes".to_string())
        );
    }

    #[test]
    fn matches_sshcfgparse_user_first_obtained_cases() {
        let cases = [
            (
                vec!["bssh", "-G", "-o", "user=foo", "-l", "bar", "baz@host"],
                "foo",
            ),
            (
                vec!["bssh", "-G", "-lbar", "baz@host", "user=foo", "baz@host"],
                "bar",
            ),
            (
                vec![
                    "bssh", "-G", "baz@host", "-o", "user=foo", "-l", "bar", "baz@host",
                ],
                "baz",
            ),
        ];
        for (values, expected) in cases {
            let argv = args(&values);
            let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
            let first_user = parsed.overrides.iter().find_map(|option| {
                option
                    .to_ascii_lowercase()
                    .strip_prefix("user=")
                    .map(str::to_string)
            });
            assert_eq!(first_user.as_deref(), Some(expected));
        }
    }

    #[test]
    fn double_dash_prevents_a_second_option_pass() {
        let argv = args(&["bssh", "-GF", "none", "--", "host", "-l", "late"]);
        let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
        assert!(!parsed.overrides.iter().any(|option| option == "User=late"));
    }

    #[test]
    fn ignored_value_options_consume_attached_and_separate_values_once() {
        let attached = args(&["bssh", "-G", "-E/tmp/path/containing/options.log", "host"]);
        let separate = args(&[
            "bssh",
            "-G",
            "-E",
            "/tmp/path/containing/options.log",
            "host",
        ]);
        for argv in [attached, separate] {
            let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
            assert!(parsed.overrides.is_empty());
        }
    }

    #[test]
    fn validates_remote_user_without_expanding_percent_tokens() {
        let literal = args(&["bssh", "-G", "-l%u", "host"]);
        let parsed = SshDumpInvocation::from_argv(&literal).unwrap();
        assert_eq!(parsed.overrides, ["User=%%u"]);

        for invalid in ["${FOO}", "bad\u{7}user", "-flag", "bad\\"] {
            let argv = args(&["bssh", "-G", "-l", invalid, "host"]);
            assert!(SshDumpInvocation::from_argv(&argv).is_err());
        }
    }

    #[test]
    fn direct_algorithms_override_o_and_inverse_flags_use_last_value() {
        for argv in [
            args(&["bssh", "-G", "-o", "Ciphers=first", "-c", "last", "host"]),
            args(&["bssh", "-G", "-c", "last", "-o", "Ciphers=first", "host"]),
        ] {
            let parsed = SshDumpInvocation::from_argv(&argv).unwrap();
            assert_eq!(
                parsed.overrides.first().map(String::as_str),
                Some("Ciphers=last")
            );
        }

        let disabled = SshDumpInvocation::from_argv(&args(&["bssh", "-GtT", "host"])).unwrap();
        assert!(disabled.overrides.contains(&"RequestTTY=no".to_string()));
        let enabled = SshDumpInvocation::from_argv(&args(&["bssh", "-GTt", "host"])).unwrap();
        assert!(enabled.overrides.contains(&"RequestTTY=yes".to_string()));
    }

    #[test]
    fn rejects_unknown_options_and_invalid_stdio_forward_targets() {
        for argv in [
            args(&["bssh", "-G", "-Z", "host"]),
            args(&["bssh", "-G", "host", "-Z", "value"]),
            args(&["bssh", "-G", "-W", "missing-port", "host"]),
            args(&["bssh", "-GW[::1]", "host"]),
            args(&["bssh", "-GW::1:22", "host"]),
            args(&["bssh", "-GWhost:0", "host"]),
            args(&["bssh", "-GWhost:definitely-not-a-service", "host"]),
        ] {
            assert!(SshDumpInvocation::from_argv(&argv).is_err());
        }
        for argv in [
            args(&["bssh", "-G", "-W", "localhost:22", "host"]),
            args(&["bssh", "-GW[::1]:22", "host"]),
            args(&["bssh", "-GWhost:ssh", "host"]),
        ] {
            assert!(SshDumpInvocation::from_argv(&argv).is_ok());
        }
    }

    #[test]
    fn detects_dump_without_rescanning_option_values() {
        assert!(SshDumpInvocation::requests_config_dump(&args(&[
            "bssh",
            "-E/tmp/log",
            "-GF",
            "none",
            "list"
        ])));
        assert!(!SshDumpInvocation::requests_config_dump(&args(&[
            "bssh",
            "-E/tmp/contains/G",
            "host"
        ])));
    }
}
