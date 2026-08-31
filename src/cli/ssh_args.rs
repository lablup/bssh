// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Order-preserving extraction of ssh_config command-line options.

use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};

/// Destination of an OpenSSH-compatible `-W host:port` stdio forwarding
/// request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioForwardTarget {
    pub host: String,
    pub port: u16,
}

impl FromStr for StdioForwardTarget {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (raw_host, raw_port) = value
            .rsplit_once(':')
            .ok_or_else(|| format!("Invalid -W target '{value}'; expected host:port"))?;
        let host = if let Some(bracketed) = raw_host.strip_prefix('[') {
            let host = bracketed
                .strip_suffix(']')
                .ok_or_else(|| format!("Invalid -W target '{value}'; expected [IPv6]:port"))?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| format!("Invalid -W target '{value}'; expected [IPv6]:port"))?;
            host.to_string()
        } else if raw_host.is_empty() || raw_host.contains([':', '[', ']']) {
            return Err(format!("Invalid -W target '{value}'; expected host:port"));
        } else {
            raw_host.to_string()
        };
        let port = raw_port
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .or_else(|| service_port(raw_port))
            .ok_or_else(|| format!("Invalid -W target '{value}'; expected host:port"))?;
        Ok(Self { host, port })
    }
}

/// Move the OpenSSH second option pass in front of the destination so clap can
/// parse it. `trailing_var_arg` intentionally captures everything after the
/// destination; OpenSSH accepts another option group there until the first
/// remote-command argument.
pub fn normalize_ssh_option_pass(
    args: &[String],
    destination: &str,
    trailing_count: usize,
) -> Vec<String> {
    if trailing_count == 0 || args.len() < trailing_count + 2 {
        return args.to_vec();
    }
    let search_end = args.len() - trailing_count;
    let Some(destination_index) = args[..search_end]
        .iter()
        .rposition(|argument| argument == destination)
    else {
        return args.to_vec();
    };
    let trailing = &args[destination_index + 1..];
    let mut consumed = 0usize;
    while consumed < trailing.len() {
        let argument = &trailing[consumed];
        if argument == "--" {
            consumed += 1;
            break;
        }
        let Some(width) = scoped_second_pass_width(argument, trailing.get(consumed + 1)) else {
            break;
        };
        consumed += width;
    }
    if consumed == 0 {
        return args.to_vec();
    }

    let mut normalized = Vec::with_capacity(args.len());
    normalized.extend_from_slice(&args[..destination_index]);
    normalized.extend_from_slice(&trailing[..consumed]);
    normalized.push(args[destination_index].clone());
    normalized.extend_from_slice(&trailing[consumed..]);
    normalized
}

fn scoped_second_pass_width(argument: &str, next: Option<&String>) -> Option<usize> {
    if let Some(long) = argument.strip_prefix("--") {
        let (name, attached) = long
            .split_once('=')
            .map_or((long, false), |(name, _)| (name, true));
        return match name {
            "subsystem" | "stdin-null" | "control-master" => Some(1),
            "cipher" | "macs" | "stdio-forward" | "ssh-config" | "option" | "control-command"
            | "control-path" => Some(usize::from(!attached && next.is_some()) + 1),
            _ => None,
        };
    }
    let shorts = argument
        .strip_prefix('-')
        .filter(|value| !value.is_empty())?;
    for (position, short) in shorts.char_indices() {
        match short {
            's' | 'n' | 'M' => {}
            'c' | 'm' | 'W' | 'F' | 'o' | 'O' => {
                let attached = position + short.len_utf8() < shorts.len();
                return Some(usize::from(!attached && next.is_some()) + 1);
            }
            _ => return None,
        }
    }
    Some(1)
}

/// Inputs needed by `ssh -G`, in the order OpenSSH obtains them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDumpInvocation {
    pub destination: String,
    pub config_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub overrides: Vec<String>,
    /// `-W` requests OpenSSH's implicit forwarding policy after config merge.
    pub stdio_forward: bool,
    /// Terminal SSH options take priority over `-G` after raw argv parsing.
    pub version: bool,
    pub query: Option<String>,
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
        let dump_requested = scan_for_dump_flag(args);
        let mut overrides = Vec::new();
        let mut priority_overrides = Vec::new();
        let mut config_file = None;
        let mut log_file = None;
        let mut index = 1usize;
        let mut destination = None;
        let mut options_terminated = false;
        let mut stdio_forward = false;
        let mut saw_dump = false;
        let mut version = false;
        let mut query = None;

        'arguments: while index < args.len() {
            let argument = &args[index];
            if argument == "--" {
                if destination.is_some() {
                    break;
                }
                options_terminated = true;
                index += 1;
                continue;
            }
            if destination.is_none()
                && (options_terminated || !argument.starts_with('-') || argument == "-")
            {
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
                        &mut query,
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
                            &mut query,
                        )?;
                        stdio_forward |= name == "stdio-forward";
                        if name == "query" {
                            break 'arguments;
                        }
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
                        'V' => {
                            version = true;
                            break 'arguments;
                        }
                        'q' | 'v' | 'y' => {}
                        _ => anyhow::bail!("Unknown option '-{short}'"),
                    }
                }
            }
            index += 1;
        }

        if !saw_dump && !dump_requested {
            anyhow::bail!("Resolved configuration invocation is missing -G");
        }
        let terminal = version || query.is_some();
        let destination = if terminal {
            destination.unwrap_or_default()
        } else {
            destination.context("-G requires a destination")?
        };
        let destination = destination.strip_prefix("ssh://").unwrap_or(&destination);
        let parsed = (!destination.is_empty())
            .then(|| parse_dump_destination(destination))
            .transpose()
            .context("Invalid destination for resolved configuration")?;
        let mut all_overrides = priority_overrides
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        all_overrides.extend(overrides);

        Ok(Self {
            destination: parsed
                .map_or_else(String::new, |destination| destination.host.to_string()),
            config_file,
            log_file,
            overrides: all_overrides,
            stdio_forward,
            version,
            query,
        })
    }
}

fn add_destination_overrides(destination: &str, overrides: &mut Vec<String>) -> Result<()> {
    let destination = destination.strip_prefix("ssh://").unwrap_or(destination);
    let parsed = parse_dump_destination(destination)
        .context("Invalid destination for resolved configuration")?;
    if let Some(user) = parsed.user {
        overrides.push(config_option("User", &literal_user(user)?)?);
    }
    if let Some(port) = parsed.port {
        overrides.push(format!("Port={port}"));
    }
    Ok(())
}

fn parse_dump_destination(destination: &str) -> Result<crate::node::NodeSpec<'_>> {
    let (user, host) = destination
        .split_once('@')
        .map_or((None, destination), |(user, host)| (Some(user), host));
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(crate::node::NodeSpec {
            user,
            host,
            port: None,
        });
    }
    crate::node::parse_node_spec(destination)
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
    query: &mut Option<String>,
) -> Result<()> {
    let option = match name {
        "option" => value.to_string(),
        "login" => config_option("User", &literal_user(value)?)?,
        "port" => {
            value
                .parse::<u16>()
                .with_context(|| format!("Invalid port '{value}'"))?;
            format!("Port={value}")
        }
        "identity" => config_option("IdentityFile", value)?,
        "jump-host" => config_option("ProxyJump", value)?,
        "cipher" => {
            set_priority(
                priority_overrides,
                "ciphers",
                config_option("Ciphers", value)?,
            );
            return Ok(());
        }
        "macs" => {
            set_priority(priority_overrides, "macs", config_option("MACs", value)?);
            return Ok(());
        }
        "local-forward" => config_option("LocalForward", value)?,
        "remote-forward" => config_option("RemoteForward", value)?,
        "dynamic-forward" => config_option("DynamicForward", value)?,
        "stdio-forward" => {
            value
                .parse::<StdioForwardTarget>()
                .map_err(anyhow::Error::msg)?;
            return Ok(());
        }
        "diagnostic-file" => {
            *log_file = Some(PathBuf::from(value));
            return Ok(());
        }
        "query" => {
            *query = Some(value.to_string());
            return Ok(());
        }
        "bind-interface" => config_option("BindInterface", value)?,
        "bind-address" => config_option("BindAddress", value)?,
        "escape-char" => config_option("EscapeChar", value)?,
        "control-path" => config_option("ControlPath", value)?,
        "tunnel-device" => config_option("TunnelDevice", value)?,
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

fn config_option(keyword: &str, value: &str) -> Result<String> {
    Ok(format!(
        "{keyword}={}",
        crate::ssh::ssh_config::encode_config_value(value)?
    ))
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

#[cfg(unix)]
fn service_port(name: &str) -> Option<u16> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return None;
    }
    std::fs::read_to_string("/etc/services")
        .ok()
        .and_then(|services| {
            services.lines().find_map(|line| {
                let fields = line
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .collect::<Vec<_>>();
                let port = fields.get(1)?.strip_suffix("/tcp")?.parse().ok()?;
                fields
                    .iter()
                    .enumerate()
                    .any(|(index, field)| index != 1 && *field == name)
                    .then_some(port)
            })
        })
}

#[cfg(not(unix))]
fn service_port(_name: &str) -> Option<u16> {
    None
}

fn scan_for_dump_flag(args: &[String]) -> bool {
    let mut index = 1usize;
    let mut destination_seen = false;
    let mut saw_dump = false;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            break;
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
                saw_dump = true;
            }
            if long_takes_value(name) && !attached {
                index += 1;
            }
        } else if let Some(shorts) = argument.strip_prefix('-') {
            for (position, short) in shorts.char_indices() {
                if short == 'G' {
                    saw_dump = true;
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
    saw_dump
}

fn scan_diagnostic_file(args: &[String]) -> Option<PathBuf> {
    let mut result = None;
    let mut index = 1usize;
    let mut destination_seen = false;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            break;
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
                if matches!(short, 'V' | 'Q') {
                    return result;
                }
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
    use super::{SshDumpInvocation, StdioForwardTarget, normalize_ssh_option_pass};

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
    fn normalizes_scoped_second_option_pass_for_clap() {
        let argv = args(&[
            "bssh",
            "host",
            "-sn",
            "-c",
            "-aes128-cbc",
            "-W[::1]:443",
            "remote-command",
        ]);
        assert_eq!(
            normalize_ssh_option_pass(&argv, "host", 5),
            args(&[
                "bssh",
                "-sn",
                "-c",
                "-aes128-cbc",
                "-W[::1]:443",
                "host",
                "remote-command",
            ])
        );

        let terminated = args(&["bssh", "host", "-s", "--", "-literal-command"]);
        assert_eq!(
            normalize_ssh_option_pass(&terminated, "host", 3),
            args(&["bssh", "-s", "--", "host", "-literal-command"])
        );

        let with_generic_option = args(&[
            "bssh",
            "host",
            "-oCiphers=aes128-ctr",
            "-c",
            "aes256-ctr",
            "command",
        ]);
        assert_eq!(
            normalize_ssh_option_pass(&with_generic_option, "host", 4),
            args(&[
                "bssh",
                "-oCiphers=aes128-ctr",
                "-c",
                "aes256-ctr",
                "host",
                "command",
            ])
        );

        let missing_value = args(&["bssh", "host", "-c"]);
        assert_eq!(
            normalize_ssh_option_pass(&missing_value, "host", 1),
            args(&["bssh", "-c", "host"])
        );
    }

    #[test]
    fn parses_numeric_service_and_bracketed_ipv6_stdio_targets() {
        assert_eq!(
            "example.com:443".parse::<StdioForwardTarget>().unwrap(),
            StdioForwardTarget {
                host: "example.com".into(),
                port: 443,
            }
        );
        assert_eq!(
            "[2001:db8::1]:22".parse::<StdioForwardTarget>().unwrap(),
            StdioForwardTarget {
                host: "2001:db8::1".into(),
                port: 22,
            }
        );
        for invalid in ["host", ":22", "host:0", "2001:db8::1:22", "[bad]:22"] {
            assert!(invalid.parse::<StdioForwardTarget>().is_err(), "{invalid}");
        }
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
        assert!(parsed.stdio_forward);
        assert!(!parsed.overrides.iter().any(|option| {
            option
                .to_ascii_lowercase()
                .starts_with("clearallforwardings=")
        }));
        assert!(!parsed.overrides.iter().any(|option| {
            option
                .to_ascii_lowercase()
                .starts_with("exitonforwardfailure=")
        }));

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
        assert!(parsed.stdio_forward);
        assert!(
            parsed
                .overrides
                .contains(&"ClearAllForwardings=no".to_string())
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
    fn direct_values_are_serialized_before_overlay_tokenization() {
        let parsed = SshDumpInvocation::from_argv(&args(&[
            "bssh",
            "-GF",
            "none",
            "-i",
            "/tmp/a b#c",
            "-S/tmp/control path#socket",
            "host",
        ]))
        .unwrap();
        assert!(
            parsed
                .overrides
                .contains(&r#"IdentityFile="/tmp/a b#c""#.to_string())
        );
        assert!(
            parsed
                .overrides
                .contains(&r#"ControlPath="/tmp/control path#socket""#.to_string())
        );
    }

    #[test]
    fn config_dump_accepts_unbracketed_ipv6_destinations() {
        let parsed = SshDumpInvocation::from_argv(&args(&["bssh", "-GF", "none", "::1"])).unwrap();
        assert_eq!(parsed.destination, "::1");

        let parsed =
            SshDumpInvocation::from_argv(&args(&["bssh", "-GF", "none", "deploy@::1"])).unwrap();
        assert_eq!(parsed.destination, "::1");
        assert!(parsed.overrides.contains(&"User=deploy".to_string()));
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
        assert!(!SshDumpInvocation::requests_config_dump(&args(&[
            "bssh", "--", "host", "-G"
        ])));
        assert_eq!(
            SshDumpInvocation::diagnostic_file(&args(&["bssh", "--", "host", "-E/tmp/remote-log"])),
            None
        );
        let terminated =
            SshDumpInvocation::from_argv(&args(&["bssh", "-G", "--", "-alias"])).unwrap();
        assert_eq!(terminated.destination, "-alias");
        assert!(SshDumpInvocation::from_argv(&args(&["bssh", "-G", "-"])).is_ok());
    }

    #[test]
    fn terminal_version_and_query_options_preempt_config_dump() {
        for argv in [
            args(&["bssh", "-VG", "host"]),
            args(&["bssh", "-GV", "host"]),
            args(&["bssh", "-GQ", "cipher", "host"]),
            args(&["bssh", "-Qcipher", "-G", "host"]),
        ] {
            assert!(SshDumpInvocation::requests_config_dump(&argv), "{argv:?}");
        }
        let version = SshDumpInvocation::from_argv(&args(&["bssh", "-VG"])).unwrap();
        assert!(version.version);
        let query = SshDumpInvocation::from_argv(&args(&["bssh", "-GQ", "cipher"])).unwrap();
        assert_eq!(query.query.as_deref(), Some("cipher"));
        assert!(SshDumpInvocation::from_argv(&args(&["bssh", "-VG", "-Z"])).is_ok());
        assert!(SshDumpInvocation::from_argv(&args(&["bssh", "-GQ", "cipher", "-Z"])).is_ok());
        assert!(SshDumpInvocation::from_argv(&args(&["bssh", "-Z", "-VG"])).is_err());
    }
}
