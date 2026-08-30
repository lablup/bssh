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
    pub overrides: Vec<String>,
}

impl SshDumpInvocation {
    /// Preserve OpenSSH's two-pass argv behavior: after capturing the first
    /// destination, another option group may follow. The next non-option is
    /// the remote command and ends option processing.
    pub fn from_argv(args: &[String], destination: &str) -> Result<Self> {
        let mut overrides = Vec::new();
        let mut config_file = None;
        let mut index = 1usize;
        let mut captured_destination = false;
        let mut options_terminated = false;
        let mut stdio_forward = false;

        while index < args.len() {
            let argument = &args[index];
            if argument == "--" {
                if captured_destination {
                    break;
                }
                options_terminated = true;
                index += 1;
                continue;
            }
            if argument == destination && !captured_destination {
                add_destination_overrides(destination, &mut overrides)?;
                captured_destination = true;
                index += 1;
                if options_terminated {
                    break;
                }
                continue;
            }
            if captured_destination && !argument.starts_with('-') {
                break;
            }

            if let Some(long) = argument.strip_prefix("--") {
                let (name, attached) = long
                    .split_once('=')
                    .map_or((long, None), |(name, value)| (name, Some(value)));
                match name {
                    "option" | "login" | "port" | "identity" | "jump-host" | "cipher" | "macs"
                    | "ssh-config" | "local-forward" | "remote-forward" | "dynamic-forward" => {
                        let (value, consumed) = value_for(args, index, attached, name)?;
                        apply_value(name, value, &mut config_file, &mut overrides)?;
                        stdio_forward |= name == "stdio-forward";
                        index += consumed;
                    }
                    "ipv4" => overrides.push("AddressFamily=inet".to_string()),
                    "ipv6" => overrides.push("AddressFamily=inet6".to_string()),
                    "tty" => overrides.push("RequestTTY=yes".to_string()),
                    "no-tty" => overrides.push("RequestTTY=no".to_string()),
                    "no-x11" => overrides.push("ForwardX11=no".to_string()),
                    _ => {}
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
                        _ => None,
                    };
                    if let Some(name) = value_name {
                        let value_start = position + short.len_utf8();
                        let attached = shorts
                            .get(value_start..)
                            .filter(|remaining| !remaining.is_empty());
                        let (value, consumed) = value_for(args, index, attached, name)?;
                        apply_value(name, value, &mut config_file, &mut overrides)?;
                        stdio_forward |= name == "stdio-forward";
                        index += consumed;
                        break;
                    }
                    match short {
                        '4' => overrides.push("AddressFamily=inet".to_string()),
                        '6' => overrides.push("AddressFamily=inet6".to_string()),
                        'A' => overrides.push("ForwardAgent=yes".to_string()),
                        'x' => overrides.push("ForwardX11=no".to_string()),
                        't' => overrides.push("RequestTTY=yes".to_string()),
                        'T' => overrides.push("RequestTTY=no".to_string()),
                        _ => {}
                    }
                }
            }
            index += 1;
        }

        let destination = destination.strip_prefix("ssh://").unwrap_or(destination);
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

        Ok(Self {
            destination: parsed.host.to_string(),
            config_file,
            overrides,
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
    overrides: &mut Vec<String>,
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
        "cipher" => format!("Ciphers={value}"),
        "macs" => format!("MACs={value}"),
        "local-forward" => format!("LocalForward={value}"),
        "remote-forward" => format!("RemoteForward={value}"),
        "dynamic-forward" => format!("DynamicForward={value}"),
        "stdio-forward" => return Ok(()),
        "diagnostic-file" | "query" => return Ok(()),
        "ssh-config" => {
            *config_file = Some(PathBuf::from(value));
            return Ok(());
        }
        _ => return Ok(()),
    };
    overrides.push(option);
    Ok(())
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
        let parsed = SshDumpInvocation::from_argv(&argv, "host").unwrap();
        assert_eq!(
            parsed.overrides,
            ["AddressFamily=inet6", "User=first", "User=second", "Port=9"]
        );
    }

    #[test]
    fn destination_values_are_last_and_ipv6_is_unwrapped() {
        let argv = args(&["bssh", "-Gp2200", "user@[::1]:2300"]);
        let parsed = SshDumpInvocation::from_argv(&argv, "user@[::1]:2300").unwrap();
        assert_eq!(parsed.destination, "::1");
        assert_eq!(parsed.overrides, ["Port=2200", "User=user", "Port=2300"]);
    }

    #[test]
    fn stdio_forward_implicit_clear_is_overridden_by_explicit_option() {
        let implicit = args(&["bssh", "-GF", "none", "-W", "a:1", "host"]);
        let parsed = SshDumpInvocation::from_argv(&implicit, "host").unwrap();
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
        let parsed = SshDumpInvocation::from_argv(&explicit, "host").unwrap();
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
            let parsed = SshDumpInvocation::from_argv(&argv, "baz@host").unwrap();
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
        let parsed = SshDumpInvocation::from_argv(&argv, "host").unwrap();
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
            let parsed = SshDumpInvocation::from_argv(&argv, "host").unwrap();
            assert!(parsed.overrides.is_empty());
        }
    }

    #[test]
    fn validates_remote_user_without_expanding_percent_tokens() {
        let literal = args(&["bssh", "-G", "-l%u", "host"]);
        let parsed = SshDumpInvocation::from_argv(&literal, "host").unwrap();
        assert_eq!(parsed.overrides, ["User=%%u"]);

        for invalid in ["${FOO}", "bad\u{7}user", "-flag", "bad\\"] {
            let argv = args(&["bssh", "-G", "-l", invalid, "host"]);
            assert!(SshDumpInvocation::from_argv(&argv, "host").is_err());
        }
    }
}
