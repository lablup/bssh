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

use crate::ssh::control::{ControlMasterMode, ControlPersist};
use crate::ssh::ssh_config::types::SshHostConfig;
use anyhow::Result;

fn exactly_one_value<'a>(keyword: &str, args: &'a [String], line_number: usize) -> Result<&'a str> {
    if args.len() != 1 || args[0].is_empty() {
        anyhow::bail!("{keyword} expects exactly one value at line {line_number}");
    }
    Ok(&args[0])
}

fn validate_control_master(value: &str, line_number: usize) -> Result<()> {
    value
        .parse::<ControlMasterMode>()
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("{error} at line {line_number}"))
}

fn validate_control_path(value: &str, line_number: usize) -> Result<()> {
    if value.contains('\0') {
        anyhow::bail!("ControlPath contains a NUL byte at line {line_number}");
    }

    let mut tokens = value.char_indices();
    while let Some((_, character)) = tokens.next() {
        if character != '%' {
            continue;
        }
        let Some((_, token)) = tokens.next() else {
            anyhow::bail!("ControlPath has an incomplete '%' token at line {line_number}");
        };
        if !matches!(token, '%' | 'C' | 'h' | 'l' | 'p' | 'r') {
            anyhow::bail!(
                "ControlPath contains unknown substitution token '%{token}' at line {line_number}"
            );
        }
    }
    Ok(())
}

fn validate_control_persist(value: &str, line_number: usize) -> Result<()> {
    value
        .parse::<ControlPersist>()
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("{error} at line {line_number}"))
}

/// Parse control socket SSH configuration options
pub(super) fn parse_control_option(
    host: &mut SshHostConfig,
    keyword: &str,
    args: &[String],
    line_number: usize,
) -> Result<()> {
    match keyword {
        "controlmaster" => {
            let value = exactly_one_value("ControlMaster", args, line_number)?;
            validate_control_master(value, line_number)?;
            host.control_master = Some(value.to_string());
        }
        "controlpath" => {
            let value = exactly_one_value("ControlPath", args, line_number)?;
            validate_control_path(value, line_number)?;
            host.control_path = Some(value.to_string());
        }
        "controlpersist" => {
            let value = exactly_one_value("ControlPersist", args, line_number)?;
            validate_control_persist(value, line_number)?;
            host.control_persist = Some(value.to_string());
        }
        _ => unreachable!("Unexpected keyword in parse_control_option: {}", keyword),
    }

    Ok(())
}

#[cfg(test)]
fn parse_for_test(keyword: &str, values: &[&str]) -> Result<SshHostConfig> {
    let mut host = SshHostConfig::default();
    let values = values
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    parse_control_option(&mut host, keyword, &values, 7)?;
    Ok(host)
}

#[test]
fn control_options_require_exactly_one_value() {
    for keyword in ["controlmaster", "controlpath", "controlpersist"] {
        assert!(parse_for_test(keyword, &[]).is_err(), "{keyword}");
        assert!(parse_for_test(keyword, &[""]).is_err(), "{keyword}");
        assert!(
            parse_for_test(keyword, &["yes", "extra"]).is_err(),
            "{keyword}"
        );
    }
}

#[test]
fn validates_control_master_modes_case_insensitively() {
    for value in [
        "yes", "true", "no", "false", "auto", "ask", "autoask", "AUTO",
    ] {
        assert!(parse_for_test("controlmaster", &[value]).is_ok(), "{value}");
    }
    for value in ["", "maybe", "auto-ask", "1"] {
        assert!(
            parse_for_test("controlmaster", &[value]).is_err(),
            "{value}"
        );
    }
}

#[test]
fn accepts_control_path_literals_and_valid_templates() {
    for value in [
        "none",
        "~/.ssh/control-%C-%h-%p-%r-%l",
        "/tmp/control path;literal|&`$(still-a-path)-%%",
    ] {
        assert!(parse_for_test("controlpath", &[value]).is_ok(), "{value:?}");
    }
    for value in ["/tmp/control-%x", "/tmp/control-%", "/tmp/control\0path"] {
        assert!(
            parse_for_test("controlpath", &[value]).is_err(),
            "{value:?}"
        );
    }
}

#[test]
fn validates_openssh_control_persist_time_grammar() {
    let valid = [
        "yes",
        "TRUE",
        "no",
        "False",
        "0",
        "2s",
        "3m",
        "1m30",
        "1H30m",
        "1w2d3h4m5s",
        "1s2s",
        "2147483647",
        "3550w5d3h14m7s",
    ];
    for value in valid {
        assert!(
            parse_for_test("controlpersist", &[value]).is_ok(),
            "{value}"
        );
    }

    let invalid = [
        "",
        "-1",
        "trout",
        "1.5m",
        "1.s",
        ".5s",
        "1m0.5s",
        "1e3",
        "2147483648",
        "3550w5d3h14m8s",
    ];
    for value in invalid {
        assert!(
            parse_for_test("controlpersist", &[value]).is_err(),
            "{value}"
        );
    }
}
