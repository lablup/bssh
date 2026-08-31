// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// OpenSSH `ControlMaster` connection-selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlMasterMode {
    /// Try an existing master but never create one.
    #[default]
    No,
    /// Create a master without prompting and do not attach to an existing one.
    Yes,
    /// Create a master and ask before accepting each shared request.
    Ask,
    /// Try an existing master and create one when none is reachable.
    Auto,
    /// `Auto` behavior with confirmation for shared requests.
    AutoAsk,
}

impl ControlMasterMode {
    /// Whether an invocation should first try the configured control socket.
    #[must_use]
    pub const fn tries_existing(self) -> bool {
        matches!(self, Self::No | Self::Auto | Self::AutoAsk)
    }

    /// Whether a direct connection should publish a master socket.
    #[must_use]
    pub const fn creates_master(self) -> bool {
        !matches!(self, Self::No)
    }

    /// Whether a master must confirm incoming shared requests.
    #[must_use]
    pub const fn requires_confirmation(self) -> bool {
        matches!(self, Self::Ask | Self::AutoAsk)
    }
}

impl FromStr for ControlMasterMode {
    type Err = ControlConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Ok(Self::No),
            "yes" | "true" => Ok(Self::Yes),
            "ask" => Ok(Self::Ask),
            "auto" => Ok(Self::Auto),
            "autoask" => Ok(Self::AutoAsk),
            _ => Err(ControlConfigError::InvalidControlMaster(value.to_string())),
        }
    }
}

impl fmt::Display for ControlMasterMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::No => "no",
            Self::Yes => "yes",
            Self::Ask => "ask",
            Self::Auto => "auto",
            Self::AutoAsk => "autoask",
        })
    }
}

/// Lifetime policy for an idle multiplexing master.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlPersist {
    /// Exit when the initial client and all shared sessions are gone.
    #[default]
    Disabled,
    /// Remain available until explicitly stopped.
    Forever,
    /// Exit after the connection has been idle for this duration.
    Timeout(Duration),
}

impl ControlPersist {
    /// Whether the master outlives its initial client.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Return the finite idle timeout, if one was configured.
    #[must_use]
    pub const fn timeout(self) -> Option<Duration> {
        match self {
            Self::Timeout(duration) => Some(duration),
            Self::Disabled | Self::Forever => None,
        }
    }
}

impl FromStr for ControlPersist {
    type Err = ControlConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Ok(Self::Disabled),
            "yes" | "true" => Ok(Self::Forever),
            _ => {
                let seconds = parse_compound_duration(value)?;
                if seconds == 0 {
                    Ok(Self::Forever)
                } else {
                    Ok(Self::Timeout(Duration::from_secs(seconds)))
                }
            }
        }
    }
}

impl fmt::Display for ControlPersist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("no"),
            Self::Forever => formatter.write_str("yes"),
            Self::Timeout(duration) => write!(formatter, "{}", duration.as_secs()),
        }
    }
}

/// Commands accepted by OpenSSH-compatible `-O` handling in issue #286.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlCommand {
    Check,
    Forward,
    Cancel,
    Exit,
    Stop,
}

impl FromStr for ControlCommand {
    type Err = ControlConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "check" => Ok(Self::Check),
            "forward" => Ok(Self::Forward),
            "cancel" => Ok(Self::Cancel),
            "exit" => Ok(Self::Exit),
            "stop" => Ok(Self::Stop),
            _ => Err(ControlConfigError::InvalidControlCommand(value.to_string())),
        }
    }
}

impl fmt::Display for ControlCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Check => "check",
            Self::Forward => "forward",
            Self::Cancel => "cancel",
            Self::Exit => "exit",
            Self::Stop => "stop",
        })
    }
}

/// Typed view over the three string-valued fields currently stored in
/// `SshHostConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ControlPolicy {
    pub master: ControlMasterMode,
    /// Unexpanded path template. `None` includes explicit `ControlPath none`.
    pub path: Option<String>,
    pub persist: ControlPersist,
}

impl ControlPolicy {
    /// Parse the resolved raw `SshHostConfig` values without changing that
    /// structure's public representation.
    pub fn from_raw(
        control_master: Option<&str>,
        control_path: Option<&str>,
        control_persist: Option<&str>,
    ) -> Result<Self, ControlConfigError> {
        let master = control_master.map_or(Ok(ControlMasterMode::No), str::parse)?;
        let path = control_path
            .filter(|value| !value.eq_ignore_ascii_case("none"))
            .map(str::to_string);
        let persist = control_persist.map_or(Ok(ControlPersist::Disabled), str::parse)?;
        Ok(Self {
            master,
            path,
            persist,
        })
    }

    /// Multiplexing has an operational socket only when `ControlPath` did not
    /// resolve to unset or `none`.
    #[must_use]
    pub const fn is_socket_enabled(&self) -> bool {
        self.path.is_some()
    }
}

/// Invalid user-authored control configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ControlConfigError {
    #[error("invalid ControlMaster value '{0}'; expected yes, no, ask, auto, or autoask")]
    InvalidControlMaster(String),
    #[error(
        "invalid ControlPersist value '{0}'; expected yes, no, or a duration such as 30s or 1h30m"
    )]
    InvalidControlPersist(String),
    #[error("ControlPersist duration '{0}' is too large")]
    ControlPersistOverflow(String),
    #[error("invalid control command '{0}'; expected check, forward, cancel, exit, or stop")]
    InvalidControlCommand(String),
}

// OpenSSH's convtime() returns an int and rejects anything larger than
// INT_MAX. Keeping the same ceiling avoids platform-dependent timer behavior.
const MAX_CONTROL_PERSIST_SECONDS: u64 = i32::MAX as u64;

fn parse_compound_duration(value: &str) -> Result<u64, ControlConfigError> {
    if value.is_empty() {
        return Err(ControlConfigError::InvalidControlPersist(value.to_string()));
    }

    let bytes = value.as_bytes();
    let mut index = 0usize;
    let mut total = 0u64;

    while index < bytes.len() {
        let mut integer = 0u64;
        let mut integer_digits = 0usize;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            integer = integer
                .checked_mul(10)
                .and_then(|number| number.checked_add(u64::from(bytes[index] - b'0')))
                .ok_or_else(|| ControlConfigError::ControlPersistOverflow(value.to_string()))?;
            integer_digits += 1;
            index += 1;
        }
        if integer_digits == 0 {
            return Err(ControlConfigError::InvalidControlPersist(value.to_string()));
        }

        let multiplier = if index == bytes.len() {
            1u64
        } else {
            let unit = bytes[index];
            index += 1;
            match unit {
                b's' | b'S' => 1,
                b'm' | b'M' => 60,
                b'h' | b'H' => 3_600,
                b'd' | b'D' => 86_400,
                b'w' | b'W' => 604_800,
                _ => {
                    return Err(ControlConfigError::InvalidControlPersist(value.to_string()));
                }
            }
        };
        let seconds = integer
            .checked_mul(multiplier)
            .ok_or_else(|| ControlConfigError::ControlPersistOverflow(value.to_string()))?;
        total = total
            .checked_add(seconds)
            .ok_or_else(|| ControlConfigError::ControlPersistOverflow(value.to_string()))?;
        if total > MAX_CONTROL_PERSIST_SECONDS {
            return Err(ControlConfigError::ControlPersistOverflow(
                value.to_string(),
            ));
        }
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_master_modes_expose_runtime_decisions() {
        let cases = [
            ("no", ControlMasterMode::No, true, false, false),
            ("yes", ControlMasterMode::Yes, false, true, false),
            ("ask", ControlMasterMode::Ask, false, true, true),
            ("auto", ControlMasterMode::Auto, true, true, false),
            ("autoask", ControlMasterMode::AutoAsk, true, true, true),
            ("TRUE", ControlMasterMode::Yes, false, true, false),
            ("FALSE", ControlMasterMode::No, true, false, false),
        ];
        for (value, expected, tries, creates, asks) in cases {
            let parsed = value.parse::<ControlMasterMode>().expect("valid mode");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.tries_existing(), tries);
            assert_eq!(parsed.creates_master(), creates);
            assert_eq!(parsed.requires_confirmation(), asks);
        }
        assert!("invalid".parse::<ControlMasterMode>().is_err());
    }

    #[test]
    fn control_persist_parses_boolean_and_compound_forms() {
        let cases = [
            ("no", ControlPersist::Disabled),
            ("false", ControlPersist::Disabled),
            ("yes", ControlPersist::Forever),
            ("true", ControlPersist::Forever),
            ("YES", ControlPersist::Forever),
            ("0", ControlPersist::Forever),
            ("30", ControlPersist::Timeout(Duration::from_secs(30))),
            ("1m", ControlPersist::Timeout(Duration::from_secs(60))),
            ("1h30m", ControlPersist::Timeout(Duration::from_secs(5_400))),
            (
                "1W2d3H4m5S",
                ControlPersist::Timeout(Duration::from_secs(788_645)),
            ),
            ("1s2s", ControlPersist::Timeout(Duration::from_secs(3))),
        ];
        for (value, expected) in cases {
            assert_eq!(
                value.parse::<ControlPersist>().expect("valid persist"),
                expected
            );
        }
    }

    #[test]
    fn control_persist_rejects_malformed_and_overflowing_values() {
        for value in ["", "maybe", "1x", "1.5m", "1.9s", "1.", ".", "-1"] {
            assert!(value.parse::<ControlPersist>().is_err(), "accepted {value}");
        }
        assert!("2147483648s".parse::<ControlPersist>().is_err());
        assert!(
            "999999999999999999999999999999999999999w"
                .parse::<ControlPersist>()
                .is_err()
        );
    }

    #[test]
    fn command_scope_is_deliberately_bounded() {
        for command in ["check", "forward", "cancel", "exit", "stop"] {
            assert_eq!(
                command
                    .parse::<ControlCommand>()
                    .expect("supported command")
                    .to_string(),
                command
            );
        }
        for command in ["proxy", "channels", "conninfo", "", "CHECK"] {
            assert!(command.parse::<ControlCommand>().is_err());
        }
    }

    #[test]
    fn raw_policy_distinguishes_defaults_and_disabled_path() {
        assert_eq!(
            ControlPolicy::from_raw(None, None, None).expect("defaults"),
            ControlPolicy::default()
        );
        let disabled =
            ControlPolicy::from_raw(Some("auto"), Some("NoNe"), Some("5m")).expect("valid policy");
        assert_eq!(disabled.master, ControlMasterMode::Auto);
        assert_eq!(disabled.path, None);
        assert_eq!(
            disabled.persist,
            ControlPersist::Timeout(Duration::from_secs(300))
        );
        assert!(!disabled.is_socket_enabled());

        let enabled =
            ControlPolicy::from_raw(None, Some("~/.ssh/cm-%C"), None).expect("valid path");
        assert_eq!(enabled.path.as_deref(), Some("~/.ssh/cm-%C"));
        assert!(enabled.is_socket_enabled());
    }
}
