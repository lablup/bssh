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

//! Typed `RekeyLimit` parsing and conversion to russh transport limits.

use std::time::Duration;

use thiserror::Error;

/// russh's hard per-direction byte ceiling.
///
/// `russh::Limits::new` asserts that neither byte limit exceeds 1 GiB to
/// prevent nonce reuse. bssh therefore caps larger explicit values instead of
/// claiming an unlimited transport that the backend cannot provide.
pub const RUSSH_REKEY_BYTE_CEILING: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RekeyDataLimit {
    #[default]
    Default,
    Bytes(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RekeyTimeLimit {
    #[default]
    Default,
    None,
    Seconds(u64),
}

/// Effective ssh_config rekey policy before applying backend safety limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RekeyLimit {
    pub data: RekeyDataLimit,
    pub time: RekeyTimeLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RekeyLimitParseError {
    #[error("a data limit is required")]
    MissingDataLimit,
    #[error("at most a data limit and an optional time limit are accepted")]
    TooManyValues,
    #[error("invalid data limit '{0}'")]
    InvalidDataLimit(String),
    #[error("data limit '{0}' overflows")]
    DataLimitOverflow(String),
    #[error("invalid time limit '{0}'")]
    InvalidTimeLimit(String),
    #[error("time limit '{0}' overflows")]
    TimeLimitOverflow(String),
}

impl RekeyLimit {
    pub fn parse(values: &[String]) -> Result<Self, RekeyLimitParseError> {
        let Some(data) = values.first() else {
            return Err(RekeyLimitParseError::MissingDataLimit);
        };
        if values.len() > 2 {
            return Err(RekeyLimitParseError::TooManyValues);
        }

        Ok(Self {
            data: parse_data_limit(data)?,
            time: values
                .get(1)
                .map_or(Ok(RekeyTimeLimit::Default), |value| parse_time_limit(value))?,
        })
    }

    /// Whether the requested data policy must be reduced to russh's hard
    /// nonce-safety ceiling.
    #[must_use]
    pub fn data_is_capped(self) -> bool {
        matches!(self.data, RekeyDataLimit::Bytes(bytes) if bytes > RUSSH_REKEY_BYTE_CEILING)
    }

    /// Convert to safe russh limits without panicking or silently disabling
    /// byte-based rekeying.
    #[must_use]
    pub fn to_russh_limits(self) -> russh::Limits {
        let defaults = russh::Limits::default();
        let requested_bytes = match self.data {
            RekeyDataLimit::Default => defaults.rekey_write_limit as u64,
            RekeyDataLimit::Bytes(bytes) => bytes,
        };
        let effective_bytes = requested_bytes.min(RUSSH_REKEY_BYTE_CEILING) as usize;
        let effective_time = match self.time {
            // OpenSSH's effective default is `RekeyLimit default none`, not
            // russh's one-hour backend default.
            RekeyTimeLimit::Default | RekeyTimeLimit::None => Duration::MAX,
            RekeyTimeLimit::Seconds(seconds) => Duration::from_secs(seconds),
        };

        russh::Limits::new(effective_bytes, effective_bytes, effective_time)
    }
}

fn parse_data_limit(value: &str) -> Result<RekeyDataLimit, RekeyLimitParseError> {
    if value.eq_ignore_ascii_case("default") {
        return Ok(RekeyDataLimit::Default);
    }
    let (number, multiplier) = split_suffix(
        value,
        &[
            ("k", 1 << 10),
            ("m", 1 << 20),
            ("g", 1 << 30),
            ("t", 1 << 40),
        ],
    );
    let parsed = number
        .parse::<u64>()
        .map_err(|_| RekeyLimitParseError::InvalidDataLimit(value.to_string()))?;
    if parsed == 0 {
        return Ok(RekeyDataLimit::Default);
    }
    let bytes = parsed
        .checked_mul(multiplier)
        .ok_or_else(|| RekeyLimitParseError::DataLimitOverflow(value.to_string()))?;
    if bytes < 16 {
        return Err(RekeyLimitParseError::InvalidDataLimit(value.to_string()));
    }
    Ok(RekeyDataLimit::Bytes(bytes))
}

fn parse_time_limit(value: &str) -> Result<RekeyTimeLimit, RekeyLimitParseError> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(RekeyTimeLimit::None);
    }

    let (number, multiplier) = split_suffix(
        value,
        &[
            ("s", 1),
            ("m", 60),
            ("h", 3_600),
            ("d", 86_400),
            ("w", 604_800),
        ],
    );
    let parsed = number
        .parse::<u64>()
        .map_err(|_| RekeyLimitParseError::InvalidTimeLimit(value.to_string()))?;
    if parsed == 0 {
        return Ok(RekeyTimeLimit::Default);
    }
    parsed
        .checked_mul(multiplier)
        .map(RekeyTimeLimit::Seconds)
        .ok_or_else(|| RekeyLimitParseError::TimeLimitOverflow(value.to_string()))
}

fn split_suffix<'a>(value: &'a str, suffixes: &[(&str, u64)]) -> (&'a str, u64) {
    suffixes
        .iter()
        .find_map(|(suffix, multiplier)| {
            value
                .get(value.len().saturating_sub(suffix.len())..)
                .filter(|ending| ending.eq_ignore_ascii_case(suffix))
                .and_then(|_| value.get(..value.len().saturating_sub(suffix.len())))
                .map(|number| (number, *multiplier))
        })
        .unwrap_or((value, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn parses_default_none_and_suffixes() {
        assert_eq!(
            RekeyLimit::parse(&values(&["default"])),
            Ok(RekeyLimit::default())
        );
        assert_eq!(
            RekeyLimit::parse(&values(&["default", "none"])),
            Ok(RekeyLimit {
                data: RekeyDataLimit::Default,
                time: RekeyTimeLimit::None,
            })
        );
        assert_eq!(
            RekeyLimit::parse(&values(&["16M", "2h"])),
            Ok(RekeyLimit {
                data: RekeyDataLimit::Bytes(16 << 20),
                time: RekeyTimeLimit::Seconds(7_200),
            })
        );
        assert_eq!(
            RekeyLimit::parse(&values(&["2t", "1W"])),
            Ok(RekeyLimit {
                data: RekeyDataLimit::Bytes(2 << 40),
                time: RekeyTimeLimit::Seconds(604_800),
            })
        );
    }

    #[test]
    fn numeric_zero_uses_backend_defaults() {
        assert_eq!(
            RekeyLimit::parse(&values(&["0", "0"])),
            Ok(RekeyLimit::default())
        );
    }

    #[test]
    fn rejects_missing_extra_invalid_and_overflow_values() {
        assert_eq!(
            RekeyLimit::parse(&[]),
            Err(RekeyLimitParseError::MissingDataLimit)
        );
        assert_eq!(
            RekeyLimit::parse(&values(&["1M", "1h", "extra"])),
            Err(RekeyLimitParseError::TooManyValues)
        );
        assert!(matches!(
            RekeyLimit::parse(&values(&["invalid"])),
            Err(RekeyLimitParseError::InvalidDataLimit(_))
        ));
        assert!(matches!(
            RekeyLimit::parse(&values(&["none"])),
            Err(RekeyLimitParseError::InvalidDataLimit(_))
        ));
        assert!(matches!(
            RekeyLimit::parse(&values(&["15"])),
            Err(RekeyLimitParseError::InvalidDataLimit(_))
        ));
        assert_eq!(
            RekeyLimit::parse(&values(&["16"])),
            Ok(RekeyLimit {
                data: RekeyDataLimit::Bytes(16),
                time: RekeyTimeLimit::Default,
            })
        );
        assert!(matches!(
            RekeyLimit::parse(&values(&["1M", "forever"])),
            Err(RekeyLimitParseError::InvalidTimeLimit(_))
        ));
        assert!(matches!(
            RekeyLimit::parse(&values(&["18446744073709551615T"])),
            Err(RekeyLimitParseError::DataLimitOverflow(_))
        ));
        assert!(matches!(
            RekeyLimit::parse(&values(&["1M", "18446744073709551615w"])),
            Err(RekeyLimitParseError::TimeLimitOverflow(_))
        ));
    }

    #[test]
    fn conversion_preserves_safe_values_and_caps_unsafe_data_requests() {
        let small = RekeyLimit {
            data: RekeyDataLimit::Bytes(4_096),
            time: RekeyTimeLimit::Seconds(30),
        };
        let small_limits = small.to_russh_limits();
        assert_eq!(small_limits.rekey_write_limit, 4_096);
        assert_eq!(small_limits.rekey_read_limit, 4_096);
        assert_eq!(small_limits.rekey_time_limit, Duration::from_secs(30));
        assert!(!small.data_is_capped());

        let policy = RekeyLimit {
            data: RekeyDataLimit::Bytes(RUSSH_REKEY_BYTE_CEILING + 1),
            time: RekeyTimeLimit::Default,
        };
        let limits = policy.to_russh_limits();
        assert_eq!(limits.rekey_write_limit, 1 << 30);
        assert_eq!(limits.rekey_read_limit, 1 << 30);
        assert!(policy.data_is_capped());
    }

    #[test]
    fn default_and_time_none_preserve_the_byte_safety_ceiling() {
        let limits = RekeyLimit::default().to_russh_limits();
        assert_eq!(limits.rekey_write_limit, 1 << 30);
        assert_eq!(limits.rekey_read_limit, 1 << 30);
        assert_eq!(limits.rekey_time_limit, Duration::MAX);

        let explicit_none = RekeyLimit {
            data: RekeyDataLimit::Default,
            time: RekeyTimeLimit::None,
        }
        .to_russh_limits();
        assert_eq!(explicit_none.rekey_time_limit, Duration::MAX);
    }
}
