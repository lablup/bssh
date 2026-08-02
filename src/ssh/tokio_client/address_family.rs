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

//! IP address family preference.
//!
//! This is the single representation behind the OpenSSH-compatible `-4` /
//! `-6` command line flags and the ssh_config `AddressFamily` keyword. It is
//! carried on [`SshConnectionConfig`](super::SshConnectionConfig) so every
//! connection path that already threads that struct honors the preference
//! without a separate parameter, and it is passed explicitly to the few leaf
//! helpers that never had a connection config to begin with.
//!
//! See `ARCHITECTURE.md` ("Address Family Preference") for the full design.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Which IP address family a connection may use.
///
/// [`Any`](Self::Any) is the default and imposes no constraint: every resolved
/// address is a candidate, tried in resolver order. The other two variants are
/// hard constraints; there is no fallback to the other family, matching
/// OpenSSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AddressFamily {
    /// No constraint (`AddressFamily any`, neither `-4` nor `-6`).
    #[default]
    Any,
    /// IPv4 only (`-4`, `AddressFamily inet`).
    V4,
    /// IPv6 only (`-6`, `AddressFamily inet6`).
    V6,
}

impl AddressFamily {
    /// Build a preference from the `-4` / `-6` command line flags.
    ///
    /// Returns `None` when neither flag is set, so callers can fall back to a
    /// lower-precedence source. clap declares the two flags as mutually
    /// exclusive (`conflicts_with`), so both being set is unreachable through
    /// the CLI; if it ever happens, `-4` wins.
    pub fn from_flags(ipv4: bool, ipv6: bool) -> Option<Self> {
        match (ipv4, ipv6) {
            (true, _) => Some(Self::V4),
            (_, true) => Some(Self::V6),
            _ => None,
        }
    }

    /// Parse an ssh_config `AddressFamily` value.
    ///
    /// Accepts `any`, `inet`, and `inet6` case-insensitively. An unrecognized
    /// value warns and falls back to [`Any`](Self::Any) rather than failing:
    /// OpenSSH tolerates a config file bssh should not reject outright, and a
    /// hard error here would make an unrelated typo block every connection.
    pub fn from_config_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "any" => Self::Any,
            "inet" => Self::V4,
            "inet6" => Self::V6,
            other => {
                tracing::warn!(
                    "Unrecognized AddressFamily value '{other}' in SSH config; expected any, inet, or inet6. Falling back to 'any'"
                );
                Self::Any
            }
        }
    }

    /// Resolve the effective preference using OpenSSH precedence:
    /// command line flag, then config keyword, then the `any` default.
    pub fn resolve(ipv4_flag: bool, ipv6_flag: bool, config_value: Option<&str>) -> Self {
        Self::from_flags(ipv4_flag, ipv6_flag)
            .or_else(|| config_value.map(Self::from_config_value))
            .unwrap_or_default()
    }

    /// Whether this preference constrains the candidate addresses at all.
    pub const fn is_forced(self) -> bool {
        !matches!(self, Self::Any)
    }

    /// Whether `addr` is usable under this preference.
    pub const fn matches(self, addr: &SocketAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => addr.is_ipv4(),
            Self::V6 => addr.is_ipv6(),
        }
    }

    /// Keep only the candidates usable under this preference, preserving the
    /// resolver's ordering.
    ///
    /// [`Any`](Self::Any) returns the input unchanged, which is what keeps the
    /// no-flag path byte-for-byte identical to the previous behavior.
    pub fn filter(self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if !self.is_forced() {
            return addrs;
        }
        addrs.into_iter().filter(|a| self.matches(a)).collect()
    }

    /// First candidate usable under this preference, or `None`.
    pub fn first_match(self, addrs: &[SocketAddr]) -> Option<SocketAddr> {
        addrs.iter().copied().find(|a| self.matches(a))
    }

    /// Default loopback listen address for this preference.
    ///
    /// Used for port-forwarding specifications that do not name a bind
    /// address: `-6` binds `::1` instead of `127.0.0.1`.
    pub const fn loopback(self) -> IpAddr {
        match self {
            Self::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    /// Default wildcard listen address for this preference, used for the `*:`
    /// bind form.
    pub const fn unspecified(self) -> IpAddr {
        match self {
            Self::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Any => "any",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        };
        f.write_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv4 socket address")
    }

    fn v6(s: &str) -> SocketAddr {
        s.parse().expect("valid IPv6 socket address")
    }

    fn mixed() -> Vec<SocketAddr> {
        vec![
            v6("[2001:db8::1]:22"),
            v4("192.0.2.10:22"),
            v6("[2001:db8::2]:22"),
            v4("192.0.2.11:22"),
        ]
    }

    #[test]
    fn ipv4_filter_keeps_only_ipv4_in_resolver_order() {
        let filtered = AddressFamily::V4.filter(mixed());
        assert_eq!(filtered, vec![v4("192.0.2.10:22"), v4("192.0.2.11:22")]);
    }

    #[test]
    fn ipv6_filter_keeps_only_ipv6_in_resolver_order() {
        let filtered = AddressFamily::V6.filter(mixed());
        assert_eq!(
            filtered,
            vec![v6("[2001:db8::1]:22"), v6("[2001:db8::2]:22")]
        );
    }

    #[test]
    fn any_filter_returns_the_original_list_unchanged_and_in_order() {
        let original = mixed();
        let filtered = AddressFamily::Any.filter(original.clone());
        assert_eq!(filtered, original);
    }

    #[test]
    fn filter_can_empty_the_candidate_list() {
        let only_v4 = vec![v4("192.0.2.10:22")];
        assert!(AddressFamily::V6.filter(only_v4).is_empty());

        let only_v6 = vec![v6("[2001:db8::1]:22")];
        assert!(AddressFamily::V4.filter(only_v6).is_empty());
    }

    #[test]
    fn first_match_picks_the_first_candidate_of_the_forced_family() {
        let addrs = mixed();
        assert_eq!(
            AddressFamily::V4.first_match(&addrs),
            Some(v4("192.0.2.10:22"))
        );
        assert_eq!(
            AddressFamily::V6.first_match(&addrs),
            Some(v6("[2001:db8::1]:22"))
        );
        assert_eq!(
            AddressFamily::Any.first_match(&addrs),
            Some(v6("[2001:db8::1]:22"))
        );
        assert_eq!(AddressFamily::V6.first_match(&[v4("192.0.2.10:22")]), None);
    }

    #[test]
    fn config_values_are_case_insensitive() {
        assert_eq!(AddressFamily::from_config_value("any"), AddressFamily::Any);
        assert_eq!(AddressFamily::from_config_value("ANY"), AddressFamily::Any);
        assert_eq!(AddressFamily::from_config_value("inet"), AddressFamily::V4);
        assert_eq!(AddressFamily::from_config_value("INet"), AddressFamily::V4);
        assert_eq!(AddressFamily::from_config_value("inet6"), AddressFamily::V6);
        assert_eq!(AddressFamily::from_config_value("INET6"), AddressFamily::V6);
        assert_eq!(
            AddressFamily::from_config_value("  inet6  "),
            AddressFamily::V6
        );
    }

    #[test]
    fn unrecognized_config_value_falls_back_to_any() {
        assert_eq!(
            AddressFamily::from_config_value("ipv6"),
            AddressFamily::Any,
            "an unrecognized value must not hard-fail a config OpenSSH tolerates"
        );
        assert_eq!(AddressFamily::from_config_value(""), AddressFamily::Any);
    }

    #[test]
    fn command_line_flag_wins_over_config_keyword() {
        // -4 beats `AddressFamily inet6`.
        assert_eq!(
            AddressFamily::resolve(true, false, Some("inet6")),
            AddressFamily::V4
        );
        // -6 beats `AddressFamily inet`.
        assert_eq!(
            AddressFamily::resolve(false, true, Some("inet")),
            AddressFamily::V6
        );
        // -4 beats `AddressFamily any`.
        assert_eq!(
            AddressFamily::resolve(true, false, Some("any")),
            AddressFamily::V4
        );
    }

    #[test]
    fn config_keyword_applies_when_no_flag_is_given() {
        assert_eq!(
            AddressFamily::resolve(false, false, Some("inet")),
            AddressFamily::V4
        );
        assert_eq!(
            AddressFamily::resolve(false, false, Some("inet6")),
            AddressFamily::V6
        );
        assert_eq!(
            AddressFamily::resolve(false, false, Some("any")),
            AddressFamily::Any
        );
    }

    #[test]
    fn default_is_any_when_neither_flag_nor_keyword_is_set() {
        assert_eq!(
            AddressFamily::resolve(false, false, None),
            AddressFamily::Any
        );
        assert_eq!(AddressFamily::default(), AddressFamily::Any);
        assert!(!AddressFamily::default().is_forced());
    }

    #[test]
    fn default_bind_addresses_follow_the_forced_family() {
        assert_eq!(
            AddressFamily::V6.loopback(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            AddressFamily::V4.loopback(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            AddressFamily::Any.loopback(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the no-flag default must stay IPv4 loopback"
        );

        assert_eq!(
            AddressFamily::V6.unspecified(),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(
            AddressFamily::Any.unspecified(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn display_names_match_the_user_facing_error_text() {
        assert_eq!(AddressFamily::V4.to_string(), "IPv4");
        assert_eq!(AddressFamily::V6.to_string(), "IPv6");
        assert_eq!(AddressFamily::Any.to_string(), "any");
    }
}
