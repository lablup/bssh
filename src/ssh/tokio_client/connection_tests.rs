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

//! Tests for [`super::connection::SshConnectionConfig`]'s compression mapping
//! and address family constraint.
//!
//! Regression coverage for #219: the ssh_config `Compression` directive was
//! parsed and resolved but never consumed when building the russh client
//! config, so `Compression yes`/`no` had no effect on the actual connection.
//!
//! Regression coverage for #246: `-4`/`-6` and the ssh_config `AddressFamily`
//! keyword were parsed but never consumed on the connect path.

use super::address_family::AddressFamily;
use super::authentication::{AuthMethod, ServerCheckMethod};
use super::connection::{Client, SshConnectionConfig, SshConnectionConfigResolver};
use crate::ssh::SshConfig;

#[test]
fn test_default_compression_advertises_none_only() {
    // `Compression` unset (and the struct default) must match the current
    // effective behavior: only `none` is advertised.
    let config = SshConnectionConfig::default();
    assert!(!config.compression);

    let russh_config = config.to_russh_config();
    assert_eq!(
        russh_config.preferred.compression.as_ref(),
        [russh::compression::NONE],
        "Compression no/unset must advertise only `none`"
    );
}

#[test]
fn test_compression_no_advertises_none_only() {
    let config = SshConnectionConfig::new().with_compression(false);

    let russh_config = config.to_russh_config();
    assert_eq!(
        russh_config.preferred.compression.as_ref(),
        [russh::compression::NONE],
        "Compression no must advertise only `none`"
    );
}

#[test]
fn test_compression_yes_advertises_zlib_then_none() {
    let config = SshConnectionConfig::new().with_compression(true);
    assert!(config.compression);

    let russh_config = config.to_russh_config();
    assert_eq!(
        russh_config.preferred.compression.as_ref(),
        [russh::compression::ZLIB, russh::compression::NONE],
        "Compression yes must advertise zlib ahead of none"
    );
}

#[test]
fn test_compression_yes_never_advertises_delayed_zlib() {
    // Regression guard tied to #215: russh's delayed-zlib (`zlib@openssh.com`)
    // transport desyncs the flate2 stream a few packets after compression
    // activates post-auth. That bug lives in russh's codec, so it applies to
    // bssh acting as a client just as much as it did to bssh acting as a
    // server. `Compression yes` must never cause the client to advertise
    // `zlib@openssh.com`, even though eager `zlib` is offered.
    let config = SshConnectionConfig::new().with_compression(true);
    let russh_config = config.to_russh_config();

    assert!(
        !russh_config
            .preferred
            .compression
            .contains(&russh::compression::ZLIB_LEGACY),
        "Compression yes must never advertise zlib@openssh.com (see #215)"
    );
}

#[test]
fn test_with_compression_is_chainable_with_keepalive_settings() {
    let config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(15))
        .with_keepalive_max(5)
        .with_compression(true);

    assert_eq!(config.keepalive_interval, Some(15));
    assert_eq!(config.keepalive_max, 5);
    assert!(config.compression);

    let russh_config = config.to_russh_config();
    assert_eq!(
        russh_config.preferred.compression.as_ref(),
        [russh::compression::ZLIB, russh::compression::NONE]
    );
}

#[test]
fn test_default_address_family_is_unconstrained() {
    let config = SshConnectionConfig::default();
    assert_eq!(config.address_family, AddressFamily::Any);
    assert!(!config.address_family.is_forced());
}

#[test]
fn test_with_address_family_is_chainable_and_leaves_other_settings_alone() {
    let config = SshConnectionConfig::new()
        .with_keepalive_interval(Some(15))
        .with_keepalive_max(5)
        .with_compression(true)
        .with_address_family(AddressFamily::V6);

    assert_eq!(config.address_family, AddressFamily::V6);
    assert_eq!(config.keepalive_interval, Some(15));
    assert_eq!(config.keepalive_max, 5);
    assert!(config.compression);
}

#[test]
fn test_connection_config_resolver_applies_ssh_config_per_host() {
    let ssh_config = SshConfig::parse(
        r#"
Host v4node
    AddressFamily inet
    Compression yes
    ServerAliveInterval 11
    ServerAliveCountMax 2

Host v6node
    AddressFamily inet6
    Compression no
    ServerAliveInterval 22
    ServerAliveCountMax 4
"#,
    )
    .expect("valid ssh_config");

    let resolver = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .with_yaml_keepalive_interval(Some(30))
        .with_yaml_keepalive_max(Some(3));

    let v4 = resolver.resolve_for_host("v4node");
    assert_eq!(v4.address_family, AddressFamily::V4);
    assert!(v4.compression);
    assert_eq!(v4.keepalive_interval, Some(11));
    assert_eq!(v4.keepalive_max, 2);

    let v6 = resolver.resolve_for_host("v6node");
    assert_eq!(v6.address_family, AddressFamily::V6);
    assert!(!v6.compression);
    assert_eq!(v6.keepalive_interval, Some(22));
    assert_eq!(v6.keepalive_max, 4);

    let fallback = resolver.resolve_for_host("unconfigured");
    assert_eq!(fallback.address_family, AddressFamily::Any);
    assert!(!fallback.compression);
    assert_eq!(fallback.keepalive_interval, Some(30));
    assert_eq!(fallback.keepalive_max, 3);
}

#[test]
fn test_connection_config_resolver_preserves_cli_precedence() {
    let ssh_config = SshConfig::parse(
        r#"
Host target
    AddressFamily inet6
    ServerAliveInterval 11
    ServerAliveCountMax 2
"#,
    )
    .expect("valid ssh_config");

    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .with_cli_keepalive_interval(Some(7))
        .with_cli_keepalive_max(Some(9))
        .with_yaml_keepalive_interval(Some(30))
        .with_yaml_keepalive_max(Some(3))
        .with_cli_address_family(Some(AddressFamily::V4))
        .resolve_for_host("target");

    assert_eq!(config.address_family, AddressFamily::V4);
    assert_eq!(config.keepalive_interval, Some(7));
    assert_eq!(config.keepalive_max, 9);
}

/// The empty-after-filter path must fail with a specific error naming the host
/// and the requested family, not the generic "could not resolve to any
/// addresses". Passing a `SocketAddr` makes the candidate list exactly one
/// address of a known family, so this exercises the real connect path in
/// `connect_with_config_inner` without any network I/O: the filter empties the
/// list and the function returns before the first `TcpStream::connect`.
#[tokio::test]
async fn test_forced_ipv6_with_no_ipv6_candidate_fails_with_specific_error() {
    let addr: std::net::SocketAddr = "127.0.0.1:22".parse().expect("valid IPv4 socket address");
    let config = SshConnectionConfig::new().with_address_family(AddressFamily::V6);

    let err = Client::connect_with_ssh_config(
        addr,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("forcing IPv6 against an IPv4-only candidate must fail");

    assert!(
        matches!(
            err,
            super::Error::NoAddressForFamily {
                family: AddressFamily::V6,
                ..
            }
        ),
        "expected NoAddressForFamily, got: {err:?}"
    );
    assert_eq!(err.to_string(), "no IPv6 address found for 127.0.0.1");
}

#[tokio::test]
async fn test_forced_ipv4_with_no_ipv4_candidate_fails_with_specific_error() {
    let addr: std::net::SocketAddr = "[::1]:22".parse().expect("valid IPv6 socket address");
    let config = SshConnectionConfig::new().with_address_family(AddressFamily::V4);

    let err = Client::connect_with_ssh_config(
        addr,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("forcing IPv4 against an IPv6-only candidate must fail");

    assert!(
        matches!(
            err,
            super::Error::NoAddressForFamily {
                family: AddressFamily::V4,
                ..
            }
        ),
        "expected NoAddressForFamily, got: {err:?}"
    );
    assert_eq!(err.to_string(), "no IPv4 address found for ::1");
}

/// With no family forced, an unreachable address must still produce the
/// ordinary connection error rather than the new family-specific one, proving
/// the default path is unchanged.
#[tokio::test]
async fn test_unforced_family_does_not_produce_the_family_error() {
    // Port 0 is never connectable, so this fails fast at the TCP layer without
    // depending on anything being reachable.
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid IPv4 socket address");
    let config = SshConnectionConfig::default();

    let err = Client::connect_with_ssh_config(
        addr,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("connecting to port 0 must fail");

    assert!(
        !matches!(err, super::Error::NoAddressForFamily { .. }),
        "the unconstrained path must never report a family mismatch, got: {err:?}"
    );
}
