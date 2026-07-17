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

//! Tests for [`super::connection::SshConnectionConfig`]'s compression mapping.
//!
//! Regression coverage for #219: the ssh_config `Compression` directive was
//! parsed and resolved but never consumed when building the russh client
//! config, so `Compression yes`/`no` had no effect on the actual connection.

use super::connection::SshConnectionConfig;

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
