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

use std::path::PathBuf;
use std::time::Duration;

use super::address_family::AddressFamily;
use super::authentication::{AuthMethod, ServerCheckMethod};
use super::connection::{
    Client, SshConnectionConfig, SshConnectionConfigResolver, configure_tcp_keepalive,
};
use super::proxy_command::{ProxyCommandConfig, ProxyMode};
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

#[test]
fn test_proxy_resolution_keeps_first_ssh_config_directive() {
    let command_first = SshConfig::parse(
        r#"
Host target
    ProxyCommand nc %h %p
    ProxyJump ignored.example.com
"#,
    )
    .expect("valid ssh_config");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(command_first))
        .resolve_for_host("target");
    assert!(matches!(config.proxy_mode, Some(ProxyMode::Command(_))));

    let jump_first = SshConfig::parse(
        r#"
Host target
    ProxyJump bastion.example.com
    ProxyCommand nc %h %p
"#,
    )
    .expect("valid ssh_config");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(jump_first))
        .resolve_for_host("target");
    assert_eq!(
        config.proxy_mode,
        Some(ProxyMode::Jump("bastion.example.com".to_string()))
    );
}

#[test]
fn test_cli_proxy_jump_overrides_ssh_config_proxy_command() {
    let ssh_config = SshConfig::parse(
        r#"
Host target
    ProxyCommand nc %h %p
"#,
    )
    .expect("valid ssh_config");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .with_cli_proxy_jump(Some("cli-bastion.example.com".to_string()))
        .resolve_for_host("target");

    assert_eq!(
        config.proxy_mode,
        Some(ProxyMode::Jump("cli-bastion.example.com".to_string()))
    );
}

#[test]
fn test_proxy_tokens_use_effective_alias_original_and_resolved_hosts() {
    let ssh_config = SshConfig::parse(
        r#"
Host original-host
    HostKeyAlias config-key-alias
    ProxyCommand printf '%h|%k|%n'
"#,
    )
    .expect("valid ssh_config");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .with_cli_host_key_alias(Some("cli-key-alias".to_string()))
        .resolve_for_host("original-host");

    assert_eq!(config.host_key_alias.as_deref(), Some("cli-key-alias"));
    let Some(ProxyMode::Command(command)) = config.proxy_mode else {
        panic!("ProxyCommand must win for original-host");
    };
    assert_eq!(
        command
            .expand("resolved.internal", 2222, "alice")
            .expect("valid proxy tokens"),
        "printf 'resolved.internal|cli-key-alias|original-host'"
    );
}

#[test]
fn test_proxy_none_disables_yaml_jump_fallback() {
    for directive in ["ProxyCommand none", "ProxyJump none"] {
        let ssh_config =
            SshConfig::parse(&format!("Host target\n    {directive}\n")).expect("valid ssh_config");
        let config = SshConnectionConfigResolver::new()
            .with_ssh_config(Some(ssh_config))
            .with_yaml_proxy_jump(Some("yaml-bastion.example.com".to_string()))
            .resolve_for_host("target");
        assert_eq!(config.proxy_mode, Some(ProxyMode::Direct));
    }
}

#[test]
fn test_yaml_jump_is_used_only_as_proxy_fallback() {
    let config = SshConnectionConfigResolver::new()
        .with_yaml_proxy_jump(Some("yaml-bastion.example.com".to_string()))
        .resolve_for_host("target");

    assert_eq!(
        config.proxy_mode,
        Some(ProxyMode::Jump("yaml-bastion.example.com".to_string()))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_proxy_command_routes_ssh_transport_through_child() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind proxy target");
    let proxy_port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("ProxyCommand did not connect")
            .expect("accept ProxyCommand connection");
        let mut banner = [0_u8; 256];
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut banner))
            .await
            .expect("SSH client did not send a banner")
            .expect("read SSH client banner");
        assert!(banner[..read].starts_with(b"SSH-2.0-"));
        stream
            .write_all(b"SSH-2.0-OpenSSH_9.9\r\n")
            .await
            .expect("write test server banner");
    });

    let command = format!(
        "sh -c 'test \"$1\" = unresolvable.invalid && test \"$2\" = 2222 && test \"$3\" = alice && test \"$4\" = target-alias && test \"$5\" = key-alias && exec nc 127.0.0.1 \"$6\"' sh %h %p %r %n %k {proxy_port}"
    );
    let proxy = ProxyCommandConfig::new(command, "target-alias")
        .with_host_key_alias(Some("key-alias".to_string()));
    let config = SshConnectionConfig::new().with_proxy_mode(Some(ProxyMode::Command(proxy)));
    let connect = Client::connect_with_ssh_config(
        "unresolvable.invalid:2222",
        "alice",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    );
    let error = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("proxy-backed SSH handshake timed out")
        .expect_err("the deliberately incomplete SSH server must fail");
    assert!(
        !matches!(error, super::Error::ProxyCommandFailed { .. }),
        "proxy child should have transported the SSH banner: {error:?}"
    );
    server.await.expect("proxy target task");
}

#[cfg(unix)]
#[tokio::test]
async fn test_proxy_command_failure_is_actionable_at_connection_boundary() {
    let proxy = ProxyCommandConfig::new(
        "sh -c 'printf connection\\ proxy\\ failed >&2; exit 23'",
        "target-alias",
    );
    let config = SshConnectionConfig::new().with_proxy_mode(Some(ProxyMode::Command(proxy)));
    let error = Client::connect_with_ssh_config(
        "unresolvable.invalid:2222",
        "alice",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("failed ProxyCommand must fail the connection");

    match error {
        super::Error::ProxyCommandFailed {
            command,
            status,
            stderr,
        } => {
            assert!(command.contains("exit 23"));
            assert!(status.contains("23"));
            assert_eq!(stderr, "connection proxy failed");
        }
        other => panic!("expected actionable ProxyCommand error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_proxy_use_fdpass_is_rejected_at_connection_boundary() {
    let proxy = ProxyCommandConfig::new("unused", "target-alias").with_fdpass(true);
    let config = SshConnectionConfig::new().with_proxy_mode(Some(ProxyMode::Command(proxy)));
    let error = Client::connect_with_ssh_config(
        "unresolvable.invalid:2222",
        "alice",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("ProxyUseFdpass must be rejected explicitly");

    assert!(matches!(
        error,
        super::Error::ProxyUseFdpassUnsupported { .. }
    ));
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

#[derive(Clone)]
struct CountingAddress {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    result: Option<std::net::SocketAddr>,
}

impl super::ToSocketAddrsWithHostname for CountingAddress {
    fn to_socket_addrs(&self) -> std::io::Result<Vec<std::net::SocketAddr>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.result.map(|address| vec![address]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "synthetic DNS failure")
        })
    }

    fn hostname(&self) -> String {
        "retry.example".to_string()
    }

    fn host_port(&self) -> std::io::Result<(String, u16)> {
        Ok((
            self.hostname(),
            self.result.map_or(22, |address| address.port()),
        ))
    }
}

#[tokio::test]
async fn connection_attempts_reresolves_dns_for_each_carrier_round() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let address = CountingAddress {
        calls: std::sync::Arc::clone(&calls),
        result: None,
    };
    let config = SshConnectionConfig::new()
        .with_connection_attempts(2)
        .with_tcp_keep_alive(false);

    let error = Client::connect_with_ssh_config(
        address,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("both synthetic DNS rounds must fail");

    match error {
        super::Error::ConnectionAttemptsExhausted { attempts, source } => {
            assert_eq!(attempts, 2);
            assert!(matches!(*source, super::Error::DnsResolution { .. }));
        }
        other => panic!("unexpected retry error: {other:?}"),
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_attempts_preserves_the_last_typed_tcp_failure() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let address = CountingAddress {
        calls: std::sync::Arc::clone(&calls),
        result: Some("127.0.0.1:0".parse().unwrap()),
    };
    let config = SshConnectionConfig::new()
        .with_connection_attempts(2)
        .with_tcp_keep_alive(false);

    let error = Client::connect_with_ssh_config(
        address,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("both synthetic TCP rounds must fail");

    match error {
        super::Error::ConnectionAttemptsExhausted { attempts, source } => {
            assert_eq!(attempts, 2);
            assert!(matches!(*source, super::Error::TcpConnect { port: 0, .. }));
        }
        other => panic!("unexpected retry error: {other:?}"),
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn connection_attempts_never_retries_ssh_handshake_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(stream);
    });
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let address = CountingAddress {
        calls: std::sync::Arc::clone(&calls),
        result: Some(socket_addr),
    };
    let config = SshConnectionConfig::new()
        .with_connection_attempts(3)
        .with_tcp_keep_alive(false);

    let error = Client::connect_with_ssh_config(
        address,
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("a non-SSH carrier must fail during handshake");
    server.await.unwrap();

    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        matches!(error, super::Error::ProtocolNegotiation { .. }),
        "post-TCP handshake failure must preserve its typed stage: {error:?}"
    );
}

#[tokio::test]
async fn tcp_keep_alive_sets_and_verifies_the_os_socket_option() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket_addr = listener.local_addr().unwrap();
    let connecting = tokio::spawn(tokio::net::TcpStream::connect(socket_addr));
    let (_server, _) = listener.accept().await.unwrap();
    let client = connecting.await.unwrap().unwrap();
    let config = SshConnectionConfig::new()
        .with_keepalive_interval(None)
        .with_tcp_keep_alive(true);
    let keepalive = config
        .to_tcp_keepalive()
        .expect("TCPKeepAlive yes must be independent of SSH keepalives");

    configure_tcp_keepalive(&client, socket_addr, &keepalive).unwrap();
    assert!(socket2::SockRef::from(&client).keepalive().unwrap());
    assert!(
        SshConnectionConfig::new()
            .with_tcp_keep_alive(false)
            .to_tcp_keepalive()
            .is_none()
    );
}

#[test]
fn configured_algorithms_reach_the_russh_transport_preferences() {
    let ssh_config = SshConfig::parse(
        "Host target\n    Ciphers aes128-ctr\n    MACs hmac-sha2-256\n    KexAlgorithms curve25519-sha256\n    HostKeyAlgorithms ssh-ed25519\n    PubkeyAcceptedAlgorithms rsa-sha2-*\n",
    )
    .unwrap();
    let connection_config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .resolve_for_host("target");
    let config = connection_config.to_russh_config();

    assert_eq!(config.preferred.cipher[0].as_ref(), "aes128-ctr");
    assert_eq!(config.preferred.mac[0].as_ref(), "hmac-sha2-256");
    assert_eq!(config.preferred.kex[0].as_ref(), "curve25519-sha256");
    assert_eq!(config.preferred.key[0].as_ref(), "ssh-ed25519");
    assert_eq!(
        connection_config.pubkey_accepted_algorithms.unwrap(),
        [
            "rsa-sha2-512-cert-v01@openssh.com",
            "rsa-sha2-512",
            "rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-256"
        ]
    );
}

#[test]
fn connection_attempts_rejects_zero() {
    let error = SshConfig::parse("Host target\n    ConnectionAttempts 0\n").unwrap_err();
    assert!(format!("{error:#}").contains("at least 1"));
}

#[test]
fn resolved_authentication_directives_reach_runtime_policy() {
    let ssh_config = SshConfig::parse(
        "Host target\n    IdentityFile ~/.ssh/config-key\n    CertificateFile ~/.ssh/config-key-cert.pub\n    IdentitiesOnly yes\n    PreferredAuthentications password,publickey\n    PubkeyAuthentication no\n    PasswordAuthentication yes\n    NumberOfPasswordPrompts 2\n    BatchMode yes\n    PubkeyAcceptedAlgorithms ssh-ed25519\n",
    )
    .unwrap();
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .resolve_for_host("target");
    let policy = config.auth_policy;

    assert_eq!(policy.identity_files.len(), 1);
    assert_eq!(policy.certificate_files.len(), 1);
    assert!(policy.identities_only);
    assert_eq!(policy.preferred_authentications, ["password", "publickey"]);
    assert!(!policy.pubkey_authentication);
    assert!(policy.password_authentication);
    assert_eq!(policy.number_of_password_prompts, 2);
    assert!(policy.batch_mode);
    assert_eq!(policy.pubkey_accepted_algorithms.unwrap(), ["ssh-ed25519"]);
}

#[test]
fn cli_identities_precede_ssh_config_identities() {
    let ssh_config = SshConfig::parse("Host target\n    IdentityFile /config-key\n").unwrap();
    let policy = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .with_cli_identity_files(vec![
            PathBuf::from("/cli-first"),
            PathBuf::from("/cli-second"),
        ])
        .resolve_for_host("target")
        .auth_policy;

    assert_eq!(
        policy.cli_identity_files,
        [PathBuf::from("/cli-first"), PathBuf::from("/cli-second")]
    );
    assert_eq!(policy.identity_files, [PathBuf::from("/config-key")]);
}

#[test]
fn authentication_yes_no_defaults_and_overrides_are_preserved() {
    let defaults = SshConnectionConfigResolver::new()
        .resolve_for_host("target")
        .auth_policy;
    assert!(!defaults.identities_only);
    assert!(defaults.pubkey_authentication);
    assert!(defaults.password_authentication);
    assert!(!defaults.batch_mode);

    let ssh_config = SshConfig::parse(
        "Host target\n    IdentitiesOnly no\n    PubkeyAuthentication yes\n    PasswordAuthentication no\n    BatchMode no\n",
    )
    .unwrap();
    let policy = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(ssh_config))
        .resolve_for_host("target")
        .auth_policy;
    assert!(!policy.identities_only);
    assert!(policy.pubkey_authentication);
    assert!(!policy.password_authentication);
    assert!(!policy.batch_mode);
}
