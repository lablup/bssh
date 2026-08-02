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

//! Integration coverage for the `-4` / `-6` address family flags and the
//! ssh_config `AddressFamily` keyword (issue #246).
//!
//! Before this, both were parsed and then discarded: `bssh -6` against a
//! dual-stack host could still connect over IPv4. These tests exercise the
//! real code paths, not helpers written for the tests.

use bssh::cli::Cli;
use bssh::forwarding::ForwardingType;
use bssh::ssh::SshConfig;
use bssh::ssh::tokio_client::{AddressFamily, AuthMethod, Client, ServerCheckMethod};
use bssh::ssh::tokio_client::{Error as SshError, SshConnectionConfig};
use clap::Parser;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpListener;

/// Resolve the effective address family exactly the way `app::dispatcher`
/// does: command line flag over ssh_config keyword over the `any` default.
fn effective_family(cli: &Cli, ssh_config: &SshConfig, hostname: &str) -> AddressFamily {
    let config_value = ssh_config.get_address_family(hostname);
    AddressFamily::resolve(cli.ipv4, cli.ipv6, config_value.as_deref())
}

#[test]
fn ssh_config_address_family_is_honored_when_no_flag_is_given() {
    let ssh_config = SshConfig::parse(
        r#"
Host v6host
    AddressFamily inet6

Host v4host
    AddressFamily inet

Host anyhost
    AddressFamily any
"#,
    )
    .expect("ssh config parses");

    let cli = Cli::parse_from(["bssh", "-H", "example.com", "true"]);

    assert_eq!(
        effective_family(&cli, &ssh_config, "v6host"),
        AddressFamily::V6
    );
    assert_eq!(
        effective_family(&cli, &ssh_config, "v4host"),
        AddressFamily::V4
    );
    assert_eq!(
        effective_family(&cli, &ssh_config, "anyhost"),
        AddressFamily::Any
    );
    assert_eq!(
        effective_family(&cli, &ssh_config, "unlisted.example.com"),
        AddressFamily::Any,
        "a host with no AddressFamily keyword must stay unconstrained"
    );
}

#[test]
fn command_line_flag_overrides_the_ssh_config_keyword() {
    let ssh_config = SshConfig::parse(
        r#"
Host v6host
    AddressFamily inet6
"#,
    )
    .expect("ssh config parses");

    let cli4 = Cli::parse_from(["bssh", "-4", "-H", "v6host", "true"]);
    assert_eq!(
        effective_family(&cli4, &ssh_config, "v6host"),
        AddressFamily::V4,
        "-4 must win over `AddressFamily inet6`"
    );

    let cli6 = Cli::parse_from(["bssh", "-6", "-H", "v6host", "true"]);
    assert_eq!(
        effective_family(&cli6, &ssh_config, "v6host"),
        AddressFamily::V6
    );
}

#[test]
fn unrecognized_ssh_config_value_falls_back_to_any_without_failing() {
    let ssh_config = SshConfig::parse(
        r#"
Host typo
    AddressFamily ipv6
"#,
    )
    .expect("an unrecognized AddressFamily value must not fail config parsing");

    let cli = Cli::parse_from(["bssh", "-H", "typo", "true"]);
    assert_eq!(
        effective_family(&cli, &ssh_config, "typo"),
        AddressFamily::Any
    );
}

#[test]
fn ipv6_flag_changes_the_default_forwarding_listen_address() {
    let cli = Cli::parse_from([
        "bssh",
        "-6",
        "-L",
        "8080:example.com:80",
        "-D",
        "1080",
        "-H",
        "example.com",
        "true",
    ]);

    let forwards = cli
        .parse_port_forwards(AddressFamily::V6)
        .expect("forwarding specs parse");

    let local = forwards
        .iter()
        .find(|f| matches!(f, ForwardingType::Local { .. }))
        .expect("local forward present");
    match local {
        ForwardingType::Local { bind_addr, .. } => {
            assert_eq!(*bind_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        }
        other => panic!("expected Local, got {other:?}"),
    }

    let dynamic = forwards
        .iter()
        .find(|f| matches!(f, ForwardingType::Dynamic { .. }))
        .expect("dynamic forward present");
    match dynamic {
        ForwardingType::Dynamic { bind_addr, .. } => {
            assert_eq!(*bind_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        }
        other => panic!("expected Dynamic, got {other:?}"),
    }
}

#[test]
fn no_flag_keeps_the_ipv4_forwarding_listen_default() {
    let cli = Cli::parse_from([
        "bssh",
        "-L",
        "8080:example.com:80",
        "-D",
        "1080",
        "-H",
        "example.com",
        "true",
    ]);

    let forwards = cli
        .parse_port_forwards(AddressFamily::Any)
        .expect("forwarding specs parse");

    for forward in &forwards {
        let bind_addr = match forward {
            ForwardingType::Local { bind_addr, .. } => *bind_addr,
            ForwardingType::Dynamic { bind_addr, .. } => *bind_addr,
            ForwardingType::Remote { bind_addr, .. } => *bind_addr,
        };
        assert_eq!(
            bind_addr,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the unflagged default must remain IPv4 loopback"
        );
    }
}

#[test]
fn explicit_forwarding_bind_address_overrides_the_flag() {
    let cli = Cli::parse_from([
        "bssh",
        "-6",
        "-L",
        "192.168.1.5:8080:example.com:80",
        "-H",
        "example.com",
        "true",
    ]);

    let forwards = cli
        .parse_port_forwards(AddressFamily::V6)
        .expect("forwarding specs parse");

    match &forwards[0] {
        ForwardingType::Local { bind_addr, .. } => {
            assert_eq!(*bind_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        }
        other => panic!("expected Local, got {other:?}"),
    }
}

/// Whether this machine can bind and resolve both loopback families, which is
/// what the dual-stack connect test needs. CI runners without IPv6 loopback
/// skip that test rather than fail it.
async fn dual_stack_listeners() -> Option<(TcpListener, TcpListener, u16)> {
    let v6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .ok()?;
    let port = v6.local_addr().ok()?.port();
    let v4 = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .await
        .ok()?;

    let resolved: Vec<SocketAddr> = ("localhost", port).to_socket_addrs().ok()?.collect();
    let has_v4 = resolved.iter().any(SocketAddr::is_ipv4);
    let has_v6 = resolved.iter().any(SocketAddr::is_ipv6);
    if !has_v4 || !has_v6 {
        return None;
    }

    Some((v4, v6, port))
}

/// The flag must change which address is actually connected to. Both loopback
/// families listen on the same port and `localhost` resolves to both, so the
/// listener that accepts is direct evidence of which candidate the connect
/// path chose. The SSH handshake never completes (these are bare TCP
/// listeners), which is fine: the TCP accept is the observation.
#[tokio::test]
async fn forced_family_selects_the_matching_candidate_address() {
    let Some((v4_listener, v6_listener, port)) = dual_stack_listeners().await else {
        eprintln!("skipping: dual-stack loopback unavailable on this host");
        return;
    };

    for (family, expect_v6) in [(AddressFamily::V6, true), (AddressFamily::V4, false)] {
        let config = SshConnectionConfig::new().with_address_family(family);
        let connect = Client::connect_with_ssh_config(
            ("localhost", port),
            "user",
            AuthMethod::with_password("unused"),
            ServerCheckMethod::NoCheck,
            &config,
        );

        let accepted_v6 = tokio::select! {
            _ = v6_listener.accept() => true,
            _ = v4_listener.accept() => false,
            _ = connect => panic!("the SSH handshake cannot complete against a bare TCP listener"),
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("no connection was accepted within 5s for {family}");
            }
        };

        assert_eq!(
            accepted_v6, expect_v6,
            "forcing {family} must connect to the {family} listener"
        );
    }
}

/// With no family forced the behavior is unchanged: whichever candidate the
/// resolver puts first wins, and neither listener is excluded up front.
#[tokio::test]
async fn unforced_family_still_connects() {
    let Some((v4_listener, v6_listener, port)) = dual_stack_listeners().await else {
        eprintln!("skipping: dual-stack loopback unavailable on this host");
        return;
    };

    let config = SshConnectionConfig::default();
    let connect = Client::connect_with_ssh_config(
        ("localhost", port),
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    );

    tokio::select! {
        _ = v6_listener.accept() => {}
        _ = v4_listener.accept() => {}
        _ = connect => panic!("the SSH handshake cannot complete against a bare TCP listener"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("no connection was accepted within 5s with no family forced");
        }
    }
}

/// The forced-family failure is a hard failure with a specific message, not a
/// silent fallback to the other family.
#[tokio::test]
async fn forced_family_with_no_candidate_fails_hard() {
    let addr: SocketAddr = "127.0.0.1:22".parse().expect("valid address");
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

    assert!(matches!(err, SshError::NoAddressForFamily { .. }));
    assert_eq!(err.to_string(), "no IPv6 address found for 127.0.0.1");
}
