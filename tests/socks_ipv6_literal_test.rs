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

//! Regression coverage for issue #256.
//!
//! The SOCKS5 handler now turns ATYP 0x04 into a bracketed `[ipv6]:port`
//! target string before it calls `open_direct_tcpip_channel_with_family`.
//! These tests exercise the same public forced-family connect path directly,
//! which keeps the verification runnable even while unrelated `cfg(test)`
//! breakage exists elsewhere in the library test modules.

use bssh::ssh::tokio_client::{AddressFamily, AuthMethod, Client, Error as SshError};
use bssh::ssh::tokio_client::{ServerCheckMethod, SshConnectionConfig};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpListener;

async fn ipv6_loopback_listener() -> Option<(TcpListener, u16)> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .ok()?;
    let port = listener.local_addr().ok()?.port();
    Some((listener, port))
}

#[tokio::test]
async fn bracketed_ipv6_literals_connect_under_forced_ipv6() {
    let Some((listener, port)) = ipv6_loopback_listener().await else {
        eprintln!("skipping: IPv6 loopback unavailable on this host");
        return;
    };

    let target = format!("[::1]:{port}");
    let config = SshConnectionConfig::new().with_address_family(AddressFamily::V6);
    let connect = Client::connect_with_ssh_config(
        target.as_str(),
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    );

    tokio::select! {
        _ = listener.accept() => {}
        _ = connect => panic!("the SSH handshake cannot complete against a bare TCP listener"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("no connection was accepted within 5s for a bracketed IPv6 literal");
        }
    }
}

#[tokio::test]
async fn bracketed_ipv6_literals_fail_closed_under_forced_ipv4() {
    let config = SshConnectionConfig::new().with_address_family(AddressFamily::V4);

    let err = Client::connect_with_ssh_config(
        "[::1]:22",
        "user",
        AuthMethod::with_password("unused"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect_err("forcing IPv4 against an IPv6 literal must fail");

    assert!(matches!(err, SshError::NoAddressForFamily { .. }));
    assert_eq!(err.to_string(), "no IPv4 address found for [::1]:22");
}
