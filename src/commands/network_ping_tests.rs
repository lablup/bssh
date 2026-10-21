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

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[derive(Default)]
struct FakeProbe {
    addresses: HashMap<String, IpAddr>,
    samples: HashMap<IpAddr, Vec<Duration>>,
    active: AtomicUsize,
    peak: AtomicUsize,
}

#[async_trait]
impl NetworkProbe for FakeProbe {
    async fn resolve(&self, host: &str, family: AddressFamily) -> Result<ResolvedTarget> {
        let address = *self.addresses.get(host).context("unknown fake host")?;
        anyhow::ensure!(family.matches_ip(address), "family mismatch");
        Ok(address.into())
    }

    async fn probe(&self, target: ResolvedTarget, settings: ProbeSettings) -> Result<ProbeSamples> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        tokio::task::yield_now().await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        let latencies = self
            .samples
            .get(&target.address)
            .cloned()
            .unwrap_or_default();
        Ok(ProbeSamples {
            sent: settings.count,
            received: u16::try_from(latencies.len()).unwrap_or(u16::MAX),
            statistics: LatencyStats::from_samples(&latencies),
            last_error: Some("timed out".to_string()),
        })
    }
}

fn node(host: &str) -> Node {
    Node::new(host.to_string(), 22, "user".to_string())
}

#[test]
fn statistics_use_population_standard_deviation() {
    let samples = [
        Duration::from_millis(1),
        Duration::from_millis(2),
        Duration::from_millis(3),
    ];
    let stats = LatencyStats::from_samples(&samples).expect("samples are non-empty");
    assert_eq!(stats.min_ms, 1.0);
    assert_eq!(stats.avg_ms, 2.0);
    assert_eq!(stats.max_ms, 3.0);
    assert!((stats.stddev_ms - 0.816_496_580_9).abs() < 1e-9);
}

#[test]
fn outcome_maps_all_partial_and_total_failure() {
    for (reachable, unreachable, expected) in [(2, 0, 0), (1, 1, 1), (0, 2, 255)] {
        assert_eq!(
            NetworkPingOutcome {
                total: reachable + unreachable,
                reachable,
                unreachable,
            }
            .exit_code(),
            expected
        );
    }
}

#[test]
fn loss_calculation_reports_three_of_four_as_twenty_five_percent() {
    let result = HostNetworkPingResult {
        node: node("host"),
        address: None,
        sent: 4,
        received: 3,
        statistics: None,
        error: None,
    };
    assert_eq!(result.loss_percent(), 25.0);
}

#[test]
fn address_selection_preserves_resolver_order_with_a_hard_family_filter() {
    let addresses = [
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 7)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
    ];
    assert_eq!(
        first_eligible_target(addresses, AddressFamily::Any),
        Some(ResolvedTarget {
            address: addresses[0].ip(),
            scope_id: 7,
        })
    );
    assert_eq!(ResolvedTarget::from(addresses[0]).to_string(), "::1%7");
    assert_eq!(
        first_eligible_target(addresses, AddressFamily::V4),
        Some(addresses[1].into())
    );
    assert_eq!(
        first_eligible_target(addresses, AddressFamily::V6),
        Some(ResolvedTarget {
            address: addresses[0].ip(),
            scope_id: 7,
        })
    );
}

#[tokio::test]
async fn probe_resolves_the_expanded_hostname_not_the_ssh_alias() {
    let address = IpAddr::from([192, 0, 2, 10]);
    let mut probe = FakeProbe::default();
    probe
        .addresses
        .insert("effective.example".to_string(), address);
    probe
        .samples
        .insert(address, vec![Duration::from_millis(1)]);
    let result = probe_node(
        &probe,
        node("effective.example").with_original_host("alias".to_string()),
        "effective.example",
        AddressFamily::V4,
        ProbeSettings {
            count: 1,
            timeout: Duration::from_secs(1),
            interval: Duration::from_millis(200),
        },
    )
    .await;

    assert_eq!(result.address, Some(address.into()));
    assert!(result.is_reachable());
}

#[tokio::test]
async fn run_expands_cluster_alias_through_ssh_config_hostname() {
    let address = IpAddr::from([192, 0, 2, 11]);
    let mut probe = FakeProbe::default();
    probe
        .addresses
        .insert("effective.example".to_string(), address);
    probe
        .samples
        .insert(address, vec![Duration::from_millis(1)]);
    let resolver = SshConnectionConfigResolver::new().with_ssh_config(Some(
        crate::ssh::SshConfig::parse(
            "Host alias\n    HostName effective.example\n    AddressFamily inet\n",
        )
        .expect("valid ssh config"),
    ));

    let results = run_network_ping(
        Arc::new(probe),
        vec![node("alias")],
        1,
        ProbeSettings {
            count: 1,
            timeout: Duration::from_secs(1),
            interval: Duration::from_millis(200),
        },
        &resolver,
    )
    .await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].address, Some(address.into()));
    assert!(results[0].is_reachable());
}

#[tokio::test]
async fn mocked_probe_is_family_aware_and_bounded() {
    let mut probe = FakeProbe::default();
    for index in 1..=4 {
        let host = format!("host{index}");
        let address = IpAddr::from([192, 0, 2, index]);
        probe.addresses.insert(host, address);
        probe
            .samples
            .insert(address, vec![Duration::from_millis(index.into())]);
    }
    let settings = ProbeSettings {
        count: 1,
        timeout: Duration::from_secs(1),
        interval: Duration::from_millis(200),
    };
    let probe = Arc::new(probe);
    let results = run_network_ping(
        Arc::clone(&probe),
        (1..=4).map(|index| node(&format!("host{index}"))).collect(),
        2,
        settings,
        &SshConnectionConfigResolver::new().with_cli_address_family(Some(AddressFamily::V4)),
    )
    .await;

    assert_eq!(results.len(), 4);
    assert!(results.iter().all(HostNetworkPingResult::is_reachable));
    assert!(probe.peak.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn mocked_probe_reports_resolution_failure_without_icmp() {
    let probe = Arc::new(FakeProbe::default());
    let result = probe_node(
        probe.as_ref(),
        node("missing"),
        "missing",
        AddressFamily::V6,
        ProbeSettings {
            count: 4,
            timeout: Duration::from_secs(2),
            interval: Duration::from_millis(200),
        },
    )
    .await;

    assert_eq!(result.sent, 0);
    assert_eq!(result.received, 0);
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unknown fake host"))
    );
}
