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

//! Direct-origin ICMP connectivity checks for the `network-ping` subcommand.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
use tokio::net::lookup_host;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::{sleep, timeout};

use crate::node::Node;
use crate::ssh::tokio_client::{AddressFamily, ProxyMode, SshConnectionConfigResolver};
use crate::ui::{Colorize, OutputFormatter};

const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PARALLELISM: usize = 4_096;
const NETWORK_PING_LEVEL_FAILURE: i32 = 255;

#[derive(Debug, Clone, Copy, PartialEq)]
struct LatencyStats {
    min_ms: f64,
    avg_ms: f64,
    max_ms: f64,
    stddev_ms: f64,
}

impl LatencyStats {
    #[cfg(test)]
    fn from_samples(samples: &[Duration]) -> Option<Self> {
        let mut accumulator = LatencyAccumulator::default();
        for sample in samples {
            accumulator.record(*sample);
        }
        accumulator.finish()
    }
}

#[derive(Debug, Default)]
struct LatencyAccumulator {
    count: u16,
    mean_ms: f64,
    squared_deviation_sum: f64,
    min_ms: f64,
    max_ms: f64,
}

impl LatencyAccumulator {
    fn record(&mut self, sample: Duration) {
        let sample_ms = sample.as_secs_f64() * 1_000.0;
        self.count += 1;
        self.min_ms = if self.count == 1 {
            sample_ms
        } else {
            self.min_ms.min(sample_ms)
        };
        self.max_ms = if self.count == 1 {
            sample_ms
        } else {
            self.max_ms.max(sample_ms)
        };
        let delta = sample_ms - self.mean_ms;
        self.mean_ms += delta / f64::from(self.count);
        self.squared_deviation_sum += delta * (sample_ms - self.mean_ms);
    }

    fn finish(self) -> Option<LatencyStats> {
        (self.count > 0).then(|| LatencyStats {
            min_ms: self.min_ms,
            avg_ms: self.mean_ms,
            max_ms: self.max_ms,
            stddev_ms: (self.squared_deviation_sum / f64::from(self.count)).sqrt(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct HostNetworkPingResult {
    node: Node,
    address: Option<ResolvedTarget>,
    sent: u16,
    received: u16,
    statistics: Option<LatencyStats>,
    error: Option<String>,
}

impl HostNetworkPingResult {
    fn failed(node: Node, address: Option<ResolvedTarget>, error: impl Into<String>) -> Self {
        Self {
            node,
            address,
            sent: 0,
            received: 0,
            statistics: None,
            error: Some(error.into()),
        }
    }

    fn is_reachable(&self) -> bool {
        self.received > 0
    }

    fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            100.0
        } else {
            f64::from(self.sent - self.received) * 100.0 / f64::from(self.sent)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkPingOutcome {
    pub total: usize,
    pub reachable: usize,
    pub unreachable: usize,
}

impl NetworkPingOutcome {
    fn from_results(results: &[HostNetworkPingResult]) -> Self {
        let reachable = results
            .iter()
            .filter(|result| result.is_reachable())
            .count();
        Self {
            total: results.len(),
            reachable,
            unreachable: results.len() - reachable,
        }
    }

    pub fn exit_code(self) -> i32 {
        if self.reachable == 0 {
            NETWORK_PING_LEVEL_FAILURE
        } else if self.unreachable > 0 {
            1
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProbeSettings {
    count: u16,
    timeout: Duration,
    interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ResolvedTarget {
    address: IpAddr,
    scope_id: u32,
}

impl From<IpAddr> for ResolvedTarget {
    fn from(address: IpAddr) -> Self {
        Self {
            address,
            scope_id: 0,
        }
    }
}

impl From<SocketAddr> for ResolvedTarget {
    fn from(address: SocketAddr) -> Self {
        Self {
            address: address.ip(),
            scope_id: match address {
                SocketAddr::V4(_) => 0,
                SocketAddr::V6(address) => address.scope_id(),
            },
        }
    }
}

impl fmt::Display for ResolvedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.address, self.scope_id) {
            (IpAddr::V6(address), scope_id) if scope_id != 0 => {
                write!(formatter, "{address}%{scope_id}")
            }
            (address, _) => address.fmt(formatter),
        }
    }
}

#[derive(Debug)]
struct ProbeSamples {
    sent: u16,
    received: u16,
    statistics: Option<LatencyStats>,
    last_error: Option<String>,
}

#[async_trait]
trait NetworkProbe: Send + Sync {
    async fn resolve(&self, host: &str, family: AddressFamily) -> Result<ResolvedTarget>;
    async fn probe(&self, target: ResolvedTarget, settings: ProbeSettings) -> Result<ProbeSamples>;
}

#[derive(Default)]
struct IcmpNetworkProbe {
    ipv4_client: OnceCell<Result<Client, String>>,
    ipv6_client: OnceCell<Result<Client, String>>,
    next_identifier: AtomicU16,
    address_locks: Mutex<HashMap<ResolvedTarget, Arc<Mutex<()>>>>,
}

impl IcmpNetworkProbe {
    async fn client(&self, address: IpAddr) -> Result<Client> {
        let (cell, kind) = match address {
            IpAddr::V4(_) => (&self.ipv4_client, ICMP::V4),
            IpAddr::V6(_) => (&self.ipv6_client, ICMP::V6),
        };
        match cell
            .get_or_init(|| async move {
                Client::new(&Config::builder().kind(kind).build())
                    .with_context(|| {
                        "cannot create an ICMP datagram socket; on Linux configure net.ipv4.ping_group_range for this process group or grant CAP_NET_RAW, and on macOS verify local ICMP socket permission"
                    })
                    .map_err(|error| format!("{error:#}"))
            })
            .await
        {
            Ok(client) => Ok(client.clone()),
            Err(error) => Err(anyhow::anyhow!(error.clone())),
        }
    }
}

#[async_trait]
impl NetworkProbe for IcmpNetworkProbe {
    async fn resolve(&self, host: &str, family: AddressFamily) -> Result<ResolvedTarget> {
        if let Ok(address) = host.parse::<IpAddr>() {
            anyhow::ensure!(
                family.matches_ip(address),
                "no {} address found for {host}",
                family.display_name()
            );
            return Ok(address.into());
        }

        let addresses = timeout(DNS_LOOKUP_TIMEOUT, lookup_host((host, 0)))
            .await
            .with_context(|| format!("DNS lookup for {host} timed out after 10 seconds"))?
            .with_context(|| format!("failed to resolve {host}"))?;
        first_eligible_target(addresses, family)
            .with_context(|| format!("no {} address found for {host}", family.display_name()))
    }

    async fn probe(&self, target: ResolvedTarget, settings: ProbeSettings) -> Result<ProbeSamples> {
        let address_lock = {
            let mut locks = self.address_locks.lock().await;
            Arc::clone(locks.entry(target).or_default())
        };
        let _address_guard = address_lock.lock().await;
        let client = self.client(target.address).await?;
        let mut pinger = client
            .pinger(
                target.address,
                PingIdentifier(self.next_identifier.fetch_add(1, Ordering::Relaxed)),
            )
            .await;
        if target.address.is_ipv6() {
            pinger.scope_id(target.scope_id);
        }
        pinger.timeout(settings.timeout);

        let mut latencies = LatencyAccumulator::default();
        let mut last_error = None;
        for sequence in 0..settings.count {
            match pinger.ping(PingSequence(sequence), &[]).await {
                Ok((_, latency)) => latencies.record(latency),
                Err(error) => last_error = Some(error.to_string()),
            }
            if sequence + 1 < settings.count {
                sleep(settings.interval).await;
            }
        }

        Ok(ProbeSamples {
            sent: settings.count,
            received: latencies.count,
            statistics: latencies.finish(),
            last_error,
        })
    }
}

trait AddressFamilyExt {
    fn matches_ip(self, address: IpAddr) -> bool;
    fn display_name(self) -> &'static str;
}

impl AddressFamilyExt for AddressFamily {
    fn matches_ip(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Any => "eligible",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

fn first_eligible_target(
    addresses: impl IntoIterator<Item = SocketAddr>,
    family: AddressFamily,
) -> Option<ResolvedTarget> {
    addresses
        .into_iter()
        .find(|address| family.matches_ip(address.ip()))
        .map(ResolvedTarget::from)
}

async fn probe_node<P: NetworkProbe>(
    probe: &P,
    node: Node,
    target_host: &str,
    family: AddressFamily,
    settings: ProbeSettings,
) -> HostNetworkPingResult {
    let target = match probe.resolve(target_host, family).await {
        Ok(target) => target,
        Err(error) => return HostNetworkPingResult::failed(node, None, format!("{error:#}")),
    };

    match probe.probe(target, settings).await {
        Ok(samples) => HostNetworkPingResult {
            node,
            address: Some(target),
            sent: samples.sent,
            received: samples.received,
            statistics: samples.statistics,
            error: (samples.received == 0).then(|| {
                samples
                    .last_error
                    .unwrap_or_else(|| "no ICMP echo reply received".to_string())
            }),
        },
        Err(error) => HostNetworkPingResult::failed(node, Some(target), format!("{error:#}")),
    }
}

async fn run_network_ping<P: NetworkProbe>(
    probe: Arc<P>,
    nodes: Vec<Node>,
    max_parallel: usize,
    settings: ProbeSettings,
    resolver: &SshConnectionConfigResolver,
) -> Vec<HostNetworkPingResult> {
    let mut results = stream::iter(nodes.into_iter().enumerate().map(|(index, node)| {
        let probe = Arc::clone(&probe);
        let config_host = node.config_host();
        let family = resolver.resolve_for_host(config_host).address_family;
        let target_host = resolver.effective_hostname(config_host);
        async move {
            let result = probe_node(probe.as_ref(), node, &target_host, family, settings).await;
            (index, result)
        }
    }))
    .buffer_unordered(max_parallel)
    .collect::<Vec<_>>()
    .await;
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn network_ping_nodes(
    nodes: Vec<Node>,
    count: u16,
    request_timeout: Duration,
    interval: Duration,
    max_parallel: usize,
    resolver: SshConnectionConfigResolver,
) -> Result<NetworkPingOutcome> {
    anyhow::ensure!(max_parallel > 0, "--parallel must be greater than 0");
    anyhow::ensure!(
        max_parallel <= MAX_PARALLELISM,
        "--parallel must not exceed {MAX_PARALLELISM}"
    );
    anyhow::ensure!(count > 0, "--count must be greater than 0");
    anyhow::ensure!(
        !request_timeout.is_zero(),
        "--timeout must be greater than 0"
    );
    anyhow::ensure!(
        interval >= Duration::from_millis(200),
        "--interval must be at least 0.2 seconds"
    );

    println!(
        "{}",
        OutputFormatter::format_command_header("network-ping", nodes.len())
    );
    if nodes.iter().any(|node| {
        !matches!(
            resolver.resolve_for_host(node.config_host()).proxy_mode,
            None | Some(ProxyMode::Direct)
        )
    }) {
        eprintln!(
            "Warning: network-ping sends ICMP directly from this machine; ProxyJump and ProxyCommand settings are not used"
        );
    }

    let settings = ProbeSettings {
        count,
        timeout: request_timeout,
        interval,
    };
    let results = run_network_ping(
        Arc::new(IcmpNetworkProbe::default()),
        nodes,
        max_parallel,
        settings,
        &resolver,
    )
    .await;
    let outcome = NetworkPingOutcome::from_results(&results);

    println!("\n{} {}\n", "▶".cyan(), "Network Ping Test Results".bold());
    for result in &results {
        print_result(result);
    }
    println!(
        "{}",
        OutputFormatter::format_summary(outcome.total, outcome.reachable, outcome.unreachable)
    );
    let success_rate = if outcome.total == 0 {
        0.0
    } else {
        outcome.reachable as f64 * 100.0 / outcome.total as f64
    };
    println!(
        "Reachability: {} reachable, {} unreachable ({success_rate:.0}% success rate)",
        outcome.reachable, outcome.unreachable
    );
    if outcome.reachable > 0 {
        let mean = results
            .iter()
            .filter_map(|result| result.statistics.map(|statistics| statistics.avg_ms))
            .sum::<f64>()
            / outcome.reachable as f64;
        println!("Average latency: {mean:.1} ms (mean of per-host averages)");
    }

    Ok(outcome)
}

fn print_result(result: &HostNetworkPingResult) {
    let host = result.node.config_host();
    let address = result
        .address
        .map(|address| format!(" ({address})"))
        .unwrap_or_default();
    if let Some(statistics) = result.statistics {
        let loss = result.loss_percent();
        let line = format!(
            "{host}{address}  {}/{} packets  min/avg/max/stddev = {:.1}/{:.1}/{:.1}/{:.1} ms  ({loss:.0}% loss)",
            result.received,
            result.sent,
            statistics.min_ms,
            statistics.avg_ms,
            statistics.max_ms,
            statistics.stddev_ms,
        );
        let (bullet, styled) = if loss > 0.0 || statistics.avg_ms > 100.0 {
            ("●".red(), line.red())
        } else if statistics.avg_ms >= 10.0 {
            ("●".yellow(), line.yellow())
        } else {
            ("●".green(), line.green())
        };
        println!("  {bullet} {styled}");
    } else {
        println!(
            "  {} {}{}  {}/{} packets - {}",
            "●".red(),
            host.bold(),
            address,
            result.received,
            result.sent,
            "Unreachable".red()
        );
        if let Some(error) = &result.error {
            println!("    {} {}", "└".dimmed(), error.dimmed());
        }
    }
}

#[cfg(test)]
#[path = "network_ping_tests.rs"]
mod tests;
