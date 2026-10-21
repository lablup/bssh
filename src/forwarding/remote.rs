//! Live remote forwarding over russh global requests and forwarded channels.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use russh::{Channel, client::Msg};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::tunnel::Tunnel;
use super::{ForwardingConfig, ForwardingMessage, ForwardingStatus, ForwardingType};
use crate::forwarding::dynamic::socks::{
    handle_socks4_connection_with, handle_socks5_connection_with,
};
use crate::ssh::tokio_client::{AddressFamily, Client};

type ForwardKey = (String, u32);

#[derive(Debug)]
struct RemoteForwardTarget {
    mode: RemoteForwardMode,
    cancel: CancellationToken,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    connect_timeout: Duration,
    connection_semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
enum RemoteForwardMode {
    Tcp {
        local_host: String,
        local_port: u16,
    },
    Dynamic {
        permitted_destinations: Vec<String>,
        address_family: AddressFamily,
    },
}

impl RemoteForwardTarget {
    fn new_tcp(
        local_host: String,
        local_port: u16,
        cancel: CancellationToken,
        connect_timeout: Duration,
        max_connections: usize,
    ) -> Self {
        Self {
            mode: RemoteForwardMode::Tcp {
                local_host,
                local_port,
            },
            cancel,
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            connect_timeout,
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
        }
    }

    fn new_dynamic(
        permitted_destinations: Vec<String>,
        address_family: AddressFamily,
        cancel: CancellationToken,
        connect_timeout: Duration,
        max_connections: usize,
    ) -> Self {
        Self {
            mode: RemoteForwardMode::Dynamic {
                permitted_destinations,
                address_family,
            },
            cancel,
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            connect_timeout,
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
        }
    }

    fn try_acquire_connection(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.connection_semaphore)
            .try_acquire_owned()
            .ok()
    }

    async fn route(self: &Arc<Self>, channel: Channel<Msg>, peer_addr: SocketAddr) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let Some(connection_permit) = self.try_acquire_connection() else {
            tracing::warn!(
                "Rejecting remote forwarding channel because the concurrent connection limit was reached"
            );
            return;
        };
        let target = Arc::clone(self);
        let task = tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let result = match &target.mode {
                RemoteForwardMode::Tcp {
                    local_host,
                    local_port,
                } => {
                    let address = super::format_host_port(local_host, *local_port);
                    let stream = tokio::select! {
                        result = tokio::time::timeout(target.connect_timeout, TcpStream::connect(&address)) => match result {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::warn!("Remote forward could not connect to {address}: {error}");
                                return;
                            }
                            Err(_) => {
                                tracing::warn!("Remote forward timed out connecting to {address}");
                                return;
                            }
                        },
                        _ = target.cancel.cancelled() => return,
                    };
                    Tunnel::run(stream, channel, target.cancel.clone())
                        .await
                        .map(|_| ())
                }
                RemoteForwardMode::Dynamic {
                    permitted_destinations,
                    address_family,
                } => handle_remote_dynamic(
                    channel,
                    peer_addr,
                    permitted_destinations,
                    *address_family,
                    target.connect_timeout,
                    target.cancel.clone(),
                )
                .await
                .map(|_| ()),
            };
            if let Err(error) = result {
                tracing::warn!("Remote forwarding tunnel failed: {error}");
            }
        });

        let mut tasks = self.tasks.lock().await;
        if self.closed.load(Ordering::Acquire) {
            task.abort();
            let _ = task.await;
        } else {
            tasks.retain(|task| !task.is_finished());
            tasks.push(task);
        }
    }

    async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn handle_remote_dynamic(
    channel: Channel<Msg>,
    peer_addr: SocketAddr,
    permitted_destinations: &[String],
    address_family: AddressFamily,
    connect_timeout: Duration,
    cancel: CancellationToken,
) -> Result<super::tunnel::TunnelStats> {
    let mut stream = tokio::io::BufReader::new(channel.into_stream());
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let version = tokio::select! {
        result = tokio::time::timeout_at(deadline, stream.fill_buf()) => result
            .context("Timed out waiting for remote dynamic SOCKS greeting")??
            .first()
            .copied()
            .context("SOCKS client closed before sending a greeting")?,
        _ = cancel.cancelled() => anyhow::bail!("Remote dynamic forwarding was cancelled"),
    };
    let permitted_destinations = Arc::new(permitted_destinations.to_vec());

    match version {
        4 => {
            let rules = Arc::clone(&permitted_destinations);
            let open_cancel = cancel.clone();
            let handler_cancel = cancel.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            let handler = handle_socks4_connection_with(
                stream,
                peer_addr,
                handler_cancel,
                address_family,
                move |destination, family| {
                    connect_dynamic_destination(
                        destination,
                        family,
                        rules,
                        connect_timeout,
                        open_cancel,
                    )
                },
                move |socks, target, cancel| async move {
                    let _ = ready_tx.send(());
                    tunnel_dynamic_streams(socks, target, cancel).await
                },
            );
            complete_remote_dynamic_handshake(handler, ready_rx, deadline, cancel).await
        }
        5 => {
            let rules = Arc::clone(&permitted_destinations);
            let open_cancel = cancel.clone();
            let handler_cancel = cancel.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            let handler = handle_socks5_connection_with(
                stream,
                peer_addr,
                address_family,
                move |destination, family| {
                    connect_dynamic_destination(
                        destination,
                        family,
                        Arc::clone(&rules),
                        connect_timeout,
                        open_cancel.clone(),
                    )
                },
                move |socks, target, cancel| async move {
                    let _ = ready_tx.send(());
                    tunnel_dynamic_streams(socks, target, cancel).await
                },
                handler_cancel,
            );
            complete_remote_dynamic_handshake(handler, ready_rx, deadline, cancel).await
        }
        other => anyhow::bail!("Unsupported SOCKS protocol version: {other}"),
    }
}

async fn complete_remote_dynamic_handshake<Handler>(
    handler: Handler,
    ready: oneshot::Receiver<()>,
    deadline: tokio::time::Instant,
    cancel: CancellationToken,
) -> Result<super::tunnel::TunnelStats>
where
    Handler: Future<Output = Result<super::tunnel::TunnelStats>>,
{
    tokio::pin!(handler);
    tokio::select! {
        biased;
        result = &mut handler => result,
        ready = tokio::time::timeout_at(deadline, ready) => match ready {
            Ok(Ok(())) => handler.await,
            Ok(Err(_)) => handler.await,
            Err(_) => anyhow::bail!("Timed out completing remote dynamic SOCKS handshake"),
        },
        _ = cancel.cancelled() => anyhow::bail!("Remote dynamic forwarding was cancelled"),
    }
}

async fn connect_dynamic_destination(
    destination: String,
    address_family: AddressFamily,
    permitted_destinations: Arc<Vec<String>>,
    timeout: Duration,
    cancel: CancellationToken,
) -> Result<TcpStream> {
    let (host, port) = split_destination(&destination)?;
    anyhow::ensure!(
        destination_is_permitted(&host, port, &permitted_destinations),
        "PermitRemoteOpen rejected {destination}"
    );

    let connect = async {
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("Could not resolve remote dynamic target {destination}"))?;
        let mut last_error = None;
        for address in addresses.filter(|address| address_family.matches(address)) {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(anyhow::Error::new(error).context(format!(
                "Could not connect to remote dynamic target {destination}"
            ))),
            None => anyhow::bail!(
                "No {} address is available for remote dynamic target {destination}",
                address_family
            ),
        }
    };

    tokio::select! {
        result = tokio::time::timeout(timeout, connect) => result
            .with_context(|| format!("Timed out connecting to remote dynamic target {destination}"))?,
        _ = cancel.cancelled() => anyhow::bail!("Remote dynamic forwarding was cancelled"),
    }
}

fn split_destination(destination: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(bracketed) = destination.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .context("Invalid bracketed remote dynamic destination")?;
        let port = suffix
            .strip_prefix(':')
            .context("Missing port in remote dynamic destination")?;
        (host, port)
    } else {
        destination
            .rsplit_once(':')
            .context("Missing port in remote dynamic destination")?
    };
    let port = port
        .parse::<u16>()
        .with_context(|| format!("Invalid port in remote dynamic destination {destination}"))?;
    Ok((host.to_string(), port))
}

fn destination_is_permitted(host: &str, port: u16, rules: &[String]) -> bool {
    // Fail closed for programmatically constructed mixed policies even though
    // ssh_config parsing rejects a sentinel combined with other entries.
    if rules.iter().any(|rule| rule.eq_ignore_ascii_case("none")) {
        return false;
    }
    if rules.is_empty() || rules.iter().any(|rule| rule.eq_ignore_ascii_case("any")) {
        return true;
    }

    rules.iter().any(|rule| {
        let (rule_host, rule_port) = if let Some(bracketed) = rule.strip_prefix('[') {
            let Some((host, suffix)) = bracketed.split_once(']') else {
                return false;
            };
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            (host, port)
        } else {
            let Some(parts) = rule.rsplit_once(':') else {
                return false;
            };
            parts
        };
        (rule_host == "*" || rule_host.eq_ignore_ascii_case(host))
            && (rule_port == "*" || rule_port.parse::<u16>() == Ok(port))
    })
}

async fn tunnel_dynamic_streams<Stream>(
    mut socks: Stream,
    mut target: TcpStream,
    cancel: CancellationToken,
) -> Result<super::tunnel::TunnelStats>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    let stats = super::tunnel::TunnelStats::new();
    let transferred = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut socks, &mut target) => Some(result?),
        _ = cancel.cancelled() => None,
    };
    if let Some((socks_to_target, target_to_socks)) = transferred {
        stats
            .bytes_local_to_remote
            .store(socks_to_target, Ordering::Relaxed);
        stats
            .bytes_remote_to_local
            .store(target_to_socks, Ordering::Relaxed);
    }
    Ok(stats)
}

/// Registry shared by a russh client handler and its public Client wrapper.
#[derive(Debug, Clone, Default)]
pub(crate) struct RemoteForwardRegistry {
    targets: Arc<RwLock<HashMap<ForwardKey, Arc<RemoteForwardTarget>>>>,
}

impl RemoteForwardRegistry {
    async fn register(
        &self,
        address: String,
        port: u32,
        target: Arc<RemoteForwardTarget>,
    ) -> Result<()> {
        let mut targets = self.targets.write().await;
        let key = (address, port);
        if targets.contains_key(&key) {
            anyhow::bail!("Remote forwarding {key:?} is already registered");
        }
        targets.insert(key, target);
        Ok(())
    }

    async fn activate_allocated_port(
        &self,
        address: &str,
        requested_port: u32,
        allocated_port: u32,
    ) -> Result<()> {
        if requested_port == allocated_port {
            return Ok(());
        }
        let mut targets = self.targets.write().await;
        let target = targets
            .remove(&(address.to_string(), requested_port))
            .context("Remote forwarding registration disappeared before allocation reply")?;
        targets.insert((address.to_string(), allocated_port), target);
        Ok(())
    }

    pub(crate) async fn route(
        &self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        channel: Channel<Msg>,
    ) -> bool {
        let targets = self.targets.read().await;
        let exact = targets
            .get(&(connected_address.to_string(), connected_port))
            .cloned();
        let target = exact.or_else(|| {
            let mut matches = targets
                .iter()
                .filter(|((_, port), _)| *port == connected_port)
                .map(|(_, target)| Arc::clone(target));
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        });
        drop(targets);
        let Some(target) = target else {
            return false;
        };
        let peer_addr = u16::try_from(originator_port)
            .ok()
            .and_then(|port| {
                originator_address
                    .parse::<IpAddr>()
                    .ok()
                    .map(|address| SocketAddr::new(address, port))
            })
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        target.route(channel, peer_addr).await;
        true
    }

    async fn unregister(&self, target: &Arc<RemoteForwardTarget>) {
        self.targets
            .write()
            .await
            .retain(|_, current| !Arc::ptr_eq(current, target));
        target.shutdown().await;
    }
}

pub struct RemoteForwarder;

impl RemoteForwarder {
    /// Validate a remote-forward specification without starting it.
    ///
    /// This preserves the constructor exposed by the earlier forwarding API;
    /// live setup is performed by [`Self::run`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel: CancellationToken,
        messages: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<Self> {
        let _ = (session_id, ssh_client, config, cancel, messages);
        if !matches!(
            &spec,
            ForwardingType::Remote { .. } | ForwardingType::RemoteDynamic { .. }
        ) {
            anyhow::bail!("Invalid forwarding type for RemoteForwarder");
        }
        super::ForwardingSpec::validate(&spec)?;
        Ok(Self)
    }

    async fn cancel_request(
        client: &Client,
        address: &str,
        port: u32,
        request_timeout: Duration,
    ) -> Result<()> {
        tokio::time::timeout(
            request_timeout,
            client.cancel_port_forward(address.to_string(), port),
        )
        .await
        .with_context(|| format!("Timed out cancelling remote forwarding {address}:{port}"))?
        .map_err(|error| anyhow::anyhow!(error))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        session_id: Uuid,
        spec: ForwardingType,
        ssh_client: Arc<Client>,
        config: ForwardingConfig,
        cancel: CancellationToken,
        messages: mpsc::UnboundedSender<ForwardingMessage>,
    ) -> Result<()> {
        let request_timeout = Duration::from_secs(config.connect_timeout_secs);
        let (bind_addr, bind_port, target, target_description) = match spec {
            ForwardingType::Remote {
                bind_addr,
                bind_port,
                local_host,
                local_port,
            } => {
                let description = format!("{local_host}:{local_port}");
                (
                    bind_addr,
                    bind_port,
                    Arc::new(RemoteForwardTarget::new_tcp(
                        local_host,
                        local_port,
                        cancel.clone(),
                        request_timeout,
                        config.max_connections,
                    )),
                    description,
                )
            }
            ForwardingType::RemoteDynamic {
                bind_addr,
                bind_port,
                permitted_destinations,
            } => (
                bind_addr,
                bind_port,
                Arc::new(RemoteForwardTarget::new_dynamic(
                    permitted_destinations,
                    config.address_family,
                    cancel.clone(),
                    request_timeout,
                    config.max_connections,
                )),
                "dynamic SOCKS destinations".to_string(),
            ),
            _ => anyhow::bail!("Invalid forwarding type for RemoteForwarder"),
        };

        let send_status = |status| {
            let _ = messages.send(ForwardingMessage::StatusUpdate {
                id: session_id,
                status,
            });
        };
        send_status(ForwardingStatus::Initializing);

        let address = bind_addr.to_string();
        let requested_port = u32::from(bind_port);
        let registry = ssh_client.remote_forward_registry();
        registry
            .register(address.clone(), requested_port, Arc::clone(&target))
            .await?;

        let request_result: Result<u32> = tokio::select! {
            result = tokio::time::timeout(
                request_timeout,
                ssh_client.request_port_forward(address.clone(), requested_port),
            ) => match result {
                Ok(result) => result.map_err(|error| anyhow::anyhow!(error)),
                Err(_) => Err(anyhow::anyhow!(
                    "Timed out requesting remote forwarding {address}:{requested_port}"
                )),
            },
            _ = cancel.cancelled() => {
                registry.unregister(&target).await;
                send_status(ForwardingStatus::Stopped);
                return Ok(());
            }
        };
        let allocated_port = match request_result {
            Ok(port) => port,
            Err(error) => {
                registry.unregister(&target).await;
                let message = format!("Remote forwarding request failed: {error}");
                send_status(ForwardingStatus::Failed(message.clone()));
                anyhow::bail!(message);
            }
        };
        if allocated_port == 0 || allocated_port > u32::from(u16::MAX) {
            let _ =
                Self::cancel_request(&ssh_client, &address, allocated_port, request_timeout).await;
            registry.unregister(&target).await;
            let message =
                format!("Remote forwarding returned invalid allocated port {allocated_port}");
            send_status(ForwardingStatus::Failed(message.clone()));
            anyhow::bail!(message);
        }
        if let Err(error) = registry
            .activate_allocated_port(&address, requested_port, allocated_port)
            .await
        {
            let _ =
                Self::cancel_request(&ssh_client, &address, allocated_port, request_timeout).await;
            registry.unregister(&target).await;
            let message = format!("Remote forwarding activation failed: {error}");
            send_status(ForwardingStatus::Failed(message.clone()));
            anyhow::bail!(message);
        }
        if requested_port == 0 {
            crate::diagnosticln!(
                "Allocated port {allocated_port} for remote forward to {target_description}"
            );
        }
        tracing::info!(
            "Remote forwarding active on {address}:{allocated_port} to {target_description}"
        );
        send_status(ForwardingStatus::Active);

        cancel.cancelled().await;

        let cancel_result =
            Self::cancel_request(&ssh_client, &address, allocated_port, request_timeout).await;
        registry.unregister(&target).await;
        if let Err(error) = cancel_result {
            let message =
                format!("Failed to cancel remote forwarding {address}:{allocated_port}: {error}");
            send_status(ForwardingStatus::Failed(message.clone()));
            anyhow::bail!(message);
        }
        send_status(ForwardingStatus::Stopped);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_target_enforces_the_configured_connection_limit() {
        let target = RemoteForwardTarget::new_tcp(
            "127.0.0.1".to_string(),
            22,
            CancellationToken::new(),
            Duration::from_secs(1),
            2,
        );

        let first = target
            .try_acquire_connection()
            .expect("first remote connection permit");
        let second = target
            .try_acquire_connection()
            .expect("second remote connection permit");
        assert!(
            target.try_acquire_connection().is_none(),
            "a remote channel above max_connections must be rejected before spawning"
        );

        drop(first);
        assert!(
            target.try_acquire_connection().is_some(),
            "a completed remote connection must release its permit"
        );
        drop(second);
    }

    #[tokio::test]
    async fn stalled_dynamic_handshake_releases_connection_capacity() {
        let target = RemoteForwardTarget::new_dynamic(
            Vec::new(),
            AddressFamily::Any,
            CancellationToken::new(),
            Duration::from_millis(10),
            1,
        );
        let permit = target
            .try_acquire_connection()
            .expect("first dynamic connection permit");
        assert!(target.try_acquire_connection().is_none());

        let (ready_tx, ready_rx) = oneshot::channel();
        let stalled = async move {
            let _permit = permit;
            let _ready_tx = ready_tx;
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok(super::super::tunnel::TunnelStats::new())
        };
        let error = complete_remote_dynamic_handshake(
            stalled,
            ready_rx,
            tokio::time::Instant::now() + Duration::from_millis(10),
            CancellationToken::new(),
        )
        .await
        .expect_err("a stalled handshake must time out");
        assert!(error.to_string().contains("Timed out completing"));
        assert!(
            target.try_acquire_connection().is_some(),
            "timing out a handshake must release its connection permit"
        );
    }

    #[test]
    fn permit_remote_open_matches_exact_hosts_ports_and_sentinels() {
        assert!(destination_is_permitted("anything", 443, &[]));
        assert!(destination_is_permitted("anything", 443, &["any".into()]));
        assert!(!destination_is_permitted(
            "127.0.0.1",
            4242,
            &["none".into()]
        ));
        assert!(
            !destination_is_permitted("127.0.0.1", 4242, &["any".into(), "none".into()]),
            "a conflicting programmatic policy must fail closed"
        );
        let rules = vec![
            "127.0.0.1:4242".into(),
            "[::1]:4242".into(),
            "localhost:4242".into(),
        ];
        assert!(destination_is_permitted("127.0.0.1", 4242, &rules));
        assert!(destination_is_permitted("::1", 4242, &rules));
        assert!(destination_is_permitted("LOCALHOST", 4242, &rules));
        assert!(!destination_is_permitted("127.0.0.1", 1, &rules));
    }
}
