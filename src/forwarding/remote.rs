//! Live remote forwarding over russh global requests and forwarded channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use russh::{Channel, client::Msg};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::tunnel::Tunnel;
use super::{ForwardingConfig, ForwardingMessage, ForwardingStatus, ForwardingType};
use crate::ssh::tokio_client::Client;

type ForwardKey = (String, u32);

#[derive(Debug)]
struct RemoteForwardTarget {
    local_host: String,
    local_port: u16,
    cancel: CancellationToken,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    connect_timeout: Duration,
    connection_semaphore: Arc<Semaphore>,
}

impl RemoteForwardTarget {
    fn new(
        local_host: String,
        local_port: u16,
        cancel: CancellationToken,
        connect_timeout: Duration,
        max_connections: usize,
    ) -> Self {
        Self {
            local_host,
            local_port,
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

    async fn route(self: &Arc<Self>, channel: Channel<Msg>) {
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
            let address = super::format_host_port(&target.local_host, target.local_port);
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
            if let Err(error) = Tunnel::run(stream, channel, target.cancel.clone()).await {
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
        target.route(channel).await;
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
        if !matches!(&spec, ForwardingType::Remote { .. }) {
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
        let ForwardingType::Remote {
            bind_addr,
            bind_port,
            local_host,
            local_port,
        } = spec
        else {
            anyhow::bail!("Invalid forwarding type for RemoteForwarder");
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
        let request_timeout = Duration::from_secs(config.connect_timeout_secs);
        let target = Arc::new(RemoteForwardTarget::new(
            local_host.clone(),
            local_port,
            cancel.clone(),
            request_timeout,
            config.max_connections,
        ));
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
                "Allocated port {allocated_port} for remote forward to {local_host}:{local_port}"
            );
        }
        tracing::info!(
            "Remote forwarding active on {address}:{allocated_port} to {local_host}:{local_port}"
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
        let target = RemoteForwardTarget::new(
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
}
