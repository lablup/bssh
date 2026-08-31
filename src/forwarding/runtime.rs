//! Forwarding lifetime attached to one authenticated SSH connection.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use super::{ForwardingConfig, ForwardingId, ForwardingManager, ForwardingPlan, ForwardingType};
use crate::ssh::tokio_client::{AddressFamily, Client};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredForwarding {
    spec: ForwardingType,
    id: ForwardingId,
}

#[derive(Default)]
struct ForwardingRuntimeState {
    manager: Option<ForwardingManager>,
    configured: Vec<ConfiguredForwarding>,
    address_family: Option<AddressFamily>,
}

impl ForwardingRuntimeState {
    fn forwarding_id(&self, spec: &ForwardingType) -> Option<ForwardingId> {
        self.configured
            .iter()
            .find(|forwarding| &forwarding.spec == spec)
            .map(|forwarding| forwarding.id)
    }

    fn track(&mut self, spec: ForwardingType, id: ForwardingId) {
        debug_assert!(self.forwarding_id(&spec).is_none());
        self.configured.push(ConfiguredForwarding { spec, id });
    }

    fn untrack(&mut self, id: ForwardingId) {
        self.configured.retain(|forwarding| forwarding.id != id);
    }

    async fn shutdown_if_idle(&mut self) -> Result<()> {
        if !self.configured.is_empty() {
            return Ok(());
        }

        let shutdown_result = match self.manager.take() {
            Some(mut manager) => manager.shutdown().await,
            None => Ok(()),
        };
        self.address_family = None;
        shutdown_result
    }
}

#[derive(Default)]
pub struct ForwardingRuntime {
    state: Mutex<ForwardingRuntimeState>,
}

impl std::fmt::Debug for ForwardingRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardingRuntime")
            .field(
                "active",
                &self
                    .state
                    .try_lock()
                    .is_ok_and(|state| state.manager.is_some()),
            )
            .finish()
    }
}

impl ForwardingRuntime {
    /// Start every resolved forward before a session channel is opened.
    pub async fn start(&self, client: &Client, plan: &ForwardingPlan) -> Result<()> {
        if plan.is_empty() {
            return Ok(());
        }

        let forwards = plan.parse()?;
        if forwards.is_empty() {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        if state.manager.is_some() {
            return Ok(());
        }

        let config = ForwardingConfig {
            auto_reconnect: false,
            max_reconnect_attempts: 1,
            address_family: plan.address_family,
            ..ForwardingConfig::default()
        };
        let mut manager = ForwardingManager::new(config);
        manager.start().await?;
        let transport = Arc::new(client.forwarding_transport_clone());
        let mut configured = Vec::with_capacity(forwards.len());

        for forward in forwards {
            let id = manager
                .add_forwarding(forward.clone())
                .await
                .with_context(|| format!("Failed to configure forwarding {forward}"))?;
            if let Err(error) = manager
                .start_forwarding_and_wait(id, Arc::clone(&transport))
                .await
            {
                let _ = manager.remove_forwarding(id).await;
                if plan.exit_on_failure {
                    manager.shutdown().await?;
                    return Err(error).with_context(|| {
                        format!("Forwarding {forward} was not ready before session execution")
                    });
                }
                crate::diagnosticln!("Warning: forwarding {forward} failed: {error}");
                continue;
            }
            configured.push(ConfiguredForwarding { spec: forward, id });
        }

        if configured.is_empty() {
            manager.shutdown().await?;
        } else {
            state.manager = Some(manager);
            state.configured = configured;
            state.address_family = Some(plan.address_family);
        }
        Ok(())
    }

    /// Add forwarding requests to an already-authenticated control master.
    ///
    /// Existing identical requests are successful no-ops, matching OpenSSH's
    /// multiplexing behavior. New requests are not reported as ready until
    /// their local listener is bound or their remote forwarding request has
    /// been acknowledged by the server. Independent requests are attempted
    /// even if another request fails.
    pub async fn add_control_forwardings(
        &self,
        client: &Client,
        plan: &ForwardingPlan,
    ) -> Result<()> {
        let forwards = plan.parse()?;
        if forwards.is_empty() {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        if let Some(address_family) = state.address_family {
            anyhow::ensure!(
                address_family == plan.address_family,
                "Cannot add forwarding with address family {:?}; the control master uses {:?}",
                plan.address_family,
                address_family
            );
        }

        if state.manager.is_none() {
            let config = ForwardingConfig {
                auto_reconnect: false,
                max_reconnect_attempts: 1,
                address_family: plan.address_family,
                ..ForwardingConfig::default()
            };
            let mut manager = ForwardingManager::new(config);
            manager
                .start()
                .await
                .context("Failed to start forwarding manager for control request")?;
            state.manager = Some(manager);
            state.address_family = Some(plan.address_family);
        }

        let transport = Arc::new(client.forwarding_transport_clone());
        let mut failures = Vec::new();
        for forward in forwards {
            if state.forwarding_id(&forward).is_some() {
                tracing::debug!(forward = %forward, "Control forwarding is already active");
                continue;
            }

            let id_result = {
                let manager = state
                    .manager
                    .as_mut()
                    .context("Forwarding manager disappeared during control request")?;
                manager.add_forwarding(forward.clone()).await
            };
            let id = match id_result {
                Ok(id) => id,
                Err(error) => {
                    failures.push(format!("{forward}: {error:#}"));
                    continue;
                }
            };
            let start_result = {
                let manager = state
                    .manager
                    .as_ref()
                    .context("Forwarding manager disappeared during control request")?;
                manager
                    .start_forwarding_and_wait(id, Arc::clone(&transport))
                    .await
            };
            match start_result {
                Ok(()) => state.track(forward, id),
                Err(error) => {
                    let cleanup_result = {
                        let manager = state
                            .manager
                            .as_mut()
                            .context("Forwarding manager disappeared during cleanup")?;
                        manager.remove_forwarding(id).await
                    };
                    if let Err(cleanup_error) = cleanup_result {
                        tracing::warn!(
                            forwarding_id = %id,
                            "Failed to clean up rejected control forwarding: {cleanup_error:#}"
                        );
                    }
                    failures.push(format!("{forward}: {error:#}"));
                }
            }
        }

        state.shutdown_if_idle().await?;

        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "One or more control forwarding requests failed: {}",
                failures.join("; ")
            )
        }
    }

    /// Cancel forwarding requests previously configured on a control master.
    ///
    /// Cancellation is exact: an unregistered specification is an error. The
    /// method waits for each forwarding task to finish before returning, which
    /// includes the remote `cancel-tcpip-forward` round trip for `-R` requests.
    /// Independent requests are attempted even if another request is missing
    /// or fails to stop.
    pub async fn cancel_control_forwardings(&self, plan: &ForwardingPlan) -> Result<()> {
        let forwards = plan.parse()?;
        if forwards.is_empty() {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        let mut failures = Vec::new();
        for forward in forwards {
            let Some(id) = state.forwarding_id(&forward) else {
                failures.push(format!("{forward}: port not forwarded"));
                continue;
            };
            let remove_result = match state.manager.as_mut() {
                Some(manager) => manager.remove_forwarding(id).await,
                None => Err(anyhow::anyhow!("Forwarding manager is not running")),
            };
            match remove_result {
                Ok(()) => state.untrack(id),
                Err(error) => failures.push(format!("{forward}: {error:#}")),
            }
        }

        state.shutdown_if_idle().await?;

        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "One or more control forwarding cancellations failed: {}",
                failures.join("; ")
            )
        }
    }

    /// Deterministically stop listeners and cancel remote forwarding requests.
    pub async fn shutdown(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        let shutdown_result = match state.manager.take() {
            Some(mut manager) => manager.shutdown().await,
            None => Ok(()),
        };
        state.configured.clear();
        state.address_family = None;
        shutdown_result
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn local_forward(bind_port: u16, remote_port: u16) -> ForwardingType {
        ForwardingType::Local {
            bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_port,
            remote_host: "example.com".to_string(),
            remote_port,
        }
    }

    #[test]
    fn forwarding_tracking_is_exact_and_removable() {
        let first = local_forward(3001, 80);
        let second = local_forward(3002, 80);
        let first_id = ForwardingId::new_v4();
        let second_id = ForwardingId::new_v4();
        let mut state = ForwardingRuntimeState::default();

        state.track(first.clone(), first_id);
        state.track(second.clone(), second_id);

        assert_eq!(state.forwarding_id(&first), Some(first_id));
        assert_eq!(state.forwarding_id(&second), Some(second_id));
        assert_eq!(state.forwarding_id(&local_forward(3001, 81)), None);

        state.untrack(first_id);
        assert_eq!(state.forwarding_id(&first), None);
        assert_eq!(state.forwarding_id(&second), Some(second_id));
    }
}
