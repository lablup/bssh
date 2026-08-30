//! Forwarding lifetime attached to one authenticated SSH connection.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use super::{ForwardingConfig, ForwardingManager, ForwardingPlan};
use crate::ssh::tokio_client::Client;

#[derive(Default)]
pub struct ForwardingRuntime {
    manager: Mutex<Option<ForwardingManager>>,
}

impl std::fmt::Debug for ForwardingRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardingRuntime")
            .field(
                "active",
                &self.manager.try_lock().is_ok_and(|slot| slot.is_some()),
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

        let mut slot = self.manager.lock().await;
        if slot.is_some() {
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
        let mut active = 0usize;

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
            active += 1;
        }

        if active == 0 {
            manager.shutdown().await?;
        } else {
            *slot = Some(manager);
        }
        Ok(())
    }

    /// Deterministically stop listeners and cancel remote forwarding requests.
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(mut manager) = self.manager.lock().await.take() {
            manager.shutdown().await?;
        }
        Ok(())
    }
}
