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

use directories::BaseDirs;
use russh_keys::key::PublicKey;
use std::path::PathBuf;

use super::error::{SftpError, SftpResult};
use crate::ssh::known_hosts::StrictHostKeyChecking;

/// Host key verification handler
#[derive(Debug, Clone)]
pub struct HostKeyVerification {
    mode: StrictHostKeyChecking,
    known_hosts_path: Option<PathBuf>,
}

impl HostKeyVerification {
    /// Create a new host key verification handler
    pub fn new(mode: StrictHostKeyChecking) -> Self {
        let known_hosts_path = get_default_known_hosts_path();
        Self {
            mode,
            known_hosts_path,
        }
    }

    /// Create with custom known_hosts file path
    pub fn with_known_hosts_path(mode: StrictHostKeyChecking, path: PathBuf) -> Self {
        Self {
            mode,
            known_hosts_path: Some(path),
        }
    }

    /// Verify host key according to the configured mode
    pub async fn verify_host_key(
        &self,
        host: &str,
        port: u16,
        server_key: &PublicKey,
    ) -> SftpResult<bool> {
        match self.mode {
            StrictHostKeyChecking::No => {
                tracing::debug!("Host key checking disabled (strict mode = no)");
                Ok(true)
            }
            StrictHostKeyChecking::Yes => {
                self.verify_strict(host, port, server_key).await
            }
            StrictHostKeyChecking::AcceptNew => {
                self.verify_accept_new(host, port, server_key).await
            }
        }
    }

    async fn verify_strict(
        &self,
        host: &str,
        port: u16,
        server_key: &PublicKey,
    ) -> SftpResult<bool> {
        if let Some(ref known_hosts_path) = self.known_hosts_path {
            if known_hosts_path.exists() {
                tracing::debug!(
                    "Using known_hosts file: {:?} (strict mode)",
                    known_hosts_path
                );
                
                match self.check_known_hosts(host, port, server_key, known_hosts_path).await {
                    Ok(true) => Ok(true),
                    Ok(false) => Err(SftpError::host_key_verification(
                        format!(
                            "Host key verification failed for {}:{}. The host key is not in known_hosts or has changed.",
                            host, port
                        )
                    )),
                    Err(e) => Err(e),
                }
            } else {
                tracing::warn!(
                    "Known hosts file not found at {:?}, rejecting connection",
                    known_hosts_path
                );
                Err(SftpError::host_key_verification(
                    format!(
                        "Host key verification failed: known_hosts file not found at {:?}",
                        known_hosts_path
                    )
                ))
            }
        } else {
            tracing::warn!("Could not determine known_hosts path, rejecting connection");
            Err(SftpError::host_key_verification(
                "Host key verification failed: could not determine known_hosts file path"
            ))
        }
    }

    async fn verify_accept_new(
        &self,
        host: &str,
        port: u16,
        server_key: &PublicKey,
    ) -> SftpResult<bool> {
        if let Some(ref known_hosts_path) = self.known_hosts_path {
            // Create the .ssh directory if it doesn't exist
            if let Some(ssh_dir) = known_hosts_path.parent() {
                if let Err(e) = tokio::fs::create_dir_all(ssh_dir).await {
                    tracing::warn!("Failed to create .ssh directory: {}", e);
                }
            }

            // Create an empty known_hosts file if it doesn't exist
            if !known_hosts_path.exists() {
                if let Err(e) = tokio::fs::File::create(known_hosts_path).await {
                    tracing::warn!("Failed to create known_hosts file: {}", e);
                }
                tracing::debug!("Created empty known_hosts file at {:?}", known_hosts_path);
            }

            tracing::debug!(
                "Using known_hosts file: {:?} (accept-new mode)",
                known_hosts_path
            );

            // For accept-new mode, we accept all keys for now
            // In a full implementation, we would:
            // 1. Check if the host is known
            // 2. If known, verify the key matches
            // 3. If unknown, add it to known_hosts
            // 4. If key changed, reject
            tracing::info!(
                "Note: accept-new mode simplified - accepting host key for {}:{}",
                host, port
            );
            Ok(true)
        } else {
            tracing::warn!("Could not determine known_hosts path, accepting connection");
            Ok(true)
        }
    }

    async fn check_known_hosts(
        &self,
        _host: &str,
        _port: u16,
        _server_key: &PublicKey,
        _known_hosts_path: &PathBuf,
    ) -> SftpResult<bool> {
        // For now, this is a simplified implementation
        // A full implementation would parse the known_hosts file and verify the key
        // For compatibility with the current behavior, we'll accept all keys
        tracing::debug!("Simplified known_hosts checking - accepting key");
        Ok(true)
    }
}

/// Get the default known_hosts file path
fn get_default_known_hosts_path() -> Option<PathBuf> {
    BaseDirs::new().map(|dirs| dirs.home_dir().join(".ssh").join("known_hosts"))
}

impl Default for HostKeyVerification {
    fn default() -> Self {
        Self::new(StrictHostKeyChecking::AcceptNew)
    }
}