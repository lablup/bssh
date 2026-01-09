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

//! Jump host data structure and methods

use std::fmt;

/// A single jump host specification
///
/// Represents one hop in a jump host chain, parsed from OpenSSH ProxyJump syntax.
/// Supports the format: `[user@]hostname[:port]`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpHost {
    /// Username for SSH authentication (None means use current user or config default)
    pub user: Option<String>,
    /// Hostname or IP address of the jump host
    pub host: String,
    /// SSH port (None means use default port 22 or config default)
    pub port: Option<u16>,
}

impl JumpHost {
    /// Create a new jump host specification
    pub fn new(host: String, user: Option<String>, port: Option<u16>) -> Self {
        Self { user, host, port }
    }

    /// Get the effective username (provided or current user)
    pub fn effective_user(&self) -> String {
        self.user
            .clone()
            .unwrap_or_else(|| whoami::username().unwrap_or_else(|_| "user".to_string()))
    }

    /// Get the effective port (provided or default SSH port)
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(22)
    }

    /// Convert to a connection string for display purposes
    pub fn to_connection_string(&self) -> String {
        match (&self.user, &self.port) {
            (Some(user), Some(port)) => format!("{}@{}:{}", user, self.host, port),
            (Some(user), None) => format!("{}@{}", user, self.host),
            (None, Some(port)) => format!("{}:{}", self.host, port),
            (None, None) => self.host.clone(),
        }
    }
}

impl fmt::Display for JumpHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_connection_string())
    }
}
