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

use crate::jump::parser::JumpHost;
use crate::ssh::tokio_client::Client;

/// A connection through the jump host chain
///
/// Represents an active connection that may go through multiple jump hosts
/// to reach the final destination. This can be either a direct connection
/// or a connection through one or more jump hosts.
#[derive(Debug)]
pub struct JumpConnection {
    /// The final client connection (either direct or through jump hosts)
    pub client: Client,
    /// Information about the jump path taken
    pub jump_info: JumpInfo,
}

/// Information about the jump host path used for a connection
#[derive(Debug, Clone)]
pub enum JumpInfo {
    /// Direct connection (no jump hosts)
    Direct { host: String, port: u16 },
    /// Connection through jump hosts
    Jumped {
        /// The jump hosts in the chain
        jump_hosts: Vec<JumpHost>,
        /// Final destination
        destination: String,
        destination_port: u16,
    },
}

impl JumpInfo {
    /// Get a human-readable description of the connection path
    pub fn path_description(&self) -> String {
        match self {
            JumpInfo::Direct { host, port } => {
                format!("Direct connection to {host}:{port}")
            }
            JumpInfo::Jumped {
                jump_hosts,
                destination,
                destination_port,
            } => {
                let jump_chain: Vec<String> = jump_hosts
                    .iter()
                    .map(|j| j.to_connection_string())
                    .collect();
                format!(
                    "Jump path: {} -> {}:{}",
                    jump_chain.join(" -> "),
                    destination,
                    destination_port
                )
            }
        }
    }

    /// Get the final destination host and port
    pub fn destination(&self) -> (&str, u16) {
        match self {
            JumpInfo::Direct { host, port } => (host, *port),
            JumpInfo::Jumped {
                destination,
                destination_port,
                ..
            } => (destination, *destination_port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jump_info_path_description() {
        let direct = JumpInfo::Direct {
            host: "example.com".to_string(),
            port: 22,
        };
        assert_eq!(
            direct.path_description(),
            "Direct connection to example.com:22"
        );

        let jumped = JumpInfo::Jumped {
            jump_hosts: vec![
                JumpHost::new("jump1".to_string(), Some("user".to_string()), Some(22)),
                JumpHost::new("jump2".to_string(), None, Some(2222)),
            ],
            destination: "target.com".to_string(),
            destination_port: 22,
        };
        assert_eq!(
            jumped.path_description(),
            "Jump path: user@jump1:22 -> jump2:2222 -> target.com:22"
        );
    }

    #[test]
    fn test_jump_info_destination() {
        let direct = JumpInfo::Direct {
            host: "example.com".to_string(),
            port: 2222,
        };
        let (host, port) = direct.destination();
        assert_eq!(host, "example.com");
        assert_eq!(port, 2222);

        let jumped = JumpInfo::Jumped {
            jump_hosts: vec![],
            destination: "target.com".to_string(),
            destination_port: 22,
        };
        let (host, port) = jumped.destination();
        assert_eq!(host, "target.com");
        assert_eq!(port, 22);
    }
}
