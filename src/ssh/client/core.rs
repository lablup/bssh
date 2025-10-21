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

/// Core SSH client structure
pub struct SshClient {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) username: String,
}

impl SshClient {
    /// Creates a new SSH client instance
    pub fn new(host: String, port: u16, username: String) -> Self {
        Self {
            host,
            port,
            username,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_client_creation() {
        let client = SshClient::new("example.com".to_string(), 22, "user".to_string());
        assert_eq!(client.host, "example.com");
        assert_eq!(client.port, 22);
        assert_eq!(client.username, "user");
    }
}
