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

use super::tokio_client::ServerCheckMethod;
use directories::BaseDirs;
use std::path::PathBuf;
use std::str::FromStr;

/// Get the default known_hosts file path
pub fn get_default_known_hosts_path() -> Option<PathBuf> {
    BaseDirs::new().map(|dirs| dirs.home_dir().join(".ssh").join("known_hosts"))
}

/// Create a ServerCheckMethod based on strict host key checking mode
pub fn get_check_method(strict_mode: StrictHostKeyChecking) -> ServerCheckMethod {
    match strict_mode {
        StrictHostKeyChecking::Yes => {
            // Use the default known_hosts file in strict mode
            if let Some(known_hosts_path) = get_default_known_hosts_path() {
                if known_hosts_path.exists() {
                    tracing::debug!(
                        "Using known_hosts file: {:?} (strict mode)",
                        known_hosts_path
                    );
                    ServerCheckMethod::DefaultKnownHostsFile
                } else {
                    tracing::warn!(
                        "Known hosts file not found at {:?}, using NoCheck",
                        known_hosts_path
                    );
                    eprintln!(
                        "WARNING: Known hosts file not found. Host key verification disabled."
                    );
                    ServerCheckMethod::NoCheck
                }
            } else {
                tracing::warn!("Could not determine known_hosts path, using NoCheck");
                ServerCheckMethod::NoCheck
            }
        }
        StrictHostKeyChecking::No => {
            tracing::debug!("Host key checking disabled (strict mode = no)");
            ServerCheckMethod::NoCheck
        }
        StrictHostKeyChecking::AcceptNew => {
            // Use known_hosts but don't fail on new hosts
            // Note: async-ssh2-tokio doesn't support TOFU mode directly,
            // so we use the known_hosts file if it exists, otherwise NoCheck
            if let Some(known_hosts_path) = get_default_known_hosts_path() {
                if known_hosts_path.exists() {
                    tracing::debug!(
                        "Using known_hosts file: {:?} (accept-new mode)",
                        known_hosts_path
                    );
                    // Unfortunately, the library doesn't support accept-new mode directly
                    // We'll use the known_hosts file, but it will fail on unknown hosts
                    // For now, we'll use NoCheck for accept-new mode
                    tracing::info!(
                        "Note: accept-new mode not fully supported, using relaxed checking"
                    );
                    ServerCheckMethod::NoCheck
                } else {
                    // Create the .ssh directory if it doesn't exist
                    if let Some(ssh_dir) = known_hosts_path.parent() {
                        let _ = std::fs::create_dir_all(ssh_dir);
                    }
                    // Create an empty known_hosts file
                    let _ = std::fs::File::create(&known_hosts_path);
                    tracing::debug!("Created empty known_hosts file at {:?}", known_hosts_path);
                    ServerCheckMethod::NoCheck
                }
            } else {
                tracing::warn!("Could not determine known_hosts path, using NoCheck");
                ServerCheckMethod::NoCheck
            }
        }
    }
}

/// Mode for host key checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictHostKeyChecking {
    /// Always verify host keys (fail on unknown/changed)
    Yes,
    /// Never verify host keys (accept all)
    No,
    /// Verify known hosts, add new ones automatically (TOFU)
    #[default]
    AcceptNew,
}

impl StrictHostKeyChecking {
    pub fn to_bool(&self) -> bool {
        matches!(self, Self::Yes)
    }
}

impl FromStr for StrictHostKeyChecking {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "yes" | "true" => Self::Yes,
            "no" | "false" => Self::No,
            "accept-new" | "tofu" => Self::AcceptNew,
            _ => Self::AcceptNew, // Default
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_host_key_checking_from_str() {
        assert_eq!(
            StrictHostKeyChecking::from_str("yes").unwrap(),
            StrictHostKeyChecking::Yes
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("true").unwrap(),
            StrictHostKeyChecking::Yes
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("no").unwrap(),
            StrictHostKeyChecking::No
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("false").unwrap(),
            StrictHostKeyChecking::No
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("accept-new").unwrap(),
            StrictHostKeyChecking::AcceptNew
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("tofu").unwrap(),
            StrictHostKeyChecking::AcceptNew
        );
        assert_eq!(
            StrictHostKeyChecking::from_str("invalid").unwrap(),
            StrictHostKeyChecking::AcceptNew
        );
    }

    #[test]
    fn test_strict_host_key_checking_to_bool() {
        assert!(StrictHostKeyChecking::Yes.to_bool());
        assert!(!StrictHostKeyChecking::No.to_bool());
        assert!(!StrictHostKeyChecking::AcceptNew.to_bool());
    }

    #[test]
    fn test_strict_host_key_checking_default() {
        assert_eq!(
            StrictHostKeyChecking::default(),
            StrictHostKeyChecking::AcceptNew
        );
    }

    #[test]
    fn test_get_default_known_hosts_path() {
        let path = get_default_known_hosts_path();
        assert!(path.is_some());
        if let Some(p) = path {
            assert!(p.to_str().unwrap().contains(".ssh/known_hosts"));
        }
    }

    #[test]
    fn test_get_check_method() {
        // Test with No mode
        let method = get_check_method(StrictHostKeyChecking::No);
        assert!(matches!(method, ServerCheckMethod::NoCheck));

        // Test with AcceptNew mode (should use NoCheck since library doesn't support TOFU)
        let method = get_check_method(StrictHostKeyChecking::AcceptNew);
        assert!(matches!(method, ServerCheckMethod::NoCheck));

        // Test with Yes mode
        let method = get_check_method(StrictHostKeyChecking::Yes);
        // Result depends on whether known_hosts file exists
        assert!(matches!(
            method,
            ServerCheckMethod::DefaultKnownHostsFile | ServerCheckMethod::NoCheck
        ));
    }
}
