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
use std::path::PathBuf;
use std::str::FromStr;

/// Get the default known_hosts file path
pub fn get_default_known_hosts_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".ssh").join("known_hosts"))
}

/// Create a ServerCheckMethod based on strict host key checking mode.
///
/// This is a pure mapping with no filesystem side effects. A missing
/// known_hosts file is handled at verification time: russh treats an
/// unreadable file as empty, so strict mode rejects unknown hosts and
/// accept-new mode records them, creating the file on first recording.
pub fn get_check_method(strict_mode: StrictHostKeyChecking) -> ServerCheckMethod {
    match strict_mode {
        StrictHostKeyChecking::Yes => match get_default_known_hosts_path() {
            Some(known_hosts_path) => {
                tracing::debug!(
                    "Using known_hosts file: {:?} (strict mode)",
                    known_hosts_path
                );
                ServerCheckMethod::KnownHostsFile(known_hosts_path.to_string_lossy().into_owned())
            }
            None => {
                // Verification must never be disabled in strict mode (#239).
                // Fall back to russh's own default path resolution; when no
                // home directory exists that resolution errors out and the
                // connection is rejected, so this fails closed.
                tracing::warn!(
                    "Could not determine known_hosts path; strict host key checking will fail closed"
                );
                ServerCheckMethod::DefaultKnownHostsFile
            }
        },
        StrictHostKeyChecking::No => {
            tracing::debug!("Host key checking disabled (strict mode = no)");
            ServerCheckMethod::NoCheck
        }
        StrictHostKeyChecking::AcceptNew => match get_default_known_hosts_path() {
            Some(known_hosts_path) => {
                tracing::debug!(
                    "Using known_hosts file: {:?} (accept-new/TOFU mode)",
                    known_hosts_path
                );
                ServerCheckMethod::AcceptNewKnownHostsFile(
                    known_hosts_path.to_string_lossy().into_owned(),
                )
            }
            None => {
                // Without a home directory there is no persistent trust state,
                // so first-use recording and change detection are impossible:
                // every host is "new" and accept-new semantics accept it. Warn
                // loudly that nothing can be recorded or verified.
                tracing::warn!(
                    "Could not determine known_hosts path; host keys cannot be recorded or verified"
                );
                eprintln!(
                    "Warning: could not determine the known_hosts path; host keys cannot be recorded or verified in accept-new mode"
                );
                ServerCheckMethod::NoCheck
            }
        },
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

        // AcceptNew must map to the TOFU variant carrying the default
        // known_hosts path, whether or not the file exists yet (#239).
        let method = get_check_method(StrictHostKeyChecking::AcceptNew);
        match method {
            ServerCheckMethod::AcceptNewKnownHostsFile(path) => {
                assert!(
                    path.ends_with("known_hosts"),
                    "expected the default known_hosts path, got: {path}"
                );
            }
            other => panic!("accept-new must map to AcceptNewKnownHostsFile, got {other:?}"),
        }

        // Yes must never disable verification, even when the known_hosts
        // file is missing: a missing file behaves as an empty one (#239).
        let method = get_check_method(StrictHostKeyChecking::Yes);
        match method {
            ServerCheckMethod::KnownHostsFile(path) => {
                assert!(
                    path.ends_with("known_hosts"),
                    "expected the default known_hosts path, got: {path}"
                );
            }
            // Only reachable when no home directory can be determined; still
            // a verifying method that fails closed.
            ServerCheckMethod::DefaultKnownHostsFile => {}
            other => panic!("strict mode must keep verification enabled, got {other:?}"),
        }
    }
}
