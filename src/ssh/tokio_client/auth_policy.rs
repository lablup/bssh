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

//! Resolved client-authentication policy for one SSH destination.

use std::path::PathBuf;

/// OpenSSH's default number of interactive password prompts.
pub const DEFAULT_PASSWORD_PROMPTS: u32 = 3;

/// Authentication settings selected from the concrete host's `ssh_config` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAuthenticationPolicy {
    pub cli_identity_files: Vec<PathBuf>,
    pub identity_files: Vec<PathBuf>,
    pub certificate_files: Vec<PathBuf>,
    /// `IdentityFile none` suppresses implicit default identity files.
    pub identity_file_none: bool,
    pub identities_only: bool,
    pub preferred_authentications: Vec<String>,
    pub pubkey_authentication: bool,
    pub password_authentication: bool,
    pub number_of_password_prompts: u32,
    pub batch_mode: bool,
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
}

impl Default for SshAuthenticationPolicy {
    fn default() -> Self {
        Self {
            cli_identity_files: Vec::new(),
            identity_file_none: false,
            identity_files: Vec::new(),
            certificate_files: Vec::new(),
            identities_only: false,
            preferred_authentications: vec![
                "publickey".to_string(),
                "keyboard-interactive".to_string(),
                "password".to_string(),
            ],
            pubkey_authentication: true,
            password_authentication: true,
            number_of_password_prompts: DEFAULT_PASSWORD_PROMPTS,
            batch_mode: false,
            pubkey_accepted_algorithms: Some(super::algorithms::default_pubkey_algorithms()),
        }
    }
}

impl SshAuthenticationPolicy {
    #[must_use]
    pub fn method_enabled(&self, method: &str) -> bool {
        let preferred = self
            .preferred_authentications
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(method));
        preferred
            && match method {
                "publickey" => self.pubkey_authentication,
                "password" => self.password_authentication,
                _ => false,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_matches_supported_openssh_order() {
        let policy = SshAuthenticationPolicy::default();
        assert!(policy.method_enabled("publickey"));
        assert!(policy.method_enabled("password"));
        assert!(!policy.method_enabled("keyboard-interactive"));
        assert_eq!(policy.number_of_password_prompts, 3);
    }

    #[test]
    fn method_flags_and_preference_list_both_gate_attempts() {
        let mut policy = SshAuthenticationPolicy {
            preferred_authentications: vec!["password".to_string()],
            ..SshAuthenticationPolicy::default()
        };
        assert!(!policy.method_enabled("publickey"));
        assert!(policy.method_enabled("password"));

        policy.password_authentication = false;
        assert!(!policy.method_enabled("password"));
    }
}
