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

//! Shared authentication types for client and server implementations.
//!
//! This module provides common types used in authentication flows that can
//! be shared between the bssh client and server implementations.
//!
//! # Types
//!
//! - [`AuthResult`]: The outcome of an authentication attempt
//! - [`UserInfo`]: Information about an authenticated user
//! - [`AuthMethod`]: Available authentication methods

use std::path::PathBuf;

/// The result of an authentication attempt.
///
/// This enum represents the three possible outcomes of attempting to
/// authenticate a user, following the SSH protocol semantics.
///
/// # Examples
///
/// ```
/// use bssh::shared::auth_types::AuthResult;
///
/// fn check_password(username: &str, password: &str) -> AuthResult {
///     if password == "secret" {
///         AuthResult::Accept
///     } else {
///         AuthResult::Reject
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthResult {
    /// Authentication succeeded - user is fully authenticated.
    Accept,

    /// Authentication failed - access denied.
    #[default]
    Reject,

    /// Partial authentication success - more methods required.
    ///
    /// This is used for multi-factor authentication scenarios where
    /// one authentication method succeeded but additional methods
    /// are required to complete authentication.
    Partial {
        /// The list of remaining authentication methods the user must complete.
        remaining_methods: Vec<String>,
    },
}

impl AuthResult {
    /// Returns `true` if the authentication was fully successful.
    pub fn is_accepted(&self) -> bool {
        matches!(self, AuthResult::Accept)
    }

    /// Returns `true` if the authentication was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, AuthResult::Reject)
    }

    /// Returns `true` if partial authentication occurred.
    pub fn is_partial(&self) -> bool {
        matches!(self, AuthResult::Partial { .. })
    }

    /// Creates a partial result with the specified remaining methods.
    ///
    /// # Arguments
    ///
    /// * `methods` - An iterator of method names that are still required
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::auth_types::AuthResult;
    ///
    /// let result = AuthResult::partial(["keyboard-interactive", "publickey"]);
    /// assert!(result.is_partial());
    /// ```
    pub fn partial<I, S>(methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        AuthResult::Partial {
            remaining_methods: methods.into_iter().map(Into::into).collect(),
        }
    }
}

/// Information about an authenticated user.
///
/// This struct contains user information that is commonly needed after
/// successful authentication, both for client-side display and server-side
/// session setup.
///
/// # Examples
///
/// ```
/// use bssh::shared::auth_types::UserInfo;
/// use std::path::PathBuf;
///
/// let user = UserInfo::new("johndoe")
///     .with_home_dir("/home/johndoe")
///     .with_shell("/bin/bash")
///     .with_uid(1000)
///     .with_gid(1000);
///
/// assert_eq!(user.username, "johndoe");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// The username of the authenticated user.
    pub username: String,

    /// The user's home directory.
    pub home_dir: PathBuf,

    /// The user's default shell.
    pub shell: PathBuf,

    /// The user's numeric user ID (Unix-specific).
    pub uid: Option<u32>,

    /// The user's primary group ID (Unix-specific).
    pub gid: Option<u32>,

    /// Additional group IDs the user belongs to (Unix-specific).
    pub groups: Vec<u32>,

    /// Display name or full name of the user.
    pub display_name: Option<String>,
}

impl UserInfo {
    /// Create a new UserInfo with just a username.
    ///
    /// Other fields are initialized to sensible defaults:
    /// - home_dir: `/home/<username>` on Unix, empty on other platforms
    /// - shell: `/bin/sh` on Unix, empty on other platforms
    /// - uid/gid: None
    ///
    /// # Arguments
    ///
    /// * `username` - The username
    ///
    /// # Examples
    ///
    /// ```
    /// use bssh::shared::auth_types::UserInfo;
    ///
    /// let user = UserInfo::new("alice");
    /// assert_eq!(user.username, "alice");
    /// ```
    pub fn new(username: impl Into<String>) -> Self {
        let username = username.into();

        #[cfg(unix)]
        let (home_dir, shell) = (
            PathBuf::from(format!("/home/{username}")),
            PathBuf::from("/bin/sh"),
        );

        #[cfg(not(unix))]
        let (home_dir, shell) = (PathBuf::new(), PathBuf::new());

        Self {
            username,
            home_dir,
            shell,
            uid: None,
            gid: None,
            groups: Vec::new(),
            display_name: None,
        }
    }

    /// Set the home directory.
    pub fn with_home_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.home_dir = path.into();
        self
    }

    /// Set the default shell.
    pub fn with_shell(mut self, path: impl Into<PathBuf>) -> Self {
        self.shell = path.into();
        self
    }

    /// Set the user ID.
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Set the primary group ID.
    pub fn with_gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    /// Set the additional group IDs.
    pub fn with_groups(mut self, groups: impl Into<Vec<u32>>) -> Self {
        self.groups = groups.into();
        self
    }

    /// Set the display name.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }
}

/// Common SSH authentication method identifiers.
///
/// These constants represent the standard SSH authentication method names
/// as defined in RFC 4252.
pub mod auth_method_names {
    /// Password authentication (RFC 4252)
    pub const PASSWORD: &str = "password";

    /// Public key authentication (RFC 4252)
    pub const PUBLICKEY: &str = "publickey";

    /// Keyboard-interactive authentication (RFC 4256)
    pub const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

    /// Host-based authentication (RFC 4252)
    pub const HOSTBASED: &str = "hostbased";

    /// No authentication required
    pub const NONE: &str = "none";
}

/// Server host key verification methods.
///
/// These methods control how the client verifies the server's host key
/// during connection. This type is re-exported from the authentication
/// module for convenience.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ServerCheckMethod {
    /// No verification - accept any host key (insecure, for testing only).
    NoCheck,

    /// Verify against a specific base64 encoded public key.
    PublicKey(String),

    /// Verify against a public key file.
    PublicKeyFile(String),

    /// Use default known_hosts file (~/.ssh/known_hosts).
    #[default]
    DefaultKnownHostsFile,

    /// Use a specific known_hosts file path.
    KnownHostsFile(String),
}

impl ServerCheckMethod {
    /// Create a ServerCheckMethod from a base64 encoded public key.
    ///
    /// # Arguments
    ///
    /// * `key` - The base64 encoded public key
    pub fn with_public_key(key: impl Into<String>) -> Self {
        Self::PublicKey(key.into())
    }

    /// Create a ServerCheckMethod from a public key file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the public key file
    pub fn with_public_key_file(path: impl Into<String>) -> Self {
        Self::PublicKeyFile(path.into())
    }

    /// Create a ServerCheckMethod from a known_hosts file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the known_hosts file
    pub fn with_known_hosts_file(path: impl Into<String>) -> Self {
        Self::KnownHostsFile(path.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_states() {
        let accept = AuthResult::Accept;
        assert!(accept.is_accepted());
        assert!(!accept.is_rejected());
        assert!(!accept.is_partial());

        let reject = AuthResult::Reject;
        assert!(!reject.is_accepted());
        assert!(reject.is_rejected());
        assert!(!reject.is_partial());

        let partial = AuthResult::partial(["password", "publickey"]);
        assert!(!partial.is_accepted());
        assert!(!partial.is_rejected());
        assert!(partial.is_partial());
    }

    #[test]
    fn test_user_info_builder() {
        let user = UserInfo::new("testuser")
            .with_home_dir("/custom/home")
            .with_shell("/bin/zsh")
            .with_uid(1001)
            .with_gid(1001)
            .with_groups(vec![100, 101])
            .with_display_name("Test User");

        assert_eq!(user.username, "testuser");
        assert_eq!(user.home_dir, PathBuf::from("/custom/home"));
        assert_eq!(user.shell, PathBuf::from("/bin/zsh"));
        assert_eq!(user.uid, Some(1001));
        assert_eq!(user.gid, Some(1001));
        assert_eq!(user.groups, vec![100, 101]);
        assert_eq!(user.display_name, Some("Test User".to_string()));
    }

    #[test]
    fn test_server_check_method() {
        let default = ServerCheckMethod::default();
        assert_eq!(default, ServerCheckMethod::DefaultKnownHostsFile);

        let key = ServerCheckMethod::with_public_key("ssh-rsa AAAA...");
        assert!(matches!(key, ServerCheckMethod::PublicKey(_)));

        let file = ServerCheckMethod::with_known_hosts_file("/path/to/known_hosts");
        assert!(matches!(file, ServerCheckMethod::KnownHostsFile(_)));
    }
}
