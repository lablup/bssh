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

//! FIDO security-key (`sk-*`) provider interface.
//!
//! OpenSSH signs with authenticator-hosted keys through a middleware library
//! that implements `sk-api.h` (`sk_api_version`, `sk_sign`, ...). bssh loads
//! the same libraries so an identity enrolled with `ssh-keygen -t ed25519-sk`
//! works unchanged, and ships the built-in USB HID provider (`internal`, the
//! default, as in OpenSSH built with `ENABLE_SK_INTERNAL`) behind the same
//! narrow [`SecurityKeyProvider`] trait: [`open_provider`] is the only place
//! that distinguishes the two.
//!
//! Both providers run in-process (`dlopen`, or the in-tree CTAPHID stack in
//! [`internal`]) rather than through an `ssh-sk-helper`-style subprocess. OpenSSH's helper keeps the middleware
//! out of its `pledge`d client and shares one implementation between `ssh`,
//! `ssh-agent`, and `ssh-keygen`; bssh has no such sandbox, and a re-exec
//! helper would add a private wire protocol without changing what code runs
//! as the user. Provider calls block on touch and PIN entry, so callers run
//! them on a blocking thread (see `tokio_client::security_key_signer`).
//!
//! Running in-process has costs the helper avoids, and they are accepted:
//!
//! - An `sk_sign` call that has started cannot be cancelled. A provider that
//!   hangs keeps its blocking thread and the process-wide provider lock until
//!   it returns, so no other security-key signature in the process can
//!   proceed meanwhile. Connections queued behind it give up at their
//!   `ConnectTimeout` without ever reaching the provider.
//! - The provider shares bssh's address space, so it can read everything
//!   bssh holds in memory, including decrypted keys and passwords for other
//!   hosts. Only configure a provider library you would trust with them.

mod external;
pub mod internal;
mod signature;

use std::fmt;
use std::path::{Path, PathBuf};

pub use signature::{SkSignResponse, encode_signature};

/// sk-api major version bssh speaks (`SSH_SK_VERSION_MAJOR`).
pub const SK_API_VERSION_MAJOR: u32 = 0x000a_0000;
/// Mask selecting the major half of an sk-api version.
pub const SK_API_VERSION_MAJOR_MASK: u32 = 0xffff_0000;

/// `SSH_SK_USER_PRESENCE_REQD`: the authenticator wants a touch.
pub const SK_FLAG_USER_PRESENCE_REQUIRED: u8 = 0x01;
/// `SSH_SK_USER_VERIFICATION_REQD`: the authenticator wants a PIN or biometric.
pub const SK_FLAG_USER_VERIFICATION_REQUIRED: u8 = 0x04;

/// The ssh_config default for `SecurityKeyProvider`: OpenSSH built with
/// `ENABLE_SK_INTERNAL` defaults to its built-in provider (`readconf.c`), and
/// so does bssh. A `$`-prefixed value names an environment variable instead.
pub const DEFAULT_PROVIDER_SETTING: &str = "internal";

/// Key algorithms the sk-api distinguishes (`SSH_SK_ECDSA`, `SSH_SK_ED25519`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkAlgorithm {
    EcdsaSha2NistP256,
    Ed25519,
}

impl SkAlgorithm {
    /// Numeric `alg` argument of `sk_sign`.
    #[must_use]
    pub const fn api_code(self) -> u32 {
        match self {
            Self::EcdsaSha2NistP256 => 0,
            Self::Ed25519 => 1,
        }
    }

    /// Plain SSH key type name, which also leads the signature blob.
    #[must_use]
    pub const fn ssh_name(self) -> &'static str {
        match self {
            Self::EcdsaSha2NistP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            Self::Ed25519 => "sk-ssh-ed25519@openssh.com",
        }
    }
}

/// One `sk_sign` call. `data` is the raw message; the provider hashes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkSignRequest<'a> {
    pub algorithm: SkAlgorithm,
    pub data: &'a [u8],
    pub application: &'a str,
    pub key_handle: &'a [u8],
    pub flags: u8,
}

impl SkSignRequest<'_> {
    /// The argument checks `sshsk_sign` makes before it opens the provider:
    /// a key without an application string is refused rather than signed.
    pub fn validate(&self) -> Result<(), SecurityKeyError> {
        if self.application.is_empty() {
            return Err(SecurityKeyError::InvalidRequest("key has no application"));
        }
        Ok(())
    }
}

/// Where `SecurityKeyProvider` points after `$VAR` expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderSource {
    /// No provider: unset environment variable or `none`.
    Disabled,
    /// `internal`: the built-in USB HID provider ([`internal`]).
    Internal,
    /// A shared library implementing `sk-api.h`.
    Library(PathBuf),
}

/// Why a provider could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityKeyError {
    #[error("no SecurityKeyProvider has been specified")]
    NoProvider,
    #[error(
        "built-in security key support is not available on this platform; set SecurityKeyProvider to an sk-api library"
    )]
    InternalUnavailable,
    #[error("Provider \"{path}\" dlopen failed: {reason}")]
    LoadFailed { path: PathBuf, reason: String },
    #[error("provider {path} is not an OpenSSH FIDO library ({reason})")]
    NotAProvider { path: PathBuf, reason: String },
    #[error(
        "Provider \"{path}\" implements unsupported version {version:#010x} (supported: {supported:#010x})"
    )]
    UnsupportedVersion {
        path: PathBuf,
        version: u32,
        supported: u32,
    },
    #[error("sk_sign failed: PIN required")]
    PinRequired,
    #[error("sk_sign failed: device not found")]
    DeviceNotFound,
    #[error("sk_sign failed: operation unsupported by the provider")]
    Unsupported,
    #[error("sk_sign failed with code {0}")]
    SignFailed(i32),
    /// The built-in provider failed with a described reason.
    #[error("sk_sign failed: {0}")]
    Failed(String),
    #[error("sk_sign response invalid: {0}")]
    InvalidResponse(&'static str),
    #[error("sk_sign request invalid: {0}")]
    InvalidRequest(&'static str),
}

impl SecurityKeyError {
    /// Map an sk-api error code the way `ssh-sk.c`'s `skerr_to_ssherr` does.
    #[must_use]
    pub fn from_sk_code(code: i32) -> Self {
        match code {
            -2 => Self::Unsupported,
            -3 => Self::PinRequired,
            -4 => Self::DeviceNotFound,
            other => Self::SignFailed(other),
        }
    }
}

/// A loaded sk-api middleware, or a built-in equivalent.
pub trait SecurityKeyProvider: Send + Sync {
    /// Sign `request.data`. `pin` is forwarded verbatim and never logged.
    fn sign(
        &self,
        request: &SkSignRequest<'_>,
        pin: Option<&str>,
    ) -> Result<SkSignResponse, SecurityKeyError>;

    /// Human-readable origin for diagnostics.
    fn describe(&self) -> String;
}

impl fmt::Debug for dyn SecurityKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityKeyProvider")
            .field("source", &self.describe())
            .finish()
    }
}

/// Resolve the configured `SecurityKeyProvider` value as `ssh.c` does: a
/// leading `$` names an environment variable; an unset variable disables
/// authenticator-hosted keys; `none` disables them; `internal` selects the
/// built-in provider. `None` means the option was not set and takes
/// [`DEFAULT_PROVIDER_SETTING`].
pub fn resolve_provider<F>(configured: Option<&str>, env: F) -> ProviderSource
where
    F: Fn(&str) -> Option<String>,
{
    let configured = configured.unwrap_or(DEFAULT_PROVIDER_SETTING);
    let value = match configured.strip_prefix('$') {
        Some(name) if !name.is_empty() => match env(name) {
            Some(value) => {
                tracing::debug!("resolved SecurityKeyProvider {configured} => {value}");
                value
            }
            None => {
                tracing::debug!("Authenticator provider {configured} did not resolve; disabling");
                return ProviderSource::Disabled;
            }
        },
        _ => configured.to_string(),
    };
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        ProviderSource::Disabled
    } else if value.eq_ignore_ascii_case("internal") {
        ProviderSource::Internal
    } else {
        ProviderSource::Library(PathBuf::from(value))
    }
}

/// Resolve against the process environment.
#[must_use]
pub fn resolve_provider_from_env(configured: Option<&str>) -> ProviderSource {
    resolve_provider(configured, |name| std::env::var(name).ok())
}

/// Open the provider a [`ProviderSource`] names, mirroring `sshsk_open`.
pub fn open_provider(
    source: &ProviderSource,
) -> Result<Box<dyn SecurityKeyProvider>, SecurityKeyError> {
    match source {
        ProviderSource::Disabled => Err(SecurityKeyError::NoProvider),
        ProviderSource::Internal => open_internal(),
        ProviderSource::Library(path) => open_library(path),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_internal() -> Result<Box<dyn SecurityKeyProvider>, SecurityKeyError> {
    Ok(Box::new(internal::InternalProvider::new()))
}

/// The HID transport is only wired up for Linux (hidraw) and macOS (IOKit).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_internal() -> Result<Box<dyn SecurityKeyProvider>, SecurityKeyError> {
    Err(SecurityKeyError::InternalUnavailable)
}

fn open_library(path: &Path) -> Result<Box<dyn SecurityKeyProvider>, SecurityKeyError> {
    external::ExternalProvider::load(path)
        .map(|provider| Box::new(provider) as Box<dyn SecurityKeyProvider>)
}

/// Check a provider's reported `sk_api_version` against the version bssh
/// implements; only the major half must match.
pub fn check_api_version(path: &Path, version: u32) -> Result<(), SecurityKeyError> {
    if version & SK_API_VERSION_MAJOR_MASK == SK_API_VERSION_MAJOR {
        Ok(())
    } else {
        Err(SecurityKeyError::UnsupportedVersion {
            path: path.to_path_buf(),
            version,
            supported: SK_API_VERSION_MAJOR,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(name: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |query| (query == name).then(|| value.to_string())
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn default_setting_is_the_internal_provider() {
        assert_eq!(DEFAULT_PROVIDER_SETTING, "internal");
        assert_eq!(resolve_provider(None, no_env), ProviderSource::Internal);
        // The environment variable OpenSSH-without-internal consults is not
        // read unless the setting names it.
        assert_eq!(
            resolve_provider(None, env_with("SSH_SK_PROVIDER", "/opt/sk.so")),
            ProviderSource::Internal
        );
        assert_eq!(
            resolve_provider(
                Some("$SSH_SK_PROVIDER"),
                env_with("SSH_SK_PROVIDER", "/opt/sk.so")
            ),
            ProviderSource::Library(PathBuf::from("/opt/sk.so"))
        );
        assert_eq!(
            resolve_provider(Some("$SSH_SK_PROVIDER"), no_env),
            ProviderSource::Disabled
        );
    }

    #[test]
    fn dollar_prefix_expands_any_variable_and_a_bare_dollar_is_literal() {
        assert_eq!(
            resolve_provider(Some("$MY_SK"), env_with("MY_SK", "/lib/sk-dummy.so")),
            ProviderSource::Library(PathBuf::from("/lib/sk-dummy.so"))
        );
        assert_eq!(
            resolve_provider(Some("$MY_SK"), no_env),
            ProviderSource::Disabled
        );
        assert_eq!(
            resolve_provider(Some("$"), env_with("", "ignored")),
            ProviderSource::Library(PathBuf::from("$"))
        );
        assert_eq!(
            resolve_provider(Some("$MY_SK"), env_with("MY_SK", "internal")),
            ProviderSource::Internal
        );
        assert_eq!(
            resolve_provider(Some("$MY_SK"), env_with("MY_SK", "none")),
            ProviderSource::Disabled
        );
    }

    #[test]
    fn literal_values_select_internal_none_or_a_library() {
        assert_eq!(
            resolve_provider(Some("internal"), no_env),
            ProviderSource::Internal
        );
        assert_eq!(
            resolve_provider(Some("Internal"), no_env),
            ProviderSource::Internal
        );
        assert_eq!(
            resolve_provider(Some("none"), no_env),
            ProviderSource::Disabled
        );
        assert_eq!(resolve_provider(Some(""), no_env), ProviderSource::Disabled);
        assert_eq!(
            resolve_provider(Some("/usr/lib/libsk-libfido2.so"), no_env),
            ProviderSource::Library(PathBuf::from("/usr/lib/libsk-libfido2.so"))
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn internal_provider_opens_without_touching_any_device() {
        let provider = open_provider(&ProviderSource::Internal).unwrap();
        assert_eq!(provider.describe(), "internal");
        assert_eq!(
            open_provider(&ProviderSource::Disabled).unwrap_err(),
            SecurityKeyError::NoProvider
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn internal_provider_reports_an_explicit_unavailable_diagnostic() {
        let error = open_provider(&ProviderSource::Internal).unwrap_err();
        assert_eq!(error, SecurityKeyError::InternalUnavailable);
        assert!(
            error
                .to_string()
                .contains("built-in security key support is not available")
        );
    }

    #[test]
    fn api_version_check_accepts_any_minor_of_the_supported_major() {
        let path = Path::new("/p.so");
        assert!(check_api_version(path, SK_API_VERSION_MAJOR).is_ok());
        assert!(check_api_version(path, SK_API_VERSION_MAJOR | 0x0001).is_ok());
        let error = check_api_version(path, 0x0009_0000).unwrap_err();
        assert_eq!(
            error,
            SecurityKeyError::UnsupportedVersion {
                path: path.to_path_buf(),
                version: 0x0009_0000,
                supported: SK_API_VERSION_MAJOR,
            }
        );
        assert!(error.to_string().contains("0x00090000"));
        assert!(error.to_string().contains("0x000a0000"));
    }

    #[test]
    fn sk_error_codes_map_like_skerr_to_ssherr() {
        assert_eq!(
            SecurityKeyError::from_sk_code(-2),
            SecurityKeyError::Unsupported
        );
        assert_eq!(
            SecurityKeyError::from_sk_code(-3),
            SecurityKeyError::PinRequired
        );
        assert_eq!(
            SecurityKeyError::from_sk_code(-4),
            SecurityKeyError::DeviceNotFound
        );
        assert_eq!(
            SecurityKeyError::from_sk_code(-1),
            SecurityKeyError::SignFailed(-1)
        );
        assert_eq!(
            SecurityKeyError::from_sk_code(-5),
            SecurityKeyError::SignFailed(-5)
        );
    }

    #[test]
    fn requests_without_an_application_are_invalid() {
        let mut request = SkSignRequest {
            algorithm: SkAlgorithm::Ed25519,
            data: b"data",
            application: "ssh:",
            key_handle: &[1, 2],
            flags: SK_FLAG_USER_PRESENCE_REQUIRED,
        };
        assert_eq!(request.validate(), Ok(()));
        request.application = "";
        assert_eq!(
            request.validate(),
            Err(SecurityKeyError::InvalidRequest("key has no application"))
        );
    }

    #[test]
    fn algorithm_codes_and_names_follow_sk_api() {
        assert_eq!(SkAlgorithm::EcdsaSha2NistP256.api_code(), 0);
        assert_eq!(SkAlgorithm::Ed25519.api_code(), 1);
        assert_eq!(
            SkAlgorithm::Ed25519.ssh_name(),
            "sk-ssh-ed25519@openssh.com"
        );
        assert_eq!(
            SkAlgorithm::EcdsaSha2NistP256.ssh_name(),
            "sk-ecdsa-sha2-nistp256@openssh.com"
        );
    }
}
