// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use thiserror::Error;

/// Deterministic values used to expand an OpenSSH `ControlPath` template.
///
/// Callers supply local host and home values explicitly so tests do not depend
/// on process-global environment or host OS identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ControlPathContext {
    local_host: String,
    home_dir: PathBuf,
    remote_host: String,
    remote_port: u16,
    remote_user: String,
    jump_host: String,
}

impl ControlPathContext {
    /// Build a context for a direct connection.
    pub fn new(
        local_host: impl Into<String>,
        home_dir: impl Into<PathBuf>,
        remote_host: impl Into<String>,
        remote_port: u16,
        remote_user: impl Into<String>,
    ) -> Self {
        Self {
            local_host: local_host.into(),
            home_dir: home_dir.into(),
            remote_host: remote_host.into(),
            remote_port,
            remote_user: remote_user.into(),
            jump_host: String::new(),
        }
    }

    /// Include the resolved ProxyJump spelling in `%C`, matching OpenSSH's
    /// connection-hash identity.
    #[must_use]
    pub fn with_jump_host(mut self, jump_host: impl Into<String>) -> Self {
        self.jump_host = jump_host.into();
        self
    }

    /// Full local hostname used by `%l`.
    #[must_use]
    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    /// Effective remote hostname used by `%h`.
    #[must_use]
    pub fn remote_host(&self) -> &str {
        &self.remote_host
    }

    /// Effective remote username used by `%r`.
    #[must_use]
    pub fn remote_user(&self) -> &str {
        &self.remote_user
    }

    /// Effective remote port used by `%p`.
    #[must_use]
    pub const fn remote_port(&self) -> u16 {
        self.remote_port
    }

    fn connection_hash(&self) -> String {
        let mut digest = Sha1::new();
        digest.update(self.local_host.as_bytes());
        digest.update(self.remote_host.as_bytes());
        digest.update(self.remote_port.to_string().as_bytes());
        digest.update(self.remote_user.as_bytes());
        digest.update(self.jump_host.as_bytes());

        let mut output = String::with_capacity(40);
        for byte in digest.finalize() {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

/// Expand the #286 ControlPath token subset and validate the resulting Unix
/// socket address before any connection or bind attempt.
pub fn expand_control_path(
    template: &str,
    context: &ControlPathContext,
) -> Result<PathBuf, ControlPathError> {
    if template.is_empty() {
        return Err(ControlPathError::Empty);
    }
    if template.as_bytes().contains(&0) {
        return Err(ControlPathError::ContainsNul);
    }

    let expanded_home = if template == "~" {
        context.home_dir.to_string_lossy().into_owned()
    } else if let Some(suffix) = template.strip_prefix("~/") {
        context.home_dir.join(suffix).to_string_lossy().into_owned()
    } else if template.starts_with('~') {
        return Err(ControlPathError::UnsupportedTilde(template.to_string()));
    } else {
        template.to_string()
    };

    let connection_hash = context.connection_hash();
    let port = context.remote_port.to_string();
    let mut output = String::with_capacity(expanded_home.len() + connection_hash.len());
    let mut characters = expanded_home.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        let token = characters.next().ok_or(ControlPathError::IncompleteToken)?;
        let replacement = match token {
            '%' => "%",
            'C' => &connection_hash,
            'h' => &context.remote_host,
            'p' => &port,
            'r' => &context.remote_user,
            'l' => &context.local_host,
            _ => return Err(ControlPathError::UnsupportedToken(token)),
        };
        output.push_str(replacement);
    }

    let path = PathBuf::from(output);
    validate_control_socket_path(&path)?;
    Ok(path)
}

/// Validate an already-expanded control socket path.
pub fn validate_control_socket_path(path: &Path) -> Result<(), ControlPathError> {
    if path.as_os_str().is_empty() {
        return Err(ControlPathError::Empty);
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            return Err(ControlPathError::ContainsNul);
        }
        let capacity = unix_socket_path_capacity().unwrap_or(0);
        // sockaddr_un.sun_path must retain one byte for its terminating NUL.
        let maximum = capacity.saturating_sub(1);
        if bytes.len() > maximum {
            return Err(ControlPathError::TooLong {
                path: path.to_path_buf(),
                length: bytes.len(),
                maximum,
            });
        }
    }

    #[cfg(not(unix))]
    if path.to_string_lossy().contains('\0') {
        return Err(ControlPathError::ContainsNul);
    }

    Ok(())
}

/// Number of bytes in `sockaddr_un.sun_path`, including its terminating NUL.
/// Non-Unix targets return `None` and remain compile-safe without claiming
/// Unix-domain socket support.
#[must_use]
pub const fn unix_socket_path_capacity() -> Option<usize> {
    #[cfg(unix)]
    {
        Some(
            std::mem::size_of::<libc::sockaddr_un>()
                - std::mem::offset_of!(libc::sockaddr_un, sun_path),
        )
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Invalid or unrepresentable `ControlPath` values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ControlPathError {
    #[error("ControlPath must not be empty")]
    Empty,
    #[error("ControlPath contains a NUL byte")]
    ContainsNul,
    #[error("ControlPath ends with an incomplete '%' token")]
    IncompleteToken,
    #[error(
        "ControlPath contains unsupported token '%{0}'; supported tokens are %C, %h, %p, %r, %l, and %%"
    )]
    UnsupportedToken(char),
    #[error(
        "ControlPath '{0}' uses unsupported '~user' expansion; use '~/' for the current user's home"
    )]
    UnsupportedTilde(String),
    #[error(
        "ControlPath '{}' is {length} bytes, but this platform permits at most {maximum}; shorten the directory or use %C",
        path.display()
    )]
    TooLong {
        path: PathBuf,
        length: usize,
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ControlPathContext {
        ControlPathContext::new(
            "workstation.example",
            "/home/alice",
            "server.example",
            2222,
            "deploy",
        )
        .with_jump_host("jump.example:22")
    }

    #[test]
    fn expands_required_tokens_tilde_and_literal_percent() {
        let short_context = ControlPathContext::new("local", "/h", "host", 22, "user");
        let expanded = expand_control_path("~/cm-%h-%p-%r-%l-%%-%C", &short_context)
            .expect("valid control path");
        let rendered = expanded.to_string_lossy();
        assert!(rendered.starts_with("/h/cm-host-22-user-local-%-"));
        let hash = rendered.rsplit('-').next().expect("hash suffix");
        assert_eq!(hash.len(), 40);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn connection_hash_is_stable_and_includes_jump_host() {
        let direct = ControlPathContext::new("local", "/home/test", "remote", 22, "user");
        let direct_hash = expand_control_path("%C", &direct).expect("direct hash");
        let repeated = expand_control_path("%C", &direct).expect("repeated hash");
        assert_eq!(direct_hash, repeated);

        let jumped = direct.clone().with_jump_host("jump");
        assert_ne!(
            direct_hash,
            expand_control_path("%C", &jumped).expect("jump hash")
        );
    }

    #[test]
    fn rejects_ambiguous_or_malformed_templates() {
        for template in ["", "~other/socket", "/tmp/%", "/tmp/%x", "/tmp/a\0b"] {
            assert!(
                expand_control_path(template, &context()).is_err(),
                "accepted {template:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn reports_platform_socket_limit_before_bind() {
        let capacity = unix_socket_path_capacity().expect("Unix capacity");
        let valid = PathBuf::from("a".repeat(capacity - 1));
        validate_control_socket_path(&valid).expect("maximum path");

        let too_long = PathBuf::from("a".repeat(capacity));
        let error = validate_control_socket_path(&too_long).expect_err("overlong path");
        assert!(matches!(
            error,
            ControlPathError::TooLong {
                length,
                maximum,
                ..
            } if length == capacity && maximum == capacity - 1
        ));
        assert!(error.to_string().contains("use %C"));
    }
}
