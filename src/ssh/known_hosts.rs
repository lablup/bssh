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

use super::tokio_client::{ServerCheckMethod, SshConnectionConfig};
use std::path::PathBuf;
use std::str::FromStr;

use crate::diagnosticln as eprintln;

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
                // but accept-new must still avoid becoming unconditional
                // NoCheck. The client will pin host keys in memory for this
                // process so parallel fan-out can detect a changed key during
                // the same run.
                tracing::warn!(
                    "Could not determine known_hosts path; host keys will be pinned only for this bssh process"
                );
                eprintln!(
                    "Warning: could not determine the known_hosts path; host keys will be pinned only for this bssh process"
                );
                ServerCheckMethod::AcceptNewInMemory
            }
        },
    }
}

/// Select host-key verification from the effective ssh_config for a target.
///
/// OpenSSH accepts multiple user and global files. bssh preserves their
/// declared order, reads user files before global files, and records a new
/// key only into the first usable user file. The default file is used only
/// when neither directive was configured.
pub fn get_check_method_for_target(
    strict_mode: StrictHostKeyChecking,
    connection_config: &SshConnectionConfig,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> ServerCheckMethod {
    if matches!(strict_mode, StrictHostKeyChecking::No) {
        return wrap_host_key_alias(
            ServerCheckMethod::NoCheck,
            connection_config.host_key_alias.as_deref(),
        );
    }

    let user_configured = connection_config.user_known_hosts_files.is_some();
    let global_configured = connection_config.global_known_hosts_files.is_some();
    let method = if !user_configured && !global_configured {
        get_check_method(strict_mode)
    } else {
        configured_check_method(
            strict_mode,
            connection_config,
            hostname,
            port,
            remote_username,
        )
    };
    wrap_host_key_alias(method, connection_config.host_key_alias.as_deref())
}

fn configured_check_method(
    strict_mode: StrictHostKeyChecking,
    connection_config: &SshConnectionConfig,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> ServerCheckMethod {
    let user_files = expand_known_hosts_files(
        connection_config.user_known_hosts_files.as_deref(),
        hostname,
        port,
        remote_username,
    );
    let global_files = expand_known_hosts_files(
        connection_config.global_known_hosts_files.as_deref(),
        hostname,
        port,
        remote_username,
    );
    let write_path = user_files.first().cloned();
    let files = user_files.into_iter().chain(global_files).collect();

    match strict_mode {
        StrictHostKeyChecking::Yes => ServerCheckMethod::KnownHostsFiles(files),
        StrictHostKeyChecking::AcceptNew => {
            ServerCheckMethod::AcceptNewKnownHostsFiles { files, write_path }
        }
        StrictHostKeyChecking::No => ServerCheckMethod::NoCheck,
    }
}

fn wrap_host_key_alias(method: ServerCheckMethod, alias: Option<&str>) -> ServerCheckMethod {
    match alias {
        Some(alias) => ServerCheckMethod::HostKeyAlias {
            alias: alias.to_string(),
            method: Box::new(method),
        },
        None => method,
    }
}

fn expand_known_hosts_files(
    templates: Option<&[String]>,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> Vec<String> {
    templates
        .into_iter()
        .flatten()
        .filter_map(|template| expand_known_hosts_path(template, hostname, port, remote_username))
        .collect()
}

fn expand_known_hosts_path(
    template: &str,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> Option<String> {
    if template.eq_ignore_ascii_case("none") || template == "/dev/null" {
        return None;
    }

    let home = dirs::home_dir().map(|path| path.to_string_lossy().into_owned());
    let local_username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()));
    let port = port.to_string();
    let mut expanded = String::with_capacity(template.len());
    let mut chars = template.chars();

    while let Some(ch) = chars.next() {
        if ch != '%' {
            expanded.push(ch);
            continue;
        }
        let Some(token) = chars.next() else {
            tracing::warn!("Ignoring known_hosts path with a trailing '%' token: {template}");
            return None;
        };
        match token {
            '%' => expanded.push('%'),
            'd' => {
                let Some(home) = home.as_deref() else {
                    tracing::warn!(
                        "Ignoring known_hosts path requiring %d because no home directory is available: {template}"
                    );
                    return None;
                };
                expanded.push_str(home);
            }
            'h' => expanded.push_str(hostname),
            'p' => expanded.push_str(&port),
            'r' => expanded.push_str(remote_username),
            'u' => expanded.push_str(&local_username),
            other => {
                tracing::warn!(
                    "Ignoring known_hosts path with unsupported %{other} token: {template}"
                );
                return None;
            }
        }
    }

    if expanded == "~" {
        let Some(home) = home else {
            tracing::warn!(
                "Ignoring known_hosts path requiring tilde expansion because no home directory is available: {template}"
            );
            return None;
        };
        return Some(home);
    }
    if let Some(suffix) = expanded.strip_prefix("~/") {
        let Some(home) = home else {
            tracing::warn!(
                "Ignoring known_hosts path requiring tilde expansion because no home directory is available: {template}"
            );
            return None;
        };
        return Some(
            PathBuf::from(home)
                .join(suffix)
                .to_string_lossy()
                .into_owned(),
        );
    }

    if expanded.eq_ignore_ascii_case("none") || expanded == "/dev/null" {
        return None;
    }

    Some(expanded)
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

/// Return all writable user known_hosts paths for proven host-key rotation.
pub(crate) fn user_known_hosts_paths(
    connection_config: &SshConnectionConfig,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> Vec<String> {
    if connection_config.user_known_hosts_files.is_none()
        && connection_config.global_known_hosts_files.is_none()
    {
        return get_default_known_hosts_path()
            .map(|path| vec![path.to_string_lossy().into_owned()])
            .unwrap_or_default();
    }
    expand_known_hosts_files(
        connection_config.user_known_hosts_files.as_deref(),
        hostname,
        port,
        remote_username,
    )
}

/// Return every user and global known_hosts path used for read-only lookup.
pub(crate) fn read_known_hosts_paths(
    connection_config: &SshConnectionConfig,
    hostname: &str,
    port: u16,
    remote_username: &str,
) -> Vec<String> {
    if connection_config.user_known_hosts_files.is_none()
        && connection_config.global_known_hosts_files.is_none()
    {
        return get_default_known_hosts_path()
            .map(|path| vec![path.to_string_lossy().into_owned()])
            .unwrap_or_default();
    }
    expand_known_hosts_files(
        connection_config.user_known_hosts_files.as_deref(),
        hostname,
        port,
        remote_username,
    )
    .into_iter()
    .chain(expand_known_hosts_files(
        connection_config.global_known_hosts_files.as_deref(),
        hostname,
        port,
        remote_username,
    ))
    .collect()
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

    #[test]
    fn configured_known_hosts_files_preserve_order_and_expand_tokens() {
        let config = SshConnectionConfig::new().with_known_hosts_files(
            Some(vec![
                "/tmp/user-first".to_string(),
                "none".to_string(),
                "/dev/null".to_string(),
                "/tmp/%h-%p-%r-%u".to_string(),
            ]),
            Some(vec!["/tmp/global".to_string()]),
        );
        let local_username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| whoami::username().unwrap_or_else(|_| "user".to_string()));

        let method = get_check_method_for_target(
            StrictHostKeyChecking::Yes,
            &config,
            "node.example.com",
            2222,
            "remote",
        );
        assert_eq!(
            method,
            ServerCheckMethod::KnownHostsFiles(vec![
                "/tmp/user-first".to_string(),
                format!("/tmp/node.example.com-2222-remote-{local_username}"),
                "/tmp/global".to_string(),
            ])
        );
    }

    #[test]
    fn accept_new_records_only_to_first_expanded_user_file() {
        let config = SshConnectionConfig::new().with_known_hosts_files(
            Some(vec!["/tmp/%h-first".to_string(), "/tmp/second".to_string()]),
            Some(vec!["/tmp/global".to_string()]),
        );

        let method = get_check_method_for_target(
            StrictHostKeyChecking::AcceptNew,
            &config,
            "node",
            22,
            "remote",
        );
        assert_eq!(
            method,
            ServerCheckMethod::AcceptNewKnownHostsFiles {
                files: vec![
                    "/tmp/node-first".to_string(),
                    "/tmp/second".to_string(),
                    "/tmp/global".to_string(),
                ],
                write_path: Some("/tmp/node-first".to_string()),
            }
        );
    }

    #[test]
    fn configured_empty_stores_do_not_fall_back_to_default() {
        let config = SshConnectionConfig::new().with_known_hosts_files(
            Some(vec!["none".to_string(), "/dev/null".to_string()]),
            None,
        );

        let method =
            get_check_method_for_target(StrictHostKeyChecking::Yes, &config, "node", 22, "remote");
        assert_eq!(method, ServerCheckMethod::KnownHostsFiles(Vec::new()));
    }

    #[test]
    fn resolver_preserves_multiple_known_hosts_paths_and_empty_sentinels() {
        let ssh_config = crate::ssh::SshConfig::parse(
            "Host target\n  HostKeyAlias config-alias.example.com\n  UserKnownHostsFile ~/.ssh/one /dev/null none\n  GlobalKnownHostsFile %d/global %h-%p-%r-%u\n",
        )
        .unwrap();
        let host = crate::ssh::tokio_client::SshConnectionConfigResolver::new()
            .with_ssh_config(Some(ssh_config))
            .resolve_for_host("target");
        assert_eq!(
            host.user_known_hosts_files,
            Some(vec!["~/.ssh/one".into(), "/dev/null".into(), "none".into()])
        );
        assert_eq!(
            host.global_known_hosts_files,
            Some(vec!["%d/global".into(), "%h-%p-%r-%u".into()])
        );
        assert_eq!(
            host.host_key_alias.as_deref(),
            Some("config-alias.example.com")
        );
    }

    #[test]
    fn cli_host_key_alias_overrides_effective_host_config() {
        let ssh_config = crate::ssh::SshConfig::parse(
            "Host target\n  HostKeyAlias config-alias.example.com\n  UserKnownHostsFile /tmp/known_hosts\n",
        )
        .unwrap();
        let config = crate::ssh::tokio_client::SshConnectionConfigResolver::new()
            .with_ssh_config(Some(ssh_config))
            .with_cli_host_key_alias(Some("cli-alias.example.com".into()))
            .resolve_for_host("target");

        assert_eq!(
            config.host_key_alias.as_deref(),
            Some("cli-alias.example.com")
        );
        assert_eq!(
            get_check_method_for_target(
                StrictHostKeyChecking::Yes,
                &config,
                "target",
                4242,
                "user"
            ),
            ServerCheckMethod::HostKeyAlias {
                alias: "cli-alias.example.com".into(),
                method: Box::new(ServerCheckMethod::KnownHostsFiles(vec![
                    "/tmp/known_hosts".into()
                ])),
            }
        );
    }

    #[test]
    fn expands_home_directory_tokens_and_tilde() {
        let home = dirs::home_dir().expect("test environment must have a home directory");
        assert_eq!(
            expand_known_hosts_path("%d/.ssh/custom", "node", 22, "remote"),
            Some(home.join(".ssh/custom").to_string_lossy().into_owned())
        );
        assert_eq!(
            expand_known_hosts_path("~/.ssh/other", "node", 22, "remote"),
            Some(home.join(".ssh/other").to_string_lossy().into_owned())
        );
    }
}
