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

//! Trust On First Use (TOFU) host key verification.
//!
//! Implements the `accept-new` host key checking mode (#239): a host key that
//! matches its known_hosts entry is accepted, an unknown host is recorded in
//! the known_hosts file and accepted, and a key that conflicts with an existing
//! entry is rejected with an OpenSSH-style warning. The recording itself is
//! delegated to `russh::keys::known_hosts::learn_known_hosts_path`, which
//! handles entry formatting (including the `[host]:port` form for non-22
//! ports) and file creation; this module adds the trust decision, restrictive
//! permissions on newly created files, and serialization of concurrent
//! first-time connections.

use russh::keys::{Algorithm, HashAlg, PublicKey};
use std::path::Path;
use tokio::sync::Mutex;

/// Serializes every known_hosts check-then-record sequence in this process.
///
/// bssh connects to many nodes in parallel, so several first-time connections
/// to the same new host can run concurrently. Without serialization each of
/// them would observe "unknown host" and append its own entry, and a reader
/// could also observe a half-written line. Holding one lock across the whole
/// check+record critical section makes the sequence atomic within the
/// process: whichever connection wins the race records the key, and the rest
/// re-run the check under the lock and see the entry as already known.
///
/// This is a `tokio::sync::Mutex` rather than `std::sync::Mutex`. The guard
/// lives inside an async fn, and while the critical section is purely
/// synchronous file I/O today, a tokio mutex keeps the guard sound if an
/// await point is ever introduced and parks contending tasks instead of
/// blocking runtime worker threads.
static KNOWN_HOSTS_LOCK: Mutex<()> = Mutex::const_new(());

/// Verify a server key in accept-new (TOFU) mode against `known_hosts_path`.
///
/// Returns `Ok(true)` when the key matches an existing entry or the host had no
/// entry at all (in which case the key is recorded first). Returns
/// [`super::Error::HostKeyChanged`] when any entry for the host already exists
/// and does not match the offered key, without modifying the file.
pub(super) async fn verify_accept_new(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<bool, super::Error> {
    let _guard = KNOWN_HOSTS_LOCK.lock().await;

    match russh::keys::check_known_hosts_path(hostname, port, server_public_key, known_hosts_path) {
        Ok(true) => Ok(true),
        // `check_known_hosts_path` reports `Err(KeyChanged)` only when an entry
        // for the host exists *with the same key algorithm* but a different
        // key. A hostname whose entries are all of some other algorithm
        // therefore also lands here, indistinguishable from a hostname with no
        // entry at all, so "unknown host" cannot be inferred from this arm
        // alone; the entries for the host have to be looked at directly.
        Ok(false) => {
            match russh::keys::known_hosts::known_host_keys_path(hostname, port, known_hosts_path) {
                // Unreadable or malformed known_hosts. `check_known_hosts_path`
                // parses the same lines, so it would normally have failed first;
                // failing closed here keeps the fallthrough from recording.
                Err(e) => Err(map_known_hosts_error(
                    hostname,
                    port,
                    server_public_key,
                    known_hosts_path,
                    e,
                )),
                Ok(existing) => match existing.first() {
                    // The host is pinned, just under a different key algorithm.
                    // Recording the offered key alongside the existing entry would
                    // hand an active man-in-the-middle a complete bypass of
                    // pinning: SSH negotiation selects the first host key
                    // algorithm on the client's list that the server also
                    // supports, so an attacker who advertises support for only an
                    // algorithm the real host has not used yet gets to choose that
                    // algorithm and would then be trusted on "first" use. OpenSSH
                    // resists this by reordering its host key algorithm proposal
                    // per host to prefer already-known types
                    // (`order_hostkeyalgs`), which russh cannot do per host, so the
                    // protection has to live in this check: an existing entry that
                    // does not match is treated as a changed key, reported against
                    // the first conflicting line.
                    Some(&(line, _)) => Err(map_known_hosts_error(
                        hostname,
                        port,
                        server_public_key,
                        known_hosts_path,
                        russh::keys::Error::KeyChanged { line },
                    )),
                    // Genuinely unknown host: trust on first use. A missing
                    // known_hosts file also lands here because russh treats an
                    // unreadable file as empty; `learn_known_hosts_path` creates it
                    // on demand.
                    None => {
                        record_host_key(hostname, port, server_public_key, known_hosts_path);
                        Ok(true)
                    }
                },
            }
        }
        Err(e) => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            known_hosts_path,
            e,
        )),
    }
}

/// Convert a known_hosts check failure into the crate error type.
///
/// A [`russh::keys::Error::KeyChanged`] becomes the dedicated
/// [`super::Error::HostKeyChanged`] variant after printing an OpenSSH-style
/// warning, so a changed key is distinguishable from an unreadable or
/// malformed known_hosts file (which stays the generic `ServerCheckFailed`).
/// Shared by the accept-new, `KnownHostsFile`, and `DefaultKnownHostsFile`
/// check methods so strict mode reports changed keys just as clearly.
pub(super) fn map_known_hosts_error(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_display: &str,
    err: russh::keys::Error,
) -> super::Error {
    match err {
        russh::keys::Error::KeyChanged { line } => {
            print_host_key_changed_warning(
                hostname,
                port,
                server_public_key,
                known_hosts_display,
                line,
            );
            super::Error::HostKeyChanged {
                host: hostname.to_string(),
                port,
                line,
            }
        }
        e => {
            tracing::error!("Host key verification failed for '{hostname}': {e}");
            super::Error::ServerCheckFailed
        }
    }
}

/// Record `server_public_key` in `known_hosts_path` and print the OpenSSH
/// "Permanently added" notice.
///
/// Recording is best effort, matching OpenSSH: in accept-new mode an unknown
/// host is accepted either way, so a failure to persist the key (read-only
/// filesystem, permission problem) is reported as a warning instead of
/// failing the connection.
fn record_host_key(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) {
    let path = Path::new(known_hosts_path);
    // Only files and directories created by this recording get their
    // permissions tightened; pre-existing ones are left untouched.
    let dir_preexisted = path.parent().is_none_or(Path::exists);
    let file_preexisted = path.exists();

    if let Err(e) =
        russh::keys::known_hosts::learn_known_hosts_path(hostname, port, server_public_key, path)
    {
        tracing::warn!("Failed to record host key for '{hostname}' in {known_hosts_path}: {e}");
        eprintln!(
            "Warning: failed to add '{}' to the list of known hosts ({known_hosts_path}): {e}",
            known_hosts_entry_name(hostname, port)
        );
        return;
    }

    #[cfg(unix)]
    restrict_created_permissions(path, dir_preexisted, file_preexisted);
    #[cfg(not(unix))]
    let _ = (dir_preexisted, file_preexisted);

    eprintln!(
        "Permanently added '{}' ({}) to the list of known hosts.",
        known_hosts_entry_name(hostname, port),
        algorithm_display_name(server_public_key)
    );
}

/// The host as it appears in the known_hosts entry: `[host]:port` for
/// non-standard ports, the bare hostname otherwise. Mirrors the convention
/// `learn_known_hosts_path` writes and `check_known_hosts_path` matches.
pub(crate) fn known_hosts_entry_name(hostname: &str, port: u16) -> String {
    if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    }
}

/// Tighten permissions on the `.ssh` directory (0700) and known_hosts file
/// (0600), but only when this recording created them.
/// `learn_known_hosts_path` creates both with the process umask, so a fresh
/// directory could otherwise be group/world readable.
#[cfg(unix)]
fn restrict_created_permissions(path: &Path, dir_preexisted: bool, file_preexisted: bool) {
    use std::os::unix::fs::PermissionsExt;

    if !dir_preexisted
        && let Some(parent) = path.parent()
        && let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
    {
        tracing::warn!("Failed to set mode 0700 on {}: {e}", parent.display());
    }
    if !file_preexisted
        && let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    {
        tracing::warn!("Failed to set mode 0600 on {}: {e}", path.display());
    }
}

/// OpenSSH-style short algorithm name for user-facing messages
/// (e.g. `ED25519` rather than `ssh-ed25519`).
fn algorithm_display_name(key: &PublicKey) -> String {
    match key.algorithm() {
        Algorithm::Ed25519 => "ED25519".to_string(),
        Algorithm::Rsa { .. } => "RSA".to_string(),
        Algorithm::Ecdsa { .. } => "ECDSA".to_string(),
        Algorithm::Dsa => "DSA".to_string(),
        Algorithm::SkEd25519 => "ED25519-SK".to_string(),
        Algorithm::SkEcdsaSha2NistP256 => "ECDSA-SK".to_string(),
        other => other.as_str().to_uppercase(),
    }
}

/// Print the loud OpenSSH-style warning for a changed host key, including the
/// SHA256 fingerprint of the offered key, the conflicting file and line, and
/// a remediation hint. The conflicting entry is never modified.
fn print_host_key_changed_warning(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_display: &str,
    line: usize,
) {
    let algo = algorithm_display_name(server_public_key);
    let fingerprint = server_public_key.fingerprint(HashAlg::Sha256);
    // The removal command names the entry as known_hosts actually records it,
    // so it works for non-standard ports: `ssh-keygen -R hostname` matches
    // nothing when the entry is `[hostname]:port`. Both arguments are double
    // quoted because an unquoted `[host]:port` is an unmatched glob that zsh
    // refuses to run ("no matches found"), and because the resolved
    // known_hosts path may contain spaces.
    let entry_name = known_hosts_entry_name(hostname, port);
    eprintln!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n\
         Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n\
         It is also possible that a host key has just been changed.\n\
         The fingerprint for the {algo} key sent by the remote host is\n\
         {fingerprint}.\n\
         Please contact your system administrator.\n\
         Add correct host key in {known_hosts_display} to get rid of this message.\n\
         Offending key in {known_hosts_display}:{line}\n\
         If the key change is expected, remove the old entry with:\n\
         \x20 ssh-keygen -f \"{known_hosts_display}\" -R \"{entry_name}\""
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::tokio_client::{ClientHandler, Error, ServerCheckMethod};
    use russh::client::Handler;
    use russh::keys::PrivateKey;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn generate_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("ed25519 key generation should not fail")
    }

    /// A fixed RSA public key, used wherever a test needs a key of a *different*
    /// algorithm than [`generate_key`]'s ED25519.
    ///
    /// This is a checked-in fixture rather than `PrivateKey::random(..,
    /// Algorithm::Rsa { .. })` because ssh-key always generates 4096-bit RSA and
    /// the pure-Rust prime search costs minutes in an unoptimized test build.
    /// Only the public half is ever needed: both `verify_accept_new` and
    /// `learn_known_hosts_path` take a `&PublicKey`.
    const RSA_PUBLIC_KEY_FIXTURE: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDHQLu1Tz0J6aMlXcWUot3RKzgkfGen5V0tlCTDCmvUsqdkNZyKjbXLz725KrF8D4KZadci68LKgJ1oqyMKnjFRH40l3JMlNUQaWSo7wROStyax3cyJB+h//z9l8BB/6diq2JZk1UOl0DflsFtKc1p0KgmUhG6hY/Gu8CZQx8L1Y0N2SC1L4LRgx0gYvGt3MisAyvjl5Hah2d3GVi+PS9Jb2Ckmfrr4JQ3BEO0x4vhJWUGn2D1Nh5asTIvW/7v5k6DfkUWY8unQv5Wu/aEOC9NfuIWX8dS5mClvm8g8HVZ7gXW7zwvCq5a7cKn3IggMehzdTG1nN/dtLUCh3FTJt7iV";

    fn rsa_public_key() -> PublicKey {
        let key = russh::keys::parse_public_key_base64(RSA_PUBLIC_KEY_FIXTURE)
            .expect("the RSA fixture must parse");
        assert!(
            matches!(key.algorithm(), Algorithm::Rsa { .. }),
            "the fixture must be an RSA key so it differs from generate_key()"
        );
        key
    }

    /// Non-empty known_hosts lines. `learn_known_hosts_path` prefixes its
    /// first append to a fresh file with a newline, so blank lines are not
    /// entries.
    fn entry_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    fn temp_known_hosts() -> (TempDir, PathBuf, String) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("known_hosts");
        let path_str = path.to_str().unwrap().to_string();
        (dir, path, path_str)
    }

    #[tokio::test]
    async fn test_accept_new_records_unknown_host_and_accepts() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        // First connection: file does not exist yet, host is unknown.
        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)), "unknown host must be accepted");

        let lines = entry_lines(&path);
        assert_eq!(lines.len(), 1, "exactly one entry must be recorded");
        assert!(
            lines[0].starts_with("node1.example.com "),
            "port 22 must be recorded as the bare hostname, got: {}",
            lines[0]
        );
        assert!(lines[0].contains("ssh-ed25519"));
    }

    #[tokio::test]
    async fn test_accept_new_second_connection_does_not_duplicate() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        for _ in 0..3 {
            let result =
                verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
            assert!(matches!(result, Ok(true)));
        }

        assert_eq!(
            entry_lines(&path).len(),
            1,
            "repeat connections with the same key must not append duplicates"
        );
    }

    #[tokio::test]
    async fn test_accept_new_rejects_changed_key_and_keeps_entry() {
        let (_dir, path, path_str) = temp_known_hosts();
        let original = generate_key();
        let imposter = generate_key();

        let result =
            verify_accept_new("node1.example.com", 22, original.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        let recorded = entry_lines(&path);

        // Same host now presents a different key: must be rejected with the
        // dedicated changed-key error, not accepted and not re-recorded.
        let result =
            verify_accept_new("node1.example.com", 22, imposter.public_key(), &path_str).await;
        match result {
            Err(Error::HostKeyChanged { host, port, line }) => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 22);
                assert!(line > 0);
            }
            other => panic!("expected HostKeyChanged, got {other:?}"),
        }

        assert_eq!(
            entry_lines(&path),
            recorded,
            "the conflicting entry must not be overwritten or appended to"
        );
    }

    #[tokio::test]
    async fn test_accept_new_rejects_alternate_algorithm_key_for_known_host() {
        let (_dir, path, path_str) = temp_known_hosts();
        let pinned = generate_key();

        let result =
            verify_accept_new("node1.example.com", 22, pinned.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        let recorded = entry_lines(&path);
        assert_eq!(recorded.len(), 1, "the ED25519 key must be pinned first");

        // The host is pinned, just not with an RSA key, and russh's checker
        // reports a changed key only when the algorithms match. This case used
        // to be indistinguishable from a first use, so the offered key was
        // appended next to the existing entry and accepted, which let an
        // attacker who advertises support for only an algorithm the real host
        // has not used yet bypass pinning entirely.
        let result = verify_accept_new("node1.example.com", 22, &rsa_public_key(), &path_str).await;
        match result {
            Err(Error::HostKeyChanged { host, port, line }) => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 22);
                assert!(line > 0);
            }
            other => {
                panic!("expected HostKeyChanged for an alternate-algorithm key, got {other:?}")
            }
        }

        assert_eq!(
            entry_lines(&path),
            recorded,
            "no second entry may be appended for an already-pinned host"
        );
    }

    #[tokio::test]
    async fn test_changed_key_error_carries_connection_port() {
        // The client-facing guidance messages build `ssh-keygen -R
        // "[host]:port"` out of this port, so it has to be the port the
        // connection actually used rather than a default 22.
        let (_dir, _path, path_str) = temp_known_hosts();
        let original = generate_key();
        let imposter = generate_key();

        let result =
            verify_accept_new("node1.example.com", 2222, original.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        let result =
            verify_accept_new("node1.example.com", 2222, imposter.public_key(), &path_str).await;
        match result {
            Err(Error::HostKeyChanged { host, port, line }) => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 2222, "the error must carry the connection port");
                assert!(line > 0);
            }
            other => panic!("expected HostKeyChanged, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_accept_new_concurrent_first_connections_record_one_entry() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = std::sync::Arc::new(generate_key());

        let mut handles = Vec::new();
        for _ in 0..8 {
            let key = std::sync::Arc::clone(&key);
            let path_str = path_str.clone();
            handles.push(tokio::spawn(async move {
                verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await
            }));
        }
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(matches!(result, Ok(true)), "every racer must be accepted");
        }

        assert_eq!(
            entry_lines(&path).len(),
            1,
            "parallel first-time connections must record exactly one entry"
        );
    }

    #[tokio::test]
    async fn test_accept_new_non_standard_port_round_trips() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        let result =
            verify_accept_new("node1.example.com", 2222, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        let lines = entry_lines(&path);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("[node1.example.com]:2222 "),
            "non-standard ports must use the [host]:port form, got: {}",
            lines[0]
        );

        // The recorded entry must round-trip through the checker.
        let result =
            verify_accept_new("node1.example.com", 2222, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(entry_lines(&path).len(), 1, "round trip must not duplicate");

        // A different key on the same host:port is a changed key.
        let imposter = generate_key();
        let result =
            verify_accept_new("node1.example.com", 2222, imposter.public_key(), &path_str).await;
        assert!(matches!(result, Err(Error::HostKeyChanged { .. })));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_accept_new_created_dir_and_file_get_restrictive_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        // Both the .ssh directory and the file are created by the recording.
        let ssh_dir = dir.path().join(".ssh");
        let path = ssh_dir.join("known_hosts");
        let path_str = path.to_str().unwrap().to_string();
        let key = generate_key();

        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        let dir_mode = std::fs::metadata(&ssh_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "created .ssh directory must be 0700");
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "created known_hosts must be 0600");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_accept_new_preserves_preexisting_dir_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = ssh_dir.join("known_hosts");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        let key = generate_key();

        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        let dir_mode = std::fs::metadata(&ssh_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755, "pre-existing directory mode must be kept");
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o644, "pre-existing file mode must be kept");
    }

    #[test]
    fn test_map_known_hosts_error_distinguishes_key_changed() {
        let key = generate_key();

        let err = map_known_hosts_error(
            "node1.example.com",
            22,
            key.public_key(),
            "/tmp/known_hosts",
            russh::keys::Error::KeyChanged { line: 7 },
        );
        match err {
            Error::HostKeyChanged { host, port, line } => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 22);
                assert_eq!(line, 7);
            }
            other => panic!("expected HostKeyChanged, got {other:?}"),
        }

        let err = map_known_hosts_error(
            "node1.example.com",
            22,
            key.public_key(),
            "/tmp/known_hosts",
            russh::keys::Error::KeyIsCorrupt,
        );
        assert!(matches!(err, Error::ServerCheckFailed));
    }

    #[test]
    fn test_known_hosts_entry_name_forms() {
        assert_eq!(known_hosts_entry_name("host", 22), "host");
        assert_eq!(known_hosts_entry_name("host", 2222), "[host]:2222");
    }

    // Strict (`yes`) mode behavior through the real handler entry point.

    fn handler_for(check: ServerCheckMethod) -> ClientHandler {
        ClientHandler::new(
            "node1.example.com".to_string(),
            "127.0.0.1:22".parse().unwrap(),
            check,
        )
    }

    #[tokio::test]
    async fn test_strict_mode_missing_known_hosts_rejects_unknown_host() {
        // Regression test for #239's second defect: a missing known_hosts
        // file in strict mode must behave as an empty file (unknown host
        // rejected), never as disabled verification.
        let (_dir, _path, path_str) = temp_known_hosts();
        let key = generate_key();

        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str));
        let result = handler.check_server_key(key.public_key()).await;
        assert!(
            matches!(result, Ok(false)),
            "unknown host must be rejected in strict mode, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_strict_mode_reports_changed_key_specifically() {
        let (_dir, _path, path_str) = temp_known_hosts();
        let original = generate_key();
        let imposter = generate_key();

        russh::keys::known_hosts::learn_known_hosts_path(
            "node1.example.com",
            22,
            original.public_key(),
            &path_str,
        )
        .unwrap();

        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str.clone()));
        let result = handler.check_server_key(imposter.public_key()).await;
        assert!(
            matches!(result, Err(Error::HostKeyChanged { .. })),
            "strict mode must report a changed key specifically, got {result:?}"
        );

        // The original key still verifies.
        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str));
        let result = handler.check_server_key(original.public_key()).await;
        assert!(matches!(result, Ok(true)));
    }

    #[tokio::test]
    async fn test_no_check_accepts_without_touching_filesystem() {
        let (_dir, path, _path_str) = temp_known_hosts();
        let key = generate_key();

        let mut handler = handler_for(ServerCheckMethod::NoCheck);
        let result = handler.check_server_key(key.public_key()).await;
        assert!(matches!(result, Ok(true)));
        assert!(!path.exists(), "NoCheck must not create a known_hosts file");
    }

    #[tokio::test]
    async fn test_accept_new_through_client_handler() {
        // The handler arm must reach the TOFU path end to end.
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        let mut handler = handler_for(ServerCheckMethod::AcceptNewKnownHostsFile(path_str));
        let result = handler.check_server_key(key.public_key()).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(entry_lines(&path).len(), 1);
    }
}
