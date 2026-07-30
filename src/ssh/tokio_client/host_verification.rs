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
//! matches any key recorded for the host is accepted, an unknown host is
//! recorded in the known_hosts file and accepted, and a key offered for a host
//! that has recorded keys, none of which match, is rejected with an
//! OpenSSH-style warning. The recording itself is delegated to
//! `russh::keys::known_hosts::learn_known_hosts_path`, which handles entry
//! formatting (including the `[host]:port` form for non-22 ports) and file
//! creation; this module adds the trust decision, restrictive permissions on
//! newly created files, and serialization of concurrent first-time connections.
//!
//! The known_hosts lookup itself ([`lookup_known_host`]) also backs strict
//! (`yes`) mode through [`verify_known_hosts_file`], so both modes agree on
//! which keys verify and which count as changed.

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

/// The outcome of looking a host up in a known_hosts file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownHostLookup {
    /// One of the host's recorded keys is the offered key.
    Match,
    /// The host has recorded keys and none of them is the offered key.
    /// `line` is the entry to report as the offending one.
    Conflict { line: usize },
    /// The host has no recorded keys at all.
    Unknown,
}

/// Look `hostname`/`port` up in `known_hosts_path` using OpenSSH's matching
/// rule: the host is trusted when *any* key recorded for it equals the offered
/// key, and only a host that has recorded keys with none matching counts as
/// changed.
///
/// This replaces `russh::keys::check_known_hosts_path`, which collects its
/// per-line results with `collect::<Result<Vec<bool>, _>>()` and so reports
/// `Err(KeyChanged)` as soon as *any* same-algorithm entry for the host
/// differs, even when another entry holds exactly the offered key. A host that
/// legitimately carries several keys of one algorithm (a stale entry kept
/// beside a rotated one, or a comma-separated cluster line beside a per-node
/// line) would otherwise be rejected with the man-in-the-middle banner where
/// OpenSSH's `check_key_in_hostkeys` accepts. Reading the entries directly also
/// parses the file once instead of twice on the unknown-host path.
fn lookup_known_host(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<KnownHostLookup, russh::keys::Error> {
    let recorded =
        russh::keys::known_hosts::known_host_keys_path(hostname, port, known_hosts_path)?;

    if recorded.iter().any(|(_, key)| key == server_public_key) {
        return Ok(KnownHostLookup::Match);
    }

    // Report the line of an entry with the same key algorithm when there is
    // one, since that is the entry OpenSSH would call the offending key. Fall
    // back to the host's first entry so an algorithm-only conflict (the
    // alternate-algorithm pinning bypass) still points at a real line.
    let offending = recorded
        .iter()
        .find(|(_, key)| key.algorithm() == server_public_key.algorithm())
        .or_else(|| recorded.first());

    Ok(match offending {
        Some(&(line, _)) => KnownHostLookup::Conflict { line },
        None => KnownHostLookup::Unknown,
    })
}

/// Verify a server key in accept-new (TOFU) mode against `known_hosts_path`.
///
/// Returns `Ok(true)` when the key matches any of the host's recorded keys, or
/// when the host has no recorded keys at all (in which case the key is recorded
/// first). Returns [`super::Error::HostKeyChanged`] when the host has recorded
/// keys and none of them matches the offered key, without modifying the file.
pub(super) async fn verify_accept_new(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<bool, super::Error> {
    let _guard = KNOWN_HOSTS_LOCK.lock().await;

    match lookup_known_host(hostname, port, server_public_key, known_hosts_path) {
        Ok(KnownHostLookup::Match) => Ok(true),
        // The host is pinned and the offered key is not one of its recorded
        // keys. That covers both a genuine key change and a key offered under
        // an algorithm the host has not used yet: recording the latter
        // alongside the existing entry would hand an active man-in-the-middle a
        // complete bypass of pinning, because SSH negotiation lets the server
        // steer the choice of host key algorithm and OpenSSH's per-host
        // reordering of that proposal (`order_hostkeyalgs`) is not available
        // through russh.
        Ok(KnownHostLookup::Conflict { line }) => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            known_hosts_path,
            russh::keys::Error::KeyChanged { line },
        )),
        // Genuinely unknown host: trust on first use. A missing known_hosts
        // file also lands here because russh treats an unopenable file as
        // empty; `learn_known_hosts_path` creates it on demand.
        Ok(KnownHostLookup::Unknown) => {
            record_host_key(hostname, port, server_public_key, known_hosts_path);
            Ok(true)
        }
        // Unreadable or malformed known_hosts: fail closed rather than record.
        Err(e) => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            known_hosts_path,
            e,
        )),
    }
}

/// Verify a server key against `known_hosts_path` without recording anything,
/// for strict (`yes`) mode.
///
/// Returns `Ok(false)` for a host with no recorded keys so the caller's own
/// unknown-host rejection applies, `Ok(true)` when one of the host's recorded
/// keys is the offered key, and [`super::Error::HostKeyChanged`] when the host
/// is pinned and none of its keys match. Shares [`lookup_known_host`] with
/// accept-new so both modes agree on what "changed" means.
pub(super) fn verify_known_hosts_file(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<bool, super::Error> {
    match lookup_known_host(hostname, port, server_public_key, known_hosts_path) {
        Ok(KnownHostLookup::Match) => Ok(true),
        Ok(KnownHostLookup::Unknown) => Ok(false),
        Ok(KnownHostLookup::Conflict { line }) => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            known_hosts_path,
            russh::keys::Error::KeyChanged { line },
        )),
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
    async fn test_accept_new_accepts_key_matching_any_recorded_entry() {
        let (_dir, path, path_str) = temp_known_hosts();
        let stale = generate_key();
        let current = generate_key();

        // Two ED25519 entries for one host: a stale key kept beside the rotated
        // one. OpenSSH's `check_key_in_hostkeys` returns HOST_OK as soon as
        // *any* key recorded for the host matches, so both of these keys
        // verify. russh's `check_known_hosts_path` instead collects its
        // per-line results with `collect::<Result<Vec<bool>, _>>()`, so a
        // non-matching same-algorithm entry short-circuits the whole check into
        // `Err(KeyChanged)` no matter which line holds the matching key. That
        // is why the entries are looked up directly here.
        std::fs::write(
            &path,
            format!(
                "node1.example.com {}\nnode1.example.com {}\n",
                stale.public_key().to_openssh().unwrap(),
                current.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let recorded = entry_lines(&path);
        assert_eq!(recorded.len(), 2, "the fixture must hold two entries");

        let result =
            verify_accept_new("node1.example.com", 22, current.public_key(), &path_str).await;
        assert!(
            matches!(result, Ok(true)),
            "a key matching the second entry must be accepted, got {result:?}"
        );
        assert_eq!(
            entry_lines(&path),
            recorded,
            "an already-recorded key must not be appended again"
        );

        // The stale key is still a recorded key for the host, so OpenSSH keeps
        // accepting it until the operator removes that entry.
        let result =
            verify_accept_new("node1.example.com", 22, stale.public_key(), &path_str).await;
        assert!(
            matches!(result, Ok(true)),
            "a key matching the first entry must be accepted, got {result:?}"
        );
        assert_eq!(entry_lines(&path), recorded);
    }

    #[tokio::test]
    async fn test_accept_new_accepts_per_host_key_beside_shared_cluster_entry() {
        let (_dir, path, path_str) = temp_known_hosts();
        let shared = generate_key();
        let own = generate_key();

        // Cluster-style known_hosts: one comma-separated line pins a shared key
        // for every node, and a later line pins node2's own key. OpenSSH
        // matches the host against both lines and accepts either key. The old
        // `check_known_hosts_path` call rejected this layout with the
        // man-in-the-middle banner, and pointed at the shared line rather than
        // at any entry that actually conflicted.
        std::fs::write(
            &path,
            format!(
                "node1,node2,node3 {}\nnode2 {}\n",
                shared.public_key().to_openssh().unwrap(),
                own.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let recorded = entry_lines(&path);

        let result = verify_accept_new("node2", 22, own.public_key(), &path_str).await;
        assert!(
            matches!(result, Ok(true)),
            "node2's own pinned key must be accepted, got {result:?}"
        );
        assert_eq!(
            entry_lines(&path),
            recorded,
            "nothing may be appended for an already-pinned host"
        );
    }

    #[tokio::test]
    async fn test_accept_new_conflict_reports_same_algorithm_line() {
        let (_dir, path, path_str) = temp_known_hosts();
        let stale = generate_key();
        let imposter = generate_key();

        // An RSA entry precedes the stale ED25519 one. OpenSSH names the key of
        // the same type as the offending one, so the banner must point at line
        // 2 rather than at the host's first entry, which is a key the operator
        // would then be told to delete for no reason.
        std::fs::write(
            &path,
            format!(
                "node1.example.com {}\nnode1.example.com {}\n",
                rsa_public_key().to_openssh().unwrap(),
                stale.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let recorded = entry_lines(&path);
        assert_eq!(recorded.len(), 2, "the fixture must hold two entries");

        let result =
            verify_accept_new("node1.example.com", 22, imposter.public_key(), &path_str).await;
        match result {
            Err(Error::HostKeyChanged { host, port, line }) => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 22);
                assert_eq!(
                    line, 2,
                    "the same-algorithm entry must be reported as the offending one"
                );
            }
            other => panic!("expected HostKeyChanged, got {other:?}"),
        }

        assert_eq!(
            entry_lines(&path),
            recorded,
            "a conflicting key must not be recorded"
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
    async fn test_strict_mode_accepts_key_matching_any_recorded_entry() {
        let (_dir, path, path_str) = temp_known_hosts();
        let stale = generate_key();
        let current = generate_key();

        // Strict mode shares the lookup with accept-new, so both modes agree on
        // what "changed" means. A stale ED25519 entry kept beside the rotated
        // one is a layout OpenSSH accepts, and short-circuiting on the
        // non-matching same-algorithm line would reject the connection here just
        // as it did in accept-new.
        std::fs::write(
            &path,
            format!(
                "node1.example.com {}\nnode1.example.com {}\n",
                stale.public_key().to_openssh().unwrap(),
                current.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str));
        let result = handler.check_server_key(current.public_key()).await;
        assert!(
            matches!(result, Ok(true)),
            "strict mode must accept a key matching any recorded entry, got {result:?}"
        );
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
