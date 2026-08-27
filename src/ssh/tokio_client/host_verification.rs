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
//! creation; this module adds the trust decision, restrictive permissions
//! created up front rather than tightened after the fact, and serialization
//! of concurrent first-time connections.
//!
//! The known_hosts lookup itself ([`lookup_known_host`]) also backs strict
//! (`yes`) mode through [`verify_known_hosts_file`], so both modes agree on
//! which keys verify and which count as changed. Both entry points also
//! lowercase the hostname once before it is used for either the lookup or the
//! recorded entry, matching OpenSSH's case-insensitive known_hosts matching
//! (russh's own matcher is a plain byte compare), and scan for
//! `@revoked`/`@cert-authority` marker lines before the ordinary lookup runs:
//! russh's parser reads the marker itself as the literal first field of the
//! host list, so a line like `@revoked node1 ssh-ed25519 <key>` never matches
//! `node1` and is otherwise invisible to [`lookup_known_host`].

use crate::diagnosticln as eprintln;

use russh::keys::{Algorithm, HashAlg, PublicKey};
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::LazyLock,
};
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

/// Host keys accepted earlier in this process, keyed by normalized host and
/// port.
///
/// This is a second line of defense for `accept-new`: when no known_hosts path
/// can be determined, this is the only trust state available; when a
/// known_hosts file exists, it catches a conflicting key that another process
/// appended after this run already accepted a different key.
static PROCESS_HOST_PINS: LazyLock<Mutex<HashMap<ProcessPinKey, PublicKey>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static FILE_LOCK_ACQUISITIONS: LazyLock<StdMutex<Vec<String>>> =
    LazyLock::new(|| StdMutex::new(Vec::new()));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessPinKey {
    hostname: String,
    port: u16,
    trust_scope: Option<String>,
}

impl ProcessPinKey {
    fn new(hostname: &str, port: u16, trust_scope: Option<&str>) -> Self {
        Self {
            hostname: hostname.to_string(),
            port,
            trust_scope: trust_scope.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertAuthorityPolicy {
    WarnAndTofu,
    Reject,
}

impl CertAuthorityPolicy {
    fn from_env() -> Self {
        match std::env::var("BSSH_CERT_AUTHORITY_POLICY") {
            Ok(value) if value.eq_ignore_ascii_case("reject") => Self::Reject,
            _ => Self::WarnAndTofu,
        }
    }
}

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

/// Whether the known_hosts path can be read as a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownHostsPathState {
    Missing,
    ReadableFile,
}

fn probe_known_hosts_path(known_hosts_path: &str) -> Result<KnownHostsPathState, super::Error> {
    let path = Path::new(known_hosts_path);
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            tracing::error!(
                "Host key verification failed: {known_hosts_path} is not a regular file"
            );
            eprintln!(
                "Host key verification failed: {known_hosts_path} exists but is not a regular file"
            );
            Err(super::Error::ServerCheckFailed)
        }
        Ok(_) => match File::open(path) {
            Ok(_) => Ok(KnownHostsPathState::ReadableFile),
            Err(e) => {
                tracing::error!(
                    "Host key verification failed: cannot read {known_hosts_path}: {e}"
                );
                eprintln!("Host key verification failed: cannot read {known_hosts_path}: {e}");
                Err(super::Error::ServerCheckFailed)
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if std::fs::symlink_metadata(path).is_ok() {
                tracing::error!(
                    "Host key verification failed: {known_hosts_path} exists but cannot be resolved"
                );
                eprintln!(
                    "Host key verification failed: {known_hosts_path} exists but cannot be resolved"
                );
                Err(super::Error::ServerCheckFailed)
            } else {
                Ok(KnownHostsPathState::Missing)
            }
        }
        Err(e) => {
            tracing::error!("Host key verification failed: cannot inspect {known_hosts_path}: {e}");
            eprintln!("Host key verification failed: cannot inspect {known_hosts_path}: {e}");
            Err(super::Error::ServerCheckFailed)
        }
    }
}

struct KnownHostsFileLock {
    file: File,
}

impl Drop for KnownHostsFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn known_hosts_lock_path(known_hosts_path: &str) -> PathBuf {
    let path = Path::new(known_hosts_path);
    let filename = path
        .file_name()
        .map(|name| format!("{}.lock", name.to_string_lossy()))
        .unwrap_or_else(|| ".known_hosts.lock".to_string());
    match path.parent() {
        Some(parent) => parent.join(filename),
        None => PathBuf::from(filename),
    }
}

fn acquire_known_hosts_file_lock(
    known_hosts_path: &str,
) -> Result<KnownHostsFileLock, super::Error> {
    let lock_path = known_hosts_lock_path(known_hosts_path);
    if let Some(parent) = lock_path.parent()
        && !parent.exists()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(parent)
                && e.kind() != io::ErrorKind::AlreadyExists
            {
                tracing::error!(
                    "Host key verification failed: cannot create lock directory {}: {e}",
                    parent.display()
                );
                eprintln!(
                    "Host key verification failed: cannot create lock directory {}: {e}",
                    parent.display()
                );
                return Err(super::Error::ServerCheckFailed);
            }
        }
        #[cfg(not(unix))]
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!(
                "Host key verification failed: cannot create lock directory {}: {e}",
                parent.display()
            );
            eprintln!(
                "Host key verification failed: cannot create lock directory {}: {e}",
                parent.display()
            );
            return Err(super::Error::ServerCheckFailed);
        }
    } else if let Some(parent) = lock_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::error!(
            "Host key verification failed: cannot create lock directory {}: {e}",
            parent.display()
        );
        eprintln!(
            "Host key verification failed: cannot create lock directory {}: {e}",
            parent.display()
        );
        return Err(super::Error::ServerCheckFailed);
    }

    let existed = lock_path.exists();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            tracing::error!(
                "Host key verification failed: cannot open lock file {}: {e}",
                lock_path.display()
            );
            eprintln!(
                "Host key verification failed: cannot open lock file {}: {e}",
                lock_path.display()
            );
            super::Error::ServerCheckFailed
        })?;

    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("Failed to set mode 0600 on {}: {e}", lock_path.display());
        }
    }

    file.lock().map_err(|e| {
        tracing::error!(
            "Host key verification failed: cannot lock {}: {e}",
            lock_path.display()
        );
        eprintln!(
            "Host key verification failed: cannot lock {}: {e}",
            lock_path.display()
        );
        super::Error::ServerCheckFailed
    })?;
    #[cfg(test)]
    FILE_LOCK_ACQUISITIONS
        .lock()
        .unwrap()
        .push(known_hosts_path.to_string());

    Ok(KnownHostsFileLock { file })
}

async fn verify_process_pin(
    hostname: &str,
    port: u16,
    trust_scope: Option<&str>,
    server_public_key: &PublicKey,
) -> Result<(), super::Error> {
    let pins = PROCESS_HOST_PINS.lock().await;
    match pins.get(&ProcessPinKey::new(hostname, port, trust_scope)) {
        Some(pinned) if pinned != server_public_key => {
            print_process_pin_changed_warning(hostname, port, server_public_key);
            Err(super::Error::HostKeyChanged {
                host: hostname.to_string(),
                port,
                line: 0,
            })
        }
        _ => Ok(()),
    }
}

async fn remember_process_pin(
    hostname: &str,
    port: u16,
    trust_scope: Option<&str>,
    server_public_key: &PublicKey,
) {
    PROCESS_HOST_PINS
        .lock()
        .await
        .entry(ProcessPinKey::new(hostname, port, trust_scope))
        .or_insert_with(|| server_public_key.clone());
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

/// The result of scanning known_hosts for `@revoked`/`@cert-authority`
/// marker lines naming a host, ahead of the ordinary lookup.
///
/// russh's `known_host_keys_path` splits each line on `' '` and takes the
/// *first* field as the host list, so on a marker line such as `@revoked
/// node1 ssh-ed25519 <key>` that first field is the literal string
/// `@revoked`, which never matches `node1`. The line is therefore invisible
/// to [`lookup_known_host`], and without this scan a revoked key would look
/// like an ordinary first use: recorded and accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerScan {
    /// A `@revoked` line names the host and its key field is exactly the
    /// offered key: the caller must hard reject without recording or
    /// accepting anything.
    Revoked { line: usize },
    /// A `@cert-authority` line names the host. bssh has no CA signature
    /// validation path to fall back to, so this does not fail closed; the
    /// caller warns and falls through to ordinary TOFU.
    CertAuthority { line: usize },
    /// No marker line applies to this host.
    None,
}

/// Scan `known_hosts_path` for `@revoked` and `@cert-authority` lines naming
/// `hostname`/`port`. `hostname` must already be normalized (lowercase) by
/// the caller, the same convention [`lookup_known_host`] relies on.
///
/// An unreadable or missing file has nothing to scan and reports
/// [`MarkerScan::None`], the same as [`lookup_known_host`] treats it as an
/// unknown host: `record_host_key` is what actually creates the file.
fn scan_known_hosts_markers(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> MarkerScan {
    let Ok(contents) = std::fs::read_to_string(known_hosts_path) else {
        return MarkerScan::None;
    };

    let host_port = known_hosts_entry_name(hostname, port);
    let mut cert_authority: Option<usize> = None;

    for (idx, raw_line) in contents.lines().enumerate() {
        let line = idx + 1;
        let text = raw_line.trim_start();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }

        let mut fields = text.split(' ').filter(|f| !f.is_empty());
        let Some(marker) = fields.next() else {
            continue;
        };
        let is_revoked = marker == "@revoked";
        if !is_revoked && marker != "@cert-authority" {
            continue;
        }
        // Fields after the marker mirror an ordinary known_hosts line: host
        // list, key type, base64 key. The key type itself is not needed here
        // (`parse_public_key_base64` recovers the algorithm from the key
        // blob), only skipped over to reach the base64 field, the same way
        // russh's own `known_host_keys_path` does for ordinary lines.
        let (Some(host_field), Some(_key_type), Some(key_field)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };

        if !marker_host_matches(&host_port, hostname, host_field, is_revoked) {
            continue;
        }

        if is_revoked {
            if let Ok(key) = russh::keys::parse_public_key_base64(key_field)
                && key == *server_public_key
            {
                return MarkerScan::Revoked { line };
            }
            // A `@revoked` line matching the host but holding a *different*
            // key revokes some other key, not the one being offered now, so
            // it must not block this one; keep scanning the rest of the file.
        } else {
            cert_authority.get_or_insert(line);
        }
    }

    match cert_authority {
        Some(line) => MarkerScan::CertAuthority { line },
        None => MarkerScan::None,
    }
}

/// Whether a marker line's host field names `hostname`/`host_port`.
///
/// Supports the exact form, the comma-separated list form, and simple `*`
/// and `?` globs, since marker lines commonly use them (`@cert-authority
/// *.example.com`). When `lenient` (used for `@revoked` only), a pattern that
/// does not match the port-qualified form is also tried against the bare
/// hostname: a `@revoked` line commonly omits the port, and failing to honor
/// a revocation is worse than an unnecessary rejection.
fn marker_host_matches(
    host_port: &str,
    hostname: &str,
    pattern_field: &str,
    lenient: bool,
) -> bool {
    pattern_field.split(',').any(|pattern| {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return false;
        }
        glob_match(host_port, pattern)
            || (lenient && host_port != hostname && glob_match(hostname, pattern))
    })
}

/// Minimal case-insensitive glob matcher supporting `*` (any sequence,
/// including empty) and `?` (any single character). known_hosts marker
/// patterns use only these two wildcards (no bracket classes), and matching
/// is case-insensitive to agree with the hostname normalization elsewhere in
/// this module.
fn glob_match(text: &str, pattern: &str) -> bool {
    if !pattern.contains(['*', '?']) {
        return text.eq_ignore_ascii_case(pattern);
    }
    let text: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let pattern: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    glob_match_chars(&text, &pattern, 0, 0)
}

/// Recursive helper for [`glob_match`].
fn glob_match_chars(text: &[char], pattern: &[char], ti: usize, pi: usize) -> bool {
    if pi == pattern.len() {
        return ti == text.len();
    }
    match pattern[pi] {
        '*' => {
            glob_match_chars(text, pattern, ti, pi + 1)
                || (ti < text.len() && glob_match_chars(text, pattern, ti + 1, pi))
        }
        '?' => ti < text.len() && glob_match_chars(text, pattern, ti + 1, pi + 1),
        c => ti < text.len() && text[ti] == c && glob_match_chars(text, pattern, ti + 1, pi + 1),
    }
}

/// Act on any `@revoked`/`@cert-authority` marker line naming
/// `hostname`/`port`, ahead of the ordinary lookup. `hostname` must already
/// be normalized (lowercase).
///
/// A `@revoked` match is a hard stop: `Err` with the dedicated
/// [`super::Error::HostKeyRevoked`], printed with a loud warning, and nothing
/// is recorded or accepted. A `@cert-authority` match only warns: bssh has no
/// CA signature validation to fall back to, so failing closed here would
/// break every working CA setup with no workaround, and the point of this
/// check is only to stop the marker being silently ignored, not to implement
/// CA validation. No marker at all is a silent `Ok(())`.
fn check_marker_lines(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<(), super::Error> {
    check_marker_lines_with_policy(
        hostname,
        port,
        server_public_key,
        known_hosts_path,
        CertAuthorityPolicy::from_env(),
    )
}

fn check_marker_lines_with_policy(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
    cert_authority_policy: CertAuthorityPolicy,
) -> Result<(), super::Error> {
    match scan_known_hosts_markers(hostname, port, server_public_key, known_hosts_path) {
        MarkerScan::Revoked { line } => {
            let entry = known_hosts_entry_name(hostname, port);
            tracing::error!(
                "Refusing host key for '{entry}': revoked by {known_hosts_path}:{line}"
            );
            eprintln!(
                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                 @    WARNING: REVOKED HOST KEY!                           @\n\
                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                 The key offered by '{entry}' matches a key explicitly revoked at {known_hosts_path}:{line}.\n\
                 This most likely means the key has been compromised. Connecting is refused.\n\
                 Do not remove the @revoked entry unless you are certain the revocation itself was a mistake."
            );
            Err(super::Error::HostKeyRevoked {
                host: hostname.to_string(),
                port,
                line,
            })
        }
        MarkerScan::CertAuthority { line } => {
            let entry = known_hosts_entry_name(hostname, port);
            match cert_authority_policy {
                CertAuthorityPolicy::WarnAndTofu => {
                    tracing::warn!(
                        "'{entry}' has a @cert-authority entry at {known_hosts_path}:{line}, which bssh does not validate; falling back to trust-on-first-use for the offered key"
                    );
                    eprintln!(
                        "Warning: {known_hosts_path}:{line} marks '{entry}' as a certificate authority (@cert-authority); bssh cannot validate CA-signed host keys, so the offered key is being trusted on first use instead"
                    );
                    Ok(())
                }
                CertAuthorityPolicy::Reject => {
                    tracing::error!(
                        "Refusing host key for '{entry}': @cert-authority at {known_hosts_path}:{line} cannot be validated"
                    );
                    eprintln!(
                        "Host key verification failed: {known_hosts_path}:{line} marks '{entry}' as a certificate authority (@cert-authority), but bssh cannot validate CA-signed host keys"
                    );
                    Err(super::Error::ServerCheckFailed)
                }
            }
        }
        MarkerScan::None => Ok(()),
    }
}

/// Longest hostname accepted in a known_hosts entry. A DNS name cannot exceed
/// 253 characters, so this only bounds the line length against a hostname that
/// could never have resolved anyway.
const MAX_KNOWN_HOSTS_HOSTNAME_LEN: usize = 255;

/// Reject a hostname that cannot be represented as a known_hosts entry.
///
/// `learn_known_hosts_path` writes `{host} <key>` (or `[{host}]:{port} <key>`)
/// with no escaping, and russh's parser splits entries on `' '`, reads `,` as
/// the host-list separator, skips any line whose first byte is `#`, and reads a
/// leading `|1|` as a hashed host field. A hostname carrying any of those, or
/// any whitespace or control character, therefore does not round-trip: it can
/// forge a second entry that pins the offered key for a host the user never
/// named, silently pin one key for a whole list of hosts, or write a line that
/// can never match again, in which case every later connection is a fresh first
/// use that accepts any key and appends yet another entry.
///
/// Nothing validates the hostname on the way here. `validate_hostname` is
/// reached only from `-H/--hosts` and is then overwritten by the unvalidated
/// `~/.ssh/config` `HostName`; `Config::from_backendai_env` only trims the
/// platform-supplied `BACKENDAI_CLUSTER_HOSTS` value; `AuthContext::new`
/// rejects only NUL, LF and CR; and the port-forwarding path in
/// `commands::exec` skips `AuthContext` entirely. So the check belongs at the
/// point of use, where every connection path passes through.
///
/// A hostname that cannot be recorded also cannot be verified on any later
/// connection, so this fails closed rather than connecting unverified.
fn ensure_recordable_hostname(hostname: &str) -> Result<(), super::Error> {
    // `*`, `?` and `!` are OpenSSH known_hosts pattern metacharacters. russh
    // does not implement patterns, but the file is shared with OpenSSH, which
    // would read such an entry as matching hosts it was never meant to.
    const REJECTED: [char; 7] = ['#', ',', '|', '*', '?', '!', '\\'];

    let problem = if hostname.is_empty() {
        Some("it is empty")
    } else if hostname.len() > MAX_KNOWN_HOSTS_HOSTNAME_LEN {
        Some("it is too long")
    } else if hostname
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        Some("it contains whitespace or a control character")
    } else if hostname.contains(REJECTED) {
        Some("it contains a known_hosts metacharacter")
    } else {
        None
    };

    match problem {
        None => Ok(()),
        Some(problem) => {
            tracing::error!(
                "Refusing to verify host key: hostname is not representable in known_hosts because {problem}"
            );
            eprintln!(
                "Host key verification failed: the hostname cannot be recorded in known_hosts because {problem}"
            );
            Err(super::Error::ServerCheckFailed)
        }
    }
}

/// Verify a server key in accept-new (TOFU) mode against `known_hosts_path`.
///
/// Returns `Ok(true)` when the key matches any of the host's recorded keys, or
/// when the host has no recorded keys at all (in which case the key is recorded
/// first). Returns [`super::Error::HostKeyChanged`] when the host has recorded
/// keys and none of them matches the offered key, without modifying the file,
/// and [`super::Error::HostKeyRevoked`] when the offered key matches a
/// known_hosts `@revoked` marker line. A hostname that cannot be represented
/// in a known_hosts entry is rejected outright, before anything is looked up
/// or written.
pub(super) async fn verify_accept_new(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<bool, super::Error> {
    // OpenSSH lowercases the hostname before every known_hosts comparison;
    // russh's `match_hostname` is a plain byte compare. Normalizing once here
    // and using the normalized value for both the lookup and the recorded
    // entry keeps a later differently-cased connection hitting the same pin
    // instead of bypassing it and re-recording, and matches what OpenSSH
    // itself would have written to the file.
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();

    // Checked before the lock is taken: serializing a hostname that is already
    // rejected would only make every other connection wait on it.
    ensure_recordable_hostname(hostname)?;

    probe_known_hosts_path(known_hosts_path)?;
    check_marker_lines(hostname, port, server_public_key, known_hosts_path)?;
    match lookup_known_host(hostname, port, server_public_key, known_hosts_path) {
        Ok(KnownHostLookup::Match) => {
            verify_process_pin(hostname, port, Some(known_hosts_path), server_public_key).await?;
            return Ok(true);
        }
        Ok(KnownHostLookup::Conflict { line }) => {
            return Err(map_known_hosts_error(
                hostname,
                port,
                server_public_key,
                known_hosts_path,
                russh::keys::Error::KeyChanged { line },
            ));
        }
        Ok(KnownHostLookup::Unknown) => {}
        Err(e) => {
            return Err(map_known_hosts_error(
                hostname,
                port,
                server_public_key,
                known_hosts_path,
                e,
            ));
        }
    }

    let _guard = KNOWN_HOSTS_LOCK.lock().await;
    let _file_lock = acquire_known_hosts_file_lock(known_hosts_path)?;

    probe_known_hosts_path(known_hosts_path)?;
    check_marker_lines(hostname, port, server_public_key, known_hosts_path)?;

    match lookup_known_host(hostname, port, server_public_key, known_hosts_path) {
        Ok(KnownHostLookup::Match) => {
            verify_process_pin(hostname, port, Some(known_hosts_path), server_public_key).await?;
            Ok(true)
        }
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
            verify_process_pin(hostname, port, Some(known_hosts_path), server_public_key).await?;
            record_host_key(hostname, port, server_public_key, known_hosts_path);
            remember_process_pin(hostname, port, Some(known_hosts_path), server_public_key).await;
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

/// Verify a server key in accept-new mode when no persistent known_hosts path
/// can be determined.
///
/// The first key seen for a normalized host:port is accepted and kept in
/// memory for the lifetime of this bssh process. A different key later in the
/// same run is rejected, so the default mode no longer degrades to
/// unconditional `NoCheck` in service/container environments without a home
/// directory.
pub(super) async fn verify_accept_new_in_memory(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
) -> Result<bool, super::Error> {
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();
    ensure_recordable_hostname(hostname)?;

    let _guard = KNOWN_HOSTS_LOCK.lock().await;
    verify_process_pin(hostname, port, None, server_public_key).await?;
    remember_process_pin(hostname, port, None, server_public_key).await;
    Ok(true)
}

/// Verify a server key against `known_hosts_path` without recording anything,
/// for strict (`yes`) mode.
///
/// Returns `Ok(false)` for a host with no recorded keys so the caller's own
/// unknown-host rejection applies, `Ok(true)` when one of the host's recorded
/// keys is the offered key, [`super::Error::HostKeyChanged`] when the host is
/// pinned and none of its keys match, and [`super::Error::HostKeyRevoked`]
/// when the offered key matches a known_hosts `@revoked` marker line. Shares
/// [`lookup_known_host`] with accept-new so both modes agree on what
/// "changed" means, and the hostname is normalized (lowercase) the same way
/// so both modes hit the same pin regardless of spelling. A hostname that
/// cannot be represented in a known_hosts entry is rejected outright: strict
/// mode never records, but such a hostname could not match a well-formed entry
/// either, so this only replaces a misleading "unknown host" with the real
/// reason.
pub(super) fn verify_known_hosts_file(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &str,
) -> Result<bool, super::Error> {
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();

    ensure_recordable_hostname(hostname)?;
    probe_known_hosts_path(known_hosts_path)?;
    check_marker_lines(hostname, port, server_public_key, known_hosts_path)?;

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum KnownHostsFilesLookup {
    Match,
    Conflict { path: String, line: usize },
    Unknown,
}

fn lookup_known_host_files(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_paths: &[String],
) -> Result<KnownHostsFilesLookup, super::Error> {
    for path in known_hosts_paths {
        probe_known_hosts_path(path)?;
        check_marker_lines(hostname, port, server_public_key, path)?;
    }

    let mut conflict = None;
    for path in known_hosts_paths {
        match lookup_known_host(hostname, port, server_public_key, path) {
            Ok(KnownHostLookup::Match) => return Ok(KnownHostsFilesLookup::Match),
            Ok(KnownHostLookup::Conflict { line }) => {
                conflict.get_or_insert_with(|| KnownHostsFilesLookup::Conflict {
                    path: path.clone(),
                    line,
                });
            }
            Ok(KnownHostLookup::Unknown) => {}
            Err(error) => {
                return Err(map_known_hosts_error(
                    hostname,
                    port,
                    server_public_key,
                    path,
                    error,
                ));
            }
        }
    }

    Ok(conflict.unwrap_or(KnownHostsFilesLookup::Unknown))
}

/// Verify a server key against every configured user/global known-hosts file.
pub(super) fn verify_known_hosts_files(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_paths: &[String],
) -> Result<bool, super::Error> {
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();
    ensure_recordable_hostname(hostname)?;

    match lookup_known_host_files(hostname, port, server_public_key, known_hosts_paths)? {
        KnownHostsFilesLookup::Match => Ok(true),
        KnownHostsFilesLookup::Unknown => Ok(false),
        KnownHostsFilesLookup::Conflict { path, line } => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            &path,
            russh::keys::Error::KeyChanged { line },
        )),
    }
}

/// Apply accept-new semantics across every configured read store and record a
/// genuinely unknown key only into the explicitly selected user write store.
pub(super) async fn verify_accept_new_files(
    hostname: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_paths: &[String],
    write_path: Option<&str>,
) -> Result<bool, super::Error> {
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();
    ensure_recordable_hostname(hostname)?;
    let trust_scope = (!known_hosts_paths.is_empty()).then(|| known_hosts_paths.join("\0"));

    match lookup_known_host_files(hostname, port, server_public_key, known_hosts_paths)? {
        KnownHostsFilesLookup::Match => {
            verify_process_pin(hostname, port, trust_scope.as_deref(), server_public_key).await?;
            return Ok(true);
        }
        KnownHostsFilesLookup::Conflict { path, line } => {
            return Err(map_known_hosts_error(
                hostname,
                port,
                server_public_key,
                &path,
                russh::keys::Error::KeyChanged { line },
            ));
        }
        KnownHostsFilesLookup::Unknown => {}
    }

    let _guard = KNOWN_HOSTS_LOCK.lock().await;
    let _file_lock = match write_path {
        Some(path) => Some(acquire_known_hosts_file_lock(path)?),
        None => None,
    };

    match lookup_known_host_files(hostname, port, server_public_key, known_hosts_paths)? {
        KnownHostsFilesLookup::Match => {
            verify_process_pin(hostname, port, trust_scope.as_deref(), server_public_key).await?;
            Ok(true)
        }
        KnownHostsFilesLookup::Conflict { path, line } => Err(map_known_hosts_error(
            hostname,
            port,
            server_public_key,
            &path,
            russh::keys::Error::KeyChanged { line },
        )),
        KnownHostsFilesLookup::Unknown => {
            verify_process_pin(hostname, port, trust_scope.as_deref(), server_public_key).await?;
            if let Some(path) = write_path {
                record_host_key(hostname, port, server_public_key, path);
            }
            remember_process_pin(hostname, port, trust_scope.as_deref(), server_public_key).await;
            Ok(true)
        }
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

    // Create with the final restrictive mode up front, before
    // `learn_known_hosts_path` gets a chance to create either one with the
    // process umask. See `precreate_with_restrictive_permissions` for why
    // this closes the window that `restrict_created_permissions` below can
    // only narrow after the fact.
    #[cfg(unix)]
    precreate_with_restrictive_permissions(path, dir_preexisted, file_preexisted);

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

    if !file_preexisted {
        remove_leading_blank_line(path);
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

fn remove_leading_blank_line(path: &Path) {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.starts_with('\n') => {
            if let Err(e) = std::fs::write(path, contents.trim_start_matches('\n')) {
                tracing::warn!(
                    "Failed to remove leading blank line from {}: {e}",
                    path.display()
                );
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "Failed to inspect {} for leading blank line cleanup: {e}",
                path.display()
            );
        }
    }
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

/// Pre-create the `.ssh` directory (0700) and known_hosts file (0600) with
/// their final permissions before `learn_known_hosts_path` touches either.
///
/// `learn_known_hosts_path` creates both with `std::fs::create_dir_all` and
/// `OpenOptions::create(true)`, which apply the process umask, and the mode
/// used to be tightened by [`restrict_created_permissions`] only *after*
/// that call returned, leaving a window where a permissive umask could leave
/// either one group- or world-writable. A `mkdir`/`open` syscall that
/// requests 0o700/0o600 directly cannot be widened by any umask, because
/// umask only ever clears requested bits and neither mode carries a group or
/// other bit for a standard umask to clear, so creating with the final mode
/// up front closes the window instead of narrowing it afterward.
///
/// Only whichever of the two does not already exist is touched, matching
/// [`restrict_created_permissions`]'s preservation of pre-existing modes. An
/// error other than "already exists" (a benign race with another creator,
/// since this runs under `KNOWN_HOSTS_LOCK` only within this process) is
/// logged and otherwise ignored: `learn_known_hosts_path` runs regardless,
/// and its own error handling in [`record_host_key`] is what decides whether
/// the connection fails.
#[cfg(unix)]
fn precreate_with_restrictive_permissions(
    path: &Path,
    dir_preexisted: bool,
    file_preexisted: bool,
) {
    use std::fs::{DirBuilder, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if !dir_preexisted
        && let Some(parent) = path.parent()
        && let Err(e) = DirBuilder::new().mode(0o700).create(parent)
        && e.kind() != ErrorKind::AlreadyExists
    {
        tracing::warn!(
            "Failed to pre-create {} with mode 0700: {e}",
            parent.display()
        );
    }

    if !file_preexisted
        && let Err(e) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        && e.kind() != ErrorKind::AlreadyExists
    {
        tracing::warn!(
            "Failed to pre-create {} with mode 0600: {e}",
            path.display()
        );
    }
}

/// Tighten permissions on the `.ssh` directory (0700) and known_hosts file
/// (0600), but only when this recording created them.
/// `learn_known_hosts_path` creates both with the process umask, so a fresh
/// directory could otherwise be group/world readable. Kept as a fallback for
/// the rare case where [`precreate_with_restrictive_permissions`] could not
/// pre-create one of them (for example a missing grandparent directory that
/// only `learn_known_hosts_path`'s `create_dir_all` fills in).
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

fn print_process_pin_changed_warning(hostname: &str, port: u16, server_public_key: &PublicKey) {
    let algo = algorithm_display_name(server_public_key);
    let fingerprint = server_public_key.fingerprint(HashAlg::Sha256);
    let entry_name = known_hosts_entry_name(hostname, port);
    eprintln!(
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
         The key offered by '{entry_name}' differs from a host key already accepted earlier in this bssh process.\n\
         The fingerprint for the {algo} key sent by the remote host is\n\
         {fingerprint}.\n\
         Connecting is refused because this may indicate a mid-run man-in-the-middle attack or a conflicting known_hosts update from another process."
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

    /// Wrap a plain host key the way russh 0.63 hands it to
    /// `Handler::check_server_key`, which now takes a `PublicKeyOrCertificate`.
    fn host_key(key: &PublicKey) -> russh::keys::PublicKeyOrCertificate {
        russh::keys::PublicKeyOrCertificate::from(key.clone())
    }

    /// Build the OpenSSH *host certificate* form of `check_server_key`'s
    /// argument: `subject`'s public key signed by `ca`.
    ///
    /// bssh never advertises certificate host key algorithms, so russh cannot
    /// negotiate one in practice; these tests pin the fail-closed behavior for
    /// the case where a peer sends one anyway.
    fn host_certificate(
        subject: &PrivateKey,
        ca: &PrivateKey,
    ) -> russh::keys::PublicKeyOrCertificate {
        let mut builder = russh::keys::ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            u64::MAX,
        )
        .expect("certificate builder should accept a valid validity window");
        builder.key_id("bssh-test").unwrap();
        builder
            .cert_type(russh::keys::ssh_key::certificate::CertType::Host)
            .unwrap();
        builder.valid_principal("node1.example.com").unwrap();
        russh::keys::PublicKeyOrCertificate::Certificate(
            builder.sign(ca).expect("signing with an ED25519 CA works"),
        )
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
    async fn test_accept_new_fresh_file_does_not_start_with_blank_line() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            !contents.starts_with('\n'),
            "fresh known_hosts must not start with a blank line, got {contents:?}"
        );
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
    async fn test_accept_new_known_match_avoids_file_lock() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();
        std::fs::write(
            &path,
            format!(
                "node1.example.com {}\n",
                key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        FILE_LOCK_ACQUISITIONS.lock().unwrap().clear();
        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        let acquisitions = FILE_LOCK_ACQUISITIONS.lock().unwrap();
        assert!(
            !acquisitions.iter().any(|path| path == &path_str),
            "a definite known-host match must return before acquiring the file lock"
        );
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

    // `@revoked` / `@cert-authority` marker lines.

    #[tokio::test]
    async fn test_accept_new_rejects_revoked_key() {
        let (_dir, path, path_str) = temp_known_hosts();
        let revoked = generate_key();

        std::fs::write(
            &path,
            format!(
                "@revoked node1.example.com {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        // russh's own parser reads "@revoked" as the literal host list, so
        // without marker handling this offered key would look like an
        // ordinary first use and get recorded and accepted.
        let result =
            verify_accept_new("node1.example.com", 22, revoked.public_key(), &path_str).await;
        match result {
            Err(Error::HostKeyRevoked { host, port, line }) => {
                assert_eq!(host, "node1.example.com");
                assert_eq!(port, 22);
                assert_eq!(line, 1);
            }
            other => panic!("expected HostKeyRevoked, got {other:?}"),
        }
        assert_eq!(
            entry_lines(&path).len(),
            1,
            "the revoked key must not be recorded"
        );
    }

    #[tokio::test]
    async fn test_accept_new_revoked_entry_for_different_key_does_not_block() {
        let (_dir, path, path_str) = temp_known_hosts();
        let revoked = generate_key();
        let genuine = generate_key();

        std::fs::write(
            &path,
            format!(
                "@revoked node1.example.com {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        // A `@revoked` line matching the host but holding a *different* key
        // revokes that other key, not the one offered now, so it must not
        // block this connection: as far as ordinary TOFU is concerned this
        // host is still unknown and the genuine key is recorded normally.
        let result =
            verify_accept_new("node1.example.com", 22, genuine.public_key(), &path_str).await;
        assert!(
            matches!(result, Ok(true)),
            "a key that is not the revoked one must not be blocked, got {result:?}"
        );
        assert_eq!(
            entry_lines(&path).len(),
            2,
            "the genuine key must be recorded alongside the @revoked marker"
        );
    }

    #[tokio::test]
    async fn test_accept_new_cert_authority_warns_and_falls_through_to_tofu() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        std::fs::write(
            &path,
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n",
        )
        .unwrap();

        // bssh has no CA signature validation path, so the marker must not
        // fail closed: the offered key still goes through ordinary TOFU and
        // is recorded like any other unknown host.
        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(
            matches!(result, Ok(true)),
            "a @cert-authority marker must not block TOFU, got {result:?}"
        );
        assert_eq!(
            entry_lines(&path).len(),
            2,
            "the offered key must still be recorded alongside the @cert-authority line"
        );
    }

    #[tokio::test]
    async fn test_cert_authority_policy_can_reject() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        std::fs::write(
            &path,
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n",
        )
        .unwrap();

        let result = check_marker_lines_with_policy(
            "node1.example.com",
            22,
            key.public_key(),
            &path_str,
            CertAuthorityPolicy::Reject,
        );
        assert!(
            matches!(result, Err(Error::ServerCheckFailed)),
            "reject policy must fail closed for unsupported @cert-authority lines, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_accept_new_revoked_marker_matches_comma_list_and_glob() {
        let revoked = generate_key();

        let (_dir, path, path_str) = temp_known_hosts();
        std::fs::write(
            &path,
            format!(
                "@revoked node2,node1.example.com,node3 {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let result =
            verify_accept_new("node1.example.com", 22, revoked.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyRevoked { .. })),
            "the comma-list form must match, got {result:?}"
        );

        let (_dir2, path2, path2_str) = temp_known_hosts();
        std::fs::write(
            &path2,
            format!(
                "@revoked *.example.com {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let result =
            verify_accept_new("node1.example.com", 22, revoked.public_key(), &path2_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyRevoked { .. })),
            "the glob form must match, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_accept_new_revoked_marker_matches_non_standard_port_entry_form() {
        let (_dir, path, path_str) = temp_known_hosts();
        let revoked = generate_key();
        std::fs::write(
            &path,
            format!(
                "@revoked [node1.example.com]:2222 {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let result =
            verify_accept_new("node1.example.com", 2222, revoked.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyRevoked { .. })),
            "the [host]:port marker form must match, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_accept_new_revoked_marker_without_port_still_matches_non_standard_port() {
        // `@revoked` errs toward matching: a marker line commonly omits the
        // port, and failing to honor a revocation is worse than an
        // unnecessary rejection.
        let (_dir, path, path_str) = temp_known_hosts();
        let revoked = generate_key();
        std::fs::write(
            &path,
            format!(
                "@revoked node1.example.com {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let result =
            verify_accept_new("node1.example.com", 2222, revoked.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyRevoked { .. })),
            "a port-less @revoked pattern must still match a non-standard port connection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_strict_mode_rejects_revoked_key() {
        let (_dir, path, path_str) = temp_known_hosts();
        let revoked = generate_key();
        std::fs::write(
            &path,
            format!(
                "@revoked node1.example.com {}\n",
                revoked.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str));
        let result = handler
            .check_server_key(&host_key(revoked.public_key()))
            .await;
        assert!(
            matches!(result, Err(Error::HostKeyRevoked { .. })),
            "strict mode must also honor @revoked, got {result:?}"
        );
    }

    // Hostname case normalization.

    #[tokio::test]
    async fn test_accept_new_hostname_matching_is_case_insensitive() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        let result = verify_accept_new("NODE1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        let recorded = entry_lines(&path);
        assert_eq!(recorded.len(), 1);
        assert!(
            recorded[0].starts_with("node1.example.com "),
            "the recorded entry must use the normalized (lowercase) hostname, got: {}",
            recorded[0]
        );

        // A differently-cased spelling of the same host must hit the same
        // pin instead of looking unknown and recording a second entry.
        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(
            entry_lines(&path),
            recorded,
            "differently-cased hostnames must resolve to the same pin"
        );

        // A changed key offered under yet another casing must still be
        // caught as a conflict, not treated as a fresh first use.
        let imposter = generate_key();
        let result =
            verify_accept_new("Node1.Example.Com", 22, imposter.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyChanged { .. })),
            "a changed key under a different casing must still be caught, got {result:?}"
        );
        assert_eq!(entry_lines(&path), recorded);
    }

    #[tokio::test]
    async fn test_strict_mode_hostname_matching_is_case_insensitive() {
        let (_dir, _path, path_str) = temp_known_hosts();
        let key = generate_key();

        russh::keys::known_hosts::learn_known_hosts_path(
            "node1.example.com",
            22,
            key.public_key(),
            &path_str,
        )
        .unwrap();

        let mut handler = ClientHandler::new(
            "NODE1.example.com".to_string(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFile(path_str),
        );
        let result = handler.check_server_key(&host_key(key.public_key())).await;
        assert!(
            matches!(result, Ok(true)),
            "strict mode must match an existing pin regardless of hostname casing, got {result:?}"
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
    async fn test_accept_new_process_pin_detects_external_conflicting_append() {
        let (_dir, path, path_str) = temp_known_hosts();
        let original = generate_key();
        let imposter = generate_key();

        let result =
            verify_accept_new("node1.example.com", 22, original.public_key(), &path_str).await;
        assert!(matches!(result, Ok(true)));

        std::fs::write(
            &path,
            format!(
                "{}\nnode1.example.com {}\n",
                entry_lines(&path).join("\n"),
                imposter.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        let result =
            verify_accept_new("node1.example.com", 22, imposter.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::HostKeyChanged { line: 0, .. })),
            "a key appended by another process must not override this process's existing pin, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_accept_new_in_memory_rejects_changed_key_in_same_run() {
        let original = generate_key();
        let imposter = generate_key();

        let result =
            verify_accept_new_in_memory("memory-only.example.com", 22, original.public_key()).await;
        assert!(matches!(result, Ok(true)));

        let result =
            verify_accept_new_in_memory("memory-only.example.com", 22, imposter.public_key()).await;
        assert!(
            matches!(result, Err(Error::HostKeyChanged { line: 0, .. })),
            "process-only accept-new must reject a changed key in the same run, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_accept_new_rejects_existing_directory_known_hosts_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::create_dir(&path).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        let key = generate_key();

        let result = verify_accept_new("node1.example.com", 22, key.public_key(), &path_str).await;
        assert!(
            matches!(result, Err(Error::ServerCheckFailed)),
            "an existing non-file known_hosts path must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_strict_mode_rejects_existing_directory_known_hosts_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::create_dir(&path).unwrap();
        let path_str = path.to_str().unwrap().to_string();
        let key = generate_key();

        let result = verify_known_hosts_file("node1.example.com", 22, key.public_key(), &path_str);
        assert!(
            matches!(result, Err(Error::ServerCheckFailed)),
            "strict mode must fail closed for an existing non-file known_hosts path, got {result:?}"
        );
    }

    #[test]
    fn test_known_hosts_file_lock_blocks_independent_handles() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_dir, _path, path_str) = temp_known_hosts();
        let first = acquire_known_hosts_file_lock(&path_str).expect("lock must be acquired");
        let (tx, rx) = mpsc::channel();
        let path_for_thread = path_str.clone();

        let handle = std::thread::spawn(move || {
            let _second = acquire_known_hosts_file_lock(&path_for_thread)
                .expect("second lock must eventually be acquired");
            tx.send(()).unwrap();
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "the second independent file handle must wait while the first lock is held"
        );
        drop(first);
        rx.recv_timeout(Duration::from_secs(2))
            .expect("the second lock must acquire after the first is released");
        handle.join().unwrap();
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
        let result = handler.check_server_key(&host_key(key.public_key())).await;
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
        let result = handler
            .check_server_key(&host_key(imposter.public_key()))
            .await;
        assert!(
            matches!(result, Err(Error::HostKeyChanged { .. })),
            "strict mode must report a changed key specifically, got {result:?}"
        );

        // The original key still verifies.
        let mut handler = handler_for(ServerCheckMethod::KnownHostsFile(path_str));
        let result = handler
            .check_server_key(&host_key(original.public_key()))
            .await;
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
        let result = handler
            .check_server_key(&host_key(current.public_key()))
            .await;
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
        let result = handler.check_server_key(&host_key(key.public_key())).await;
        assert!(matches!(result, Ok(true)));
        assert!(!path.exists(), "NoCheck must not create a known_hosts file");
    }

    #[tokio::test]
    async fn test_accept_new_through_client_handler() {
        // The handler arm must reach the TOFU path end to end.
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();

        let mut handler = handler_for(ServerCheckMethod::AcceptNewKnownHostsFile(path_str));
        let result = handler.check_server_key(&host_key(key.public_key())).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(entry_lines(&path).len(), 1);
    }

    // Hostnames that cannot be written back out as a known_hosts entry.

    #[tokio::test]
    async fn test_accept_new_rejects_hostnames_that_cannot_be_recorded() {
        let key = generate_key();
        let over_long = "a".repeat(300);

        // `learn_known_hosts_path` writes the hostname into the entry with no
        // escaping at all, and russh's parser splits on ' ', treats ',' as the
        // host-list separator, skips any line starting with '#', and reads a
        // leading '|1|' as a hashed host. None of these hostnames survives that
        // round trip, so recording one is worse than refusing to connect.
        let unrecordable = [
            // The dangerous one: the embedded newline ends the forged entry and
            // starts a second line, so the server gets its own key pinned for
            // `[node1]:2200`, a host the user never named. Every later
            // connection to node1 then trusts the attacker's key or is refused
            // as a changed key.
            "victim]:2200 ssh-ed25519 AAAA\n[node1",
            // A space makes russh read `plaintext` as the key field, which then
            // fails to parse, so the host stays permanently unconnectable with
            // only a generic "Server check failed".
            "evil.example.com plaintext",
            "evil.example.com\tplaintext",
            // russh skips a line whose first byte is '#', so the entry can
            // never match again: every connection is a fresh first use that
            // accepts whatever key is offered and appends yet another entry,
            // growing the file without bound.
            "#node1.example.com",
            // A comma writes a host list, silently pinning one server's key for
            // every name in it.
            "node1,node2",
            // A leading '|' is how russh spells a hashed host field.
            "node1|node2",
            // OpenSSH reads this as a pattern and would match hosts the entry
            // was never meant to cover.
            "*.example.com",
            "",
            over_long.as_str(),
        ];

        for hostname in unrecordable {
            let (_dir, path, path_str) = temp_known_hosts();
            let result = verify_accept_new(hostname, 2200, key.public_key(), &path_str).await;
            assert!(
                matches!(result, Err(Error::ServerCheckFailed)),
                "hostname {hostname:?} must be refused, got {result:?}"
            );
            assert!(
                !path.exists(),
                "hostname {hostname:?} must not cause anything to be written"
            );
        }
    }

    #[tokio::test]
    async fn test_accept_new_still_records_normal_and_ipv6_hostnames() {
        let key = generate_key();

        // Regression guard for the rejection set above: IPv6 literals, zone
        // identifiers, the bracketed form and ordinary DNS names all have to
        // keep working, so the character set may not grow past what actually
        // breaks the known_hosts round trip.
        for hostname in [
            "node1.example.com",
            "host-1.sub.example.com",
            "10.0.0.1",
            "::1",
            "fe80::1%eth0",
            "[::1]",
        ] {
            let (_dir, path, path_str) = temp_known_hosts();
            let result = verify_accept_new(hostname, 22, key.public_key(), &path_str).await;
            assert!(
                matches!(result, Ok(true)),
                "hostname {hostname:?} must still be accepted, got {result:?}"
            );
            assert_eq!(
                entry_lines(&path).len(),
                1,
                "hostname {hostname:?} must record exactly one entry"
            );
        }
    }

    #[tokio::test]
    async fn test_strict_mode_rejects_hostname_that_cannot_be_recorded() {
        // Strict mode never records, so it cannot be poisoned, but it shares
        // the guard so both modes fail for the same stated reason instead of
        // reporting a misleading "not in known_hosts" for a hostname that
        // could never have matched a well-formed entry anyway.
        let (_dir, _path, path_str) = temp_known_hosts();
        let key = generate_key();

        // `handler_for` hardcodes a valid hostname, so build the handler here.
        let mut handler = ClientHandler::new(
            "evil.example.com plaintext".to_string(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFile(path_str),
        );
        let result = handler.check_server_key(&host_key(key.public_key())).await;
        assert!(
            matches!(result, Err(Error::ServerCheckFailed)),
            "strict mode must refuse an unrecordable hostname, got {result:?}"
        );
    }

    // Host certificates (russh 0.63 widened `check_server_key`).

    /// A host certificate carries a key signed by a CA. bssh verifies no CA
    /// signatures, so every verifying mode must refuse it rather than fall
    /// back to matching the key inside it against known_hosts.
    #[tokio::test]
    async fn test_host_certificate_is_rejected_by_verifying_modes() {
        let ca = generate_key();
        let subject = generate_key();
        let cert = host_certificate(&subject, &ca);

        let (_dir, path, path_str) = temp_known_hosts();
        // Pin the key *inside* the certificate, so a naive implementation that
        // unwrapped the certificate would wrongly accept.
        std::fs::write(
            &path,
            format!(
                "node1.example.com {}\n",
                subject.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        for check in [
            ServerCheckMethod::KnownHostsFile(path_str.clone()),
            ServerCheckMethod::KnownHostsFiles(vec![path_str.clone()]),
            ServerCheckMethod::AcceptNewKnownHostsFile(path_str.clone()),
            ServerCheckMethod::AcceptNewKnownHostsFiles {
                files: vec![path_str.clone()],
                write_path: Some(path_str),
            },
            ServerCheckMethod::HostKeyAlias {
                alias: "alias.example.com".into(),
                method: Box::new(ServerCheckMethod::KnownHostsFiles(Vec::new())),
            },
            ServerCheckMethod::AcceptNewInMemory,
            ServerCheckMethod::PublicKey(
                subject.public_key().to_openssh().unwrap()[..]
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string(),
            ),
        ] {
            let mut handler = handler_for(check.clone());
            let result = handler.check_server_key(&cert).await;
            assert!(
                matches!(result, Err(Error::ServerCheckFailed)),
                "{check:?} must refuse an unverifiable host certificate, got {result:?}"
            );
        }
    }

    /// `NoCheck` means the user turned host verification off entirely, so it
    /// stays permissive for certificates too.
    #[tokio::test]
    async fn test_host_certificate_is_accepted_under_no_check() {
        let ca = generate_key();
        let subject = generate_key();
        let cert = host_certificate(&subject, &ca);

        let mut handler = handler_for(ServerCheckMethod::NoCheck);
        let result = handler.check_server_key(&cert).await;
        assert!(
            matches!(result, Ok(true)),
            "NoCheck disables verification for certificates too, got {result:?}"
        );
    }

    /// The certificate rejection must not have been reachable by accident:
    /// bssh never advertises certificate host key algorithms, so russh cannot
    /// negotiate one.
    #[test]
    fn test_bssh_never_advertises_host_key_certificates() {
        assert!(
            russh::Preferred::DEFAULT.host_key_certificates.is_empty(),
            "bssh's Preferred overrides inherit this field from DEFAULT; a \
             non-empty default would silently opt bssh into host certificates"
        );
        assert!(
            crate::ssh::tokio_client::Config::default()
                .preferred
                .host_key_certificates
                .is_empty(),
            "the client config must not advertise certificate host key algorithms"
        );
    }

    #[tokio::test]
    async fn test_host_key_alias_changes_lookup_identity_at_non_default_port() {
        let (_alias_dir, _alias_path, alias_store) = temp_known_hosts();
        let (_target_dir, _target_path, target_store) = temp_known_hosts();
        let key = generate_key();
        record_host_key(
            "trust-alias.example.com",
            22,
            key.public_key(),
            &alias_store,
        );
        record_host_key(
            "connection-target.example.com",
            4242,
            key.public_key(),
            &target_store,
        );

        let mut alias_handler = ClientHandler::new(
            "connection-target.example.com".into(),
            "127.0.0.1:4242".parse().unwrap(),
            ServerCheckMethod::HostKeyAlias {
                alias: "trust-alias.example.com".into(),
                method: Box::new(ServerCheckMethod::KnownHostsFiles(vec![
                    alias_store.clone(),
                ])),
            },
        );
        assert!(matches!(
            alias_handler
                .check_server_key(&host_key(key.public_key()))
                .await,
            Ok(true)
        ));

        let mut target_against_alias_store = ClientHandler::new(
            "connection-target.example.com".into(),
            "127.0.0.1:4242".parse().unwrap(),
            ServerCheckMethod::KnownHostsFiles(vec![alias_store]),
        );
        assert!(matches!(
            target_against_alias_store
                .check_server_key(&host_key(key.public_key()))
                .await,
            Ok(false)
        ));

        let mut target_handler = ClientHandler::new(
            "connection-target.example.com".into(),
            "127.0.0.1:4242".parse().unwrap(),
            ServerCheckMethod::KnownHostsFiles(vec![target_store.clone()]),
        );
        assert!(matches!(
            target_handler
                .check_server_key(&host_key(key.public_key()))
                .await,
            Ok(true)
        ));

        let mut alias_against_target_store = ClientHandler::new(
            "connection-target.example.com".into(),
            "127.0.0.1:4242".parse().unwrap(),
            ServerCheckMethod::HostKeyAlias {
                alias: "trust-alias.example.com".into(),
                method: Box::new(ServerCheckMethod::KnownHostsFiles(vec![target_store])),
            },
        );
        assert!(matches!(
            alias_against_target_store
                .check_server_key(&host_key(key.public_key()))
                .await,
            Ok(false)
        ));
    }

    #[tokio::test]
    async fn test_host_key_alias_accept_new_records_unbracketed_alias() {
        let (_dir, path, path_str) = temp_known_hosts();
        let key = generate_key();
        let mut handler = ClientHandler::new(
            "connection-target.example.com".into(),
            "127.0.0.1:4242".parse().unwrap(),
            ServerCheckMethod::HostKeyAlias {
                alias: "record-alias.example.com".into(),
                method: Box::new(ServerCheckMethod::AcceptNewKnownHostsFiles {
                    files: vec![path_str.clone()],
                    write_path: Some(path_str),
                }),
            },
        );

        assert!(matches!(
            handler.check_server_key(&host_key(key.public_key())).await,
            Ok(true)
        ));
        let lines = entry_lines(&path);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("record-alias.example.com "),
            "HostKeyAlias must be recorded verbatim without port brackets: {}",
            lines[0]
        );
        assert!(!lines[0].contains("connection-target.example.com"));
        assert!(!lines[0].starts_with("[record-alias.example.com]:4242 "));
    }

    #[tokio::test]
    async fn test_known_hosts_files_distinguishes_matching_and_empty_user_store() {
        let (_matching_dir, _matching_path, matching) = temp_known_hosts();
        let (_empty_dir, _empty_path, empty) = temp_known_hosts();
        let expected = generate_key();
        record_host_key("explicit.example.com", 22, expected.public_key(), &matching);

        let mut matching_handler = ClientHandler::new(
            "explicit.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFiles(vec![matching]),
        );
        assert!(matches!(
            matching_handler
                .check_server_key(&host_key(expected.public_key()))
                .await,
            Ok(true)
        ));

        let mut empty_handler = ClientHandler::new(
            "explicit.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFiles(vec![empty]),
        );
        assert!(matches!(
            empty_handler
                .check_server_key(&host_key(expected.public_key()))
                .await,
            Ok(false)
        ));
    }

    #[tokio::test]
    async fn test_known_hosts_files_accepts_match_after_earlier_conflict() {
        let (_first_dir, _first_path, first) = temp_known_hosts();
        let (_second_dir, _second_path, second) = temp_known_hosts();
        let expected = generate_key();
        let conflicting = generate_key();
        record_host_key("multi.example.com", 22, conflicting.public_key(), &first);
        record_host_key("multi.example.com", 22, expected.public_key(), &second);

        let mut handler = ClientHandler::new(
            "multi.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::KnownHostsFiles(vec![first, second]),
        );
        assert!(matches!(
            handler
                .check_server_key(&host_key(expected.public_key()))
                .await,
            Ok(true)
        ));
    }

    #[tokio::test]
    async fn test_known_hosts_files_with_no_stores_fails_closed_as_unknown() {
        let key = generate_key();
        let mut handler = handler_for(ServerCheckMethod::KnownHostsFiles(Vec::new()));
        assert!(matches!(
            handler.check_server_key(&host_key(key.public_key())).await,
            Ok(false)
        ));
    }

    #[tokio::test]
    async fn test_accept_new_files_records_only_explicit_user_write_path() {
        let (_user_dir, user_path, user) = temp_known_hosts();
        let (_global_dir, global_path, global) = temp_known_hosts();
        let (_second_user_dir, second_user_path, second_user) = temp_known_hosts();
        let key = generate_key();
        let mut handler = handler_for(ServerCheckMethod::AcceptNewKnownHostsFiles {
            files: vec![user.clone(), second_user, global],
            write_path: Some(user),
        });

        assert!(matches!(
            handler.check_server_key(&host_key(key.public_key())).await,
            Ok(true)
        ));
        assert_eq!(entry_lines(&user_path).len(), 1);
        assert!(
            !second_user_path.exists(),
            "only the first user store may receive a learned key"
        );
        assert!(!global_path.exists(), "global store must remain read-only");
    }

    #[tokio::test]
    async fn test_accept_new_files_uses_global_match_without_writing_user_file() {
        let (_user_dir, user_path, user) = temp_known_hosts();
        let (_global_dir, _global_path, global) = temp_known_hosts();
        let key = generate_key();
        record_host_key("global-match.example.com", 22, key.public_key(), &global);
        let mut handler = ClientHandler::new(
            "global-match.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            ServerCheckMethod::AcceptNewKnownHostsFiles {
                files: vec![user.clone(), global],
                write_path: Some(user),
            },
        );

        assert!(matches!(
            handler.check_server_key(&host_key(key.public_key())).await,
            Ok(true)
        ));
        assert!(
            !user_path.exists(),
            "a later matching read store must prevent first-use recording"
        );
    }

    #[tokio::test]
    async fn test_accept_new_files_without_write_path_keeps_process_pin() {
        let original = generate_key();
        let changed = generate_key();
        let method = ServerCheckMethod::AcceptNewKnownHostsFiles {
            files: Vec::new(),
            write_path: None,
        };
        let mut first = ClientHandler::new(
            "memory-only-multifile.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            method.clone(),
        );
        assert!(matches!(
            first
                .check_server_key(&host_key(original.public_key()))
                .await,
            Ok(true)
        ));

        let mut second = ClientHandler::new(
            "memory-only-multifile.example.com".into(),
            "127.0.0.1:22".parse().unwrap(),
            method,
        );
        assert!(matches!(
            second
                .check_server_key(&host_key(changed.public_key()))
                .await,
            Err(Error::HostKeyChanged { .. })
        ));
    }
}
