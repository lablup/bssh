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

//! OpenSSH host certificate validation.
//!
//! A server may prove its identity with a `*-cert-v01@openssh.com`
//! certificate instead of a bare key. The certificate is accepted only when
//! every check OpenSSH's `check_host_cert` performs passes:
//!
//! - a `@cert-authority` line naming the host, in a known_hosts file or in
//!   the `KnownHostsCommand` output, carries the key that signed the
//!   certificate;
//! - neither that CA key nor the certified key is revoked by a `@revoked`
//!   line in either source or by any of the `RevokedHostKeys` files;
//! - the certificate is a host certificate whose principals include the host
//!   name (or `HostKeyAlias`), it carries no critical options, and it is
//!   inside its validity window;
//! - the CA signed it with an algorithm permitted by `CASignatureAlgorithms`,
//!   and the signature verifies.
//!
//! When no `@cert-authority` line matches the CA, the certified key is
//! checked as a plain host key, exactly as OpenSSH downgrades the
//! certificate ("No matching CA found. Retry with plain key"). A certificate
//! whose CA is trusted but that fails any other check is rejected outright;
//! bssh does not downgrade such a certificate to its plain key.

use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::PublicKey;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, HashAlg};

use super::host_verification::{
    command_host_field_matches, glob_match_case_sensitive, known_hosts_entry_name,
    revoked_marker_line, revoked_marker_line_in_text,
};

/// Outcome of validating a presented host certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CertificateVerdict {
    /// A trusted CA signed the certificate and every check passed.
    Accepted,
    /// No `@cert-authority` line names this host with the signing key; the
    /// caller continues with the certified key as a plain host key.
    NoMatchingAuthority,
}

/// Magic prefix of an OpenSSH key revocation list (KRL) file.
const KRL_MAGIC: &[u8] = b"SSHKRL\n\0";

/// Source label for `KnownHostsCommand` output in log messages, where a
/// file source is named by its path.
pub(super) const KNOWN_HOSTS_COMMAND_SOURCE: &str = "KnownHostsCommand";

/// Validate `certificate` for `hostname`/`port` against the configured
/// known_hosts files, the `KnownHostsCommand` output (consulted after the
/// files, as OpenSSH loads it into the same host-key set), and the
/// `RevokedHostKeys` files.
pub(super) fn verify_host_certificate(
    certificate: &Certificate,
    hostname: &str,
    port: u16,
    known_hosts_paths: &[String],
    command_output: Option<&str>,
    ca_signature_algorithms: &[String],
    revoked_host_keys: &[String],
) -> Result<CertificateVerdict, super::Error> {
    let hostname = hostname.to_ascii_lowercase();
    let ca_key = PublicKey::new(certificate.signature_key().clone(), "");
    let certified_key = PublicKey::new(certificate.public_key().clone(), "");

    // Revocation is checked before trust: a revoked CA or certified key is a
    // hard stop even when no CA line would have matched.
    for key in [&ca_key, &certified_key] {
        for path in known_hosts_paths {
            if let Some(line) = revoked_marker_line(&hostname, port, key, path) {
                return Err(reject_revoked(&hostname, port, path, line));
            }
        }
        if let Some(output) = command_output
            && let Some(line) = revoked_marker_line_in_text(&hostname, port, key, output)
        {
            return Err(reject_revoked(
                &hostname,
                port,
                KNOWN_HOSTS_COMMAND_SOURCE,
                line,
            ));
        }
    }
    for path in revoked_host_keys {
        ensure_not_revoked_by_file(path, &[&ca_key, &certified_key], &hostname, port)?;
    }

    let authority = match find_cert_authority(&hostname, port, &ca_key, known_hosts_paths)? {
        Some(found) => Some(found),
        None => command_output.and_then(|output| {
            find_cert_authority_in_text(
                &hostname,
                port,
                &ca_key,
                KNOWN_HOSTS_COMMAND_SOURCE,
                output,
            )
            .map(|line| (KNOWN_HOSTS_COMMAND_SOURCE.to_string(), line))
        }),
    };
    let Some((path, line)) = authority else {
        return Ok(CertificateVerdict::NoMatchingAuthority);
    };
    tracing::debug!(
        "Host '{hostname}' certificate CA matches @cert-authority at {path}:{line}; validating certificate '{}'",
        certificate.key_id()
    );

    if certificate.cert_type() != CertType::Host {
        return Err(reject(
            &hostname,
            "Certificate invalid: not a host certificate",
        ));
    }
    let signature_algorithm = certificate.signature().algorithm().to_string();
    if !ca_signature_algorithms.contains(&signature_algorithm) {
        return Err(reject(
            &hostname,
            &format!(
                "Certificate signature algorithm {signature_algorithm} is not permitted by CASignatureAlgorithms"
            ),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    if now < certificate.valid_after() {
        return Err(reject(&hostname, "Certificate invalid: not yet valid"));
    }
    if now >= certificate.valid_before() {
        return Err(reject(&hostname, "Certificate invalid: expired"));
    }
    // The signature is verified before any principal is read. Until then the
    // certificate is whatever the peer sent: anyone can copy a trusted CA's
    // public key into it, so its principals are untrusted input.
    let ca_fingerprint = ca_key.fingerprint(HashAlg::Sha256);
    if let Err(error) = certificate.validate_at(now, [&ca_fingerprint]) {
        return Err(reject(
            &hostname,
            &format!("Certificate invalid: signature verification failed ({error})"),
        ));
    }
    if certificate.valid_principals().is_empty() {
        return Err(reject(&hostname, "Certificate lacks principal list"));
    }
    // OpenSSH 10.3 `sshkey_cert_check_host` matches host principals as
    // case-sensitive patterns (`match_pattern`), not only as literal names.
    if !certificate
        .valid_principals()
        .iter()
        .any(|principal| glob_match_case_sensitive(&hostname, principal))
    {
        return Err(reject(
            &hostname,
            "Certificate invalid: name is not a listed principal",
        ));
    }
    if !certificate.critical_options().is_empty() {
        return Err(reject(
            &hostname,
            "Certificate contains unsupported critical options(s)",
        ));
    }
    Ok(CertificateVerdict::Accepted)
}

/// Find the first `@cert-authority` line naming `hostname`/`port` whose key
/// is `ca_key` in the known_hosts files. Returns the path and line for
/// diagnostics. A missing file is skipped; an unreadable one fails closed.
fn find_cert_authority(
    hostname: &str,
    port: u16,
    ca_key: &PublicKey,
    known_hosts_paths: &[String],
) -> Result<Option<(String, usize)>, super::Error> {
    for path in known_hosts_paths {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::error!(
                    "Cannot read known_hosts file {path} for @cert-authority lookup: {error}"
                );
                return Err(super::Error::ServerCheckFailed);
            }
        };
        if let Some(line) = find_cert_authority_in_text(hostname, port, ca_key, path, &contents) {
            return Ok(Some((path.clone(), line)));
        }
    }
    Ok(None)
}

/// Line number of the first `@cert-authority` line in `contents` naming
/// `hostname`/`port` whose key is `ca_key`. `source` names the text in log
/// messages: a file path, or [`KNOWN_HOSTS_COMMAND_SOURCE`].
///
/// On a non-default port OpenSSH looks the CA up as `[host]:port` and, when
/// nothing matches, retries with the bare host name ("checking without port
/// identifier"), so a `*.example.com` CA line also covers port 2222. A line
/// matching either form is accepted here, which gives the same result: a CA
/// line naming a different key never matches in either lookup.
fn find_cert_authority_in_text(
    hostname: &str,
    port: u16,
    ca_key: &PublicKey,
    source: &str,
    contents: &str,
) -> Option<usize> {
    let host_port = known_hosts_entry_name(hostname, port);
    let names_host = |host_field: &str| {
        command_host_field_matches(host_field, &host_port)
            || (port != 22 && command_host_field_matches(host_field, hostname))
    };
    for (index, raw_line) in contents.lines().enumerate() {
        let mut fields = raw_line.split_whitespace();
        if fields.next() != Some("@cert-authority") {
            continue;
        }
        let (Some(host_field), Some(_key_type), Some(key_field)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // Negated (`!host`) patterns exclude a host from the CA's scope, and
        // hashed (`|1|`) fields are matched by HMAC, as in OpenSSH.
        if !names_host(host_field) {
            continue;
        }
        match russh::keys::parse_public_key_base64(key_field) {
            Ok(key) if key.key_data() == ca_key.key_data() => return Some(index + 1),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    "Ignoring unparsable @cert-authority key at {source}:{}: {error}",
                    index + 1
                );
            }
        }
    }
    None
}

/// Reject any of `keys` that the `RevokedHostKeys` file at `path` lists.
/// The file is read once for all keys.
///
/// Only the plain-text key list format is supported. A binary KRL cannot be
/// evaluated by bssh, so a KRL file fails closed: every host key is refused
/// until the file is replaced with a key list. An unreadable file also fails
/// closed, since the revocation policy cannot be applied.
pub(super) fn ensure_not_revoked_by_file(
    path: &str,
    keys: &[&PublicKey],
    hostname: &str,
    port: u16,
) -> Result<(), super::Error> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(error) => {
            tracing::error!("Cannot read RevokedHostKeys file {path}: {error}; refusing host key");
            return Err(super::Error::ServerCheckFailed);
        }
    };
    if contents.starts_with(KRL_MAGIC) {
        tracing::error!(
            "RevokedHostKeys file {path} is a binary KRL, which bssh cannot evaluate; refusing host key"
        );
        return Err(super::Error::ServerCheckFailed);
    }
    let text = String::from_utf8_lossy(&contents);
    for (index, raw_line) in text.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let key_field = if fields.len() >= 2 {
            fields[1]
        } else {
            fields[0]
        };
        if let Ok(revoked) = russh::keys::parse_public_key_base64(key_field)
            && keys.iter().any(|key| revoked.key_data() == key.key_data())
        {
            return Err(reject_revoked(hostname, port, path, index + 1));
        }
    }
    Ok(())
}

fn reject(hostname: &str, reason: &str) -> super::Error {
    tracing::error!("Refusing host certificate for '{hostname}': {reason}");
    crate::diagnosticln!("{reason}");
    super::Error::ServerCheckFailed
}

/// `source` is the file path or [`KNOWN_HOSTS_COMMAND_SOURCE`].
fn reject_revoked(hostname: &str, port: u16, source: &str, line: usize) -> super::Error {
    let entry = known_hosts_entry_name(hostname, port);
    tracing::error!("Refusing host key for '{entry}': revoked by {source}:{line}");
    crate::diagnosticln!(
        "Host key for '{entry}' is revoked by {source}:{line}; connecting is refused"
    );
    super::Error::HostKeyRevoked {
        host: hostname.to_string(),
        port,
        line,
    }
}

#[cfg(test)]
#[path = "host_certificate_tests.rs"]
mod tests;
