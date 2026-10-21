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
//! - a `@cert-authority` known_hosts line naming the host carries the key
//!   that signed the certificate;
//! - neither that CA key nor the certified key is revoked by a `@revoked`
//!   line or by the `RevokedHostKeys` file;
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

use super::host_verification::{known_hosts_entry_name, marker_host_matches, revoked_marker_line};

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

/// Validate `certificate` for `hostname`/`port` against the configured
/// known_hosts files and revocation sources.
pub(super) fn verify_host_certificate(
    certificate: &Certificate,
    hostname: &str,
    port: u16,
    known_hosts_paths: &[String],
    ca_signature_algorithms: &[String],
    revoked_host_keys: Option<&str>,
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
        if let Some(path) = revoked_host_keys {
            ensure_not_revoked_by_file(path, key, &hostname, port)?;
        }
    }

    let Some((path, line)) = find_cert_authority(&hostname, port, &ca_key, known_hosts_paths)?
    else {
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
    if certificate.valid_principals().is_empty() {
        return Err(reject(&hostname, "Certificate lacks principal list"));
    }
    if !certificate
        .valid_principals()
        .iter()
        .any(|principal| principal.eq_ignore_ascii_case(&hostname))
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
    let ca_fingerprint = ca_key.fingerprint(HashAlg::Sha256);
    if let Err(error) = certificate.validate_at(now, [&ca_fingerprint]) {
        return Err(reject(
            &hostname,
            &format!("Certificate invalid: signature verification failed ({error})"),
        ));
    }
    Ok(CertificateVerdict::Accepted)
}

/// Find the first `@cert-authority` line naming `hostname`/`port` whose key
/// is `ca_key`. Returns the path and line for diagnostics.
fn find_cert_authority(
    hostname: &str,
    port: u16,
    ca_key: &PublicKey,
    known_hosts_paths: &[String],
) -> Result<Option<(String, usize)>, super::Error> {
    let host_port = known_hosts_entry_name(hostname, port);
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
        for (index, raw_line) in contents.lines().enumerate() {
            let mut fields = raw_line.split(' ').filter(|field| !field.is_empty());
            if fields.next() != Some("@cert-authority") {
                continue;
            }
            let (Some(host_field), Some(_key_type), Some(key_field)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if !marker_host_matches(&host_port, hostname, host_field, false) {
                continue;
            }
            match russh::keys::parse_public_key_base64(key_field) {
                Ok(key) if key.key_data() == ca_key.key_data() => {
                    return Ok(Some((path.clone(), index + 1)));
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        "Ignoring unparsable @cert-authority key at {path}:{}: {error}",
                        index + 1
                    );
                }
            }
        }
    }
    Ok(None)
}

/// Reject `key` if the `RevokedHostKeys` file at `path` lists it.
///
/// Only the plain-text key list format is supported. A binary KRL cannot be
/// evaluated by bssh, so a KRL file fails closed: every host key is refused
/// until the file is replaced with a key list. An unreadable file also fails
/// closed, since the revocation policy cannot be applied.
pub(super) fn ensure_not_revoked_by_file(
    path: &str,
    key: &PublicKey,
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
            && revoked.key_data() == key.key_data()
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

fn reject_revoked(hostname: &str, port: u16, path: &str, line: usize) -> super::Error {
    let entry = known_hosts_entry_name(hostname, port);
    tracing::error!("Refusing host key for '{entry}': revoked by {path}:{line}");
    crate::diagnosticln!(
        "Host key for '{entry}' is revoked by {path}:{line}; connecting is refused"
    );
    super::Error::HostKeyRevoked {
        host: hostname.to_string(),
        port,
        line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::certificate::Builder;

    fn generate_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap()
    }

    struct CertificateShape {
        cert_type: CertType,
        principal: &'static str,
        valid_before: u64,
        critical_option: Option<(&'static str, &'static str)>,
    }

    impl Default for CertificateShape {
        fn default() -> Self {
            Self {
                cert_type: CertType::Host,
                principal: "node1.example.com",
                valid_before: u64::MAX,
                critical_option: None,
            }
        }
    }

    fn build_certificate(
        subject: &PrivateKey,
        ca: &PrivateKey,
        shape: CertificateShape,
    ) -> Certificate {
        let mut builder = Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            0,
            shape.valid_before,
        )
        .unwrap();
        builder.key_id("bssh-test").unwrap();
        builder.cert_type(shape.cert_type).unwrap();
        builder.valid_principal(shape.principal).unwrap();
        if let Some((name, value)) = shape.critical_option {
            builder.critical_option(name, value).unwrap();
        }
        builder.sign(ca).unwrap()
    }

    fn known_hosts_with(lines: &[String]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let path = path.to_str().unwrap().to_string();
        (dir, path)
    }

    fn ca_line(pattern: &str, ca: &PrivateKey) -> String {
        format!(
            "@cert-authority {pattern} {}",
            ca.public_key().to_openssh().unwrap()
        )
    }

    fn defaults() -> Vec<String> {
        super::super::algorithms::resolve_ca_signature_algorithms(&[]).unwrap()
    }

    #[test]
    fn trusted_ca_with_matching_principal_is_accepted() {
        let (ca, subject) = (generate_key(), generate_key());
        let cert = build_certificate(&subject, &ca, CertificateShape::default());
        let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &ca)]);
        let verdict =
            verify_host_certificate(&cert, "node1.example.com", 22, &[path], &defaults(), None)
                .unwrap();
        assert_eq!(verdict, CertificateVerdict::Accepted);
    }

    #[test]
    fn unknown_ca_falls_back_to_plain_key_checking() {
        let (ca, other_ca, subject) = (generate_key(), generate_key(), generate_key());
        let cert = build_certificate(&subject, &ca, CertificateShape::default());
        let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &other_ca)]);
        let verdict =
            verify_host_certificate(&cert, "node1.example.com", 22, &[path], &defaults(), None)
                .unwrap();
        assert_eq!(verdict, CertificateVerdict::NoMatchingAuthority);

        let (_dir, unrelated) = known_hosts_with(&[ca_line("*.other.net", &ca)]);
        let verdict = verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &[unrelated],
            &defaults(),
            None,
        )
        .unwrap();
        assert_eq!(
            verdict,
            CertificateVerdict::NoMatchingAuthority,
            "a CA line for another host pattern must not vouch for this host"
        );
    }

    #[test]
    fn trusted_ca_with_invalid_certificate_is_rejected() {
        let (ca, subject) = (generate_key(), generate_key());
        let (_dir, path) = known_hosts_with(&[ca_line("node1.example.com", &ca)]);
        let paths = [path];
        let cases: Vec<(&str, Certificate)> = vec![
            (
                "wrong principal",
                build_certificate(
                    &subject,
                    &ca,
                    CertificateShape {
                        principal: "other.example.com",
                        ..CertificateShape::default()
                    },
                ),
            ),
            (
                "user certificate",
                build_certificate(
                    &subject,
                    &ca,
                    CertificateShape {
                        cert_type: CertType::User,
                        ..CertificateShape::default()
                    },
                ),
            ),
            (
                "critical option",
                build_certificate(
                    &subject,
                    &ca,
                    CertificateShape {
                        critical_option: Some(("force-command", "true")),
                        ..CertificateShape::default()
                    },
                ),
            ),
            (
                "expired",
                build_certificate(
                    &subject,
                    &ca,
                    CertificateShape {
                        valid_before: 1,
                        ..CertificateShape::default()
                    },
                ),
            ),
        ];
        for (case, cert) in cases {
            let result =
                verify_host_certificate(&cert, "node1.example.com", 22, &paths, &defaults(), None);
            assert!(
                matches!(result, Err(super::super::Error::ServerCheckFailed)),
                "{case}: a trusted CA must not accept an invalid certificate, got {result:?}"
            );
        }
    }

    #[test]
    fn ca_signature_algorithm_policy_is_enforced() {
        let (ca, subject) = (generate_key(), generate_key());
        let cert = build_certificate(&subject, &ca, CertificateShape::default());
        let (_dir, path) = known_hosts_with(&[ca_line("node1.example.com", &ca)]);
        let result = verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &[path],
            &["rsa-sha2-512".to_string()],
            None,
        );
        assert!(
            matches!(result, Err(super::super::Error::ServerCheckFailed)),
            "an Ed25519 CA signature must be refused when CASignatureAlgorithms excludes it"
        );
    }

    #[test]
    fn revoked_ca_or_certified_key_is_refused_before_trust() {
        let (ca, subject) = (generate_key(), generate_key());
        let cert = build_certificate(&subject, &ca, CertificateShape::default());
        let (_dir, path) = known_hosts_with(&[
            ca_line("node1.example.com", &ca),
            format!(
                "@revoked node1.example.com {}",
                ca.public_key().to_openssh().unwrap()
            ),
        ]);
        let result =
            verify_host_certificate(&cert, "node1.example.com", 22, &[path], &defaults(), None);
        assert!(matches!(
            result,
            Err(super::super::Error::HostKeyRevoked { .. })
        ));

        let dir = tempfile::tempdir().unwrap();
        let revoked = dir.path().join("revoked");
        std::fs::write(&revoked, subject.public_key().to_openssh().unwrap()).unwrap();
        let (_dir2, path) = known_hosts_with(&[ca_line("node1.example.com", &ca)]);
        let result = verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &[path],
            &defaults(),
            Some(revoked.to_str().unwrap()),
        );
        assert!(matches!(
            result,
            Err(super::super::Error::HostKeyRevoked { .. })
        ));
    }

    #[test]
    fn krl_and_unreadable_revocation_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let krl = dir.path().join("krl");
        std::fs::write(&krl, b"SSHKRL\n\0\0\0\0\x01").unwrap();
        let key = generate_key();
        let result = ensure_not_revoked_by_file(
            krl.to_str().unwrap(),
            key.public_key(),
            "node1.example.com",
            22,
        );
        assert!(matches!(
            result,
            Err(super::super::Error::ServerCheckFailed)
        ));
        let result = ensure_not_revoked_by_file(
            dir.path().join("missing").to_str().unwrap(),
            key.public_key(),
            "node1.example.com",
            22,
        );
        assert!(matches!(
            result,
            Err(super::super::Error::ServerCheckFailed)
        ));
        let list = dir.path().join("list");
        std::fs::write(&list, "# comment\n\n").unwrap();
        assert!(
            ensure_not_revoked_by_file(
                list.to_str().unwrap(),
                key.public_key(),
                "node1.example.com",
                22
            )
            .is_ok()
        );
    }
}
