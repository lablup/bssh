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
    let verdict = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[path],
        None,
        &defaults(),
        &[],
    )
    .unwrap();
    assert_eq!(verdict, CertificateVerdict::Accepted);
}

#[test]
fn unknown_ca_falls_back_to_plain_key_checking() {
    let (ca, other_ca, subject) = (generate_key(), generate_key(), generate_key());
    let cert = build_certificate(&subject, &ca, CertificateShape::default());
    let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &other_ca)]);
    let verdict = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[path],
        None,
        &defaults(),
        &[],
    )
    .unwrap();
    assert_eq!(verdict, CertificateVerdict::NoMatchingAuthority);

    let (_dir, unrelated) = known_hosts_with(&[ca_line("*.other.net", &ca)]);
    let verdict = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[unrelated],
        None,
        &defaults(),
        &[],
    )
    .unwrap();
    assert_eq!(
        verdict,
        CertificateVerdict::NoMatchingAuthority,
        "a CA line for another host pattern must not vouch for this host"
    );
}

#[test]
fn negated_and_hashed_ca_host_patterns_follow_openssh() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(&subject, &ca, CertificateShape::default());

    let (_dir, negated) = known_hosts_with(&[ca_line("*.example.com,!node1.example.com", &ca)]);
    let verdict = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[negated],
        None,
        &defaults(),
        &[],
    )
    .unwrap();
    assert_eq!(
        verdict,
        CertificateVerdict::NoMatchingAuthority,
        "a negated pattern must exclude the host from the CA's scope"
    );

    let hashed = super::super::hostkey_rotation::hash_host_pattern("node1.example.com").unwrap();
    let (_dir, path) = known_hosts_with(&[ca_line(&hashed, &ca).replacen(' ', "\t", 2)]);
    let verdict = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[path],
        None,
        &defaults(),
        &[],
    )
    .unwrap();
    assert_eq!(
        verdict,
        CertificateVerdict::Accepted,
        "a hashed, tab-separated @cert-authority line must vouch for its host"
    );
}

#[test]
fn wildcard_principal_matches_like_openssh() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(
        &subject,
        &ca,
        CertificateShape {
            principal: "*.example.com",
            ..CertificateShape::default()
        },
    );
    let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &ca)]);
    let paths = [path];
    assert_eq!(
        verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &paths,
            None,
            &defaults(),
            &[]
        )
        .unwrap(),
        CertificateVerdict::Accepted
    );
    assert!(matches!(
        verify_host_certificate(
            &cert,
            "node1.example.net",
            22,
            &paths,
            None,
            &defaults(),
            &[]
        ),
        Ok(CertificateVerdict::NoMatchingAuthority)
    ));
    let (_dir, any_host) = known_hosts_with(&[ca_line("*", &ca)]);
    assert!(matches!(
        verify_host_certificate(
            &cert,
            "node1.example.net",
            22,
            &[any_host],
            None,
            &defaults(),
            &[]
        ),
        Err(super::super::Error::ServerCheckFailed)
    ));
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
        let result = verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &paths,
            None,
            &defaults(),
            &[],
        );
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
        None,
        &["rsa-sha2-512".to_string()],
        &[],
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
    let result = verify_host_certificate(
        &cert,
        "node1.example.com",
        22,
        &[path],
        None,
        &defaults(),
        &[],
    );
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
        None,
        &defaults(),
        &[revoked.to_str().unwrap().to_string()],
    );
    assert!(matches!(
        result,
        Err(super::super::Error::HostKeyRevoked { .. })
    ));
}

#[test]
fn ca_lookup_retries_without_port_like_openssh() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(&subject, &ca, CertificateShape::default());
    let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &ca)]);
    assert_eq!(
        verify_host_certificate(
            &cert,
            "node1.example.com",
            2222,
            &[path],
            None,
            &defaults(),
            &[]
        )
        .unwrap(),
        CertificateVerdict::Accepted,
        "a bare-host CA pattern covers a non-default port, as OpenSSH's portless retry does"
    );
    let (_dir, scoped) = known_hosts_with(&[ca_line("[node1.example.com]:2200", &ca)]);
    assert_eq!(
        verify_host_certificate(
            &cert,
            "node1.example.com",
            2222,
            &[scoped],
            None,
            &defaults(),
            &[]
        )
        .unwrap(),
        CertificateVerdict::NoMatchingAuthority,
        "a CA line scoped to another port does not vouch for this one"
    );
}

#[test]
fn principals_match_case_sensitively_like_openssh() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(
        &subject,
        &ca,
        CertificateShape {
            principal: "NODE1.example.com",
            ..CertificateShape::default()
        },
    );
    let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &ca)]);
    assert!(matches!(
        verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &[path],
            None,
            &defaults(),
            &[]
        ),
        Err(super::super::Error::ServerCheckFailed)
    ));
}

/// A forged certificate copies a trusted CA's public key but cannot carry
/// its signature. Its principals are attacker input and must never be
/// pattern-matched before the signature is verified, and the matcher
/// itself must not backtrack exponentially or recurse per `*`.
#[test]
fn forged_certificate_with_pathological_principal_is_rejected_quickly() {
    let (ca, forger, subject) = (generate_key(), generate_key(), generate_key());
    let hostile = format!("{}x", "*".repeat(64));
    let mut builder =
        Builder::new_with_random_nonce(&mut rand::rng(), subject.public_key(), 0, u64::MAX)
            .unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal(hostile.as_str()).unwrap();
    let forged = builder.sign(&forger).unwrap();
    let mut bytes = forged.to_bytes().unwrap();
    let forger_blob = forger.public_key().to_bytes().unwrap();
    let ca_blob = ca.public_key().to_bytes().unwrap();
    let at = bytes
        .windows(forger_blob.len())
        .position(|window| window == forger_blob.as_slice())
        .unwrap();
    bytes[at..at + forger_blob.len()].copy_from_slice(&ca_blob);
    let forged = Certificate::from_bytes(&bytes).unwrap();
    assert_eq!(forged.signature_key(), ca.public_key().key_data());

    let (_dir, path) = known_hosts_with(&[ca_line("*.example.com", &ca)]);
    let started = std::time::Instant::now();
    let result = verify_host_certificate(
        &forged,
        "node1.example.com",
        22,
        &[path],
        None,
        &defaults(),
        &[],
    );
    assert!(matches!(
        result,
        Err(super::super::Error::ServerCheckFailed)
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));

    let started = std::time::Instant::now();
    assert!(!glob_match_case_sensitive("node1.example.com", &hostile));
    let deep = format!("{}x", "*".repeat(200_000));
    assert!(!glob_match_case_sensitive(&"a".repeat(253), &deep));
    assert!(glob_match_case_sensitive("node1.example.com", "*.*.c?m"));
    assert!(!glob_match_case_sensitive("node1.example.com", "*.*.c?"));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn krl_and_unreadable_revocation_files_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let krl = dir.path().join("krl");
    std::fs::write(&krl, b"SSHKRL\n\0\0\0\0\x01").unwrap();
    let key = generate_key();
    let result = ensure_not_revoked_by_file(
        krl.to_str().unwrap(),
        &[key.public_key()],
        "node1.example.com",
        22,
    );
    assert!(matches!(
        result,
        Err(super::super::Error::ServerCheckFailed)
    ));
    let result = ensure_not_revoked_by_file(
        dir.path().join("missing").to_str().unwrap(),
        &[key.public_key()],
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
            &[key.public_key()],
            "node1.example.com",
            22
        )
        .is_ok()
    );
}

#[test]
fn cert_authority_text_core_applies_file_matching_rules() {
    let (ca, other) = (generate_key(), generate_key());
    let ca_key = ca.public_key().clone();
    let find = |port: u16, text: &str| {
        find_cert_authority_in_text("node1.example.com", port, &ca_key, "test", text)
    };
    let hashed = super::super::hostkey_rotation::hash_host_pattern("node1.example.com").unwrap();
    let text = [
        "# comment".to_string(),
        "@cert-authority *.example.com ssh-ed25519 not-base64".to_string(),
        ca_line("*.example.com", &other),
        ca_line("*.example.com,!node1.example.com", &ca),
        ca_line("[node1.example.com]:2200", &ca),
    ]
    .join("\n");
    assert_eq!(
        find(22, &text),
        None,
        "negated, other-key, and other-port lines"
    );
    assert_eq!(find(2200, &text), Some(5));
    assert_eq!(find(22, &ca_line(&hashed, &ca)), Some(1));
    assert_eq!(
        find(2222, &format!("\n{}", ca_line("*.example.com", &ca))),
        Some(2),
        "a bare-host pattern covers a non-default port"
    );
    assert_eq!(
        find(22, &ca_line("*.example.com", &ca).replacen("@", "", 1)),
        None
    );
}

#[test]
fn command_output_vouches_after_the_files_with_the_same_checks() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(&subject, &ca, CertificateShape::default());
    let (_dir, empty) = known_hosts_with(&[]);
    let paths = [empty];
    let output = ca_line("*.example.com", &ca);
    let verify = |cert: &Certificate, output: &str| {
        verify_host_certificate(
            cert,
            "node1.example.com",
            22,
            &paths,
            Some(output),
            &defaults(),
            &[],
        )
    };
    assert_eq!(
        verify(&cert, &output).unwrap(),
        CertificateVerdict::Accepted
    );
    assert_eq!(
        verify(&cert, "").unwrap(),
        CertificateVerdict::NoMatchingAuthority
    );
    assert_eq!(
        verify(&cert, &ca_line("*.example.com,!node1.example.com", &ca)).unwrap(),
        CertificateVerdict::NoMatchingAuthority
    );

    let wrong_principal = build_certificate(
        &subject,
        &ca,
        CertificateShape {
            principal: "other.example.com",
            ..CertificateShape::default()
        },
    );
    assert!(matches!(
        verify(&wrong_principal, &output),
        Err(super::super::Error::ServerCheckFailed)
    ));
    let expired = build_certificate(
        &subject,
        &ca,
        CertificateShape {
            valid_before: 1,
            ..CertificateShape::default()
        },
    );
    assert!(matches!(
        verify(&expired, &output),
        Err(super::super::Error::ServerCheckFailed)
    ));
    assert!(matches!(
        verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            &paths,
            Some(&output),
            &["rsa-sha2-512".to_string()],
            &[],
        ),
        Err(super::super::Error::ServerCheckFailed)
    ));

    for revoked in [&ca, &subject] {
        let text = format!(
            "{output}\n@revoked node1.example.com {}",
            revoked.public_key().to_openssh().unwrap()
        );
        assert!(
            matches!(
                verify(&cert, &text),
                Err(super::super::Error::HostKeyRevoked { line: 2, .. })
            ),
            "a @revoked line in the command output refuses the certificate"
        );
    }
}

#[test]
fn every_revoked_host_keys_file_is_consulted_for_certificates() {
    let (ca, subject) = (generate_key(), generate_key());
    let cert = build_certificate(&subject, &ca, CertificateShape::default());
    let (_dir, path) = known_hosts_with(&[ca_line("node1.example.com", &ca)]);
    let dir = tempfile::tempdir().unwrap();
    let clean = dir.path().join("clean");
    std::fs::write(&clean, "# nothing\n").unwrap();
    let revoking = dir.path().join("revoking");
    std::fs::write(&revoking, ca.public_key().to_openssh().unwrap()).unwrap();
    let clean = clean.to_str().unwrap().to_string();
    let revoking = revoking.to_str().unwrap().to_string();
    let verify = |files: &[String]| {
        verify_host_certificate(
            &cert,
            "node1.example.com",
            22,
            std::slice::from_ref(&path),
            None,
            &defaults(),
            files,
        )
    };
    assert_eq!(
        verify(std::slice::from_ref(&clean)).unwrap(),
        CertificateVerdict::Accepted
    );
    for files in [
        vec![revoking.clone(), clean.clone()],
        vec![clean.clone(), revoking.clone()],
    ] {
        assert!(
            matches!(
                verify(&files),
                Err(super::super::Error::HostKeyRevoked { .. })
            ),
            "{files:?}"
        );
    }
}
