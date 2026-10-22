// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ssh::security_key::{SecurityKeyError, SkSignRequest, SkSignResponse};
use std::fs;
use tempfile::tempdir;

struct MockProvider;
impl SecurityKeyProvider for MockProvider {
    fn sign(
        &self,
        _: &SkSignRequest<'_>,
        _: Option<&str>,
    ) -> std::result::Result<SkSignResponse, SecurityKeyError> {
        Err(SecurityKeyError::Unsupported)
    }
    fn enroll(
        &self,
        request: &SkEnrollRequest<'_>,
        pin: Option<&str>,
    ) -> std::result::Result<SkEnrollResponse, SecurityKeyError> {
        if pin != Some("1234") {
            return Err(SecurityKeyError::PinRequired);
        }
        assert_eq!(request.challenge, b"challenge");
        assert_eq!(request.user, Some("alice"));
        assert_eq!(request.device, Some("device"));
        Ok(response(request.algorithm, request.flags))
    }
    fn describe(&self) -> String {
        "mock".into()
    }
}

fn response(algorithm: SkAlgorithm, flags: u8) -> SkEnrollResponse {
    let public_key = match algorithm {
        SkAlgorithm::Ed25519 => ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
        SkAlgorithm::EcdsaSha2NistP256 => {
            // P-256 generator, uncompressed SEC1 point.
            let hex = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        }
    };
    SkEnrollResponse {
        flags,
        public_key,
        key_handle: Zeroizing::new(vec![7; 64]),
    }
}

fn resident(application: &str, user: &[u8]) -> SkResidentKey {
    SkResidentKey {
        algorithm: SkAlgorithm::Ed25519,
        application: application.into(),
        key: response(
            SkAlgorithm::Ed25519,
            SK_FLAG_USER_PRESENCE_REQUIRED | SK_FLAG_RESIDENT_KEY,
        ),
        user_id: user.into(),
    }
}

#[test]
fn enrollment_roundtrips_both_algorithms_and_openssh_reads_them() {
    let directory = tempdir().unwrap();
    let options = EnrollmentOptions::parse(&[
        "user=alice".into(),
        "device=device".into(),
        "application=ssh:test".into(),
        "resident".into(),
        "verify-required".into(),
    ])
    .unwrap();
    for algorithm in [SkAlgorithm::Ed25519, SkAlgorithm::EcdsaSha2NistP256] {
        let path = directory
            .path()
            .join(format!("key{}", algorithm.api_code()));
        let request = options.request(algorithm, b"challenge");
        let error = generate(&MockProvider, &request, None, &path, None, false).unwrap_err();
        assert_eq!(
            error.downcast_ref::<SecurityKeyError>(),
            Some(&SecurityKeyError::PinRequired)
        );
        assert!(!path.exists());
        let saved = generate(
            &MockProvider,
            &request,
            Some("1234"),
            &path,
            Some("alice"),
            false,
        )
        .unwrap();
        let key = PrivateKey::from_openssh(fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            key.public_key().to_openssh().unwrap(),
            saved.public_key_openssh
        );
        match key.key_data() {
            private::KeypairData::SkEd25519(key) => {
                assert_eq!(key.public().application(), "ssh:test");
                assert_eq!(key.flags(), options.flags);
                assert_eq!(key.key_handle(), &[7; 64]);
            }
            private::KeypairData::SkEcdsaSha2NistP256(key) => {
                assert_eq!(key.public().application(), "ssh:test");
                assert_eq!(key.flags(), options.flags);
                assert_eq!(key.key_handle(), &[7; 64]);
            }
            _ => panic!("wrong key type"),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Keep tests portable if OpenSSH is not installed; errors from an
        // installed binary are mandatory failures.
        match std::process::Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(&path)
            .output()
        {
            Ok(output) => {
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let parsed =
                    ssh_key::PublicKey::from_openssh(std::str::from_utf8(&output.stdout).unwrap())
                        .unwrap();
                assert_eq!(parsed.key_data(), key.public_key().key_data());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("Cannot invoke ssh-keygen: {error}"),
        }
    }
}

#[test]
fn resident_names_match_openssh_and_cannot_escape_directory() {
    for (application, user, expected) in [
        ("ssh:", &b""[..], "id_ed25519_sk_rk"),
        ("ssh:work", &b"alice\0\0"[..], "id_ed25519_sk_rk_work_alice"),
        ("ssh://work", &b""[..], "id_ed25519_sk_rk_work"),
        ("ssh:", &b"alice"[..], "id_ed25519_sk_rk__alice"),
        ("ssh:work", &b"../x"[..], "id_ed25519_sk_rk_work_2e2e2f78"),
    ] {
        assert_eq!(resident_filename(&resident(application, user)), expected);
    }
    for app in ["ssh:../../escape", "ssh:/tmp/key", "ssh:bad\nname"] {
        let name = resident_filename(&resident(app, b"user\\..\xff"));
        assert_eq!(Path::new(&name).components().count(), 1);
        assert!(!name.contains(".."));
        assert!(!name.contains('\n'));
    }
    let directory = tempdir().unwrap();
    let key = resident("ssh:work", b"alice");
    let saved = save_resident(key.clone(), directory.path(), false).unwrap();
    assert!(saved.public_key_openssh.ends_with("ssh:work"));
    assert!(save_resident(key.clone(), directory.path(), false).is_err());
    save_resident(key, directory.path(), true).unwrap();
}

#[test]
fn options_and_challenge_are_validated_before_device_access() {
    for option in [
        "application=web:site",
        "application=ssh:x\0",
        "unknown",
        "write-attestation=file",
        "resident=yes",
        "user=",
        "challenge=",
    ] {
        assert!(
            EnrollmentOptions::parse(&[option.into()]).is_err(),
            "{option}"
        );
    }
    assert!(EnrollmentOptions::parse(&["resident".into(), "resident".into()]).is_err());
    let options =
        EnrollmentOptions::parse(&["no-touch-required".into(), "verify-required".into()]).unwrap();
    assert_eq!(options.flags, SK_FLAG_USER_VERIFICATION_REQUIRED);
    assert_eq!(options.challenge_bytes().unwrap().len(), 32);
    let dir = tempdir().unwrap();
    let path = dir.path().join("challenge");
    let options = EnrollmentOptions {
        challenge: Some(path.clone()),
        ..Default::default()
    };
    for bytes in [vec![], vec![0; 1024 * 1024 + 1]] {
        fs::write(&path, bytes).unwrap();
        assert!(options.challenge_bytes().is_err());
    }
    fs::write(path, b"custom challenge").unwrap();
    assert_eq!(&**options.challenge_bytes().unwrap(), b"custom challenge");
}

#[test]
fn rejects_malformed_handle_and_public_key_without_creating_files() {
    let dir = tempdir().unwrap();
    for size in [0, 256] {
        let mut key = resident("ssh:", b"");
        key.key.key_handle = Zeroizing::new(vec![7; size]);
        assert!(save_resident(key, dir.path(), false).is_err());
    }
    let mut key = resident("ssh:", b"");
    key.key.public_key.pop();
    assert!(save_resident(key, dir.path(), false).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn refuses_symlinks_in_either_key_destination_and_replaces_hardlinks_safely() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    let key = resident("ssh:", b"");
    let path = dir.path().join(resident_filename(&key));
    for destination in [&path, &public_path(&path)] {
        symlink(&victim, destination).unwrap();
        assert!(save_resident(key.clone(), dir.path(), true).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        fs::remove_file(destination).unwrap();
    }
    fs::hard_link(&victim, &path).unwrap();
    save_resident(key, dir.path(), true).unwrap();
    assert_eq!(fs::read(victim).unwrap(), b"untouched");
}

#[test]
fn enrollment_never_overwrites_a_file_created_during_device_access() {
    struct RacingProvider(PathBuf);
    impl SecurityKeyProvider for RacingProvider {
        fn sign(
            &self,
            _: &SkSignRequest<'_>,
            _: Option<&str>,
        ) -> std::result::Result<SkSignResponse, SecurityKeyError> {
            Err(SecurityKeyError::Unsupported)
        }
        fn enroll(
            &self,
            request: &SkEnrollRequest<'_>,
            _: Option<&str>,
        ) -> std::result::Result<SkEnrollResponse, SecurityKeyError> {
            fs::write(&self.0, b"other writer").unwrap();
            Ok(response(request.algorithm, request.flags))
        }
        fn describe(&self) -> String {
            "racing mock".into()
        }
    }
    let dir = tempdir().unwrap();
    let output = dir.path().join("key");
    let options = EnrollmentOptions::default();
    let request = options.request(SkAlgorithm::Ed25519, b"challenge");
    let provider = RacingProvider(output.clone());
    assert!(generate(&provider, &request, None, &output, None, false).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"other writer");
    assert!(!public_path(&output).exists());
}

#[test]
fn resident_allocation_preserves_every_duplicate_and_portable_alias() {
    let dir = tempdir().unwrap();
    let mut keys = vec![
        resident("ssh:work", b"alice"),
        resident("ssh:work", b"alice"),
        resident("ssh:WORK", b"ALICE"),
        resident("ssh:work_alice.pub", b""),
        resident("ssh:work_alice_2", b""),
        resident("ssh:a:b", b""),
        resident("ssh:613a62", b""),
        resident("ssh:trailing.", b"user "),
        resident("ssh:\u{00e9}", b""),
        resident("ssh:e\u{0301}", b""),
    ];
    for (index, key) in keys.iter_mut().enumerate() {
        key.key.key_handle = Zeroizing::new(vec![index as u8 + 1; 32]);
    }
    let names = resident_filenames(&keys);
    assert_eq!(names, resident_filenames(&keys));
    assert_eq!(names[0], "id_ed25519_sk_rk_work_alice");
    assert_eq!(names[1], "id_ed25519_sk_rk_work_alice_2");
    assert_eq!(names[2], "id_ed25519_sk_rk_WORK_ALICE_3");
    let mut normalized = std::collections::HashSet::new();
    for (index, (key, name)) in keys.into_iter().zip(&names).enumerate() {
        assert!(name.is_ascii());
        assert!(!name.contains([':', ' ', '/', '\\']));
        assert!(!name.ends_with('.'));
        assert!(normalized.insert(name.to_ascii_lowercase()));
        assert!(normalized.insert(format!("{}.pub", name.to_ascii_lowercase())));
        // Even -y must leave a distinct keypair for every returned credential.
        let path = dir.path().join(name);
        save_resident_at(key, &path, true).unwrap();
        let decoded = PrivateKey::from_openssh(fs::read(path).unwrap()).unwrap();
        let private::KeypairData::SkEd25519(key) = decoded.key_data() else {
            panic!("wrong key type")
        };
        assert_eq!(key.key_handle(), &[index as u8 + 1; 32]);
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), names.len() * 2);
    // Later credentials did not overwrite earlier files.
    for (index, name) in names.iter().enumerate() {
        let decoded = PrivateKey::from_openssh(fs::read(dir.path().join(name)).unwrap()).unwrap();
        let private::KeypairData::SkEd25519(key) = decoded.key_data() else {
            panic!("wrong key type")
        };
        assert_eq!(key.key_handle(), &[index as u8 + 1; 32]);
    }
}

#[test]
fn malformed_or_weak_ed25519_provider_keys_are_rejected() {
    let dir = tempdir().unwrap();
    let malformed = (0..=255)
        .map(|byte| vec![byte; 32])
        .find(|bytes| {
            ed25519_dalek::VerifyingKey::from_bytes(bytes.as_slice().try_into().unwrap()).is_err()
        })
        .unwrap();
    for bytes in [malformed, vec![0; 32]] {
        let mut key = resident("ssh:", b"");
        key.key.public_key = bytes;
        let error = save_resident(key, dir.path(), false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Ed25519 security-key public key")
        );
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
