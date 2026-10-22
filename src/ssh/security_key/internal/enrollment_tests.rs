// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::cbor::Value;
use super::mock::enrollment::Resident;
use super::mock::{Credential, CredentialKey, Fido2Config, MockAuthenticator, Protocol, Request};
use super::tests::{DATA, provider_with, public_key, verify};
use super::*;
use crate::ssh::security_key::{SK_FLAG_RESIDENT_KEY, SkEnrollRequest};

fn request(algorithm: SkAlgorithm, flags: u8) -> SkEnrollRequest<'static> {
    SkEnrollRequest {
        algorithm,
        challenge: b"challenge from keygen",
        application: "ssh:example",
        flags,
        user: Some("alice"),
        device: None,
    }
}

fn resident_config(protocol: u64, preview: bool) -> Fido2Config {
    let mut config = Fido2Config::with_pin("1234");
    config.pin_protocols = vec![protocol];
    config.options.insert("rk".into(), true);
    config.options.insert("testCredProtect".into(), true);
    config.options.insert(
        if preview {
            "credentialMgmtPreview"
        } else {
            "credMgmt"
        }
        .into(),
        true,
    );
    if preview {
        config.options.remove("pinUvAuthToken");
    }
    config
}

#[test]
fn enroll_each_algorithm_then_sign_using_returned_handle() {
    for algorithm in [SkAlgorithm::Ed25519, SkAlgorithm::EcdsaSha2NistP256] {
        let (provider, devices) = provider_with(vec![(
            "/dev/key",
            MockAuthenticator::new(Protocol::Fido2(Fido2Config::plain()), None),
        )]);
        let request = request(algorithm, 1);
        let enrolled = provider.enroll(&request, None).unwrap();
        assert_eq!(enrolled.flags, 1);
        assert_eq!(
            enrolled.public_key.len(),
            if algorithm == SkAlgorithm::Ed25519 {
                32
            } else {
                65
            }
        );
        let signed = provider
            .sign(
                &SkSignRequest {
                    algorithm,
                    data: DATA,
                    application: request.application,
                    key_handle: &enrolled.key_handle,
                    flags: enrolled.flags,
                },
                None,
            )
            .unwrap();
        verify(
            &public_key(&devices[0].lock().unwrap()),
            &crate::ssh::security_key::encode_signature(algorithm, &signed).unwrap(),
        );
        let device = devices[0].lock().unwrap();
        let Request::MakeCredential(map) = device
            .requests
            .iter()
            .find(|v| matches!(v, Request::MakeCredential(_)))
            .unwrap()
        else {
            unreachable!()
        };
        use sha2::{Digest, Sha256};
        assert_eq!(
            map.get_int(1).unwrap().as_bytes().unwrap(),
            Sha256::digest(request.challenge).as_slice()
        );
        assert!(
            map.get_int(7).is_none(),
            "makeCredential must not send an up option"
        );
    }
}

#[test]
fn pin_protocols_and_preview_enroll_download_and_refuse_replacement() {
    for (protocol, preview) in [(1, false), (2, false), (1, true)] {
        let (provider, devices) = provider_with(vec![(
            "/dev/key",
            MockAuthenticator::new(Protocol::Fido2(resident_config(protocol, preview)), None),
        )]);
        let request = request(SkAlgorithm::Ed25519, 1 | 4 | SK_FLAG_RESIDENT_KEY);
        assert_eq!(
            provider.enroll(&request, None).unwrap_err(),
            SecurityKeyError::PinRequired
        );
        let created = provider.enroll(&request, Some("1234")).unwrap();
        let keys = provider.load_resident_keys(Some("1234"), None).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, created);
        assert_eq!(keys[0].application, request.application);
        assert_eq!(
            keys[0].user_id,
            enrollment_wire::user_id(Some("alice")).unwrap()
        );
        assert!(
            provider
                .enroll(&request, Some("1234"))
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        let device = devices[0].lock().unwrap();
        assert_eq!(
            device
                .requests
                .iter()
                .filter(|r| matches!(r, Request::MakeCredential(_)))
                .count(),
            1
        );
        if !preview {
            let token_messages = device
                .pin_messages
                .iter()
                .filter(|m| m.get_int(2).and_then(Value::as_int) == Some(9))
                .collect::<Vec<_>>();
            assert!(token_messages.iter().any(
                |m| m.get_int(9).and_then(Value::as_int) == Some(4) && m.get_int(10).is_none()
            ));
            assert!(
                token_messages
                    .iter()
                    .any(|m| m.get_int(9).and_then(Value::as_int) == Some(1)
                        && m.get_int(10).and_then(Value::as_text) == Some("ssh:example"))
            );
        }
    }
}

#[test]
fn no_touch_flags_and_biometric_make_credential_tokens_are_preserved() {
    for protocol in [1, 2] {
        let mut config = resident_config(protocol, false);
        config.options.insert("uv".into(), true);
        let (provider, devices) = provider_with(vec![(
            "/dev/key",
            MockAuthenticator::new(Protocol::Fido2(config), None),
        )]);
        let result = provider
            .enroll(&request(SkAlgorithm::EcdsaSha2NistP256, 4), None)
            .unwrap();
        assert_eq!(result.flags, 4);
        let device = devices[0].lock().unwrap();
        assert!(
            device
                .pin_messages
                .iter()
                .any(|m| m.get_int(2).and_then(Value::as_int) == Some(6)
                    && m.get_int(9).and_then(Value::as_int) == Some(1))
        );
        let Request::MakeCredential(map) = device
            .requests
            .iter()
            .find(|r| matches!(r, Request::MakeCredential(_)))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(
            map.get_int(7).is_none(),
            "token proof omits uv, up remains omitted even with no-touch-required"
        );
    }
}

#[test]
fn protected_enrollment_fails_closed_without_credprotect_or_valid_pin() {
    for flags in [1 | SK_FLAG_RESIDENT_KEY, 1 | 4] {
        let (provider, devices) = provider_with(vec![(
            "/dev/key",
            MockAuthenticator::new(Protocol::Fido2(Fido2Config::plain()), None),
        )]);
        assert!(
            provider
                .enroll(&request(SkAlgorithm::Ed25519, flags), None)
                .unwrap_err()
                .to_string()
                .contains("credProtect")
        );
        assert!(
            !devices[0]
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|r| matches!(r, Request::MakeCredential(_)))
        );
    }
    let (provider, devices) = provider_with(vec![(
        "/dev/key",
        MockAuthenticator::new(Protocol::Fido2(resident_config(2, false)), None),
    )]);
    assert_eq!(
        provider
            .enroll(&request(SkAlgorithm::Ed25519, 1 | 4), Some("wrong"))
            .unwrap_err(),
        SecurityKeyError::PinRequired
    );
    assert!(
        !devices[0]
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| matches!(r, Request::MakeCredential(_)))
    );
}

#[test]
fn u2f_registers_p256_retries_presence_and_rejects_ed25519_and_resident() {
    let mut device = MockAuthenticator::new(Protocol::U2f, None);
    device.u2f_presence_retries = 1;
    let (provider, devices) = provider_with(vec![("/dev/key", device)]);
    let result = provider
        .enroll(&request(SkAlgorithm::EcdsaSha2NistP256, 1), None)
        .unwrap();
    assert_eq!(result.public_key.len(), 65);
    assert_eq!(&result.key_handle[..], &[0x42, 0x43, 0x44]);
    assert_eq!(
        devices[0]
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| matches!(r, Request::U2fRegister { .. }))
            .count(),
        2
    );
    assert!(
        provider
            .enroll(&request(SkAlgorithm::Ed25519, 1), None)
            .unwrap_err()
            .to_string()
            .contains("ed25519-sk requires CTAP2")
    );
    assert!(
        provider
            .load_resident_keys(Some("1234"), None)
            .unwrap_err()
            .to_string()
            .contains("U2F")
    );
}

#[test]
fn resident_enumeration_finishes_all_rps_before_enumerating_credentials() {
    let mut device = MockAuthenticator::new(Protocol::Fido2(resident_config(2, false)), None);
    for (index, application) in ["https://example.test", "ssh:one", "ssh:one", "ssh:two"]
        .into_iter()
        .enumerate()
    {
        device.resident_credentials.push(Resident {
            credential: Credential {
                rp_id: application.into(),
                id: vec![index as u8],
                key: CredentialKey::ed25519(2 + index as u8),
            },
            user: vec![index as u8],
            protection: 2,
        });
    }
    let (provider, devices) = provider_with(vec![("/dev/key", device)]);
    let keys = provider
        .load_resident_keys(Some("1234"), Some("/dev/key"))
        .unwrap();
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k.application.starts_with("ssh:")));
    let device = devices[0].lock().unwrap();
    let commands = device
        .requests
        .iter()
        .filter_map(|r| match r {
            Request::CredentialManagement(map) => map.get_int(1).and_then(Value::as_int),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(commands, vec![2, 3, 3, 4, 5, 4]);
}

#[test]
fn resident_count_is_bounded_before_any_followup_and_explicit_device_is_honored() {
    let mut device = MockAuthenticator::new(Protocol::Fido2(resident_config(2, false)), None);
    let mut reply = vec![0];
    reply.extend(cbor::encode(&Value::Map(vec![(
        Value::Int(5),
        Value::Int(1025),
    )])));
    device.management_reply = Some(reply);
    let (provider, devices) = provider_with(vec![("/dev/key", device)]);
    assert!(
        provider
            .load_resident_keys(Some("1234"), None)
            .unwrap_err()
            .to_string()
            .contains("count")
    );
    assert_eq!(
        devices[0]
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| matches!(r, Request::CredentialManagement(_)))
            .count(),
        1
    );
    assert_eq!(
        provider
            .load_resident_keys(Some("1234"), Some("/dev/missing"))
            .unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
}
