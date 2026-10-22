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

//! Device selection, PIN, U2F fallback and error mapping of the built-in
//! provider over the mock transport.

use std::sync::Arc;

use super::mock::{
    Credential, CredentialKey, Fido2Config, MockAuthenticator, MockBackend, Protocol, Request,
};
use super::tests::{
    APPLICATION, KEY_HANDLE, credential, fido2, provider_with, public_key, request, verify,
};
use super::*;
use crate::ssh::security_key::encode_signature;

#[test]
fn the_device_holding_the_credential_is_selected_among_several() {
    let mut other = Credential {
        rp_id: APPLICATION.to_string(),
        id: vec![0xde, 0xad],
        key: CredentialKey::ed25519(5),
    };
    other.id.push(0x01);
    let stranger = MockAuthenticator::new(Protocol::Fido2(Fido2Config::plain()), Some(other));
    let (provider, devices) = provider_with(vec![
        ("/dev/hidraw1", stranger),
        (
            "/dev/hidraw2",
            fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
        ),
    ]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
        .unwrap();
    verify(
        &public_key(&devices[1].lock().unwrap()),
        &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
    );
    // The stranger only saw the silent probe (up: false), never the real
    // request; the holder saw the probe and then the signature request.
    let stranger = devices[0].lock().unwrap();
    assert_eq!(
        stranger.assertion_requests(),
        [&Request::GetAssertion {
            rp_id: APPLICATION.to_string(),
            credential_ids: vec![KEY_HANDLE.to_vec()],
            up: Some(false),
            uv: None,
            pin_auth: None,
        }]
    );
    let holder = devices[1].lock().unwrap();
    let requests = holder.assertion_requests();
    assert_eq!(requests.len(), 2);
    assert!(matches!(
        requests[0],
        Request::GetAssertion {
            up: Some(false),
            ..
        }
    ));
    assert!(matches!(
        requests[1],
        Request::GetAssertion { up: Some(true), .. }
    ));
}

#[test]
fn a_lone_fido2_device_reporting_uv_is_used_without_a_probe() {
    let mut config = Fido2Config::plain();
    config.options.insert("uv".to_string(), false);
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(config, Some(CredentialKey::ed25519(1))),
    )]);
    provider
        .sign(&request(SkAlgorithm::Ed25519, 0x00), None)
        .unwrap();
    let device = devices[0].lock().unwrap();
    let requests = device.assertion_requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(matches!(
        requests[0],
        Request::GetAssertion {
            up: Some(false),
            uv: None,
            ..
        }
    ));
}

#[test]
fn no_touch_required_keys_ask_for_no_presence() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
    )]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x00), None)
        .unwrap();
    assert_eq!(response.flags, 0x00);
    let device = devices[0].lock().unwrap();
    assert!(matches!(
        device.assertion_requests()[1],
        Request::GetAssertion {
            up: Some(false),
            ..
        }
    ));
}

#[test]
fn verify_required_without_a_pin_needs_one_unless_the_device_verifies_itself() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
    )]);
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x05), None)
            .unwrap_err(),
        SecurityKeyError::PinRequired
    );
    assert!(
        devices[0].lock().unwrap().assertion_requests().is_empty(),
        "nothing is sent before the PIN is known"
    );

    let mut biometric = Fido2Config::plain();
    biometric.options.insert("uv".to_string(), true);
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(biometric, Some(CredentialKey::ed25519(1))),
    )]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x05), None)
        .unwrap();
    assert_eq!(response.flags, 0x05);
    let device = devices[0].lock().unwrap();
    assert!(matches!(
        device.assertion_requests()[0],
        Request::GetAssertion {
            up: Some(true),
            uv: Some(true),
            pin_auth: None,
            ..
        }
    ));
}

#[test]
fn a_pin_obtains_a_scoped_token_and_the_device_reports_verification() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(
            Fido2Config::with_pin("123456"),
            Some(CredentialKey::ed25519(1)),
        ),
    )]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
        .unwrap();
    assert_eq!(response.flags, 0x05);
    verify(
        &public_key(&devices[0].lock().unwrap()),
        &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
    );
    let device = devices[0].lock().unwrap();
    let pin_requests = device
        .requests
        .iter()
        .filter(|request| matches!(request, Request::ClientPin { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        pin_requests,
        [
            &Request::ClientPin {
                subcommand: 0x02,
                protocol: 2,
                permissions: None,
            },
            &Request::ClientPin {
                subcommand: 0x09,
                protocol: 2,
                permissions: Some((0x02, APPLICATION.to_string())),
            },
        ]
    );
    assert!(matches!(
        device.assertion_requests()[0],
        Request::GetAssertion {
            uv: None,
            pin_auth: Some((_, 2)),
            ..
        }
    ));
}

#[test]
fn a_ctap_2_0_device_gets_an_unscoped_protocol_1_token() {
    let mut config = Fido2Config::with_pin("123456");
    config.options.remove("pinUvAuthToken");
    config.pin_protocols = vec![1];
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(config, Some(CredentialKey::p256(2))),
    )]);
    let response = provider
        .sign(
            &request(SkAlgorithm::EcdsaSha2NistP256, 0x05),
            Some("123456"),
        )
        .unwrap();
    assert_eq!(response.flags, 0x05);
    let device = devices[0].lock().unwrap();
    assert!(device.requests.contains(&Request::ClientPin {
        subcommand: 0x05,
        protocol: 1,
        permissions: None,
    }));
    assert!(matches!(
        device.assertion_requests()[0],
        Request::GetAssertion {
            pin_auth: Some((param, 1)),
            ..
        } if param.len() == 16
    ));
}

#[test]
fn a_wrong_pin_is_reported_as_pin_required() {
    let (provider, _) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(
            Fido2Config::with_pin("123456"),
            Some(CredentialKey::ed25519(1)),
        ),
    )]);
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("654321"))
            .unwrap_err(),
        SecurityKeyError::PinRequired
    );
}

#[test]
fn u2f_devices_sign_ecdsa_after_presence_retries_and_cannot_hold_ed25519() {
    let mut u2f = MockAuthenticator::new(Protocol::U2f, Some(credential(CredentialKey::p256(3))));
    u2f.u2f_presence_retries = 2;
    let (provider, devices) = provider_with(vec![("/dev/hidraw1", u2f)]);
    let response = provider
        .sign(&request(SkAlgorithm::EcdsaSha2NistP256, 0x01), None)
        .unwrap();
    assert_eq!(response.flags, 0x01);
    verify(
        &public_key(&devices[0].lock().unwrap()),
        &encode_signature(SkAlgorithm::EcdsaSha2NistP256, &response).unwrap(),
    );
    let device = devices[0].lock().unwrap();
    assert_eq!(
        device.requests,
        [
            Request::U2fCheck,
            Request::U2fCheck,
            Request::U2fSign,
            Request::U2fSign,
            Request::U2fSign,
        ],
        "probe lookup, then lookup and sign with two presence retries"
    );
    drop(device);

    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
            .unwrap_err(),
        SecurityKeyError::Unsupported
    );
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::EcdsaSha2NistP256, 0x05), Some("1234"))
            .unwrap_err(),
        SecurityKeyError::Unsupported
    );
}

#[test]
fn missing_devices_and_credentials_are_device_not_found() {
    let (provider, _) = provider_with(vec![]);
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
            .unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
    let (provider, devices) = provider_with(vec![
        ("/dev/hidraw1", fido2(Fido2Config::plain(), None)),
        (
            "/dev/hidraw2",
            MockAuthenticator::new(Protocol::U2f, Some(credential(CredentialKey::p256(9)))),
        ),
    ]);
    let mut strange = request(SkAlgorithm::EcdsaSha2NistP256, 0x01);
    strange.key_handle = &[0x99];
    assert_eq!(
        provider.sign(&strange, None).unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
    assert_eq!(devices[1].lock().unwrap().requests, [Request::U2fCheck]);
}

#[test]
fn devices_that_cannot_be_opened_are_reported_with_the_reason() {
    let mut backend = MockBackend::default();
    backend.add(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
    );
    backend.unopenable.push("/dev/hidraw1".to_string());
    let provider = InternalProvider::with_backend(Arc::new(backend));
    let error = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
        .unwrap_err();
    match error {
        SecurityKeyError::Failed(reason) => {
            assert!(
                reason.contains("1 FIDO device(s) found but none could be opened"),
                "{reason}"
            );
            assert!(reason.contains("Permission denied"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn keepalives_during_the_assertion_are_tolerated() {
    let mut slow = fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1)));
    slow.keepalives_before_reply = 3;
    let (provider, devices) = provider_with(vec![("/dev/hidraw1", slow)]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
        .unwrap();
    verify(
        &public_key(&devices[0].lock().unwrap()),
        &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
    );
}

#[test]
fn with_a_pin_and_several_devices_the_touched_one_is_chosen_and_the_rest_cancelled() {
    let mut untouched = fido2(
        Fido2Config::with_pin("123456"),
        Some(CredentialKey::ed25519(7)),
    );
    untouched.touch_on_probe = false;
    let (provider, devices) = provider_with(vec![
        ("/dev/hidraw1", untouched),
        (
            "/dev/hidraw2",
            fido2(
                Fido2Config::with_pin("123456"),
                Some(CredentialKey::ed25519(1)),
            ),
        ),
    ]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
        .unwrap();
    verify(
        &public_key(&devices[1].lock().unwrap()),
        &encode_signature(SkAlgorithm::Ed25519, &response).unwrap(),
    );
    let untouched = devices[0].lock().unwrap();
    assert_eq!(
        untouched.requests,
        [Request::GetInfo, Request::TouchProbe, Request::Cancel]
    );
    let touched = devices[1].lock().unwrap();
    assert_eq!(touched.cancels, 0);
    assert!(touched.requests.contains(&Request::TouchProbe));
}

#[test]
fn a_u2f_device_among_several_is_selected_by_touch_too() {
    let mut untouched = MockAuthenticator::new(Protocol::U2f, None);
    untouched.touch_on_probe = false;
    let (provider, devices) = provider_with(vec![
        ("/dev/hidraw1", untouched),
        (
            "/dev/hidraw2",
            fido2(
                Fido2Config::with_pin("123456"),
                Some(CredentialKey::ed25519(1)),
            ),
        ),
    ]);
    provider
        .sign(&request(SkAlgorithm::Ed25519, 0x05), Some("123456"))
        .unwrap();
    let untouched = devices[0].lock().unwrap();
    // Re-sent REGISTER probes (P1 0, as libfido2 sends them) while it kept
    // answering "not touched", and no CANCEL once the other device was
    // chosen: libfido2 sends CANCEL to CTAP2 devices only.
    assert!(
        !untouched.requests.is_empty()
            && untouched
                .requests
                .iter()
                .all(|request| *request == Request::U2fRegister { p1: 0 }),
        "{:?}",
        untouched.requests
    );
    assert_eq!(untouched.cancels, 0);
}
