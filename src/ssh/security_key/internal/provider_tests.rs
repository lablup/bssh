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

//! `sk_sign` end to end over the mock transport, with the resulting SSH
//! signatures verified by `ssh-key`.

use std::sync::{Arc, Mutex};

use p256::ecdsa::signature::Verifier as _;
use russh::keys::ssh_encoding::Decode as _;
use russh::keys::ssh_key::Signature;
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, SkEcdsaSha2NistP256, SkEd25519};

use super::mock::{
    Credential, CredentialKey, Fido2Config, MockAuthenticator, MockBackend, Protocol,
};
use super::*;
use crate::ssh::security_key::encode_signature;

pub(super) const APPLICATION: &str = "ssh:example";
pub(super) const KEY_HANDLE: &[u8] = &[0xc0, 0xff, 0xee, 0x01];
pub(super) const DATA: &[u8] = b"session identifier and request";

pub(super) fn credential(key: CredentialKey) -> Credential {
    Credential {
        rp_id: APPLICATION.to_string(),
        id: KEY_HANDLE.to_vec(),
        key,
    }
}

pub(super) fn fido2(config: Fido2Config, key: Option<CredentialKey>) -> MockAuthenticator {
    MockAuthenticator::new(Protocol::Fido2(config), key.map(credential))
}

pub(super) type Handles = Vec<Arc<Mutex<MockAuthenticator>>>;

pub(super) fn provider_with(
    devices: Vec<(&str, MockAuthenticator)>,
) -> (InternalProvider, Handles) {
    let mut backend = MockBackend::default();
    backend.add_non_fido("/dev/hidraw0");
    let handles = devices
        .into_iter()
        .map(|(path, device)| backend.add(path, device))
        .collect();
    (InternalProvider::with_backend(Arc::new(backend)), handles)
}

pub(super) fn request(algorithm: SkAlgorithm, flags: u8) -> SkSignRequest<'static> {
    SkSignRequest {
        algorithm,
        data: DATA,
        application: APPLICATION,
        key_handle: KEY_HANDLE,
        flags,
    }
}

pub(super) fn public_key(device: &MockAuthenticator) -> KeyData {
    match &device.credential.as_ref().unwrap().key {
        CredentialKey::Ed25519(key) => KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey(key.verifying_key().to_bytes()),
            APPLICATION,
        )),
        CredentialKey::P256(key) => {
            let point = key.verifying_key().to_sec1_point(false);
            KeyData::SkEcdsaSha2NistP256(SkEcdsaSha2NistP256::new(point, APPLICATION))
        }
    }
}

pub(super) fn verify(public: &KeyData, blob: &[u8]) {
    let signature = Signature::decode(&mut &blob[..]).unwrap();
    public.verify(DATA, &signature).unwrap();
}

#[test]
fn ed25519_signature_through_the_provider_verifies_with_ssh_key() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
    )]);
    let response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
        .unwrap();
    assert_eq!(response.flags, 0x01);
    assert_eq!(
        response.counter, 43,
        "probe and signature each advance the counter"
    );
    assert_eq!(response.sig_r.len(), 64);
    assert!(response.sig_s.is_empty());
    let blob = encode_signature(SkAlgorithm::Ed25519, &response).unwrap();
    verify(&public_key(&devices[0].lock().unwrap()), &blob);
    assert_eq!(provider.describe(), "internal");
}

#[test]
fn ecdsa_signature_through_the_provider_verifies_with_minimal_components() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::p256(2))),
    )]);
    let response = provider
        .sign(&request(SkAlgorithm::EcdsaSha2NistP256, 0x01), None)
        .unwrap();
    assert!(!response.sig_r.is_empty() && response.sig_r[0] != 0);
    assert!(!response.sig_s.is_empty() && response.sig_s[0] != 0);
    assert!(response.sig_r.len() <= 32 && response.sig_s.len() <= 32);
    let blob = encode_signature(SkAlgorithm::EcdsaSha2NistP256, &response).unwrap();
    verify(&public_key(&devices[0].lock().unwrap()), &blob);
}

#[test]
fn a_mutated_signature_does_not_verify() {
    let (provider, devices) = provider_with(vec![(
        "/dev/hidraw1",
        fido2(Fido2Config::plain(), Some(CredentialKey::ed25519(1))),
    )]);
    let mut response = provider
        .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
        .unwrap();
    response.counter += 1;
    let blob = encode_signature(SkAlgorithm::Ed25519, &response).unwrap();
    let signature = Signature::decode(&mut &blob[..]).unwrap();
    assert!(
        public_key(&devices[0].lock().unwrap())
            .verify(DATA, &signature)
            .is_err()
    );
}

#[test]
fn authenticator_statuses_map_like_fidoerr_to_skerr() {
    use ctap2::status;
    for code in [
        status::PIN_INVALID,
        status::PIN_REQUIRED,
        status::OPERATION_DENIED,
    ] {
        assert_eq!(
            SecurityKeyError::from(CtapError::Status(code)),
            SecurityKeyError::PinRequired
        );
    }
    for code in [status::UNSUPPORTED_OPTION, status::UNSUPPORTED_ALGORITHM] {
        assert_eq!(
            SecurityKeyError::from(CtapError::Status(code)),
            SecurityKeyError::Unsupported
        );
    }
    assert_eq!(
        SecurityKeyError::from(CtapError::Unsupported("x")),
        SecurityKeyError::Unsupported
    );
    assert_eq!(
        SecurityKeyError::from(CtapError::Status(status::NO_CREDENTIALS)).to_string(),
        "sk_sign failed: authenticator returned CTAP2 status 0x2e (no credentials)"
    );
    assert_eq!(
        SecurityKeyError::from(CtapError::Timeout).to_string(),
        "sk_sign failed: timed out waiting for the authenticator"
    );
}

#[test]
fn pack_signature_strips_leading_zeros_and_checks_ed25519_length() {
    let assertion = AssertionResult {
        flags: 0x01,
        counter: 9,
        signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
    };
    let packed = pack_signature(SkAlgorithm::EcdsaSha2NistP256, &assertion).unwrap();
    assert_eq!(&packed.sig_r[..], &[0x01]);
    assert_eq!(&packed.sig_s[..], &[0x02]);
    assert_eq!((packed.flags, packed.counter), (0x01, 9));
    assert_eq!(
        pack_signature(
            SkAlgorithm::EcdsaSha2NistP256,
            &AssertionResult {
                signature: vec![0x30, 0x00],
                ..assertion.clone()
            }
        )
        .unwrap_err(),
        SecurityKeyError::InvalidResponse("malformed DER ECDSA signature")
    );
    assert_eq!(
        pack_signature(
            SkAlgorithm::Ed25519,
            &AssertionResult {
                signature: vec![1; 63],
                ..assertion.clone()
            }
        )
        .unwrap_err(),
        SecurityKeyError::InvalidResponse("Ed25519 assertion signature is not 64 bytes")
    );
    let packed = pack_signature(
        SkAlgorithm::Ed25519,
        &AssertionResult {
            signature: vec![1; 64],
            ..assertion
        },
    )
    .unwrap();
    assert_eq!(packed.sig_r.len(), 64);
    assert!(packed.sig_s.is_empty());
}

#[test]
fn non_fido_hid_devices_are_never_opened() {
    let mut backend = MockBackend::default();
    backend.add_non_fido("/dev/hidraw0");
    let backend: Arc<dyn ctaphid::HidBackend> = Arc::new(backend);
    assert!(select::fido_devices(&*backend).unwrap().is_empty());
    let provider = InternalProvider::with_backend(backend);
    assert_eq!(
        provider
            .sign(&request(SkAlgorithm::Ed25519, 0x01), None)
            .unwrap_err(),
        SecurityKeyError::DeviceNotFound
    );
}
