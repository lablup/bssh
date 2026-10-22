// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::cbor::{self, Value};
use super::enrollment_wire as wire;
use crate::ssh::security_key::{SkAlgorithm, SkEnrollRequest};
use sha2::{Digest, Sha256};

fn request() -> SkEnrollRequest<'static> {
    SkEnrollRequest {
        algorithm: SkAlgorithm::Ed25519,
        application: "ssh:example",
        challenge: b"challenge",
        flags: 1,
        user: None,
        device: None,
    }
}

fn cose() -> Value {
    let public = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
        .verifying_key()
        .to_bytes();
    Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(3), Value::Int(-8)),
        (Value::Int(-1), Value::Int(6)),
        (Value::Int(-2), Value::Bytes(public.to_vec())),
    ])
}

fn authenticator_data() -> Vec<u8> {
    let mut data = Sha256::digest(request().application).to_vec();
    data.push(0x41);
    data.extend([0; 20]);
    data.extend([0, 3, 1, 2, 3]);
    data.extend(cbor::encode(&cose()));
    data
}

fn reply(data: &[u8]) -> Vec<u8> {
    let mut response = vec![0];
    response.extend(cbor::encode(&Value::Map(vec![
        (Value::Int(1), Value::from("none")),
        (Value::Int(2), Value::Bytes(data.to_vec())),
        (Value::Int(3), Value::Map(vec![])),
    ])));
    response
}

#[test]
fn every_truncated_enrollment_prefix_is_rejected() {
    let complete = reply(&authenticator_data());
    assert!(wire::parse_created(&complete, &request()).is_ok());
    for end in 0..complete.len() {
        assert!(
            wire::parse_created(&complete[..end], &request()).is_err(),
            "length {end}"
        );
    }
    for end in 0..authenticator_data().len() {
        assert!(wire::parse_created(&reply(&authenticator_data()[..end]), &request()).is_err());
    }
}

#[test]
fn enrollment_rejects_wrong_rp_flags_handle_curve_and_trailing_data() {
    for (offset, value) in [(0, 0), (32, 0x40), (32, 1), (53, 0xff), (54, 0xff), (54, 0)] {
        let mut data = authenticator_data();
        data[offset] = value;
        assert!(
            wire::parse_created(&reply(&data), &request()).is_err(),
            "offset {offset}"
        );
    }
    let mut data = authenticator_data();
    data.push(0xa0);
    assert!(wire::parse_created(&reply(&data), &request()).is_err());
    let mut non_map = authenticator_data();
    non_map[32] |= 0x80;
    non_map.push(0);
    assert!(wire::parse_created(&reply(&non_map), &request()).is_err());
    let mut requested = request();
    requested.algorithm = SkAlgorithm::EcdsaSha2NistP256;
    assert!(wire::parse_created(&reply(&authenticator_data()), &requested).is_err());
    requested = request();
    requested.flags |= 4;
    assert!(wire::parse_created(&reply(&authenticator_data()), &requested).is_err());
    let wrong_curve = Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(3), Value::Int(-8)),
        (Value::Int(-1), Value::Int(1)),
        (Value::Int(-2), Value::Bytes(vec![0; 32])),
    ]);
    assert!(wire::public_key(&wrong_curve).is_err());
}

#[test]
fn required_credprotect_must_be_returned_and_enforced() {
    let mut requested = request();
    requested.flags |= 0x20;
    let mut data = authenticator_data();
    assert!(wire::parse_created(&reply(&data), &requested).is_err());
    data[32] |= 0x80;
    for policy in [1, 2, 3] {
        let mut extended = data.clone();
        extended.extend(cbor::encode(&Value::Map(vec![(
            Value::from("credProtect"),
            Value::Int(policy),
        )])));
        assert_eq!(
            wire::parse_created(&reply(&extended), &requested).is_ok(),
            policy == 2
        );
    }
}

#[test]
fn resident_parser_rejects_missing_fields_and_unbounded_counts() {
    for count in [-1, 0, 1025, i64::MAX] {
        assert!(wire::count(&Value::Map(vec![(Value::Int(5), Value::Int(count))]), 5).is_err());
    }
    assert!(wire::resident(&Value::Map(vec![]), "ssh:").is_err());
    let party = Value::Map(vec![
        (
            Value::Int(3),
            Value::Map(vec![(Value::from("id"), Value::from("ssh:example"))]),
        ),
        (Value::Int(4), Value::Bytes(vec![0; 32])),
    ]);
    assert!(wire::relying_party(&party).is_err());
    let duplicate = [0xa2, 0x01, 0x02, 0x01, 0x03];
    assert!(cbor::decode(&duplicate).is_err());
}

#[test]
fn user_option_is_bounded_and_matches_openssh_nul_padding() {
    assert_eq!(wire::user_id(None).unwrap(), [0; 32]);
    let id = wire::user_id(Some("alice")).unwrap();
    assert_eq!(&id[..5], b"alice");
    assert_eq!(&id[5..], &[0; 27]);
    assert!(wire::user_id(Some(&"a".repeat(32))).is_err());
    assert!(wire::user_id(Some("a\0b")).is_err());
}

#[test]
fn packed_signature_verification_is_integrated_into_enrollment_parser() {
    use ed25519_dalek::Signer;
    let data = authenticator_data();
    let mut signed = data.clone();
    signed.extend(Sha256::digest(request().challenge));
    let signature = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
        .sign(&signed)
        .to_bytes();
    for corrupt in [false, true] {
        let mut signature = signature.to_vec();
        if corrupt {
            signature[0] ^= 1;
        }
        let mut response = vec![0];
        response.extend(cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::from("packed")),
            (Value::Int(2), Value::Bytes(data.clone())),
            (
                Value::Int(3),
                Value::Map(vec![
                    (Value::from("alg"), Value::Int(-8)),
                    (Value::from("sig"), Value::Bytes(signature)),
                ]),
            ),
        ])));
        assert_eq!(wire::parse_created(&response, &request()).is_ok(), !corrupt);
    }
}

#[test]
fn u2f_parser_verifies_registration_binding_and_rejects_truncated_der() {
    let point = p256::ecdsa::SigningKey::from_slice(&[2; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    let application = [3; 32];
    let challenge = [4; 32];
    let handle = [5, 6, 7];
    let (certificate, signature) = super::attestation::tests::u2f_attestation(
        &application,
        &challenge,
        &handle,
        point.as_bytes(),
    );
    let mut data = vec![5];
    data.extend(point.as_bytes());
    data.push(3);
    data.extend(handle);
    data.extend(certificate);
    data.extend(signature);
    assert!(super::u2f::parse_registration(&data, 1, &application, &challenge).is_ok());
    assert!(super::u2f::parse_registration(&data, 1, &application, &[9; 32]).is_err());
    for end in 0..data.len() {
        assert!(super::u2f::parse_registration(&data[..end], 1, &application, &challenge).is_err());
    }
    *data.last_mut().unwrap() ^= 1;
    assert!(super::u2f::parse_registration(&data, 1, &application, &challenge).is_err());
}

#[test]
fn resident_protection_type_must_not_silently_drop_verification_requirement() {
    let map = Value::Map(vec![
        (
            Value::Int(6),
            Value::Map(vec![(Value::from("id"), Value::Bytes(vec![1]))]),
        ),
        (
            Value::Int(7),
            Value::Map(vec![
                (Value::from("id"), Value::Bytes(vec![1])),
                (Value::from("type"), Value::from("public-key")),
            ]),
        ),
        (Value::Int(8), cose()),
        (Value::Int(10), Value::Bool(true)),
    ]);
    assert!(wire::resident(&map, "ssh:").is_err());
}
