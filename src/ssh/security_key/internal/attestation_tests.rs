// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::*;
use base64::Engine as _;
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    pkcs8::DecodePrivateKey,
};

// Public, test-only signing keys and self-signed certificates, generated with
// OpenSSL. They authenticate synthetic protocol fixtures, never real credentials.
const P256_CERT: &str = "MIIBojCCAUegAwIBAgIUGH2GgwBlr++SRGRGPm+eQPg0wNIwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwaYnNzaCB0ZXN0LW9ubHkgYXR0ZXN0YXRpb24wIBcNMjYxMDIyMTQ0OTU3WhgPMjEyNjA5MjgxNDQ5NTdaMCUxIzAhBgNVBAMMGmJzc2ggdGVzdC1vbmx5IGF0dGVzdGF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQs6GoyklrhfvBzpHLr09aXYQkylQ6lGzHVoCkNVzvvfx19pi9Z8rE4lbRfuKyhLqXDS6YUjreFkVIQQNF/k0w6NTMFEwHQYDVR0OBBYEFBjwWj5yauN2zv262wr6Yi8aUE8xMB8GA1UdIwQYMBaAFBjwWj5yauN2zv262wr6Yi8aUE8xMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANI12ioSxLsYNfBvRc1eqD3ULU7wMCdjJanMnaQaWAviAiEAo9Gwi/CpNU+qb51iQziH36mtSLQQrw0148cviXPFw+o=";
const P256_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF+Z7aoMbqE180lIKDyTYT7fc79yLHzffyBwoOJ2L4gGhRANCAARCzoajKSWuF+8HOkcuvT1pdhCTKVDqUbMdWgKQ1XO+9/HX2mL1nysTiVtF+4rKEupcNLphSOt4WRUhBA0X+TTD";
const ED_CERT: &str = "MIIBcTCCASOgAwIBAgIUQdxYJOaq9/zHyxxnua6wmjLLQ24wBQYDK2VwMC0xKzApBgNVBAMMImJzc2ggdGVzdC1vbmx5IEVkMjU1MTkgYXR0ZXN0YXRpb24wIBcNMjYxMDIyMTQ1MjMxWhgPMjEyNjA5MjgxNDUyMzFaMC0xKzApBgNVBAMMImJzc2ggdGVzdC1vbmx5IEVkMjU1MTkgYXR0ZXN0YXRpb24wKjAFBgMrZXADIQB2qkF2U/ahnLgFb8Z5JSI/3qapne8APiB+6ZPHfmv72aNTMFEwHQYDVR0OBBYEFLHlEOSDQVzpgWs2UaedOdhzwmaEMB8GA1UdIwQYMBaAFLHlEOSDQVzpgWs2UaedOdhzwmaEMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA+6Z3T2pqOIyZ+Ky21YXS8Tx9Dpcl87QMnpm5GYeUCdzn7N72kDeLMBU7SR+KBI0skkdAaOcuAbZq6gR81IeOBA==";
const ED_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIGEisOqGQF5S10r98q+Tg7QfG3H+udmpXR6ruTnAPz/g";

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

fn p256_key() -> SigningKey {
    SigningKey::from_pkcs8_der(&decode(P256_KEY)).unwrap()
}

fn ed_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_pkcs8_der(&decode(ED_KEY)).unwrap()
}

fn sign_p256(message: &[u8]) -> Vec<u8> {
    let signature: P256Signature = p256_key().sign(message);
    signature.to_der().to_bytes().to_vec()
}

/// Produce a real U2F registration attestation for the mock authenticator.
pub(crate) fn u2f_attestation(
    application_hash: &[u8; 32],
    challenge_hash: &[u8; 32],
    key_handle: &[u8],
    public_key: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut signed = vec![0];
    signed.extend(application_hash);
    signed.extend(challenge_hash);
    signed.extend(key_handle);
    signed.extend(public_key);
    (decode(P256_CERT), sign_p256(&signed))
}

fn attestation(format: &str, fields: Vec<(&str, Value)>) -> Value {
    Value::Map(vec![
        (Value::Int(1), Value::from(format)),
        (
            Value::Int(3),
            Value::Map(
                fields
                    .into_iter()
                    .map(|(k, v)| (Value::from(k), v))
                    .collect(),
            ),
        ),
    ])
}

fn packed(algorithm: i64, signature: Vec<u8>, certificate: Option<Vec<u8>>) -> Value {
    let mut fields = vec![
        ("alg", Value::Int(algorithm)),
        ("sig", Value::Bytes(signature)),
    ];
    if let Some(certificate) = certificate {
        fields.push(("x5c", Value::Array(vec![Value::Bytes(certificate)])));
    }
    attestation("packed", fields)
}

#[test]
fn packed_self_attestation_verifies_both_algorithms_and_rejects_mutations() {
    let data = b"complete authenticator data";
    let hash = [3; 32];
    let message = [data.as_slice(), &hash].concat();
    for algorithm in [SkAlgorithm::EcdsaSha2NistP256, SkAlgorithm::Ed25519] {
        let (code, public, signature) = match algorithm {
            SkAlgorithm::EcdsaSha2NistP256 => (
                -7,
                p256_key().verifying_key().to_sec1_bytes().to_vec(),
                sign_p256(&message),
            ),
            SkAlgorithm::Ed25519 => (
                -8,
                ed_key().verifying_key().to_bytes().to_vec(),
                ed_key().sign(&message).to_bytes().to_vec(),
            ),
        };
        let map = packed(code, signature.clone(), None);
        verify_ctap(&map, data, &hash, algorithm, &public).unwrap();
        assert!(verify_ctap(&map, data, &[4; 32], algorithm, &public).is_err());
        assert!(
            verify_ctap(
                &map,
                b"mutated authenticator data",
                &hash,
                algorithm,
                &public
            )
            .is_err()
        );
        let mut wrong_public = public.clone();
        wrong_public[10] ^= 1;
        assert!(verify_ctap(&map, data, &hash, algorithm, &wrong_public).is_err());
        let other = if code == -7 {
            SkAlgorithm::Ed25519
        } else {
            SkAlgorithm::EcdsaSha2NistP256
        };
        assert!(verify_ctap(&map, data, &hash, other, &public).is_err());
        let mut signature = signature;
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(
            verify_ctap(
                &packed(code, signature, None),
                data,
                &hash,
                algorithm,
                &public
            )
            .is_err()
        );
    }
}

#[test]
fn certificate_attestation_uses_its_key_and_binds_all_authenticator_data() {
    let data = b"authenticator data including handle and credential public key";
    let hash = [5; 32];
    let message = [data.as_slice(), &hash].concat();
    for (code, certificate, signature) in [
        (-7, decode(P256_CERT), sign_p256(&message)),
        (
            -8,
            decode(ED_CERT),
            ed_key().sign(&message).to_bytes().to_vec(),
        ),
    ] {
        let map = packed(code, signature.clone(), Some(certificate.clone()));
        // Attestation key algorithm need not match the credential algorithm.
        verify_ctap(&map, data, &hash, SkAlgorithm::Ed25519, &[7; 32]).unwrap();
        assert!(verify_ctap(&map, data, &[6; 32], SkAlgorithm::Ed25519, &[7; 32]).is_err());
        assert!(
            verify_ctap(
                &map,
                b"altered authData",
                &hash,
                SkAlgorithm::Ed25519,
                &[7; 32]
            )
            .is_err()
        );
        let mut signature = signature;
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(
            verify_ctap(
                &packed(code, signature, Some(certificate)),
                data,
                &hash,
                SkAlgorithm::Ed25519,
                &[7; 32]
            )
            .is_err()
        );
    }
    let signature = sign_p256(&message);
    for certificate in [
        vec![],
        vec![0x30, 0],
        [decode(P256_CERT), vec![0]].concat(),
        decode(ED_CERT),
    ] {
        assert!(
            verify_ctap(
                &packed(-7, signature.clone(), Some(certificate)),
                data,
                &hash,
                SkAlgorithm::Ed25519,
                &[7; 32]
            )
            .is_err()
        );
    }
    assert!(
        verify_ctap(
            &packed(-257, signature, Some(decode(P256_CERT))),
            data,
            &hash,
            SkAlgorithm::Ed25519,
            &[7; 32]
        )
        .is_err()
    );
}

#[test]
fn u2f_registration_binds_application_challenge_handle_and_public_key() {
    let app = [1; 32];
    let challenge = [2; 32];
    let handle = [3; 17];
    let public = p256_key().verifying_key().to_sec1_bytes();
    let (certificate, signature) = u2f_attestation(&app, &challenge, &handle, &public);
    verify_u2f(&certificate, &signature, &app, &challenge, &handle, &public).unwrap();
    assert!(
        verify_u2f(
            &certificate,
            &signature,
            &[8; 32],
            &challenge,
            &handle,
            &public
        )
        .is_err()
    );
    assert!(verify_u2f(&certificate, &signature, &app, &[8; 32], &handle, &public).is_err());
    assert!(
        verify_u2f(
            &certificate,
            &signature,
            &app,
            &challenge,
            &[8; 17],
            &public
        )
        .is_err()
    );
    let other = SigningKey::from_slice(&[8; 32]).unwrap();
    assert!(
        verify_u2f(
            &certificate,
            &signature,
            &app,
            &challenge,
            &handle,
            &other.verifying_key().to_sec1_bytes()
        )
        .is_err()
    );
    let mut signature = signature;
    let last = signature.len() - 1;
    signature[last] ^= 1;
    assert!(verify_u2f(&certificate, &signature, &app, &challenge, &handle, &public).is_err());
}

#[test]
fn ctap_fido_u2f_uses_the_u2f_signed_message() {
    let app = [1; 32];
    let challenge = [2; 32];
    let handle = [3; 17];
    let public = p256_key().verifying_key().to_sec1_bytes();
    let (certificate, signature) = u2f_attestation(&app, &challenge, &handle, &public);
    let map = attestation(
        "fido-u2f",
        vec![
            ("sig", Value::Bytes(signature)),
            ("x5c", Value::Array(vec![Value::Bytes(certificate)])),
        ],
    );
    let mut data = app.to_vec();
    data.push(0x41);
    data.extend([0; 20]);
    data.extend((handle.len() as u16).to_be_bytes());
    data.extend(handle);
    verify_ctap(
        &map,
        &data,
        &challenge,
        SkAlgorithm::EcdsaSha2NistP256,
        &public,
    )
    .unwrap();
    assert!(
        verify_ctap(
            &map,
            &data,
            &[9; 32],
            SkAlgorithm::EcdsaSha2NistP256,
            &public
        )
        .is_err()
    );
    assert!(verify_ctap(&map, &data, &challenge, SkAlgorithm::Ed25519, &public).is_err());
    data[37] = 1;
    assert!(
        verify_ctap(
            &map,
            &data,
            &challenge,
            SkAlgorithm::EcdsaSha2NistP256,
            &public
        )
        .is_err()
    );
    for truncated in [&data[..3], &data[..54], &data[..60]] {
        assert!(
            verify_ctap(
                &map,
                truncated,
                &challenge,
                SkAlgorithm::EcdsaSha2NistP256,
                &public
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_statements_and_unknown_formats_are_rejected() {
    let verify = |map: Value| verify_ctap(&map, b"data", &[0; 32], SkAlgorithm::Ed25519, &[0; 32]);
    verify(attestation("none", vec![])).unwrap();
    for map in [
        Value::Map(vec![]),
        attestation("none", vec![("sig", Value::Bytes(vec![]))]),
        attestation("tpm", vec![]),
        attestation("packed", vec![]),
        attestation(
            "packed",
            vec![
                ("alg", Value::Int(-8)),
                ("sig", Value::Bytes(vec![0; 64])),
                ("x5c", Value::Array(vec![])),
            ],
        ),
        attestation(
            "packed",
            vec![
                ("alg", Value::Int(-8)),
                ("sig", Value::Bytes(vec![0; 64])),
                ("x5c", Value::Null),
            ],
        ),
        attestation(
            "packed",
            vec![
                ("alg", Value::Int(-8)),
                ("sig", Value::Bytes(vec![0; 64])),
                ("ecdaaKeyId", Value::Bytes(vec![1])),
            ],
        ),
    ] {
        assert!(verify(map).is_err());
    }
}
