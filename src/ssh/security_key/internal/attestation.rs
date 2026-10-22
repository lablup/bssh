// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! Verify registration signatures without imposing vendor/CA trust policy.
//!
//! Signature inputs follow WebAuthn §8.2 (packed) and §8.6 (FIDO U2F):
//! <https://www.w3.org/TR/webauthn-2/#sctn-attestation>.
//! Certificates are parsed by RustCrypto x509-cert; their subject public key
//! authenticates the response. Certificate chain, lifetime, vendor metadata,
//! and attestation certificate profile checks are intentionally not trust gates.

use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier};
use x509_cert::{
    Certificate,
    der::{Decode, asn1::ObjectIdentifier},
};
use zeroize::Zeroizing;

use super::{CtapError, cbor::Value};
use crate::ssh::security_key::SkAlgorithm;

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const MAX_CERTIFICATE: usize = 64 * 1024;

pub(super) fn verify_ctap(
    map: &Value,
    auth_data: &[u8],
    challenge_hash: &[u8; 32],
    credential_algorithm: SkAlgorithm,
    credential_public_key: &[u8],
) -> Result<(), CtapError> {
    let format = map
        .get_int(1)
        .and_then(Value::as_text)
        .ok_or(CtapError::Protocol("missing attestation format"))?;
    let statement = map
        .get_int(3)
        .filter(|v| v.as_map().is_some())
        .ok_or(CtapError::Protocol("missing attestation statement"))?;
    match format {
        "none" => {
            if statement.as_map().is_some_and(|pairs| pairs.is_empty()) {
                Ok(())
            } else {
                Err(CtapError::Protocol(
                    "none attestation statement is not empty",
                ))
            }
        }
        "packed" => {
            let algorithm = statement
                .get(&Value::from("alg"))
                .and_then(Value::as_int)
                .ok_or(CtapError::Protocol("packed attestation algorithm missing"))?;
            let signature = signature(statement)?;
            if statement.get(&Value::from("ecdaaKeyId")).is_some() {
                return Err(CtapError::Unsupported("ECDAA attestation"));
            }
            let mut signed = Zeroizing::new(Vec::with_capacity(auth_data.len() + 32));
            signed.extend_from_slice(auth_data);
            signed.extend_from_slice(challenge_hash);
            if statement.get(&Value::from("x5c")).is_some() {
                validate_fields(statement, &["alg", "sig", "x5c"])?;
                verify_certificate(
                    certificate(statement, false)?,
                    algorithm,
                    &signed,
                    signature,
                )
            } else {
                validate_fields(statement, &["alg", "sig"])?;
                let expected = match credential_algorithm {
                    SkAlgorithm::EcdsaSha2NistP256 => -7,
                    SkAlgorithm::Ed25519 => -8,
                };
                if algorithm != expected {
                    return Err(CtapError::Protocol(
                        "self attestation algorithm differs from credential",
                    ));
                }
                verify_signature(algorithm, credential_public_key, &signed, signature)
            }
        }
        "fido-u2f" => {
            validate_fields(statement, &["sig", "x5c"])?;
            if credential_algorithm != SkAlgorithm::EcdsaSha2NistP256 {
                return Err(CtapError::Protocol(
                    "U2F attestation requires a P-256 credential",
                ));
            }
            if auth_data.len() < 55 || auth_data[32] & 0x40 == 0 || auth_data[37..53] != [0; 16] {
                return Err(CtapError::Protocol("invalid U2F attested credential data"));
            }
            let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
            let handle = auth_data
                .get(55..55 + length)
                .ok_or(CtapError::Protocol("truncated U2F credential ID"))?;
            let application_hash = auth_data[..32]
                .try_into()
                .map_err(|_| CtapError::Protocol("missing U2F application hash"))?;
            verify_u2f(
                certificate(statement, true)?,
                signature(statement)?,
                application_hash,
                challenge_hash,
                handle,
                credential_public_key,
            )
        }
        _ => Err(CtapError::Unsupported("attestation format")),
    }
}

pub(super) fn verify_u2f(
    certificate: &[u8],
    signature: &[u8],
    application_hash: &[u8; 32],
    challenge_hash: &[u8; 32],
    key_handle: &[u8],
    public_key: &[u8],
) -> Result<(), CtapError> {
    if key_handle.is_empty()
        || key_handle.len() > 4096
        || public_key.len() != 65
        || public_key[0] != 4
    {
        return Err(CtapError::Protocol(
            "invalid U2F registration key or handle",
        ));
    }
    P256Key::from_sec1_bytes(public_key)
        .map_err(|_| CtapError::Protocol("invalid U2F registration public point"))?;
    let mut signed = Zeroizing::new(Vec::with_capacity(130 + key_handle.len()));
    signed.push(0);
    signed.extend_from_slice(application_hash);
    signed.extend_from_slice(challenge_hash);
    signed.extend_from_slice(key_handle);
    signed.extend_from_slice(public_key);
    verify_certificate(certificate, -7, &signed, signature)
}

fn validate_fields(statement: &Value, fields: &[&str]) -> Result<(), CtapError> {
    let pairs = statement
        .as_map()
        .ok_or(CtapError::Protocol("attestation statement is not a map"))?;
    if pairs.len() != fields.len()
        || pairs
            .iter()
            .any(|(key, _)| !key.as_text().is_some_and(|key| fields.contains(&key)))
    {
        return Err(CtapError::Protocol(
            "unexpected attestation statement fields",
        ));
    }
    Ok(())
}

fn signature(statement: &Value) -> Result<&[u8], CtapError> {
    statement
        .get(&Value::from("sig"))
        .and_then(Value::as_bytes)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or(CtapError::Protocol(
            "missing or invalid attestation signature",
        ))
}

fn parse_certificate(bytes: &[u8]) -> Result<Certificate, CtapError> {
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE {
        return Err(CtapError::Protocol(
            "attestation certificate length invalid",
        ));
    }
    Certificate::from_der(bytes)
        .map_err(|_| CtapError::Protocol("invalid attestation certificate DER"))
}

fn certificate(statement: &Value, single: bool) -> Result<&[u8], CtapError> {
    let chain = statement
        .get(&Value::from("x5c"))
        .and_then(Value::as_array)
        .filter(|chain| !chain.is_empty() && chain.len() <= 8 && (!single || chain.len() == 1))
        .ok_or(CtapError::Protocol("invalid attestation certificate array"))?;
    // Parse supplied intermediates too, without treating their presence as trust.
    for entry in &chain[1..] {
        parse_certificate(
            entry
                .as_bytes()
                .ok_or(CtapError::Protocol("attestation certificate is not bytes"))?,
        )?;
    }
    chain[0]
        .as_bytes()
        .ok_or(CtapError::Protocol("attestation certificate is not bytes"))
}

fn verify_certificate(
    certificate: &[u8],
    algorithm: i64,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CtapError> {
    let certificate = parse_certificate(certificate)?;
    let spki = certificate.tbs_certificate().subject_public_key_info();
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CtapError::Protocol(
            "attestation certificate public key has unused bits",
        ))?;
    match algorithm {
        -7 => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            if spki.algorithm.oid != EC_PUBLIC_KEY || curve != Some(PRIME256V1) {
                return Err(CtapError::Protocol("attestation certificate is not P-256"));
            }
        }
        -8 => {
            if spki.algorithm.oid != ED25519 || spki.algorithm.parameters.is_some() {
                return Err(CtapError::Protocol(
                    "attestation certificate is not Ed25519",
                ));
            }
        }
        _ => return Err(CtapError::Unsupported("attestation signature algorithm")),
    }
    verify_signature(algorithm, key, message, signature)
}

fn verify_signature(
    algorithm: i64,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CtapError> {
    match algorithm {
        -7 => {
            let key = P256Key::from_sec1_bytes(public_key)
                .map_err(|_| CtapError::Protocol("invalid attestation P-256 key"))?;
            let signature = P256Signature::from_der(signature)
                .map_err(|_| CtapError::Protocol("invalid attestation ECDSA signature DER"))?;
            key.verify(message, &signature)
                .map_err(|_| CtapError::Protocol("attestation signature verification failed"))
        }
        -8 => {
            let key = public_key
                .try_into()
                .ok()
                .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).ok())
                .ok_or(CtapError::Protocol("invalid attestation Ed25519 key"))?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| CtapError::Protocol("invalid attestation Ed25519 signature"))?;
            key.verify_strict(message, &signature)
                .map_err(|_| CtapError::Protocol("attestation signature verification failed"))
        }
        _ => Err(CtapError::Unsupported("attestation signature algorithm")),
    }
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
pub(crate) mod tests;
