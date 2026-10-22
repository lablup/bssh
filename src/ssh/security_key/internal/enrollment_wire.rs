// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! CTAP credential creation and read-only credential-management messages.
//! CTAP 2.1 sections 6.1 and 6.8; OpenSSH sk-usbhid.c credential formats.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::CtapError;
use super::cbor::{self, Value};
use super::ctap2;
use super::pin_protocol::{PinProtocol, authenticate_with};
use crate::ssh::security_key::{
    SK_FLAG_RESIDENT_KEY, SK_FLAG_USER_PRESENCE_REQUIRED, SK_FLAG_USER_VERIFICATION_REQUIRED,
    SkAlgorithm, SkEnrollRequest, SkEnrollResponse, SkResidentKey,
};

pub(super) const MAX_RESIDENT_KEYS: usize = 1024;

pub(super) fn user_id(user: Option<&str>) -> Result<[u8; 32], CtapError> {
    let mut id = [0; 32];
    if let Some(user) = user {
        if user.len() >= id.len() || user.as_bytes().contains(&0) {
            return Err(CtapError::Unsupported(
                "-O user= must contain at most 31 bytes and no NUL",
            ));
        }
        id[..user.len()].copy_from_slice(user.as_bytes());
    }
    Ok(id)
}

pub(super) fn protection(flags: u8) -> Option<i64> {
    if flags & SK_FLAG_USER_VERIFICATION_REQUIRED != 0 {
        Some(3)
    } else if flags & SK_FLAG_RESIDENT_KEY != 0 {
        Some(2)
    } else {
        None
    }
}

pub(super) fn make_credential(
    request: &SkEnrollRequest<'_>,
    hash: &[u8; 32],
    user: &[u8; 32],
    auth: Option<(&[u8], PinProtocol)>,
    uv: bool,
) -> Zeroizing<Vec<u8>> {
    let algorithm = match request.algorithm {
        SkAlgorithm::Ed25519 => -8,
        SkAlgorithm::EcdsaSha2NistP256 => -7,
    };
    let mut pairs = vec![
        (Value::Int(1), Value::from(hash.as_slice())),
        (
            Value::Int(2),
            Value::Map(vec![(Value::from("id"), Value::from(request.application))]),
        ),
        (
            Value::Int(3),
            Value::Map(vec![
                (Value::from("id"), Value::from(user.as_slice())),
                (Value::from("name"), Value::from("openssh")),
                (Value::from("displayName"), Value::from("openssh")),
            ]),
        ),
        (
            Value::Int(4),
            Value::Array(vec![Value::Map(vec![
                (Value::from("type"), Value::from("public-key")),
                (Value::from("alg"), Value::Int(algorithm)),
            ])]),
        ),
    ];
    if let Some(policy) = protection(request.flags) {
        pairs.push((
            Value::Int(6),
            Value::Map(vec![(Value::from("credProtect"), Value::Int(policy))]),
        ));
    }
    let mut options = Vec::new();
    if request.flags & SK_FLAG_RESIDENT_KEY != 0 {
        options.push((Value::from("rk"), Value::Bool(true)));
    }
    if uv && auth.is_none() {
        options.push((Value::from("uv"), Value::Bool(true)));
    }
    if !options.is_empty() {
        pairs.push((Value::Int(7), Value::Map(options)));
    }
    if let Some((param, protocol)) = auth {
        pairs.push((Value::Int(8), Value::from(param)));
        pairs.push((Value::Int(9), Value::Int(protocol.number() as i64)));
    }
    let value = Zeroizing::new(Value::Map(pairs));
    let mut encoded = Zeroizing::new(vec![ctap2::CMD_MAKE_CREDENTIAL]);
    encoded.extend(cbor::encode(&value));
    encoded
}

/// Strictly match the algorithm, curve, coordinates and actual public point.
pub(super) fn public_key(value: &Value) -> Result<(SkAlgorithm, Vec<u8>), CtapError> {
    let integer = |key| value.get_int(key).and_then(Value::as_int);
    let x = value
        .get_int(-2)
        .and_then(Value::as_bytes)
        .filter(|v| v.len() == 32)
        .ok_or(CtapError::Protocol(
            "credential public key x missing or not 32 bytes",
        ))?;
    match (integer(1), integer(3), integer(-1)) {
        (Some(1), Some(-8), Some(6)) => {
            let bytes: [u8; 32] = x
                .try_into()
                .map_err(|_| CtapError::Protocol("invalid Ed25519 public key"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|_| CtapError::Protocol("invalid Ed25519 public key"))?;
            if key.is_weak() {
                return Err(CtapError::Protocol("weak Ed25519 public key"));
            }
            Ok((SkAlgorithm::Ed25519, x.to_vec()))
        }
        (Some(2), Some(-7), Some(1)) => {
            let y = value
                .get_int(-3)
                .and_then(Value::as_bytes)
                .filter(|v| v.len() == 32)
                .ok_or(CtapError::Protocol(
                    "credential public key y missing or not 32 bytes",
                ))?;
            let mut point = vec![4];
            point.extend(x);
            point.extend(y);
            p256::PublicKey::from_sec1_bytes(&point)
                .map_err(|_| CtapError::Protocol("invalid P-256 public point"))?;
            Ok((SkAlgorithm::EcdsaSha2NistP256, point))
        }
        _ => Err(CtapError::Unsupported("credential public key algorithm")),
    }
}

pub(super) fn parse_created(
    response: &[u8],
    request: &SkEnrollRequest<'_>,
) -> Result<SkEnrollResponse, CtapError> {
    let map = Zeroizing::new(cbor::decode(ctap2::response_body(response)?)?);
    let data = map
        .get_int(2)
        .and_then(Value::as_bytes)
        .filter(|v| v.len() >= 55)
        .ok_or(CtapError::Protocol(
            "makeCredential missing attested credential data",
        ))?;
    if data[..32] != Sha256::digest(request.application.as_bytes())[..] || data[32] & 0x41 != 0x41 {
        return Err(CtapError::Protocol(
            "makeCredential RP hash, presence or attested-data flag mismatch",
        ));
    }
    if request.flags & SK_FLAG_USER_VERIFICATION_REQUIRED != 0 && data[32] & 4 == 0 {
        return Err(CtapError::Protocol(
            "makeCredential did not verify the user",
        ));
    }
    let len = usize::from(u16::from_be_bytes([data[53], data[54]]));
    let end = 55 + len;
    if len == 0 || len > 4096 || end >= data.len() {
        return Err(CtapError::Protocol(
            "invalid enrollment credential ID length",
        ));
    }
    let (key, consumed) = cbor::decode_prefix(&data[end..])?;
    let (algorithm, public_key) = public_key(&key)?;
    if algorithm != request.algorithm {
        return Err(CtapError::Protocol(
            "enrollment algorithm differs from request",
        ));
    }
    let trailing = &data[end + consumed..];
    let extensions = if data[32] & 0x80 != 0 {
        let extensions = cbor::decode(trailing)?;
        if extensions.as_map().is_none() {
            return Err(CtapError::Protocol(
                "authenticator extensions are not a map",
            ));
        }
        Some(extensions)
    } else if trailing.is_empty() {
        None
    } else {
        return Err(CtapError::Protocol(
            "unexpected trailing authenticator data",
        ));
    };
    if let Some(required) = protection(request.flags) {
        let actual = extensions
            .as_ref()
            .and_then(|v| v.get(&Value::from("credProtect")))
            .and_then(Value::as_int);
        if actual != Some(required) {
            return Err(CtapError::Protocol(
                "authenticator did not enforce requested credProtect policy",
            ));
        }
    }
    let challenge_hash: [u8; 32] = Sha256::digest(request.challenge).into();
    super::attestation::verify_ctap(&map, data, &challenge_hash, algorithm, &public_key)?;
    Ok(SkEnrollResponse {
        flags: request.flags,
        public_key,
        key_handle: Zeroizing::new(data[55..end].to_vec()),
    })
}

pub(super) fn management(
    command: u8,
    subcommand: u8,
    params: Option<Value>,
    auth: Option<(&[u8], PinProtocol)>,
) -> Zeroizing<Vec<u8>> {
    let mut pairs = vec![(Value::Int(1), Value::Int(i64::from(subcommand)))];
    let mut message = Zeroizing::new(vec![subcommand]);
    if let Some(params) = params {
        message.extend(cbor::encode(&params));
        pairs.push((Value::Int(2), params));
    }
    if let Some((token, protocol)) = auth {
        pairs.push((Value::Int(3), Value::Int(protocol.number() as i64)));
        pairs.push((
            Value::Int(4),
            Value::Bytes(authenticate_with(protocol, token, &message)),
        ));
    }
    let value = Zeroizing::new(Value::Map(pairs));
    let mut encoded = Zeroizing::new(vec![command]);
    encoded.extend(cbor::encode(&value));
    encoded
}

pub(super) fn count(map: &Value, key: i64) -> Result<usize, CtapError> {
    map.get_int(key)
        .and_then(Value::as_int)
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0 && *v <= MAX_RESIDENT_KEYS)
        .ok_or(CtapError::Protocol(
            "resident enumeration count missing or outside 1..1024",
        ))
}

pub(super) fn relying_party(map: &Value) -> Result<(String, [u8; 32]), CtapError> {
    let id = map
        .get_int(3)
        .and_then(|v| v.get(&Value::from("id")))
        .and_then(Value::as_text)
        .filter(|id| !id.is_empty() && id.len() <= 1024 && !id.as_bytes().contains(&0))
        .ok_or(CtapError::Protocol("resident RP ID missing or invalid"))?;
    let hash: [u8; 32] = map
        .get_int(4)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(CtapError::Protocol("resident RP hash missing or invalid"))?;
    // Truncated RP IDs cannot reconstruct a usable SSH key; fail closed.
    if id.starts_with("ssh:") && hash != <[u8; 32]>::from(Sha256::digest(id.as_bytes())) {
        return Err(CtapError::Protocol(
            "resident RP ID hash mismatch (possibly truncated)",
        ));
    }
    Ok((id.to_owned(), hash))
}

pub(super) fn resident(map: &Value, application: &str) -> Result<SkResidentKey, CtapError> {
    let descriptor = map.get_int(7).ok_or(CtapError::Protocol(
        "resident credential descriptor missing",
    ))?;
    if descriptor
        .get(&Value::from("type"))
        .and_then(Value::as_text)
        != Some("public-key")
    {
        return Err(CtapError::Protocol("invalid resident credential type"));
    }
    let handle = descriptor
        .get(&Value::from("id"))
        .and_then(Value::as_bytes)
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or(CtapError::Protocol(
            "resident credential handle missing or invalid",
        ))?;
    let user_id = map
        .get_int(6)
        .and_then(|v| v.get(&Value::from("id")))
        .and_then(Value::as_bytes)
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or(CtapError::Protocol("resident user ID missing or invalid"))?;
    let key = map
        .get_int(8)
        .ok_or(CtapError::Protocol("resident public key missing"))?;
    let (algorithm, public_key) = public_key(key)?;
    let policy = map
        .get_int(10)
        .map(|value| {
            value
                .as_int()
                .ok_or(CtapError::Protocol("invalid resident credProtect type"))
        })
        .transpose()?;
    if policy.is_some_and(|v| !(1..=3).contains(&v)) {
        return Err(CtapError::Protocol("invalid resident credProtect policy"));
    }
    let flags = SK_FLAG_RESIDENT_KEY
        | SK_FLAG_USER_PRESENCE_REQUIRED
        | if policy == Some(3) {
            SK_FLAG_USER_VERIFICATION_REQUIRED
        } else {
            0
        };
    Ok(SkResidentKey {
        algorithm,
        application: application.to_owned(),
        key: SkEnrollResponse {
            flags,
            public_key,
            key_handle: Zeroizing::new(handle.to_vec()),
        },
        user_id: user_id.to_vec(),
    })
}
