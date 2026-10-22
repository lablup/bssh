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

//! CTAP2 messages: `authenticatorGetInfo`, `authenticatorGetAssertion`, the
//! `authenticatorClientPIN` subcommands the sign path needs, and the dummy
//! `authenticatorMakeCredential` libfido2 uses to detect a touch.
//!
//! A request is `command byte || CBOR map`; a response is
//! `status byte || CBOR map`.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::CtapError;
use super::cbor::{self, Value};

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;

/// CTAP2 status codes the sign path interprets.
pub mod status {
    pub const OK: u8 = 0x00;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const UNSUPPORTED_OPTION: u8 = 0x2b;
    pub const INVALID_OPTION: u8 = 0x2c;
    pub const KEEPALIVE_CANCEL: u8 = 0x2d;
    pub const NO_CREDENTIALS: u8 = 0x2e;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2f;
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const PIN_REQUIRED: u8 = 0x36;
    pub const UV_BLOCKED: u8 = 0x3c;
    pub const UV_INVALID: u8 = 0x3f;
}

/// Human-readable name for a status byte, for diagnostics.
#[must_use]
pub fn status_name(code: u8) -> &'static str {
    match code {
        status::OK => "success",
        0x01 => "invalid command",
        0x02 => "invalid parameter",
        0x11 => "unexpected CBOR type",
        0x12 => "invalid CBOR",
        0x14 => "missing parameter",
        0x21 => "credential excluded",
        status::UNSUPPORTED_ALGORITHM => "unsupported algorithm",
        status::OPERATION_DENIED => "operation denied",
        status::UNSUPPORTED_OPTION => "unsupported option",
        status::INVALID_OPTION => "invalid option",
        status::KEEPALIVE_CANCEL => "cancelled",
        status::NO_CREDENTIALS => "no credentials",
        status::USER_ACTION_TIMEOUT => "user action timeout",
        status::PIN_INVALID => "PIN invalid",
        status::PIN_BLOCKED => "PIN blocked",
        status::PIN_AUTH_INVALID => "PIN authentication invalid",
        status::PIN_AUTH_BLOCKED => "PIN authentication blocked",
        status::PIN_NOT_SET => "PIN not set",
        status::PIN_REQUIRED => "PIN required",
        status::UV_BLOCKED => "user verification blocked",
        status::UV_INVALID => "user verification invalid",
        _ => "unknown status",
    }
}

/// Strip and check the status byte of a CTAP2 response.
pub fn response_body(response: &[u8]) -> Result<&[u8], CtapError> {
    let (&code, body) = response
        .split_first()
        .ok_or(CtapError::Protocol("empty CTAP2 response"))?;
    if code != status::OK {
        return Err(CtapError::Status(code));
    }
    Ok(body)
}

/// What `authenticatorGetInfo` reports, limited to the fields consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatorInfo {
    pub versions: Vec<String>,
    pub options: BTreeMap<String, bool>,
    pub pin_protocols: Vec<u64>,
}

impl AuthenticatorInfo {
    #[must_use]
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options.get(name).copied()
    }

    /// CTAP 2.1 `pinUvAuthToken`: the device issues permission-scoped
    /// tokens (`getPinUvAuthTokenUsingPinWithPermissions`).
    #[must_use]
    pub fn supports_permissions(&self) -> bool {
        self.option("pinUvAuthToken") == Some(true)
    }
}

pub fn parse_get_info(response: &[u8]) -> Result<AuthenticatorInfo, CtapError> {
    let map = cbor::decode(response_body(response)?)?;
    let versions = map
        .get_int(1)
        .and_then(Value::as_array)
        .ok_or(CtapError::Protocol("getInfo without versions"))?
        .iter()
        .filter_map(|item| item.as_text().map(str::to_string))
        .collect();
    let options = map
        .get_int(4)
        .and_then(Value::as_map)
        .map(|pairs| {
            pairs
                .iter()
                .filter_map(|(key, value)| Some((key.as_text()?.to_string(), value.as_bool()?)))
                .collect()
        })
        .unwrap_or_default();
    let pin_protocols = map
        .get_int(6)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_int().and_then(|v| u64::try_from(v).ok()))
                .collect()
        })
        .unwrap_or_default();
    Ok(AuthenticatorInfo {
        versions,
        options,
        pin_protocols,
    })
}

/// `authenticatorGetAssertion` parameters for one allowed credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a [u8; 32],
    pub credential_id: &'a [u8],
    /// `options.up`; omitted when `None`.
    pub up: Option<bool>,
    /// `options.uv`; omitted when `None`.
    pub uv: Option<bool>,
    /// `pinUvAuthParam` and `pinUvAuthProtocol`.
    pub pin_auth: Option<(&'a [u8], u64)>,
}

#[must_use]
pub fn encode_get_assertion(request: &GetAssertionRequest<'_>) -> Vec<u8> {
    let mut pairs = vec![
        (Value::Int(1), Value::from(request.rp_id)),
        (Value::Int(2), Value::from(&request.client_data_hash[..])),
        (
            Value::Int(3),
            Value::Array(vec![Value::Map(vec![
                (Value::from("id"), Value::from(request.credential_id)),
                (Value::from("type"), Value::from("public-key")),
            ])]),
        ),
    ];
    let mut options = Vec::new();
    if let Some(up) = request.up {
        options.push((Value::from("up"), Value::Bool(up)));
    }
    if let Some(uv) = request.uv {
        options.push((Value::from("uv"), Value::Bool(uv)));
    }
    if !options.is_empty() {
        pairs.push((Value::Int(5), Value::Map(options)));
    }
    if let Some((param, protocol)) = request.pin_auth {
        pairs.push((Value::Int(6), Value::from(param)));
        pairs.push((Value::Int(7), Value::Int(protocol as i64)));
    }
    let mut out = vec![CMD_GET_ASSERTION];
    out.extend(cbor::encode(&Value::Map(pairs)));
    out
}

/// The parts of an assertion the SSH signature needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    /// `authData`: `rpIdHash(32) || flags(1) || signCount(4) || ...`.
    pub auth_data: Vec<u8>,
    /// Raw signature: DER ECDSA for ES256, 64 bytes for EdDSA.
    pub signature: Vec<u8>,
}

impl Assertion {
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.auth_data[32]
    }

    #[must_use]
    pub fn counter(&self) -> u32 {
        u32::from_be_bytes(self.auth_data[33..37].try_into().expect("four bytes"))
    }
}

pub fn parse_get_assertion(response: &[u8]) -> Result<Assertion, CtapError> {
    let map = cbor::decode(response_body(response)?)?;
    let auth_data = map
        .get_int(2)
        .and_then(Value::as_bytes)
        .ok_or(CtapError::Protocol("assertion without authData"))?;
    if auth_data.len() < 37 {
        return Err(CtapError::Protocol("authData shorter than 37 bytes"));
    }
    let signature = map
        .get_int(3)
        .and_then(Value::as_bytes)
        .ok_or(CtapError::Protocol("assertion without signature"))?;
    if signature.is_empty() {
        return Err(CtapError::Protocol("empty assertion signature"));
    }
    Ok(Assertion {
        auth_data: auth_data.to_vec(),
        signature: signature.to_vec(),
    })
}

/// An uncompressed P-256 point as a COSE_Key (`ECDH-ES+HKDF-256`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosePublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl CosePublicKey {
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(3), Value::Int(-25)),
            (Value::Int(-1), Value::Int(1)),
            (Value::Int(-2), Value::from(&self.x[..])),
            (Value::Int(-3), Value::from(&self.y[..])),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, CtapError> {
        let coordinate = |key: i64| -> Result<[u8; 32], CtapError> {
            value
                .get_int(key)
                .and_then(Value::as_bytes)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(CtapError::Protocol(
                    "COSE key coordinate missing or not 32 bytes",
                ))
        };
        if value.get_int(1).and_then(Value::as_int) != Some(2)
            || value.get_int(-1).and_then(Value::as_int) != Some(1)
        {
            return Err(CtapError::Protocol("COSE key is not an EC2 P-256 key"));
        }
        Ok(Self {
            x: coordinate(-2)?,
            y: coordinate(-3)?,
        })
    }
}

const PIN_SUB_GET_KEY_AGREEMENT: i64 = 0x02;
const PIN_SUB_GET_PIN_TOKEN: i64 = 0x05;
const PIN_SUB_GET_PIN_TOKEN_WITH_PERMISSIONS: i64 = 0x09;
/// `pinUvAuthToken` permission bit for `getAssertion`.
pub const PERMISSION_GET_ASSERTION: i64 = 0x02;

#[must_use]
pub fn encode_client_pin_key_agreement(protocol: u64) -> Vec<u8> {
    let mut out = vec![CMD_CLIENT_PIN];
    out.extend(cbor::encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(protocol as i64)),
        (Value::Int(2), Value::Int(PIN_SUB_GET_KEY_AGREEMENT)),
    ])));
    out
}

pub fn parse_key_agreement(response: &[u8]) -> Result<CosePublicKey, CtapError> {
    let map = cbor::decode(response_body(response)?)?;
    let key = map.get_int(1).ok_or(CtapError::Protocol(
        "clientPIN response without keyAgreement",
    ))?;
    CosePublicKey::from_value(key)
}

/// `getPinToken` (0x05), or `getPinUvAuthTokenUsingPinWithPermissions`
/// (0x09) when `permissions` names the operation and relying party.
#[must_use]
pub fn encode_client_pin_get_token(
    protocol: u64,
    platform_key: &CosePublicKey,
    pin_hash_enc: &[u8],
    permissions: Option<(i64, &str)>,
) -> Vec<u8> {
    let subcommand = if permissions.is_some() {
        PIN_SUB_GET_PIN_TOKEN_WITH_PERMISSIONS
    } else {
        PIN_SUB_GET_PIN_TOKEN
    };
    let mut pairs = vec![
        (Value::Int(1), Value::Int(protocol as i64)),
        (Value::Int(2), Value::Int(subcommand)),
        (Value::Int(3), platform_key.to_value()),
        (Value::Int(6), Value::from(pin_hash_enc)),
    ];
    if let Some((bits, rp_id)) = permissions {
        pairs.push((Value::Int(9), Value::Int(bits)));
        pairs.push((Value::Int(10), Value::from(rp_id)));
    }
    let mut out = vec![CMD_CLIENT_PIN];
    out.extend(cbor::encode(&Value::Map(pairs)));
    out
}

/// The still-encrypted `pinUvAuthToken`.
pub fn parse_pin_token(response: &[u8]) -> Result<Zeroizing<Vec<u8>>, CtapError> {
    let map = cbor::decode(response_body(response)?)?;
    map.get_int(2)
        .and_then(Value::as_bytes)
        .map(|bytes| Zeroizing::new(bytes.to_vec()))
        .ok_or(CtapError::Protocol(
            "clientPIN response without pinUvAuthToken",
        ))
}

/// The dummy `makeCredential` libfido2's `fido_dev_get_touch_begin` sends
/// to make a device wait for a touch without creating anything useful: with
/// an empty `pinUvAuthParam` the device asks for presence and then answers
/// with a PIN error. Devices without PIN support get a plain request.
#[must_use]
pub fn encode_touch_probe(with_pin_auth: Option<u64>) -> Vec<u8> {
    let mut pairs = vec![
        (Value::Int(1), Value::Bytes(vec![0; 32])),
        (
            Value::Int(2),
            Value::Map(vec![(Value::from("id"), Value::from("localhost"))]),
        ),
        (
            Value::Int(3),
            Value::Map(vec![
                (Value::from("id"), Value::Bytes(vec![0x01])),
                (Value::from("name"), Value::from("dummy")),
            ]),
        ),
        (
            Value::Int(4),
            Value::Array(vec![Value::Map(vec![
                (Value::from("alg"), Value::Int(-7)),
                (Value::from("type"), Value::from("public-key")),
            ])]),
        ),
    ];
    if let Some(protocol) = with_pin_auth {
        pairs.push((Value::Int(8), Value::Bytes(Vec::new())));
        pairs.push((Value::Int(9), Value::Int(protocol as i64)));
    }
    let mut out = vec![CMD_MAKE_CREDENTIAL];
    out.extend(cbor::encode(&Value::Map(pairs)));
    out
}

#[cfg(test)]
#[path = "ctap2_tests.rs"]
mod tests;
