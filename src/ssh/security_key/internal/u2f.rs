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

//! CTAP1/U2F raw messages (FIDO U2F Raw Message Formats), carried in
//! `CTAPHID_MSG` as extended-length ISO 7816-4 APDUs, for authenticators
//! that predate CTAP2. Only ECDSA P-256 keys exist in U2F.

use super::CtapError;

pub const INS_REGISTER: u8 = 0x01;
pub const INS_AUTHENTICATE: u8 = 0x02;

/// `P1` of AUTHENTICATE: check whether the key handle belongs to the
/// application without signing.
pub const P1_CHECK_ONLY: u8 = 0x07;
/// `P1` of AUTHENTICATE: sign, requiring user presence.
pub const P1_ENFORCE_USER_PRESENCE: u8 = 0x03;

pub const SW_NO_ERROR: u16 = 0x9000;
/// The key handle is valid, but the user has not touched the device yet.
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// The key handle does not belong to this device or application.
pub const SW_WRONG_DATA: u16 = 0x6a80;

/// Largest key handle a one-byte length field can carry.
const MAX_KEY_HANDLE_LEN: usize = 255;

/// Build an extended-length APDU: `CLA INS P1 P2 00 Lc(2) data Le(2)`.
#[must_use]
pub fn encode_apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = Vec::with_capacity(9 + data.len());
    apdu.extend_from_slice(&[0x00, ins, p1, 0x00, 0x00]);
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu.extend_from_slice(&[0x00, 0x00]);
    apdu
}

/// U2F AUTHENTICATE request data:
/// `challenge(32) || application(32) || len(1) || key handle`.
pub fn encode_authenticate(
    p1: u8,
    challenge: &[u8; 32],
    application: &[u8; 32],
    key_handle: &[u8],
) -> Result<Vec<u8>, CtapError> {
    if key_handle.is_empty() || key_handle.len() > MAX_KEY_HANDLE_LEN {
        return Err(CtapError::Unsupported(
            "key handle length is not valid for U2F",
        ));
    }
    let mut data = Vec::with_capacity(65 + key_handle.len());
    data.extend_from_slice(challenge);
    data.extend_from_slice(application);
    data.push(key_handle.len() as u8);
    data.extend_from_slice(key_handle);
    Ok(encode_apdu(INS_AUTHENTICATE, p1, &data))
}

/// U2F REGISTER with dummy parameters, used only to make a device wait for a
/// touch during multi-device selection. `P1` is 0, as in libfido2's
/// `u2f_get_touch_begin`.
#[must_use]
pub fn encode_touch_probe() -> Vec<u8> {
    encode_apdu(INS_REGISTER, 0x00, &[0u8; 64])
}

/// Split a response into its data and status word.
pub fn split_status(response: &[u8]) -> Result<(&[u8], u16), CtapError> {
    if response.len() < 2 {
        return Err(CtapError::Protocol(
            "U2F response shorter than a status word",
        ));
    }
    let (data, sw) = response.split_at(response.len() - 2);
    Ok((data, u16::from_be_bytes([sw[0], sw[1]])))
}

/// A successful AUTHENTICATE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    /// The user-presence byte (bit 0 set when the user touched the device).
    pub presence: u8,
    pub counter: u32,
    /// DER-encoded ECDSA signature.
    pub signature_der: Vec<u8>,
}

/// Parse the data part of an AUTHENTICATE response:
/// `presence(1) || counter(4) || DER signature`.
pub fn parse_authenticate(data: &[u8]) -> Result<Authentication, CtapError> {
    if data.len() < 6 {
        return Err(CtapError::Protocol("U2F authentication response too short"));
    }
    Ok(Authentication {
        presence: data[0],
        counter: u32::from_be_bytes(data[1..5].try_into().expect("four bytes")),
        signature_der: data[5..].to_vec(),
    })
}

#[cfg(test)]
#[path = "u2f_tests.rs"]
mod tests;
