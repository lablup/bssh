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

use super::*;

const CDH: [u8; 32] = [0x11; 32];

fn request<'a>(
    up: Option<bool>,
    uv: Option<bool>,
    pin_auth: Option<(&'a [u8], u64)>,
) -> GetAssertionRequest<'a> {
    GetAssertionRequest {
        rp_id: "ssh:",
        client_data_hash: &CDH,
        credential_id: &[0xaa, 0xbb],
        up,
        uv,
        pin_auth,
    }
}

#[test]
fn get_assertion_encodes_the_spec_layout_in_canonical_order() {
    let mut expected = vec![
        0x02, 0xa4, 0x01, 0x64, b's', b's', b'h', b':', 0x02, 0x58, 0x20,
    ];
    expected.extend_from_slice(&CDH);
    expected.extend_from_slice(&[
        0x03, 0x81, 0xa2, 0x62, b'i', b'd', 0x42, 0xaa, 0xbb, 0x64, b't', b'y', b'p', b'e', 0x6a,
    ]);
    expected.extend_from_slice(b"public-key");
    expected.extend_from_slice(&[0x05, 0xa1, 0x62, b'u', b'p', 0xf5]);
    assert_eq!(
        encode_get_assertion(&request(Some(true), None, None)),
        expected
    );

    // Both options, in canonical (byte) order, and the PIN parameters.
    let param = [0x5a; 16];
    let encoded = encode_get_assertion(&request(Some(false), Some(true), Some((&param, 1))));
    assert_eq!(encoded[1], 0xa6);
    let options_at = encoded.windows(2).position(|w| w == [0x05, 0xa2]).unwrap();
    assert_eq!(
        &encoded[options_at..options_at + 10],
        &[0x05, 0xa2, 0x62, b'u', b'p', 0xf4, 0x62, b'u', b'v', 0xf5]
    );
    let mut tail = vec![0x06, 0x50];
    tail.extend_from_slice(&param);
    tail.extend_from_slice(&[0x07, 0x01]);
    assert!(encoded.ends_with(&tail), "{encoded:02x?}");

    // No options at all when neither is set.
    let encoded = encode_get_assertion(&request(None, None, None));
    assert_eq!(encoded[1], 0xa3);
    assert!(!encoded.windows(2).any(|w| w == [0x05, 0xa1]));
}

fn assertion_response(auth_data: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut response = vec![status::OK];
    response.extend(cbor::encode(&Value::Map(vec![
        (
            Value::Int(1),
            Value::Map(vec![(Value::from("id"), Value::Bytes(vec![1]))]),
        ),
        (Value::Int(2), Value::Bytes(auth_data.to_vec())),
        (Value::Int(3), Value::Bytes(signature.to_vec())),
    ])));
    response
}

#[test]
fn get_assertion_response_yields_flags_counter_and_signature() {
    let mut auth_data = vec![0x33; 32];
    auth_data.push(0x05);
    auth_data.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    let assertion = parse_get_assertion(&assertion_response(&auth_data, &[0x77; 64])).unwrap();
    assert_eq!(assertion.flags(), 0x05);
    assert_eq!(assertion.counter(), 0x0102_0304);
    assert_eq!(assertion.signature, vec![0x77; 64]);

    assert_eq!(
        parse_get_assertion(&assertion_response(&auth_data[..36], &[1])).unwrap_err(),
        CtapError::Protocol("authData shorter than 37 bytes")
    );
    assert_eq!(
        parse_get_assertion(&assertion_response(&auth_data, &[])).unwrap_err(),
        CtapError::Protocol("empty assertion signature")
    );
    assert_eq!(
        parse_get_assertion(&[status::NO_CREDENTIALS]).unwrap_err(),
        CtapError::Status(status::NO_CREDENTIALS)
    );
    assert_eq!(
        parse_get_assertion(&[]).unwrap_err(),
        CtapError::Protocol("empty CTAP2 response")
    );
}

#[test]
fn get_info_reports_versions_options_and_pin_protocols() {
    let mut response = vec![status::OK];
    response.extend(cbor::encode(&Value::Map(vec![
        (
            Value::Int(1),
            Value::Array(vec![Value::from("FIDO_2_1"), Value::from("U2F_V2")]),
        ),
        (
            Value::Int(4),
            Value::Map(vec![
                (Value::from("clientPin"), Value::Bool(true)),
                (Value::from("uv"), Value::Bool(false)),
                (Value::from("pinUvAuthToken"), Value::Bool(true)),
            ]),
        ),
        (
            Value::Int(6),
            Value::Array(vec![Value::Int(2), Value::Int(1)]),
        ),
    ])));
    let info = parse_get_info(&response).unwrap();
    assert_eq!(info.versions, ["FIDO_2_1", "U2F_V2"]);
    assert_eq!(info.option("clientPin"), Some(true));
    assert_eq!(info.option("uv"), Some(false));
    assert_eq!(info.option("rk"), None);
    assert!(info.supports_permissions());
    assert_eq!(info.pin_protocols, [2, 1]);

    let mut minimal = vec![status::OK];
    minimal.extend(cbor::encode(&Value::Map(vec![(
        Value::Int(1),
        Value::Array(vec![Value::from("FIDO_2_0")]),
    )])));
    let info = parse_get_info(&minimal).unwrap();
    assert!(info.options.is_empty());
    assert!(info.pin_protocols.is_empty());
    assert!(!info.supports_permissions());

    let mut no_versions = vec![status::OK];
    no_versions.extend(cbor::encode(&Value::Map(vec![])));
    assert_eq!(
        parse_get_info(&no_versions).unwrap_err(),
        CtapError::Protocol("getInfo without versions")
    );
}

#[test]
fn cose_keys_round_trip_and_reject_other_curves() {
    let key = CosePublicKey {
        x: [1; 32],
        y: [2; 32],
    };
    let value = key.to_value();
    assert_eq!(
        &cbor::encode(&value)[..8],
        &[0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01]
    );
    assert_eq!(CosePublicKey::from_value(&value).unwrap(), key);

    let mut wrong_curve = value.as_map().unwrap().to_vec();
    wrong_curve[2] = (Value::Int(-1), Value::Int(2));
    assert_eq!(
        CosePublicKey::from_value(&Value::Map(wrong_curve)).unwrap_err(),
        CtapError::Protocol("COSE key is not an EC2 P-256 key")
    );
    let mut short = value.as_map().unwrap().to_vec();
    short[3] = (Value::Int(-2), Value::Bytes(vec![1; 31]));
    assert!(CosePublicKey::from_value(&Value::Map(short)).is_err());
}

#[test]
fn client_pin_requests_select_the_subcommand_and_carry_permissions() {
    assert_eq!(
        encode_client_pin_key_agreement(2),
        [0x06, 0xa2, 0x01, 0x02, 0x02, 0x02]
    );
    let platform = CosePublicKey {
        x: [3; 32],
        y: [4; 32],
    };
    let plain = encode_client_pin_get_token(1, &platform, &[0x9c; 16], None);
    assert_eq!(&plain[..6], &[0x06, 0xa4, 0x01, 0x01, 0x02, 0x05]);
    assert!(!plain.windows(2).any(|w| w == [0x09, 0x02]));

    let scoped = encode_client_pin_get_token(
        2,
        &platform,
        &[0x9c; 32],
        Some((PERMISSION_GET_ASSERTION, "ssh:")),
    );
    assert_eq!(&scoped[..6], &[0x06, 0xa6, 0x01, 0x02, 0x02, 0x09]);
    let mut tail = vec![0x09, 0x02, 0x0a, 0x64];
    tail.extend_from_slice(b"ssh:");
    assert!(scoped.ends_with(&tail), "{scoped:02x?}");

    let decoded = cbor::decode(&scoped[1..]).unwrap();
    assert_eq!(
        CosePublicKey::from_value(decoded.get_int(3).unwrap()).unwrap(),
        platform
    );
    assert_eq!(
        decoded.get_int(6).unwrap().as_bytes(),
        Some(&[0x9c; 32][..])
    );
}

#[test]
fn client_pin_responses_are_parsed() {
    let key = CosePublicKey {
        x: [5; 32],
        y: [6; 32],
    };
    let mut response = vec![status::OK];
    response.extend(cbor::encode(&Value::Map(vec![(
        Value::Int(1),
        key.to_value(),
    )])));
    assert_eq!(parse_key_agreement(&response).unwrap(), key);

    let mut response = vec![status::OK];
    response.extend(cbor::encode(&Value::Map(vec![(
        Value::Int(2),
        Value::Bytes(vec![0xab; 32]),
    )])));
    assert_eq!(&parse_pin_token(&response).unwrap()[..], &[0xab; 32]);
    assert_eq!(
        parse_pin_token(&[status::PIN_INVALID]).unwrap_err(),
        CtapError::Status(status::PIN_INVALID)
    );
    let mut without = vec![status::OK];
    without.extend(cbor::encode(&Value::Map(vec![])));
    assert!(parse_pin_token(&without).is_err());
    assert!(parse_key_agreement(&without).is_err());
}

#[test]
fn touch_probe_carries_an_empty_pin_auth_only_for_pin_capable_devices() {
    let with = encode_touch_probe(Some(1));
    assert_eq!(with[0], CMD_MAKE_CREDENTIAL);
    assert_eq!(with[1], 0xa6);
    assert!(with.ends_with(&[0x08, 0x40, 0x09, 0x01]), "{with:02x?}");
    let without = encode_touch_probe(None);
    assert_eq!(without[1], 0xa4);
    assert!(!without.windows(2).any(|w| w == [0x08, 0x40]));
    let decoded = cbor::decode(&without[1..]).unwrap();
    assert_eq!(
        decoded
            .get_int(2)
            .unwrap()
            .get(&Value::from("id"))
            .unwrap()
            .as_text(),
        Some("localhost")
    );
}

#[test]
fn status_names_cover_the_codes_the_sign_path_maps() {
    assert_eq!(status_name(status::NO_CREDENTIALS), "no credentials");
    assert_eq!(status_name(status::PIN_INVALID), "PIN invalid");
    assert_eq!(status_name(status::OPERATION_DENIED), "operation denied");
    assert_eq!(status_name(0xfe), "unknown status");
    assert_eq!(
        CtapError::Status(status::PIN_REQUIRED).to_string(),
        "authenticator returned CTAP2 status 0x36 (PIN required)"
    );
}
