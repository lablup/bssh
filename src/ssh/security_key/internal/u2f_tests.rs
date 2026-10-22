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

#[test]
fn apdus_use_extended_length_encoding() {
    let apdu = encode_apdu(INS_AUTHENTICATE, P1_CHECK_ONLY, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(
        apdu,
        [
            0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x00
        ]
    );
    let big = encode_apdu(INS_REGISTER, P1_ENFORCE_USER_PRESENCE, &[0; 300]);
    assert_eq!(&big[..7], &[0x00, 0x01, 0x03, 0x00, 0x00, 0x01, 0x2c]);
    assert_eq!(big.len(), 7 + 300 + 2);
}

#[test]
fn authenticate_requests_carry_challenge_application_and_key_handle() {
    let challenge = [0x11; 32];
    let application = [0x22; 32];
    let apdu = encode_authenticate(
        P1_ENFORCE_USER_PRESENCE,
        &challenge,
        &application,
        &[9, 8, 7],
    )
    .unwrap();
    assert_eq!(&apdu[..7], &[0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 68]);
    assert_eq!(&apdu[7..39], &challenge);
    assert_eq!(&apdu[39..71], &application);
    assert_eq!(&apdu[71..75], &[3, 9, 8, 7]);
    assert_eq!(&apdu[75..], &[0, 0]);
    assert!(encode_authenticate(P1_CHECK_ONLY, &challenge, &application, &[]).is_err());
    assert!(encode_authenticate(P1_CHECK_ONLY, &challenge, &application, &[1; 256]).is_err());
    assert!(encode_authenticate(P1_CHECK_ONLY, &challenge, &application, &[1; 255]).is_ok());
    let probe = encode_touch_probe();
    assert_eq!(probe[1], INS_REGISTER);
    assert_eq!(probe[2], 0, "P1 0, as libfido2's u2f_get_touch_begin sends");
    assert_eq!(probe.len(), 7 + 64 + 2);
}

#[test]
fn responses_split_into_data_and_status_word() {
    assert_eq!(
        split_status(&[0x69, 0x85]).unwrap(),
        (&[][..], SW_CONDITIONS_NOT_SATISFIED)
    );
    assert_eq!(
        split_status(&[1, 2, 0x6a, 0x80]).unwrap(),
        (&[1u8, 2][..], SW_WRONG_DATA)
    );
    assert!(split_status(&[0x90]).is_err());
}

#[test]
fn authentication_responses_parse_presence_counter_and_der_signature() {
    let mut data = vec![0x01, 0x00, 0x00, 0x01, 0x02];
    data.extend_from_slice(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    let auth = parse_authenticate(&data).unwrap();
    assert_eq!(auth.presence, 0x01);
    assert_eq!(auth.counter, 0x0102);
    assert_eq!(auth.signature_der, data[5..]);
    assert!(parse_authenticate(&data[..5]).is_err());
}
