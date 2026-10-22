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
fn integers_use_minimal_heads() {
    let cases: [(i64, &[u8]); 10] = [
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65535, &[0x19, 0xff, 0xff]),
        (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (1 << 32, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        (-1, &[0x20]),
        (-25, &[0x38, 0x18]),
    ];
    for (value, expected) in cases {
        assert_eq!(encode(&Value::Int(value)), expected, "{value}");
        assert_eq!(decode(expected).unwrap(), Value::Int(value), "{value}");
    }
    assert_eq!(
        encode(&Value::Int(i64::MIN)),
        [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    // -2^64 does not fit an i64.
    assert!(decode(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
}

#[test]
fn simple_values_strings_and_arrays_encode_per_rfc_8949() {
    assert_eq!(
        encode(&Value::Bytes(b"abc".to_vec())),
        [0x43, b'a', b'b', b'c']
    );
    assert_eq!(encode(&Value::from("ab")), [0x62, b'a', b'b']);
    assert_eq!(
        encode(&Value::Array(vec![Value::Int(1), Value::Int(2)])),
        [0x82, 0x01, 0x02]
    );
    assert_eq!(encode(&Value::Bool(true)), [0xf5]);
    assert_eq!(encode(&Value::Bool(false)), [0xf4]);
    assert_eq!(encode(&Value::Null), [0xf6]);
    let long = vec![0xab; 300];
    let encoded = encode(&Value::Bytes(long.clone()));
    assert_eq!(&encoded[..3], &[0x59, 0x01, 0x2c]);
    assert_eq!(&encoded[3..], &long[..]);
}

#[test]
fn map_keys_are_sorted_in_ctap2_canonical_order() {
    // A COSE key written in scrambled order must come out as 1, 3, -1, -2, -3:
    // lower major type first (unsigned before negative), then by length,
    // then by bytes.
    let map = Value::Map(vec![
        (Value::Int(-3), Value::Int(0)),
        (Value::Int(1), Value::Int(2)),
        (Value::Int(-1), Value::Int(1)),
        (Value::Int(3), Value::Int(-25)),
        (Value::Int(-2), Value::Int(0)),
    ]);
    assert_eq!(
        encode(&map),
        [
            0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x00, 0x22, 0x00
        ]
    );
    // Text keys: the shorter key sorts first regardless of alphabet, and
    // integer keys sort before text keys.
    let map = Value::Map(vec![
        (Value::from("type"), Value::Int(0)),
        (Value::from("id"), Value::Int(1)),
        (Value::from("zz"), Value::Int(2)),
        (Value::Int(200), Value::Int(3)),
    ]);
    assert_eq!(
        encode(&map),
        [
            0xa4, 0x18, 0xc8, 0x03, 0x62, b'i', b'd', 0x01, 0x62, b'z', b'z', 0x02, 0x64, b't',
            b'y', b'p', b'e', 0x00
        ]
    );
}

#[test]
fn nested_structures_round_trip() {
    let value = Value::Map(vec![
        (Value::Int(1), Value::from("ssh:")),
        (
            Value::Int(3),
            Value::Array(vec![Value::Map(vec![
                (Value::from("id"), Value::Bytes(vec![1, 2, 3])),
                (Value::from("type"), Value::from("public-key")),
            ])]),
        ),
        (
            Value::Int(5),
            Value::Map(vec![(Value::from("up"), Value::Bool(false))]),
        ),
        (Value::Int(-7), Value::Null),
    ]);
    let decoded = decode(&encode(&value)).unwrap();
    assert_eq!(decoded.get_int(1).unwrap().as_text(), Some("ssh:"));
    assert_eq!(
        decoded.get_int(3).unwrap().as_array().unwrap()[0]
            .get(&Value::from("id"))
            .unwrap()
            .as_bytes(),
        Some(&[1u8, 2, 3][..])
    );
    assert_eq!(
        decoded
            .get_int(5)
            .unwrap()
            .get(&Value::from("up"))
            .unwrap()
            .as_bool(),
        Some(false)
    );
    assert_eq!(decoded.get_int(-7), Some(&Value::Null));
    assert_eq!(decoded.get_int(99), None);
}

#[test]
fn decoder_rejects_what_ctap2_forbids() {
    let rejected: [(&[u8], &str); 8] = [
        (&[0x9f, 0x01, 0xff], "indefinite array"),
        (&[0x5f, 0x41, 0x01, 0xff], "indefinite bytes"),
        (&[0x01, 0x02], "trailing bytes"),
        (&[0x43, 0x01], "truncated bytes"),
        (&[0xc0, 0x00], "tag"),
        (&[0xf9, 0x3c, 0x00], "float"),
        (&[0x5a, 0xff, 0xff, 0xff, 0xff], "length beyond input"),
        (&[0x61, 0xff], "invalid UTF-8"),
    ];
    for (input, what) in rejected {
        assert!(decode(input).is_err(), "{what} was accepted");
    }
    let mut deep = vec![0x81; MAX_DEPTH + 2];
    deep.push(0x00);
    assert!(
        decode(&deep).is_err(),
        "nesting beyond {MAX_DEPTH} was accepted"
    );
    let mut shallow = vec![0x81; MAX_DEPTH];
    shallow.push(0x00);
    assert!(decode(&shallow).is_ok());
}
