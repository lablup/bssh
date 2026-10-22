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

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn hkdf_matches_rfc_5869_test_case_1() {
    let okm = hkdf_sha256(
        &hex("000102030405060708090a0b0c"),
        &[0x0b; 22],
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    );
    assert_eq!(
        okm[..],
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
            [..]
    );
}

#[test]
fn protocol_1_derives_sha256_of_the_shared_x_and_uses_a_zero_iv() {
    let x = [0x42; 32];
    let secret = SharedSecret::derive(PinProtocol::V1, &x);
    let expected = SharedSecret::from_keys(
        PinProtocol::V1,
        Sha256::digest(x).into(),
        Sha256::digest(x).into(),
    );
    let block = [0x10; 16];
    let mut rng = rand::rng();
    assert_eq!(
        secret.encrypt(&block, &mut rng).unwrap(),
        expected.encrypt(&block, &mut rng).unwrap()
    );

    // FIPS-197 C.3 AES-256 vector: with a zero IV the first CBC block is
    // plain AES.
    let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .try_into()
        .unwrap();
    let secret = SharedSecret::from_keys(PinProtocol::V1, key, key);
    let plaintext = hex("00112233445566778899aabbccddeeff");
    let ciphertext = secret.encrypt(&plaintext, &mut rng).unwrap();
    assert_eq!(ciphertext, hex("8ea2b7ca516745bfeafc49904b496089"));
    assert_eq!(secret.decrypt(&ciphertext).unwrap()[..], plaintext[..]);
    assert!(secret.encrypt(&[1; 15], &mut rng).is_err());
    assert!(secret.encrypt(&[], &mut rng).is_err());
    assert!(secret.decrypt(&[1; 17]).is_err());
}

#[test]
fn authenticate_is_hmac_sha256_truncated_only_in_protocol_1() {
    // RFC 4231 test case 2.
    let full = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let message = b"what do ya want for nothing?";
    assert_eq!(
        authenticate_with(PinProtocol::V1, b"Jefe", message),
        full[..16]
    );
    assert_eq!(authenticate_with(PinProtocol::V2, b"Jefe", message), full);
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(b"Jefe");
    // A full-length key is a different key, so only the API shape is checked.
    let secret = SharedSecret::from_keys(PinProtocol::V2, key, key);
    assert_eq!(secret.authenticate(message).len(), 32);
    assert_eq!(PinProtocol::V1.auth_len(), 16);
    assert_eq!(PinProtocol::V2.auth_len(), 32);
}

#[test]
fn protocol_2_derives_separate_keys_and_prefixes_a_random_iv() {
    let x = [0x24; 32];
    let secret = SharedSecret::derive(PinProtocol::V2, &x);
    let expected_hmac = hkdf_sha256(&[0; 32], &x, b"CTAP2 HMAC key", 32);
    let expected_aes = hkdf_sha256(&[0; 32], &x, b"CTAP2 AES key", 32);
    assert_ne!(expected_hmac[..], expected_aes[..]);
    let expected = SharedSecret::from_keys(
        PinProtocol::V2,
        expected_hmac[..].try_into().unwrap(),
        expected_aes[..].try_into().unwrap(),
    );
    assert_eq!(secret.authenticate(b"m"), expected.authenticate(b"m"));

    let mut rng = rand::rng();
    let plaintext = [0x77; 32];
    let first = secret.encrypt(&plaintext, &mut rng).unwrap();
    let second = secret.encrypt(&plaintext, &mut rng).unwrap();
    assert_eq!(first.len(), 16 + 32);
    assert_ne!(first, second, "protocol 2 must use a fresh IV");
    assert_eq!(expected.decrypt(&first).unwrap()[..], plaintext);
    assert_eq!(expected.decrypt(&second).unwrap()[..], plaintext);
    assert!(secret.decrypt(&first[..15]).is_err());
    assert!(secret.decrypt(&first[..16]).is_err());
    assert!(secret.decrypt(&first[..40]).is_err());
}

#[test]
fn both_sides_of_the_key_agreement_derive_the_same_secret() {
    let mut rng = rand::rng();
    for protocol in [PinProtocol::V1, PinProtocol::V2] {
        let platform = PlatformKeyAgreement::generate(&mut rng);
        let authenticator = PlatformKeyAgreement::generate(&mut rng);
        let ours = platform
            .shared_secret(protocol, authenticator.public_key())
            .unwrap();
        let theirs = authenticator
            .shared_secret(protocol, platform.public_key())
            .unwrap();
        let pin_hash_enc = ours.encrypt_pin_hash("123456", &mut rng).unwrap();
        let pin_hash = theirs.decrypt(&pin_hash_enc).unwrap();
        assert_eq!(pin_hash[..], Sha256::digest(b"123456")[..16]);
        assert_eq!(ours.authenticate(b"x"), theirs.authenticate(b"x"));
    }
    let bogus = CosePublicKey {
        x: [0xff; 32],
        y: [0xff; 32],
    };
    assert!(
        PlatformKeyAgreement::generate(&mut rng)
            .shared_secret(PinProtocol::V1, &bogus)
            .is_err()
    );
}

#[test]
fn protocol_2_is_preferred_when_advertised() {
    assert_eq!(PinProtocol::select(&[1, 2]), PinProtocol::V2);
    assert_eq!(PinProtocol::select(&[2]), PinProtocol::V2);
    assert_eq!(PinProtocol::select(&[1]), PinProtocol::V1);
    assert_eq!(PinProtocol::select(&[]), PinProtocol::V1);
    assert_eq!(PinProtocol::V1.number(), 1);
    assert_eq!(PinProtocol::V2.number(), 2);
}
