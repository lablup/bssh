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

//! SSH signature blob assembly for `sk-*` keys (`sshsk_sign` in `ssh-sk.c`).

use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::Mpint;
use zeroize::Zeroizing;

use super::{SecurityKeyError, SkAlgorithm};

/// The provider's `struct sk_sign_response`, copied out of C memory.
///
/// `sig_s` is empty for Ed25519, whose whole signature travels in `sig_r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkSignResponse {
    pub flags: u8,
    pub counter: u32,
    pub sig_r: Zeroizing<Vec<u8>>,
    pub sig_s: Zeroizing<Vec<u8>>,
}

/// Build the wire signature `string name || string sig || u8 flags || u32 counter`.
///
/// For ECDSA the inner `sig` is `mpint r || mpint s`; for Ed25519 it is the
/// raw 64-byte signature. This is the blob an agent returns for the same key,
/// so russh and OpenSSH both decode it unchanged.
pub fn encode_signature(
    algorithm: SkAlgorithm,
    response: &SkSignResponse,
) -> Result<Vec<u8>, SecurityKeyError> {
    let inner = match algorithm {
        SkAlgorithm::Ed25519 => {
            if response.sig_r.is_empty() {
                return Err(SecurityKeyError::InvalidResponse("missing sig_r"));
            }
            response.sig_r.to_vec()
        }
        SkAlgorithm::EcdsaSha2NistP256 => {
            if response.sig_r.is_empty() || response.sig_s.is_empty() {
                return Err(SecurityKeyError::InvalidResponse("missing sig_r or sig_s"));
            }
            let mut inner = Vec::new();
            for component in [&response.sig_r, &response.sig_s] {
                Mpint::from_positive_bytes(component)
                    .encode(&mut inner)
                    .map_err(|_| SecurityKeyError::InvalidResponse("malformed ECDSA component"))?;
            }
            inner
        }
    };
    let mut blob = Vec::new();
    algorithm
        .ssh_name()
        .encode(&mut blob)
        .and_then(|()| inner.as_slice().encode(&mut blob))
        .and_then(|()| response.flags.encode(&mut blob))
        .and_then(|()| response.counter.encode(&mut blob))
        .map_err(|_| SecurityKeyError::InvalidResponse("signature encoding failed"))?;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_encoding::Decode;
    use russh::keys::ssh_key::{Algorithm, Signature};

    fn response(sig_r: &[u8], sig_s: &[u8]) -> SkSignResponse {
        SkSignResponse {
            flags: 0x01,
            counter: 0x1234_5678,
            sig_r: Zeroizing::new(sig_r.to_vec()),
            sig_s: Zeroizing::new(sig_s.to_vec()),
        }
    }

    #[test]
    fn ed25519_blob_is_name_signature_flags_counter() {
        let sig = [0xabu8; 64];
        let blob = encode_signature(SkAlgorithm::Ed25519, &response(&sig, &[])).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&26u32.to_be_bytes());
        expected.extend_from_slice(b"sk-ssh-ed25519@openssh.com");
        expected.extend_from_slice(&64u32.to_be_bytes());
        expected.extend_from_slice(&sig);
        expected.push(0x01);
        expected.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        assert_eq!(blob, expected);

        let decoded = Signature::decode(&mut blob.as_slice()).unwrap();
        assert_eq!(decoded.algorithm(), Algorithm::SkEd25519);
        assert_eq!(&decoded.as_bytes()[..64], &sig);
        assert_eq!(&decoded.as_bytes()[64..], &[0x01, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn ecdsa_blob_wraps_r_and_s_as_mpints_inside_one_string() {
        let mut r = [0x11u8; 32];
        r[0] = 0x80;
        let s = [0x22u8; 32];
        let blob = encode_signature(SkAlgorithm::EcdsaSha2NistP256, &response(&r, &s)).unwrap();

        let mut inner = Vec::new();
        inner.extend_from_slice(&33u32.to_be_bytes());
        inner.push(0);
        inner.extend_from_slice(&r);
        inner.extend_from_slice(&32u32.to_be_bytes());
        inner.extend_from_slice(&s);
        let mut expected = Vec::new();
        expected.extend_from_slice(&34u32.to_be_bytes());
        expected.extend_from_slice(b"sk-ecdsa-sha2-nistp256@openssh.com");
        expected.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        expected.extend_from_slice(&inner);
        expected.push(0x01);
        expected.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        assert_eq!(blob, expected);

        let decoded = Signature::decode(&mut blob.as_slice()).unwrap();
        assert_eq!(decoded.algorithm(), Algorithm::SkEcdsaSha2NistP256);
        assert_eq!(decoded.as_bytes().len(), inner.len() + 5);
    }

    #[test]
    fn incomplete_responses_are_rejected() {
        assert_eq!(
            encode_signature(SkAlgorithm::Ed25519, &response(&[], &[])).unwrap_err(),
            SecurityKeyError::InvalidResponse("missing sig_r")
        );
        assert_eq!(
            encode_signature(SkAlgorithm::EcdsaSha2NistP256, &response(&[1; 32], &[])).unwrap_err(),
            SecurityKeyError::InvalidResponse("missing sig_r or sig_s")
        );
    }
}
