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

//! CTAP2 PIN/UV auth protocols 1 and 2 (CTAP 2.1 section 6.5.6 and 6.5.7).
//!
//! Both start from an ECDH P-256 agreement with the authenticator. Protocol
//! 1 uses `SHA-256(x)` as the single key, AES-256-CBC with a zero IV, and the
//! first 16 bytes of HMAC-SHA-256; protocol 2 derives separate HMAC and AES
//! keys with HKDF, prepends a random IV, and uses the full HMAC. libfido2
//! picks 2 when the authenticator lists it, and so does this module.
//!
//! Every key, hash and token lives in `Zeroizing` memory; the PIN itself is
//! only ever hashed here and never logged.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::CtapError;
use super::ctap2::CosePublicKey;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

const AES_BLOCK_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    V1,
    V2,
}

impl PinProtocol {
    /// The `pinUvAuthProtocol` number on the wire.
    #[must_use]
    pub const fn number(self) -> u64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// Prefer protocol 2 when the device lists it; a device that lists
    /// nothing is a CTAP 2.0 device, which implements protocol 1.
    #[must_use]
    pub fn select(advertised: &[u64]) -> Self {
        if advertised.contains(&2) {
            Self::V2
        } else {
            Self::V1
        }
    }

    /// Length of a `pinUvAuthParam` under this protocol.
    #[must_use]
    pub const fn auth_len(self) -> usize {
        match self {
            Self::V1 => 16,
            Self::V2 => 32,
        }
    }
}

/// The platform's ephemeral ECDH key for one PIN exchange.
pub struct PlatformKeyAgreement {
    secret: EphemeralSecret,
    public: CosePublicKey,
}

impl std::fmt::Debug for PlatformKeyAgreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformKeyAgreement")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PlatformKeyAgreement {
    pub fn generate<R: rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let secret = EphemeralSecret::generate_from_rng(rng);
        let point = secret.public_key().to_sec1_point(false);
        let coordinate = |bytes: Option<&p256::FieldBytes>| -> [u8; 32] {
            bytes
                .map(|bytes| {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(bytes);
                    out
                })
                .expect("uncompressed point has both coordinates")
        };
        let public = CosePublicKey {
            x: coordinate(point.x()),
            y: coordinate(point.y()),
        };
        Self { secret, public }
    }

    #[must_use]
    pub fn public_key(&self) -> &CosePublicKey {
        &self.public
    }

    /// Complete the agreement with the authenticator's key.
    pub fn shared_secret(
        &self,
        protocol: PinProtocol,
        peer: &CosePublicKey,
    ) -> Result<SharedSecret, CtapError> {
        let mut encoded = Vec::with_capacity(65);
        encoded.push(0x04);
        encoded.extend_from_slice(&peer.x);
        encoded.extend_from_slice(&peer.y);
        let peer = p256::PublicKey::from_sec1_bytes(&encoded)
            .map_err(|_| CtapError::Protocol("authenticator key agreement point is invalid"))?;
        let shared = self.secret.diffie_hellman(&peer);
        let mut x = Zeroizing::new([0u8; 32]);
        x.copy_from_slice(shared.raw_secret_bytes());
        Ok(SharedSecret::derive(protocol, &x))
    }
}

/// Keys derived from the ECDH shared point.
pub struct SharedSecret {
    protocol: PinProtocol,
    hmac_key: Zeroizing<[u8; 32]>,
    aes_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// `kdf(Z)` of the protocol, with `Z` the x coordinate of the shared point.
    #[must_use]
    pub fn derive(protocol: PinProtocol, point_x: &[u8; 32]) -> Self {
        match protocol {
            PinProtocol::V1 => {
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&Sha256::digest(point_x));
                Self {
                    protocol,
                    hmac_key: key.clone(),
                    aes_key: key,
                }
            }
            PinProtocol::V2 => {
                let salt = [0u8; 32];
                let hmac = hkdf_sha256(&salt, point_x, b"CTAP2 HMAC key", 32);
                let aes = hkdf_sha256(&salt, point_x, b"CTAP2 AES key", 32);
                let mut hmac_key = Zeroizing::new([0u8; 32]);
                hmac_key.copy_from_slice(&hmac);
                let mut aes_key = Zeroizing::new([0u8; 32]);
                aes_key.copy_from_slice(&aes);
                Self {
                    protocol,
                    hmac_key,
                    aes_key,
                }
            }
        }
    }

    /// Build from known keys, for test vectors.
    #[cfg(test)]
    pub(crate) fn from_keys(protocol: PinProtocol, hmac_key: [u8; 32], aes_key: [u8; 32]) -> Self {
        Self {
            protocol,
            hmac_key: Zeroizing::new(hmac_key),
            aes_key: Zeroizing::new(aes_key),
        }
    }

    #[must_use]
    pub fn protocol(&self) -> PinProtocol {
        self.protocol
    }

    /// `encrypt(key, demPlaintext)`; the plaintext must be whole AES blocks.
    pub fn encrypt<R: rand::CryptoRng + ?Sized>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        if plaintext.is_empty() || !plaintext.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(CtapError::Protocol(
                "PIN protocol plaintext is not whole blocks",
            ));
        }
        let mut iv = [0u8; AES_BLOCK_LEN];
        if self.protocol == PinProtocol::V2 {
            rng.fill_bytes(&mut iv);
        }
        let cipher = Aes256CbcEncryptor::new_from_slices(&self.aes_key[..], &iv)
            .map_err(|_| CtapError::Protocol("AES key or IV length"))?;
        let ciphertext = cipher.encrypt_padded_vec::<NoPadding>(plaintext);
        Ok(match self.protocol {
            PinProtocol::V1 => ciphertext,
            PinProtocol::V2 => {
                let mut out = Vec::with_capacity(AES_BLOCK_LEN + ciphertext.len());
                out.extend_from_slice(&iv);
                out.extend(ciphertext);
                out
            }
        })
    }

    /// `decrypt(key, demCiphertext)`.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CtapError> {
        let (iv, body): ([u8; AES_BLOCK_LEN], &[u8]) = match self.protocol {
            PinProtocol::V1 => ([0u8; AES_BLOCK_LEN], ciphertext),
            PinProtocol::V2 => {
                if ciphertext.len() < AES_BLOCK_LEN {
                    return Err(CtapError::Protocol("PIN protocol 2 ciphertext without IV"));
                }
                let (iv, body) = ciphertext.split_at(AES_BLOCK_LEN);
                (iv.try_into().expect("16 bytes"), body)
            }
        };
        if body.is_empty() || !body.len().is_multiple_of(AES_BLOCK_LEN) {
            return Err(CtapError::Protocol(
                "PIN protocol ciphertext is not whole blocks",
            ));
        }
        let cipher = Aes256CbcDecryptor::new_from_slices(&self.aes_key[..], &iv)
            .map_err(|_| CtapError::Protocol("AES key or IV length"))?;
        cipher
            .decrypt_padded_vec::<NoPadding>(body)
            .map(Zeroizing::new)
            .map_err(|_| CtapError::Protocol("PIN protocol decryption failed"))
    }

    /// `authenticate(key, message)` with the shared HMAC key.
    #[must_use]
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        authenticate_with(self.protocol, &self.hmac_key[..], message)
    }

    /// `pinHashEnc`: the first 16 bytes of `SHA-256(pin)`, encrypted.
    pub fn encrypt_pin_hash<R: rand::CryptoRng + ?Sized>(
        &self,
        pin: &str,
        rng: &mut R,
    ) -> Result<Vec<u8>, CtapError> {
        let hash = Zeroizing::new(Sha256::digest(pin.as_bytes()));
        self.encrypt(&hash[..16], rng)
    }
}

/// `authenticate(key, message)` with an arbitrary key, as used with the
/// `pinUvAuthToken` to compute `pinUvAuthParam`.
#[must_use]
pub fn authenticate_with(protocol: PinProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    tag[..protocol.auth_len()].to_vec()
}

/// HKDF-SHA-256 (RFC 5869) extract-and-expand.
#[must_use]
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut extract = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk = Zeroizing::new(extract.finalize().into_bytes());
    let mut okm = Zeroizing::new(Vec::with_capacity(len));
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut expand = HmacSha256::new_from_slice(&prk[..]).expect("HMAC accepts any key length");
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        let take = (len - okm.len()).min(previous.len());
        okm.extend_from_slice(&previous[..take]);
        counter += 1;
    }
    okm
}

#[cfg(test)]
#[path = "pin_protocol_tests.rs"]
mod tests;
