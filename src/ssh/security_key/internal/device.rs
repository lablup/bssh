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

//! One opened authenticator: CTAP2 when the device advertises CBOR support
//! and answers `getInfo`, U2F otherwise (libfido2's `fido_dev_open` makes
//! the same decision). Mirrors the parts of `fido_dev_get_assert` and
//! `fido_dev_get_touch_begin/status` that `sk-usbhid.c` relies on.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::ctap2::{self, AuthenticatorInfo, GetAssertionRequest, PERMISSION_GET_ASSERTION};
use super::ctaphid::{CMD_CBOR, CMD_MSG, CtapHidChannel, HidBackend, HidDeviceInfo};
use super::pin_protocol::{PinProtocol, PlatformKeyAgreement, authenticate_with};
use super::u2f;
use super::{CtapError, UserPresence};

/// Pause between U2F presence retries (`U2F_PACE_MS` in libfido2).
const U2F_PACE: Duration = Duration::from_millis(100);

/// What the provider asks the device to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionRequest<'a> {
    pub rp_id: &'a str,
    /// Raw data; the client data hash is `SHA-256(data)`, as
    /// `fido_assert_set_clientdata` computes it.
    pub data: &'a [u8],
    pub credential_id: &'a [u8],
    pub up: Option<bool>,
    pub uv: Option<bool>,
}

/// The parts of the device's answer the SSH signature needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResult {
    pub flags: u8,
    pub counter: u32,
    /// DER ECDSA for P-256 credentials, 64 raw bytes for Ed25519.
    pub signature: Vec<u8>,
}

pub struct Authenticator {
    channel: CtapHidChannel,
    info: Option<AuthenticatorInfo>,
    path: String,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("path", &self.path)
            .field("fido2", &self.info.is_some())
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    pub fn open<R: rand::CryptoRng + ?Sized>(
        backend: &dyn HidBackend,
        device: &HidDeviceInfo,
        rng: &mut R,
    ) -> Result<Self, CtapError> {
        let hid = backend.open(&device.path)?;
        let mut nonce = [0u8; 8];
        rng.fill_bytes(&mut nonce);
        let mut channel = CtapHidChannel::open(hid, nonce)?;
        let info = if channel.supports_cbor() {
            match channel
                .transact(
                    CMD_CBOR,
                    &[ctap2::CMD_GET_INFO],
                    Some(Duration::from_secs(2)),
                )
                .and_then(|reply| ctap2::parse_get_info(&reply))
            {
                Ok(info) => Some(info),
                Err(error) => {
                    tracing::debug!(
                        "{}: getInfo failed ({error}); falling back to U2F",
                        device.path
                    );
                    None
                }
            }
        } else {
            None
        };
        Ok(Self {
            channel,
            info,
            path: device.path.clone(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn is_fido2(&self) -> bool {
        self.info.is_some()
    }

    /// A `getInfo` option, or `None` for U2F devices and unknown options
    /// (`check_sk_options` reports both as `-1`).
    #[must_use]
    pub fn option(&self, name: &str) -> Option<bool> {
        self.info.as_ref()?.option(name)
    }

    /// `fido_dev_get_assert`.
    pub fn get_assertion<R: rand::CryptoRng + ?Sized>(
        &mut self,
        request: &AssertionRequest<'_>,
        pin: Option<&str>,
        timeout: Option<Duration>,
        rng: &mut R,
    ) -> Result<AssertionResult, CtapError> {
        let client_data_hash: [u8; 32] = Sha256::digest(request.data).into();
        match &self.info {
            Some(info) => {
                let info = info.clone();
                self.get_assertion_fido2(&info, request, &client_data_hash, pin, timeout, rng)
            }
            None => self.get_assertion_u2f(request, &client_data_hash, pin, timeout),
        }
    }

    fn get_assertion_fido2<R: rand::CryptoRng + ?Sized>(
        &mut self,
        info: &AuthenticatorInfo,
        request: &AssertionRequest<'_>,
        client_data_hash: &[u8; 32],
        pin: Option<&str>,
        timeout: Option<Duration>,
        rng: &mut R,
    ) -> Result<AssertionResult, CtapError> {
        let pin_auth: Option<(Zeroizing<Vec<u8>>, PinProtocol)> = match pin {
            Some(pin) => {
                let (token, protocol) = self.pin_token(info, request.rp_id, pin, timeout, rng)?;
                let param = Zeroizing::new(authenticate_with(protocol, &token, client_data_hash));
                Some((param, protocol))
            }
            None => None,
        };
        let encoded = ctap2::encode_get_assertion(&GetAssertionRequest {
            rp_id: request.rp_id,
            client_data_hash,
            credential_id: request.credential_id,
            up: request.up,
            uv: request.uv,
            pin_auth: pin_auth
                .as_ref()
                .map(|(param, protocol)| (&param[..], protocol.number())),
        });
        let reply = self.channel.transact(CMD_CBOR, &encoded, timeout)?;
        let assertion = ctap2::parse_get_assertion(&reply)?;
        Ok(AssertionResult {
            flags: assertion.flags(),
            counter: assertion.counter(),
            signature: assertion.signature,
        })
    }

    /// `fido_dev_get_uv_token`: agree on a shared secret, prove the PIN,
    /// and decrypt the token the device hands back.
    fn pin_token<R: rand::CryptoRng + ?Sized>(
        &mut self,
        info: &AuthenticatorInfo,
        rp_id: &str,
        pin: &str,
        timeout: Option<Duration>,
        rng: &mut R,
    ) -> Result<(Zeroizing<Vec<u8>>, PinProtocol), CtapError> {
        let protocol = PinProtocol::select(&info.pin_protocols);
        let platform = PlatformKeyAgreement::generate(rng);
        let reply = self.channel.transact(
            CMD_CBOR,
            &ctap2::encode_client_pin_key_agreement(protocol.number()),
            timeout,
        )?;
        let peer = ctap2::parse_key_agreement(&reply)?;
        let secret = platform.shared_secret(protocol, &peer)?;
        let pin_hash_enc = secret.encrypt_pin_hash(pin, rng)?;
        let permissions = info
            .supports_permissions()
            .then_some((PERMISSION_GET_ASSERTION, rp_id));
        let reply = self.channel.transact(
            CMD_CBOR,
            &ctap2::encode_client_pin_get_token(
                protocol.number(),
                platform.public_key(),
                &pin_hash_enc,
                permissions,
            ),
            timeout,
        )?;
        let token = secret.decrypt(&ctap2::parse_pin_token(&reply)?)?;
        Ok((token, protocol))
    }

    /// `u2f_authenticate`: look the key handle up with a check-only request,
    /// then sign with user presence enforced, retrying while the device
    /// reports that the user has not touched it yet.
    fn get_assertion_u2f(
        &mut self,
        request: &AssertionRequest<'_>,
        client_data_hash: &[u8; 32],
        pin: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<AssertionResult, CtapError> {
        if pin.is_some() || request.uv == Some(true) {
            return Err(CtapError::Unsupported(
                "U2F authenticators support neither PINs nor user verification",
            ));
        }
        let application: [u8; 32] = Sha256::digest(request.rp_id.as_bytes()).into();
        let lookup = u2f::encode_authenticate(
            u2f::P1_CHECK_ONLY,
            &[0u8; 32],
            &application,
            request.credential_id,
        )?;
        let reply = self.channel.transact(CMD_MSG, &lookup, timeout)?;
        match u2f::split_status(&reply)?.1 {
            u2f::SW_CONDITIONS_NOT_SATISFIED => {}
            u2f::SW_WRONG_DATA => return Err(CtapError::Status(ctap2::status::NO_CREDENTIALS)),
            other => return Err(CtapError::Apdu(other)),
        }
        if request.up == Some(false) {
            // The credential exists; a signature needs a touch U2F cannot skip.
            return Err(CtapError::UserPresenceRequired);
        }
        let sign = u2f::encode_authenticate(
            u2f::P1_ENFORCE_USER_PRESENCE,
            client_data_hash,
            &application,
            request.credential_id,
        )?;
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        loop {
            let reply = self.channel.transact(CMD_MSG, &sign, timeout)?;
            let (data, sw) = u2f::split_status(&reply)?;
            match sw {
                u2f::SW_NO_ERROR => {
                    let auth = u2f::parse_authenticate(data)?;
                    return Ok(AssertionResult {
                        flags: auth.presence,
                        counter: auth.counter,
                        signature: auth.signature_der,
                    });
                }
                u2f::SW_CONDITIONS_NOT_SATISFIED => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(CtapError::Timeout);
                    }
                    std::thread::sleep(U2F_PACE);
                }
                other => return Err(CtapError::Apdu(other)),
            }
        }
    }

    /// `fido_dev_get_touch_begin`: make the device wait for a touch.
    pub fn touch_begin(&mut self) -> Result<(), CtapError> {
        match &self.info {
            Some(info) => {
                let pin_auth = info
                    .option("clientPin")
                    .is_some()
                    .then(|| PinProtocol::select(&info.pin_protocols).number());
                self.channel
                    .send(CMD_CBOR, &ctap2::encode_touch_probe(pin_auth))
            }
            None => self.channel.send(CMD_MSG, &u2f::encode_touch_probe()),
        }
    }

    /// `fido_dev_get_touch_status`: did the device answer the probe within
    /// `poll`? Any CTAP2 answer means the user touched it; a U2F device
    /// answering "conditions not satisfied" is asked again.
    pub fn touch_status(&mut self, poll: Duration) -> Result<UserPresence, CtapError> {
        let Some((_, reply)) = self.channel.receive(Some(poll))? else {
            return Ok(UserPresence::Waiting);
        };
        if self.info.is_some() {
            return Ok(UserPresence::Touched);
        }
        match u2f::split_status(&reply)?.1 {
            u2f::SW_NO_ERROR => Ok(UserPresence::Touched),
            u2f::SW_CONDITIONS_NOT_SATISFIED => {
                self.channel.send(CMD_MSG, &u2f::encode_touch_probe())?;
                Ok(UserPresence::Waiting)
            }
            other => Err(CtapError::Apdu(other)),
        }
    }

    /// Stop waiting on this device.
    pub fn cancel(&mut self) {
        if let Err(error) = self.channel.cancel() {
            tracing::debug!("{}: cancel failed: {error}", self.path);
        }
    }
}
