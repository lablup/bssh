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

//! The built-in `SecurityKeyProvider internal`: USB HID authenticators
//! driven over CTAPHID, after OpenSSH's `sk-usbhid.c` (which uses libfido2).
//!
//! Layers, bottom up: [`ctaphid`] (report framing and channels over a
//! [`HidDevice`](ctaphid::HidDevice) trait), [`cbor`], [`ctap2`] and
//! [`u2f`] (messages), [`pin_protocol`] (PIN/UV auth protocols 1 and 2),
//! [`device`] (one authenticator's `getAssertion` with PIN and U2F
//! fallback), [`select`] (which attached device to use), and
//! [`InternalProvider`], which is `sk_sign` behind the
//! [`SecurityKeyProvider`] trait. Only [`hidapi_backend`] touches the OS.
//!
//! Only signing exists. Enrollment (`ssh-keygen -t ed25519-sk`) and resident
//! key loading (`ssh-keygen -K`) stay with OpenSSH's tools.
//!
//! One deliberate deviation from libfido2: a whole `sk_sign` call is bounded
//! by [`SIGN_TIMEOUT`] (120 s, sshd's default `LoginGraceTime`). libfido2
//! waits without limit for a reply, so a device that streams KEEPALIVE or
//! frames for other channels forever, or a U2F key nobody touches, holds
//! `ssh` until the user interrupts it. bssh serializes every provider call
//! in the process behind one lock, so such a device would stall
//! authentication to every host. On expiry the pending request is cancelled
//! (on CTAP2 devices), the signature fails with "timed out waiting for the
//! security key", and authentication moves on to the next identity.

pub mod cbor;
pub mod ctap2;
pub mod ctaphid;
pub mod device;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod hidapi_backend;
#[cfg(test)]
pub(crate) mod mock;
pub mod pin_protocol;
pub mod select;
pub mod u2f;

use std::sync::Arc;
use std::time::{Duration, Instant};

use p256::ecdsa::Signature as EcdsaSignature;
use zeroize::Zeroizing;

use super::{
    SK_FLAG_USER_PRESENCE_REQUIRED, SK_FLAG_USER_VERIFICATION_REQUIRED, SecurityKeyError,
    SecurityKeyProvider, SkAlgorithm, SkSignRequest, SkSignResponse,
};
use ctaphid::HidBackend;
use device::{AssertionRequest, AssertionResult};
use select::Probe;

/// Failures below the sk-api surface. [`SecurityKeyError::from`] folds them
/// into the codes `fidoerr_to_skerr` would produce.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CtapError {
    #[error("HID transport: {0}")]
    Transport(String),
    #[error("CTAPHID error {0:#04x}")]
    HidError(u8),
    #[error("CTAPHID protocol: {0}")]
    Protocol(&'static str),
    #[error("timed out waiting for the authenticator")]
    Timeout,
    /// The overall [`SIGN_TIMEOUT`] of one signature ran out.
    #[error("timed out waiting for the security key")]
    DeadlineExceeded,
    #[error("authenticator returned CTAP2 status {code:#04x} ({name})", code = .0, name = ctap2::status_name(*.0))]
    Status(u8),
    #[error("authenticator returned U2F status {0:#06x}")]
    Apdu(u16),
    #[error("CBOR: {0}")]
    Cbor(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// A U2F device recognised the key handle but needs a touch to sign.
    #[error("user presence required")]
    UserPresenceRequired,
}

/// Outcome of one touch poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPresence {
    Touched,
    Waiting,
}

impl From<CtapError> for SecurityKeyError {
    /// `fidoerr_to_skerr`: unsupported options and algorithms map to
    /// `SSH_SK_ERR_UNSUPPORTED`; PIN required/invalid and operation denied
    /// map to `SSH_SK_ERR_PIN_REQUIRED`; everything else is a general
    /// failure, which keeps its description here.
    fn from(error: CtapError) -> Self {
        use ctap2::status;
        match error {
            CtapError::Status(status::UNSUPPORTED_OPTION | status::UNSUPPORTED_ALGORITHM)
            | CtapError::Unsupported(_) => Self::Unsupported,
            CtapError::Status(
                status::PIN_INVALID | status::PIN_REQUIRED | status::OPERATION_DENIED,
            ) => Self::PinRequired,
            other => Self::Failed(other.to_string()),
        }
    }
}

/// Bound on one whole `sk_sign` call; see the module documentation.
pub const SIGN_TIMEOUT: Duration = Duration::from_secs(120);
/// `SELECT_MS`: how long a touch is awaited when several devices are attached.
pub const SELECT_TIMEOUT: Duration = Duration::from_secs(15);
/// `POLL_SLEEP_NS`: pause before each touch-polling round.
pub const POLL_SLEEP: Duration = Duration::from_millis(200);

/// The provider's waits. Only tests change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub sign_timeout: Duration,
    pub select_timeout: Duration,
    pub poll_sleep: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            sign_timeout: SIGN_TIMEOUT,
            select_timeout: SELECT_TIMEOUT,
            poll_sleep: POLL_SLEEP,
        }
    }
}

/// `sk_sign` over USB HID.
pub struct InternalProvider {
    backend: Arc<dyn HidBackend>,
    timing: Timing,
}

impl std::fmt::Debug for InternalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalProvider").finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Default for InternalProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InternalProvider {
    /// The provider over the host's HID devices.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(Arc::new(hidapi_backend::HidapiBackend::default()))
    }

    #[must_use]
    pub fn with_backend(backend: Arc<dyn HidBackend>) -> Self {
        Self {
            backend,
            timing: Timing::default(),
        }
    }

    /// Replace the waits (tests use short ones).
    #[must_use]
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }
}

impl SecurityKeyProvider for InternalProvider {
    fn sign(
        &self,
        request: &SkSignRequest<'_>,
        pin: Option<&str>,
    ) -> Result<SkSignResponse, SecurityKeyError> {
        request.validate()?;
        let deadline = Instant::now() + self.timing.sign_timeout;
        let mut rng = rand::rng();
        let wants_uv = request.flags & SK_FLAG_USER_VERIFICATION_REQUIRED != 0;
        // With a PIN in hand or verification required, the probe assertion
        // would itself need the PIN, so the device is chosen by touch.
        let probe = if pin.is_some() || wants_uv {
            Probe::ByTouch
        } else {
            Probe::ByCredential {
                application: request.application,
                key_handle: request.key_handle,
            }
        };
        let selected = select::probe(&*self.backend, probe, &self.timing, deadline, &mut rng)
            .map_err(|error| past_deadline(error, deadline))?;
        let Some(mut device) = selected else {
            return Err(if Instant::now() >= deadline {
                CtapError::DeadlineExceeded.into()
            } else {
                SecurityKeyError::DeviceNotFound
            });
        };
        if !device.is_fido2() && request.algorithm == SkAlgorithm::Ed25519 {
            return Err(SecurityKeyError::Unsupported);
        }
        let up = Some(request.flags & SK_FLAG_USER_PRESENCE_REQUIRED != 0);
        let mut uv = None;
        if pin.is_none() && wants_uv {
            // Without a PIN, verification must come from the device itself
            // (biometrics); a device that cannot verify needs the PIN.
            if device.option("uv") != Some(true) {
                return Err(SecurityKeyError::PinRequired);
            }
            uv = Some(true);
        }
        let assertion = device.get_assertion(
            &AssertionRequest {
                rp_id: request.application,
                data: request.data,
                credential_id: request.key_handle,
                up,
                uv,
            },
            pin,
            deadline,
            &mut rng,
        );
        let assertion = match assertion {
            Ok(assertion) => assertion,
            Err(error) => {
                let error = past_deadline(error, deadline);
                if error == CtapError::DeadlineExceeded {
                    // Stop the device from waiting for a touch nobody gives.
                    device.cancel();
                }
                return Err(error.into());
            }
        };
        pack_signature(request.algorithm, &assertion)
    }

    fn describe(&self) -> String {
        "internal".to_string()
    }
}

/// A wait that ended because the overall deadline passed.
fn past_deadline(error: CtapError, deadline: Instant) -> CtapError {
    if error == CtapError::Timeout && Instant::now() >= deadline {
        CtapError::DeadlineExceeded
    } else {
        error
    }
}

/// `pack_sig`: the device signature as sk-api `sig_r`/`sig_s`. ECDSA
/// components are the minimal big-endian integers `BN_bn2bin` produces;
/// an Ed25519 signature travels whole in `sig_r`.
pub fn pack_signature(
    algorithm: SkAlgorithm,
    assertion: &AssertionResult,
) -> Result<SkSignResponse, SecurityKeyError> {
    let (sig_r, sig_s) = match algorithm {
        SkAlgorithm::Ed25519 => {
            if assertion.signature.len() != 64 {
                return Err(SecurityKeyError::InvalidResponse(
                    "Ed25519 assertion signature is not 64 bytes",
                ));
            }
            (assertion.signature.clone(), Vec::new())
        }
        SkAlgorithm::EcdsaSha2NistP256 => {
            let signature = EcdsaSignature::from_der(&assertion.signature)
                .map_err(|_| SecurityKeyError::InvalidResponse("malformed DER ECDSA signature"))?;
            let (r, s) = signature.split_bytes();
            (minimal_big_endian(&r), minimal_big_endian(&s))
        }
    };
    Ok(SkSignResponse {
        flags: assertion.flags,
        counter: assertion.counter,
        sig_r: Zeroizing::new(sig_r),
        sig_s: Zeroizing::new(sig_s),
    })
}

/// Strip leading zero bytes the way `BN_bn2bin` omits them.
fn minimal_big_endian(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "selection_tests.rs"]
mod selection_tests;

#[cfg(test)]
#[path = "robustness_tests.rs"]
mod robustness_tests;
