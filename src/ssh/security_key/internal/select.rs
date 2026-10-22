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

//! Device discovery and selection, after `sk_probe`, `sk_select_by_cred`
//! and `sk_select_by_touch` in `sk-usbhid.c`.

use std::time::{Duration, Instant};

use super::ctaphid::{HidBackend, HidDeviceInfo};
use super::device::{AssertionRequest, Authenticator};
use super::{CtapError, UserPresence};

/// `SELECT_MS`: how long a touch is awaited when several devices are attached.
const SELECT_TIMEOUT: Duration = Duration::from_secs(15);
/// `FIDO_POLL_MS`: per-device wait in each polling round.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How `sk_probe` chooses among attached devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe<'a> {
    /// Pick the device holding the credential (silent per-device assertion).
    ByCredential {
        application: &'a str,
        key_handle: &'a [u8],
    },
    /// Pick the device the user touches (a PIN or user verification is
    /// involved, so a silent assertion would not be possible anyway).
    ByTouch,
}

/// Attached devices on the FIDO usage page.
pub fn fido_devices(backend: &dyn HidBackend) -> Result<Vec<HidDeviceInfo>, CtapError> {
    Ok(backend
        .enumerate()?
        .into_iter()
        .filter(HidDeviceInfo::is_fido)
        .collect())
}

/// `sk_probe`: `Ok(None)` when no attached device fits.
pub fn probe<R: rand::CryptoRng + ?Sized>(
    backend: &dyn HidBackend,
    probe: Probe<'_>,
    rng: &mut R,
) -> Result<Option<Authenticator>, CtapError> {
    let devices = fido_devices(backend)?;
    tracing::debug!("{} FIDO device(s) detected", devices.len());
    if devices.is_empty() {
        return Ok(None);
    }
    let (opened, failures) = open_all(backend, &devices, rng);
    if opened.is_empty() {
        let detail = failures.first().cloned().unwrap_or_default();
        return Err(CtapError::Transport(format!(
            "{} FIDO device(s) found but none could be opened: {detail}",
            devices.len()
        )));
    }
    match probe {
        Probe::ByCredential {
            application,
            key_handle,
        } => Ok(select_by_credential(opened, application, key_handle, rng)),
        Probe::ByTouch => select_by_touch(opened),
    }
}

/// `sk_openv`: open every candidate, keeping the reasons for failures so a
/// permission problem can be reported when nothing opens at all.
fn open_all<R: rand::CryptoRng + ?Sized>(
    backend: &dyn HidBackend,
    devices: &[HidDeviceInfo],
    rng: &mut R,
) -> (Vec<Authenticator>, Vec<String>) {
    let mut opened = Vec::with_capacity(devices.len());
    let mut failures = Vec::new();
    for device in devices {
        match Authenticator::open(backend, device, rng) {
            Ok(authenticator) => opened.push(authenticator),
            Err(error) => {
                tracing::debug!("{}: open failed: {error}", device.path);
                failures.push(format!("{}: {error}", device.path));
            }
        }
    }
    (opened, failures)
}

/// `sk_try`: does this device hold the credential? A silent assertion with
/// dummy data answers it; a U2F device reports "user presence required"
/// for a key handle it recognises.
fn holds_credential<R: rand::CryptoRng + ?Sized>(
    device: &mut Authenticator,
    application: &str,
    key_handle: &[u8],
    rng: &mut R,
) -> bool {
    let request = AssertionRequest {
        rp_id: application,
        data: &[0u8; 32],
        credential_id: key_handle,
        up: Some(false),
        uv: None,
    };
    match device.get_assertion(&request, None, Some(Duration::from_secs(5)), rng) {
        Ok(_) | Err(CtapError::UserPresenceRequired) => true,
        Err(error) => {
            tracing::debug!("{}: credential probe failed: {error}", device.path());
            false
        }
    }
}

/// `sk_select_by_cred`.
fn select_by_credential<R: rand::CryptoRng + ?Sized>(
    mut devices: Vec<Authenticator>,
    application: &str,
    key_handle: &[u8],
    rng: &mut R,
) -> Option<Authenticator> {
    if devices.len() == 1 && devices[0].option("uv").is_some() {
        // A lone CTAP2 device that reports its `uv` option is used as is;
        // `sk_select_by_cred` skips the probe for it.
        return devices.pop();
    }
    let position = devices
        .iter_mut()
        .position(|device| holds_credential(device, application, key_handle, rng))?;
    let selected = devices.swap_remove(position);
    tracing::debug!("found key in {}", selected.path());
    Some(selected)
}

/// `sk_select_by_touch`: with one device there is nothing to choose; with
/// several, every device is asked to wait for a touch and the first one
/// that reports it wins. The others are cancelled.
fn select_by_touch(mut devices: Vec<Authenticator>) -> Result<Option<Authenticator>, CtapError> {
    if devices.len() < 2 {
        return Ok(devices.pop());
    }
    let mut polling = Vec::with_capacity(devices.len());
    for mut device in devices {
        match device.touch_begin() {
            Ok(()) => polling.push(device),
            Err(error) => tracing::debug!("{}: touch begin failed: {error}", device.path()),
        }
    }
    if polling.is_empty() {
        return Err(CtapError::Transport(
            "no attached device accepted a touch request".to_string(),
        ));
    }
    let deadline = Instant::now() + SELECT_TIMEOUT;
    let mut selected = None;
    'select: while Instant::now() + POLL_INTERVAL <= deadline && !polling.is_empty() {
        let mut index = 0;
        while index < polling.len() {
            match polling[index].touch_status(POLL_INTERVAL) {
                Ok(UserPresence::Touched) => {
                    selected = Some(polling.swap_remove(index));
                    break 'select;
                }
                Ok(UserPresence::Waiting) => index += 1,
                Err(error) => {
                    tracing::debug!("{}: touch poll failed: {error}", polling[index].path());
                    polling.swap_remove(index);
                }
            }
        }
    }
    for mut device in polling {
        device.cancel();
    }
    if selected.is_none() {
        tracing::debug!("timeout waiting for a touch to select a device");
    }
    Ok(selected)
}
