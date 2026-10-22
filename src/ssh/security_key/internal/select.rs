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

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::ctaphid::{HidBackend, HidDeviceInfo};
use super::device::{AssertionRequest, Authenticator};
use super::{CtapError, Timing, UserPresence};

/// `FIDO_POLL_MS`: per-device wait in each polling round.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// `MAX_FIDO_DEVICES`: how many attached devices are considered at most.
pub const MAX_FIDO_DEVICES: usize = 8;
/// Bound on the silent assertion that asks one device for the credential.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Attached devices on the FIDO usage page, each path once and at most
/// [`MAX_FIDO_DEVICES`] of them, in enumeration order. hidapi lists a device
/// once per top-level collection, so a crafted report descriptor could
/// otherwise repeat one node many times, and every entry costs channel
/// allocation, `getInfo` and a probe under the provider lock.
pub fn fido_devices(backend: &dyn HidBackend) -> Result<Vec<HidDeviceInfo>, CtapError> {
    let mut seen = HashSet::new();
    Ok(backend
        .enumerate()?
        .into_iter()
        .filter(HidDeviceInfo::is_fido)
        .filter(|device| seen.insert(device.path.clone()))
        .take(MAX_FIDO_DEVICES)
        .collect())
}

/// `sk_probe`: `Ok(None)` when no attached device fits; nothing waits
/// past `deadline`.
pub fn probe<R: rand::CryptoRng + ?Sized>(
    backend: &dyn HidBackend,
    probe: Probe<'_>,
    timing: &Timing,
    deadline: Instant,
    rng: &mut R,
) -> Result<Option<Authenticator>, CtapError> {
    let devices = fido_devices(backend)?;
    tracing::debug!("{} FIDO device(s) detected", devices.len());
    if devices.is_empty() {
        return Ok(None);
    }
    let (opened, failures) = open_all(backend, &devices, deadline, rng);
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
        } => Ok(select_by_credential(
            opened,
            application,
            key_handle,
            deadline,
            rng,
        )),
        Probe::ByTouch => select_by_touch(opened, timing, deadline),
    }
}

/// `sk_openv`: open every candidate, keeping the reasons for failures so a
/// permission problem can be reported when nothing opens at all.
fn open_all<R: rand::CryptoRng + ?Sized>(
    backend: &dyn HidBackend,
    devices: &[HidDeviceInfo],
    deadline: Instant,
    rng: &mut R,
) -> (Vec<Authenticator>, Vec<String>) {
    let mut opened = Vec::with_capacity(devices.len());
    let mut failures = Vec::new();
    for device in devices {
        match Authenticator::open(backend, device, deadline, rng) {
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
    deadline: Instant,
    rng: &mut R,
) -> bool {
    let request = AssertionRequest {
        rp_id: application,
        data: &[0u8; 32],
        credential_id: key_handle,
        up: Some(false),
        uv: None,
    };
    let deadline = deadline.min(Instant::now() + PROBE_TIMEOUT);
    match device.get_assertion(&request, None, deadline, rng) {
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
    deadline: Instant,
    rng: &mut R,
) -> Option<Authenticator> {
    if devices.len() == 1 && devices[0].option("uv").is_some() {
        // A lone CTAP2 device that reports its `uv` option is used as is;
        // `sk_select_by_cred` skips the probe for it.
        return devices.pop();
    }
    let position = devices
        .iter_mut()
        .position(|device| holds_credential(device, application, key_handle, deadline, rng))?;
    let selected = devices.swap_remove(position);
    tracing::debug!("found key in {}", selected.path());
    Some(selected)
}

/// `sk_select_by_touch`: with one device there is nothing to choose; with
/// several, every device is asked to wait for a touch and the first one
/// that reports it wins. The others are cancelled. Each polling round
/// starts after a [`Timing::poll_sleep`] pause, as `sk_touch_poll` does.
fn select_by_touch(
    mut devices: Vec<Authenticator>,
    timing: &Timing,
    deadline: Instant,
) -> Result<Option<Authenticator>, CtapError> {
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
    let deadline = deadline.min(Instant::now() + timing.select_timeout);
    let mut selected = None;
    'select: while Instant::now() + POLL_INTERVAL <= deadline && !polling.is_empty() {
        std::thread::sleep(
            timing
                .poll_sleep
                .min(deadline.saturating_duration_since(Instant::now())),
        );
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
