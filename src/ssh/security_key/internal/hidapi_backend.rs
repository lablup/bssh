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

//! [`HidBackend`] over the `hidapi` crate: hidraw through its pure-Rust
//! backend on Linux (sysfs enumeration, no libudev) and IOKit on macOS.
//!
//! hidapi's write takes a leading report ID byte (0 for CTAPHID devices,
//! which use unnumbered reports) and its reads return the report without
//! one, on both platforms.

use std::ffi::CString;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use super::CtapError;
use super::ctaphid::{HidBackend, HidDevice, HidDeviceInfo, REPORT_LEN, Report};

/// One hidapi context, created by the first enumeration and refreshed by
/// later ones, which device opens reuse instead of building (and so
/// re-enumerating) a context of their own.
#[derive(Default)]
pub struct HidapiBackend {
    api: Mutex<Option<hidapi::HidApi>>,
    /// Contexts created, so tests can check the reuse.
    #[cfg(test)]
    contexts: AtomicUsize,
}

impl std::fmt::Debug for HidapiBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HidapiBackend").finish_non_exhaustive()
    }
}

fn transport(error: hidapi::HidError) -> CtapError {
    CtapError::Transport(error.to_string())
}

impl HidapiBackend {
    /// Run `f` with the context, creating it first if there is none.
    fn with_api<T>(
        &self,
        refresh: bool,
        f: impl FnOnce(&hidapi::HidApi) -> Result<T, CtapError>,
    ) -> Result<T, CtapError> {
        let mut guard = self.api.lock().unwrap_or_else(PoisonError::into_inner);
        match guard.as_mut() {
            Some(api) if refresh => api.refresh_devices().map_err(transport)?,
            Some(_) => {}
            None => {
                *guard = Some(hidapi::HidApi::new().map_err(transport)?);
                #[cfg(test)]
                self.contexts.fetch_add(1, Ordering::Relaxed);
            }
        }
        f(guard.as_ref().expect("context created above"))
    }
}

impl HidBackend for HidapiBackend {
    fn enumerate(&self) -> Result<Vec<HidDeviceInfo>, CtapError> {
        self.with_api(true, |api| {
            Ok(api
                .device_list()
                .map(|device| HidDeviceInfo {
                    path: device.path().to_string_lossy().into_owned(),
                    usage_page: device.usage_page(),
                    usage: device.usage(),
                    vendor_id: device.vendor_id(),
                    product_id: device.product_id(),
                    product: device.product_string().map(str::to_string),
                })
                .collect())
        })
    }

    fn open(&self, path: &str) -> Result<Box<dyn HidDevice>, CtapError> {
        let path = CString::new(path)
            .map_err(|_| CtapError::Transport("device path contains NUL".to_string()))?;
        let device = self.with_api(false, |api| api.open_path(&path).map_err(transport))?;
        Ok(Box::new(HidapiDevice(device)))
    }
}

struct HidapiDevice(hidapi::HidDevice);

impl HidDevice for HidapiDevice {
    fn write_report(&mut self, report: &Report) -> Result<(), CtapError> {
        let mut buffer = [0u8; REPORT_LEN + 1];
        buffer[1..].copy_from_slice(report);
        let written = self.0.write(&buffer).map_err(transport)?;
        if written != buffer.len() {
            return Err(CtapError::Transport(format!(
                "short HID write: {written} of {} bytes",
                buffer.len()
            )));
        }
        Ok(())
    }

    fn read_report(&mut self, timeout: Option<Duration>) -> Result<Option<Report>, CtapError> {
        let millis = timeout.map_or(-1, |timeout| {
            i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX)
        });
        let mut report = [0u8; REPORT_LEN];
        let read = self
            .0
            .read_timeout(&mut report, millis)
            .map_err(transport)?;
        if read == 0 {
            return Ok(None);
        }
        if read != REPORT_LEN {
            return Err(CtapError::Transport(format!(
                "short HID report: {read} of {REPORT_LEN} bytes"
            )));
        }
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_a_device_reuses_the_enumeration_context() {
        let backend = HidapiBackend::default();
        if backend.enumerate().is_err() {
            // No HID subsystem here (a container without sysfs); nothing
            // to check.
            return;
        }
        assert!(backend.open("/nonexistent/bssh-hidraw-test").is_err());
        assert!(backend.open("/nonexistent/bssh-hidraw-test").is_err());
        backend.enumerate().unwrap();
        assert_eq!(backend.contexts.load(Ordering::Relaxed), 1);
    }
}
