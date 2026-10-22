// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ssh::security_key::{SkEnrollRequest, SkEnrollResponse, SkResidentKey};

impl InternalProvider {
    fn enrollment_device(
        &self,
        path: Option<&str>,
        deadline: Instant,
    ) -> Result<device::Authenticator, SecurityKeyError> {
        let mut rng = rand::rng();
        if let Some(path) = path {
            let devices = select::fido_devices(&*self.backend)?;
            let info = devices
                .iter()
                .find(|info| info.path == path)
                .ok_or(SecurityKeyError::DeviceNotFound)?;
            return device::Authenticator::open(&*self.backend, info, deadline, &mut rng)
                .map_err(Into::into);
        }
        select::probe(
            &*self.backend,
            Probe::ByTouch,
            &self.timing,
            deadline,
            &mut rng,
        )?
        .ok_or(SecurityKeyError::DeviceNotFound)
    }

    pub(super) fn enroll_credential(
        &self,
        request: &SkEnrollRequest<'_>,
        pin: Option<&str>,
    ) -> Result<SkEnrollResponse, SecurityKeyError> {
        request.validate()?;
        let deadline = Instant::now() + self.timing.sign_timeout;
        let mut device = self.enrollment_device(request.device, deadline)?;
        let result = device.enroll(request, pin, deadline, &mut rand::rng());
        self.finish_enrollment(&mut device, result, deadline)
    }

    pub(super) fn download_resident(
        &self,
        pin: Option<&str>,
        path: Option<&str>,
    ) -> Result<Vec<SkResidentKey>, SecurityKeyError> {
        let deadline = Instant::now() + self.timing.sign_timeout;
        let mut device = self.enrollment_device(path, deadline)?;
        let result = device.resident_keys(pin, deadline, &mut rand::rng());
        self.finish_enrollment(&mut device, result, deadline)
    }

    fn finish_enrollment<T>(
        &self,
        device: &mut device::Authenticator,
        result: Result<T, CtapError>,
        deadline: Instant,
    ) -> Result<T, SecurityKeyError> {
        result.map_err(|error| {
            let error = past_deadline(error, deadline);
            if error == CtapError::DeadlineExceeded {
                device.cancel();
            }
            match error {
                // Preserve named optional-feature and U2F diagnostics for keygen.
                CtapError::Unsupported(reason) => SecurityKeyError::Failed(reason.to_owned()),
                other => other.into(),
            }
        })
    }
}
