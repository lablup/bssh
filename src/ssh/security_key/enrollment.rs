// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::{
    SK_FLAG_USER_PRESENCE_REQUIRED, SK_FLAG_USER_VERIFICATION_REQUIRED, SecurityKeyError,
    SkAlgorithm,
};
use std::fmt;
use zeroize::Zeroizing;

/// Request a discoverable credential during enrollment.
pub const SK_FLAG_RESIDENT_KEY: u8 = 0x20;

/// Inputs to authenticator credential creation. Challenge bytes are hashed by the provider.
#[derive(Debug, Clone)]
pub struct SkEnrollRequest<'a> {
    pub algorithm: SkAlgorithm,
    pub challenge: &'a [u8],
    pub application: &'a str,
    pub flags: u8,
    pub user: Option<&'a str>,
    pub device: Option<&'a str>,
}

impl SkEnrollRequest<'_> {
    pub fn validate(&self) -> Result<(), SecurityKeyError> {
        if !self.application.starts_with("ssh:")
            || self.application.len() > 1024
            || self.application.as_bytes().contains(&0)
        {
            return Err(SecurityKeyError::InvalidRequest(
                "-O application= must start with ssh:, contain no NUL and fit in 1024 bytes",
            ));
        }
        if self
            .user
            .is_some_and(|user| user.is_empty() || user.len() > 31 || user.as_bytes().contains(&0))
        {
            return Err(SecurityKeyError::InvalidRequest(
                "-O user= must contain 1 to 31 bytes and no NUL",
            ));
        }
        if self.device.is_some_and(|device| {
            device.is_empty() || device.len() > 4096 || device.as_bytes().contains(&0)
        }) {
            return Err(SecurityKeyError::InvalidRequest(
                "-O device= must contain 1 to 4096 bytes and no NUL",
            ));
        }
        if self.challenge.is_empty() || self.challenge.len() > 1024 * 1024 {
            return Err(SecurityKeyError::InvalidRequest(
                "challenge must contain 1 to 1048576 bytes",
            ));
        }
        if self.flags
            & !(SK_FLAG_USER_PRESENCE_REQUIRED
                | SK_FLAG_USER_VERIFICATION_REQUIRED
                | SK_FLAG_RESIDENT_KEY)
            != 0
        {
            return Err(SecurityKeyError::InvalidRequest(
                "unsupported enrollment flags",
            ));
        }
        Ok(())
    }
}

/// Public credential and opaque private handle returned by enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct SkEnrollResponse {
    pub flags: u8,
    /// 32 raw Ed25519 bytes or a 65-byte uncompressed SEC1 P-256 point.
    pub public_key: Vec<u8>,
    pub key_handle: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SkEnrollResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkEnrollResponse")
            .field("flags", &self.flags)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// One downloaded resident credential. User identifiers are untrusted device data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkResidentKey {
    pub algorithm: SkAlgorithm,
    pub application: String,
    pub key: SkEnrollResponse,
    pub user_id: Vec<u8>,
}
