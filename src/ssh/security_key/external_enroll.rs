// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! Enrollment ABI and ownership for the pinned OpenSSH `sk-api.h`.
//!
//! Providers are trusted native code: pointer allocation sizes cannot be
//! verified here. Bounds reject malformed lengths before slicing or wiping;
//! pointers must still refer to distinct malloc allocations as the ABI requires.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use zeroize::{Zeroize, Zeroizing};

use super::super::{
    SK_FLAG_RESIDENT_KEY, SK_FLAG_USER_PRESENCE_REQUIRED, SK_FLAG_USER_VERIFICATION_REQUIRED,
    SecurityKeyError, SkAlgorithm, SkEnrollRequest, SkEnrollResponse, SkResidentKey,
};
use super::pin_buffer;

const MAX_BLOB: usize = 1024 * 1024;
const MAX_RESIDENT_KEYS: usize = 1024;
const MAX_APPLICATION: usize = 4096;

#[repr(C)]
pub(super) struct RawEnrollResponse {
    flags: u8,
    public_key: *mut u8,
    public_key_len: usize,
    key_handle: *mut u8,
    key_handle_len: usize,
    signature: *mut u8,
    signature_len: usize,
    attestation_cert: *mut u8,
    attestation_cert_len: usize,
    authdata: *mut u8,
    authdata_len: usize,
}

#[repr(C)]
pub(super) struct RawResidentKey {
    alg: u32,
    slot: usize,
    application: *mut c_char,
    key: RawEnrollResponse,
    flags: u8,
    user_id: *mut u8,
    user_id_len: usize,
}

#[repr(C)]
pub(super) struct RawOption {
    name: *mut c_char,
    value: *mut c_char,
    required: u8,
}

pub(super) type SkEnrollFn = unsafe extern "C" fn(
    u32,
    *const u8,
    usize,
    *const c_char,
    u8,
    *const c_char,
    *mut *mut RawOption,
    *mut *mut RawEnrollResponse,
) -> c_int;
pub(super) type SkLoadResidentFn = unsafe extern "C" fn(
    *const c_char,
    *mut *mut RawOption,
    *mut *mut *mut RawResidentKey,
    *mut usize,
) -> c_int;

/// Own the strings, structs, and NULL-terminated array for the entire call.
struct Options {
    _strings: Vec<CString>,
    entries: Vec<RawOption>,
    pointers: Vec<*mut RawOption>,
}

impl Options {
    fn new(device: Option<&str>, user: Option<&str>) -> Result<Self, SecurityKeyError> {
        let mut strings = Vec::new();
        let mut entries = Vec::new();
        for (name, value) in [("device", device), ("user", user)] {
            let Some(value) = value else { continue };
            let name = CString::new(name)
                .map_err(|_| SecurityKeyError::InvalidRequest("invalid option name"))?;
            let value = CString::new(value)
                .map_err(|_| SecurityKeyError::InvalidRequest("provider option contains NUL"))?;
            entries.push(RawOption {
                name: name.as_ptr().cast_mut(),
                value: value.as_ptr().cast_mut(),
                required: 0,
            });
            strings.extend([name, value]);
        }
        // All entries are in place before taking addresses, so reallocations
        // cannot invalidate the pointer array.
        let mut pointers: Vec<_> = entries.iter_mut().map(ptr::from_mut).collect();
        pointers.push(ptr::null_mut());
        Ok(Self {
            _strings: strings,
            entries,
            pointers,
        })
    }

    fn as_ptr(&mut self) -> *mut *mut RawOption {
        if self.entries.is_empty() {
            ptr::null_mut()
        } else {
            self.pointers.as_mut_ptr()
        }
    }
}

pub(super) fn enroll(
    operation: SkEnrollFn,
    request: &SkEnrollRequest<'_>,
    pin: Option<&str>,
) -> Result<SkEnrollResponse, SecurityKeyError> {
    request.validate()?;
    let application = CString::new(request.application)
        .map_err(|_| SecurityKeyError::InvalidRequest("application contains NUL"))?;
    let mut options = Options::new(request.device, request.user)?;
    let pin = pin.map(pin_buffer).transpose()?;
    let mut response = EnrollGuard(ptr::null_mut());
    // SAFETY: inputs and out-pointer live for the full call; types match sk-api.h.
    let code = unsafe {
        operation(
            request.algorithm.api_code(),
            request.challenge.as_ptr(),
            request.challenge.len(),
            application.as_ptr(),
            request.flags,
            pin.as_ref().map_or(ptr::null(), |p| p.as_ptr().cast()),
            options.as_ptr(),
            &mut response.0,
        )
    };
    drop(pin);
    if code != 0 {
        return Err(SecurityKeyError::from_sk_code(code));
    }
    if response.0.is_null() {
        return Err(SecurityKeyError::InvalidResponse(
            "missing enrollment response",
        ));
    }
    // SAFETY: provider transferred ownership of an initialized response;
    // the guard frees it on success and on every validation failure.
    unsafe { copy_enrollment(&*response.0, request.algorithm) }
}

pub(super) fn load_resident(
    operation: SkLoadResidentFn,
    pin: Option<&str>,
    device: Option<&str>,
) -> Result<Vec<SkResidentKey>, SecurityKeyError> {
    let mut options = Options::new(device, None)?;
    let pin = pin.map(pin_buffer).transpose()?;
    let mut response = ResidentGuard {
        pointer: ptr::null_mut(),
        count: 0,
    };
    // SAFETY: arguments match sk-api.h and remain valid for the whole call.
    let code = unsafe {
        operation(
            pin.as_ref().map_or(ptr::null(), |p| p.as_ptr().cast()),
            options.as_ptr(),
            &mut response.pointer,
            &mut response.count,
        )
    };
    drop(pin);
    if code != 0 {
        return Err(SecurityKeyError::from_sk_code(code));
    }
    if response.count > MAX_RESIDENT_KEYS || (response.count != 0 && response.pointer.is_null()) {
        return Err(SecurityKeyError::InvalidResponse(
            "invalid resident key array",
        ));
    }
    let mut result = Vec::with_capacity(response.count);
    for index in 0..response.count {
        // SAFETY: count was bounded and provider owns an array of that length.
        let pointer = unsafe { *response.pointer.add(index) };
        if pointer.is_null() {
            return Err(SecurityKeyError::InvalidResponse("null resident key"));
        }
        // SAFETY: non-null array elements are initialized sk_resident_key objects.
        let raw = unsafe { &*pointer };
        // SAFETY: application is an ABI C string; scanning is bounded.
        let application = unsafe { copy_application(raw.application) }?;
        // OpenSSH filters unrelated RPs and algorithms instead of failing all downloads.
        if !application.starts_with("ssh:") {
            continue;
        }
        let algorithm = match raw.alg {
            0 => SkAlgorithm::EcdsaSha2NistP256,
            1 => SkAlgorithm::Ed25519,
            _ => continue,
        };
        // SAFETY: embedded enrollment response and user ID use the same ABI ownership.
        let mut key = unsafe { copy_enrollment(&raw.key, algorithm) }?;
        key.flags = SK_FLAG_USER_PRESENCE_REQUIRED
            | SK_FLAG_RESIDENT_KEY
            | (raw.flags & SK_FLAG_USER_VERIFICATION_REQUIRED);
        // SAFETY: pointer/length pairs are bounded before copying.
        if raw.user_id_len == 0 || raw.user_id_len > 64 {
            return Err(SecurityKeyError::InvalidResponse(
                "invalid resident user ID length",
            ));
        }
        let user_id =
            unsafe { copy_blob(raw.user_id, raw.user_id_len, "invalid resident user ID") }?
                .to_vec();
        result.push(SkResidentKey {
            algorithm,
            application,
            key,
            user_id,
        });
    }
    Ok(result)
}

fn check_blob(pointer: *const u8, len: usize, name: &'static str) -> Result<(), SecurityKeyError> {
    if len > MAX_BLOB || (len > 0 && pointer.is_null()) {
        return Err(SecurityKeyError::InvalidResponse(name));
    }
    Ok(())
}

/// The pointer must be NULL or address the declared readable allocation.
unsafe fn copy_blob(
    pointer: *const u8,
    len: usize,
    name: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SecurityKeyError> {
    check_blob(pointer, len, name)?;
    if len == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }
    // SAFETY: caller supplies allocated memory and check_blob bounds the length.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec(),
    ))
}

/// The provider must supply a valid NUL-terminated C string or NULL.
unsafe fn copy_application(pointer: *const c_char) -> Result<String, SecurityKeyError> {
    if pointer.is_null() {
        return Err(SecurityKeyError::InvalidResponse(
            "missing resident application",
        ));
    }
    // SAFETY: the ABI requires a C string; strnlen stops at the first NUL.
    let len = unsafe { libc::strnlen(pointer, MAX_APPLICATION) };
    if len == MAX_APPLICATION {
        return Err(SecurityKeyError::InvalidResponse(
            "resident application too long",
        ));
    }
    // SAFETY: strnlen found a terminator at len, so len+1 bytes are readable.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast(), len + 1) };
    CStr::from_bytes_with_nul(bytes)
        .ok()
        .and_then(|s| s.to_str().ok())
        .map(str::to_owned)
        .ok_or(SecurityKeyError::InvalidResponse(
            "resident application is not UTF-8",
        ))
}

/// All fields follow sk-api allocation and initialization requirements.
unsafe fn copy_enrollment(
    raw: &RawEnrollResponse,
    algorithm: SkAlgorithm,
) -> Result<SkEnrollResponse, SecurityKeyError> {
    for (pointer, len) in [
        (raw.signature, raw.signature_len),
        (raw.attestation_cert, raw.attestation_cert_len),
        (raw.authdata, raw.authdata_len),
    ] {
        check_blob(pointer, len, "invalid enrollment attestation field")?;
    }
    let expected = match algorithm {
        SkAlgorithm::Ed25519 => 32,
        SkAlgorithm::EcdsaSha2NistP256 => 65,
    };
    if raw.public_key_len != expected || raw.key_handle_len == 0 || raw.key_handle_len > 4096 {
        return Err(SecurityKeyError::InvalidResponse(
            "invalid enrollment public key or handle length",
        ));
    }
    // SAFETY: bounded copy helpers validate each provider-owned pointer/length pair.
    let public_key = unsafe {
        copy_blob(
            raw.public_key,
            raw.public_key_len,
            "invalid enrollment public key",
        )
    }?
    .to_vec();
    if algorithm == SkAlgorithm::EcdsaSha2NistP256
        && (public_key[0] != 4 || p256::PublicKey::from_sec1_bytes(&public_key).is_err())
    {
        return Err(SecurityKeyError::InvalidResponse(
            "invalid enrollment P-256 point",
        ));
    }
    if algorithm == SkAlgorithm::Ed25519 {
        let bytes: &[u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            SecurityKeyError::InvalidResponse("invalid enrollment Ed25519 key length")
        })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| SecurityKeyError::InvalidResponse("invalid enrollment Ed25519 point"))?;
        if key.is_weak() {
            return Err(SecurityKeyError::InvalidResponse(
                "weak enrollment Ed25519 key",
            ));
        }
    }
    // SAFETY: same ownership contract as the public-key component.
    let key_handle = unsafe {
        copy_blob(
            raw.key_handle,
            raw.key_handle_len,
            "invalid enrollment key handle",
        )
    }?;
    Ok(SkEnrollResponse {
        flags: raw.flags,
        public_key,
        key_handle,
    })
}

struct EnrollGuard(*mut RawEnrollResponse);
impl Drop for EnrollGuard {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: guard exclusively owns this provider-allocated response.
        unsafe {
            free_enrollment_fields(&mut *self.0);
            wipe_free(self.0.cast(), size_of::<RawEnrollResponse>());
        }
    }
}

struct ResidentGuard {
    pointer: *mut *mut RawResidentKey,
    count: usize,
}
impl Drop for ResidentGuard {
    fn drop(&mut self) {
        if self.pointer.is_null() {
            return;
        }
        // A corrupt count gives no safe array extent: free the outer allocation
        // without traversing it. Native middleware must uphold allocation sizes.
        if self.count <= MAX_RESIDENT_KEYS {
            for index in 0..self.count {
                // SAFETY: bounded ABI array whose ownership the provider transferred.
                let pointer = unsafe { *self.pointer.add(index) };
                if pointer.is_null() {
                    continue;
                }
                // SAFETY: each non-null element and its fields are owned malloc allocations.
                unsafe {
                    let raw = &mut *pointer;
                    libc::free(raw.application.cast());
                    wipe_free(raw.user_id, raw.user_id_len);
                    free_enrollment_fields(&mut raw.key);
                    wipe_free(pointer.cast(), size_of::<RawResidentKey>());
                }
            }
        }
        // SAFETY: the outer array itself is a provider malloc allocation.
        unsafe { libc::free(self.pointer.cast()) };
    }
}

/// Fields must own distinct malloc allocations, or be NULL.
unsafe fn free_enrollment_fields(raw: &mut RawEnrollResponse) {
    for (pointer, len) in [
        (raw.public_key, raw.public_key_len),
        (raw.key_handle, raw.key_handle_len),
        (raw.signature, raw.signature_len),
        (raw.attestation_cert, raw.attestation_cert_len),
        (raw.authdata, raw.authdata_len),
    ] {
        // SAFETY: provider transferred each allocation; wipe_free bounds the wipe.
        unsafe { wipe_free(pointer, len) };
    }
}

/// Pointer must be a malloc allocation with the declared length, or NULL.
unsafe fn wipe_free(pointer: *mut u8, len: usize) {
    if pointer.is_null() {
        return;
    }
    if len > 0 && len <= MAX_BLOB {
        // SAFETY: valid declared allocation with bounded length. Zeroize uses
        // volatile writes so clearing handles/PIN-related material is not elided.
        unsafe { std::slice::from_raw_parts_mut(pointer, len) }.zeroize();
    }
    // SAFETY: the pointer belongs to the ABI's C allocator.
    unsafe { libc::free(pointer.cast::<c_void>()) };
}

#[cfg(test)]
#[path = "external_enroll_tests.rs"]
mod tests;
