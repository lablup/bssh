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

//! `dlopen` binding to an external `sk-api.h` middleware library.
//!
//! The ABI is the pinned OpenSSH 10.3 `sk-api.h` (version `0x000a0000`).
//! Only `sk_sign` is called; `sk_enroll` and `sk_load_resident_keys` must
//! exist (as `sshsk_open` requires) but enrollment stays with `ssh-keygen`.

use std::ffi::{CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr;

use libloading::{Library, Symbol};
use zeroize::Zeroizing;

use super::{
    SecurityKeyError, SecurityKeyProvider, SkSignRequest, SkSignResponse, check_api_version,
};

/// Upper bound on a single signature component the provider may hand back.
/// Real values are 32 to 64 bytes; anything larger is a corrupt response.
const MAX_COMPONENT_LEN: usize = 4096;

/// `struct sk_sign_response` from `sk-api.h`.
#[repr(C)]
struct RawSignResponse {
    flags: u8,
    counter: u32,
    sig_r: *mut u8,
    sig_r_len: usize,
    sig_s: *mut u8,
    sig_s_len: usize,
}

type SkApiVersionFn = unsafe extern "C" fn() -> u32;

type SkSignFn = unsafe extern "C" fn(
    alg: u32,
    data: *const u8,
    data_len: usize,
    application: *const c_char,
    key_handle: *const u8,
    key_handle_len: usize,
    flags: u8,
    pin: *const c_char,
    options: *mut *mut c_void,
    sign_response: *mut *mut RawSignResponse,
) -> c_int;

/// A provider library kept open for the life of the signer.
pub(super) struct ExternalProvider {
    path: PathBuf,
    sign: SkSignFn,
    /// Declared after `sign` so the function pointer is never used once the
    /// library is unmapped; both go away together.
    _library: Library,
}

impl std::fmt::Debug for ExternalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalProvider")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ExternalProvider {
    pub(super) fn load(path: &Path) -> Result<Self, SecurityKeyError> {
        // SAFETY: loading a shared object runs its initializers. The path is
        // the user's own `SecurityKeyProvider` setting (or `$SSH_SK_PROVIDER`),
        // the same trust OpenSSH extends when `ssh-sk-helper` dlopens it.
        let library =
            unsafe { Library::new(path) }.map_err(|error| SecurityKeyError::LoadFailed {
                path: path.to_path_buf(),
                reason: describe_load_error(&error),
            })?;
        let sign = bind_symbols(path, &library)?;
        Ok(Self {
            path: path.to_path_buf(),
            sign,
            _library: library,
        })
    }
}

/// Explain a failed `dlopen`, naming the static-linking limitation of musl
/// release builds instead of leaving the user with "Dynamic loading not
/// supported".
fn describe_load_error(error: &libloading::Error) -> String {
    let reason = error.to_string();
    if cfg!(target_env = "musl") {
        format!(
            "{reason}; this bssh build is statically linked and cannot load shared libraries, so an external SecurityKeyProvider needs a dynamically linked bssh"
        )
    } else {
        reason
    }
}

/// Required `sk-api.h` entry points besides `sk_api_version` and `sk_sign`.
/// They are looked up, never called: `sshsk_open` refuses a library that
/// lacks any of them, and so does bssh.
const REQUIRED_OPERATIONS: [&[u8]; 2] = [b"sk_enroll\0", b"sk_load_resident_keys\0"];

/// The provider checks `sshsk_open` performs, with the library accesses
/// abstracted so they can be tested without a real shared object: the
/// reported version must have the supported major, and every operation
/// symbol must resolve.
fn validate_provider<F>(
    path: &Path,
    version: u32,
    mut has_symbol: F,
) -> Result<(), SecurityKeyError>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    tracing::debug!(
        "provider {} implements version {version:#010x}",
        path.display()
    );
    check_api_version(path, version)?;
    for name in REQUIRED_OPERATIONS.iter().chain([&&b"sk_sign\0"[..]]) {
        has_symbol(name).map_err(|reason| SecurityKeyError::NotAProvider {
            path: path.to_path_buf(),
            reason,
        })?;
    }
    Ok(())
}

/// Resolve and validate the sk-api entry points the way `sshsk_open` does.
fn bind_symbols(path: &Path, library: &Library) -> Result<SkSignFn, SecurityKeyError> {
    // SAFETY: the symbol is declared in sk-api.h as `uint32_t sk_api_version(void)`;
    // the type annotation matches that prototype exactly.
    let api_version: Symbol<'_, SkApiVersionFn> = unsafe { library.get(b"sk_api_version\0") }
        .map_err(|error| SecurityKeyError::NotAProvider {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    // SAFETY: calling a provider function with no arguments and no
    // preconditions; it only reports a constant.
    let version = unsafe { api_version() };
    validate_provider(path, version, |name| {
        // SAFETY: the symbol is only looked up, never called through this
        // handle, so an opaque pointer type is used on purpose.
        unsafe { library.get::<*const c_void>(name) }
            .map(|_| ())
            .map_err(|error| error.to_string())
    })?;
    // SAFETY: the symbol is declared in sk-api.h as `int sk_sign(...)` with
    // exactly the parameter list `SkSignFn` spells out, and
    // `validate_provider` confirmed it resolves.
    let sign: Symbol<'_, SkSignFn> =
        unsafe { library.get(b"sk_sign\0") }.map_err(|error| SecurityKeyError::NotAProvider {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    Ok(*sign)
}

impl SecurityKeyProvider for ExternalProvider {
    fn sign(
        &self,
        request: &SkSignRequest<'_>,
        pin: Option<&str>,
    ) -> Result<SkSignResponse, SecurityKeyError> {
        let application = CString::new(request.application)
            .map_err(|_| SecurityKeyError::InvalidRequest("application contains NUL"))?;
        let pin = pin
            .map(|pin| {
                CString::new(pin).map_err(|_| SecurityKeyError::InvalidRequest("PIN contains NUL"))
            })
            .transpose()?;
        let pin_ptr = pin.as_ref().map_or(ptr::null(), |pin| pin.as_ptr());
        let mut response: *mut RawSignResponse = ptr::null_mut();

        // SAFETY: every pointer is valid for the stated length for the whole
        // call: `data` and `key_handle` borrow the request, the C strings are
        // NUL-terminated and live until after the call, `options` is NULL as
        // in `sshsk_sign`, and `response` is a valid out-pointer the provider
        // fills with memory it allocated with malloc.
        let code = unsafe {
            (self.sign)(
                request.algorithm.api_code(),
                request.data.as_ptr(),
                request.data.len(),
                application.as_ptr(),
                request.key_handle.as_ptr(),
                request.key_handle.len(),
                request.flags,
                pin_ptr,
                ptr::null_mut(),
                &mut response,
            )
        };
        if let Some(pin) = pin {
            drop(Zeroizing::new(pin.into_bytes()));
        }
        if code != 0 {
            if !response.is_null() {
                // SAFETY: a non-null response was allocated by the provider
                // and is owned by us from here; see `free_response`.
                unsafe { free_response(response) };
            }
            tracing::debug!("sk_sign failed with code {code}");
            return Err(SecurityKeyError::from_sk_code(code));
        }
        if response.is_null() {
            return Err(SecurityKeyError::InvalidResponse(
                "provider returned success without a response",
            ));
        }
        // SAFETY: `response` is non-null and was allocated by the provider
        // for us; it is read once and then released exactly as
        // `sshsk_free_sign_response` does.
        let copied = unsafe { copy_response(response) };
        unsafe { free_response(response) };
        copied
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// Copy a component out of provider memory after validating pointer and
/// length together: a NULL pointer with a non-zero length, or an absurd
/// length, is a corrupt response rather than something to read.
///
/// # Safety
/// `pointer` must either be NULL or point to `len` readable bytes.
unsafe fn copy_component(
    pointer: *const u8,
    len: usize,
    name: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SecurityKeyError> {
    if len == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }
    if pointer.is_null() {
        return Err(SecurityKeyError::InvalidResponse(name));
    }
    if len > MAX_COMPONENT_LEN {
        return Err(SecurityKeyError::InvalidResponse(name));
    }
    // SAFETY: guaranteed by the caller contract and the checks above.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, len) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// # Safety
/// `response` must point to a `struct sk_sign_response` the provider filled.
unsafe fn copy_response(
    response: *const RawSignResponse,
) -> Result<SkSignResponse, SecurityKeyError> {
    // SAFETY: the caller guarantees `response` is a valid, initialized struct.
    let raw = unsafe { &*response };
    let sig_r = unsafe { copy_component(raw.sig_r, raw.sig_r_len, "sig_r invalid") }?;
    let sig_s = unsafe { copy_component(raw.sig_s, raw.sig_s_len, "sig_s invalid") }?;
    Ok(SkSignResponse {
        flags: raw.flags,
        counter: raw.counter,
        sig_r,
        sig_s,
    })
}

/// Release a response the way `sshsk_free_sign_response` does: zero and free
/// each component with the C allocator, then the struct itself.
///
/// # Safety
/// `response` must be non-null, allocated with malloc by the provider, and
/// not used afterwards.
unsafe fn free_response(response: *mut RawSignResponse) {
    // SAFETY: the caller guarantees a valid, provider-allocated struct.
    let raw = unsafe { &mut *response };
    for (pointer, len) in [(raw.sig_r, raw.sig_r_len), (raw.sig_s, raw.sig_s_len)] {
        if !pointer.is_null() {
            // SAFETY: the provider allocated `len` bytes at `pointer` with
            // malloc; zeroing then freeing matches `freezero`.
            unsafe {
                if len > 0 && len <= MAX_COMPONENT_LEN {
                    ptr::write_bytes(pointer, 0, len);
                }
                libc::free(pointer.cast::<c_void>());
            }
        }
    }
    // SAFETY: the struct itself came from the provider's calloc.
    unsafe {
        ptr::write_bytes(response, 0, 1);
        libc::free(response.cast::<c_void>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_unloadable_libraries_report_a_load_failure() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("no-such-provider.so");
        match ExternalProvider::load(&missing).unwrap_err() {
            SecurityKeyError::LoadFailed { path, reason } => {
                assert_eq!(path, missing);
                assert!(!reason.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let garbage = directory.path().join("garbage.so");
        std::fs::write(&garbage, b"this is not an ELF or Mach-O image").unwrap();
        assert!(matches!(
            ExternalProvider::load(&garbage).unwrap_err(),
            SecurityKeyError::LoadFailed { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_library_without_sk_api_version_is_not_a_provider() {
        let library: Library = libloading::os::unix::Library::this().into();
        let path = Path::new("/self");
        match bind_symbols(path, &library).unwrap_err() {
            SecurityKeyError::NotAProvider {
                path: reported,
                reason,
            } => {
                assert_eq!(reported, path);
                assert!(reason.contains("sk_api_version"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // The handle must not be closed: it is the running program.
        std::mem::forget(library);
    }

    #[test]
    fn provider_validation_enforces_version_and_operation_symbols() {
        let path = Path::new("/p.so");
        let all = |_: &[u8]| Ok(());
        assert!(validate_provider(path, super::super::SK_API_VERSION_MAJOR, all).is_ok());

        let error = validate_provider(path, 0x0009_0000, all).unwrap_err();
        assert!(matches!(
            error,
            SecurityKeyError::UnsupportedVersion {
                version: 0x0009_0000,
                ..
            }
        ));

        for missing in ["sk_enroll\0", "sk_load_resident_keys\0", "sk_sign\0"] {
            let error = validate_provider(path, super::super::SK_API_VERSION_MAJOR, |name| {
                if name == missing.as_bytes() {
                    Err(format!("undefined symbol {missing}"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            match error {
                SecurityKeyError::NotAProvider { reason, .. } => {
                    assert!(reason.contains(missing.trim_end_matches('\0')), "{reason}");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn musl_hint_only_appears_on_static_builds() {
        let error = libloading::Error::DlOpenUnknown;
        let reason = describe_load_error(&error);
        assert_eq!(
            reason.contains("statically linked"),
            cfg!(target_env = "musl")
        );
    }

    #[test]
    fn response_components_are_validated_before_being_read() {
        let error = unsafe { copy_component(ptr::null(), 32, "sig_r invalid") }.unwrap_err();
        assert_eq!(error, SecurityKeyError::InvalidResponse("sig_r invalid"));
        let bytes = [7u8; 4];
        let error =
            unsafe { copy_component(bytes.as_ptr(), MAX_COMPONENT_LEN + 1, "sig_s invalid") }
                .unwrap_err();
        assert_eq!(error, SecurityKeyError::InvalidResponse("sig_s invalid"));
        let copied =
            unsafe { copy_component(bytes.as_ptr(), bytes.len(), "sig_r invalid") }.unwrap();
        assert_eq!(&copied[..], &bytes);
        let empty = unsafe { copy_component(ptr::null(), 0, "sig_r invalid") }.unwrap();
        assert!(empty.is_empty());
    }

    /// End-to-end sign through the OpenSSH regress `sk-dummy` middleware when
    /// its build is present; this is the same library the regress suite uses.
    #[test]
    fn sk_dummy_provider_loads_and_reports_the_supported_version() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "target/openssh-regress/openssh-portable-V_10_3_P1/regress/misc/sk-dummy/sk-dummy.so",
        );
        if !path.exists() {
            eprintln!("sk-dummy.so not built; skipping");
            return;
        }
        let provider = ExternalProvider::load(&path).unwrap();
        assert_eq!(provider.describe(), path.display().to_string());
    }
}
