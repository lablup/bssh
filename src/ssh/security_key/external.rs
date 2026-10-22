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
//!
//! A library is opened with `RTLD_NOW | RTLD_LOCAL`, as `sshsk_open` opens it
//! with `RTLD_NOW`, so an unresolved symbol fails the load instead of
//! aborting bssh at the first `sk_sign`. Each library is opened once per
//! canonical path and kept for the life of the process: OpenSSH's helper
//! process exits after one signature, while bssh would otherwise rerun the
//! library's initializers and `dlclose` it for every identity on every
//! connection, which leaves thread-local destructors pointing into unmapped
//! code.

use std::collections::HashMap;
use std::ffi::{CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

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

/// A validated provider library. Instances live in [`LOADED_LIBRARIES`] and
/// are never dropped, so the library is never unmapped while `sign` exists.
struct LoadedLibrary {
    sign: SkSignFn,
    /// Held so the code `sign` points into stays mapped.
    _library: Library,
}

/// Validated provider libraries by canonical path, for the process lifetime.
static LOADED_LIBRARIES: LazyLock<Mutex<HashMap<PathBuf, Arc<LoadedLibrary>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// An sk-api library as named by one `SecurityKeyProvider` setting.
pub(super) struct ExternalProvider {
    path: PathBuf,
    loaded: Arc<LoadedLibrary>,
}

impl std::fmt::Debug for ExternalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalProvider")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ExternalProvider {
    #[cfg(test)]
    fn _loaded_for_tests(&self) -> &Library {
        &self.loaded._library
    }

    pub(super) fn load(path: &Path) -> Result<Self, SecurityKeyError> {
        let loaded = load_cached(&LOADED_LIBRARIES, path, |canonical| {
            let library =
                open_library(canonical).map_err(|error| SecurityKeyError::LoadFailed {
                    path: path.to_path_buf(),
                    reason: describe_load_error(&error),
                })?;
            let sign = bind_symbols(path, &library)?;
            Ok(LoadedLibrary {
                sign,
                _library: library,
            })
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            loaded,
        })
    }
}

/// Return the entry for `path`'s canonical form, running `load` only when
/// none exists yet. A failed load is not remembered, so a provider that is
/// installed or fixed later is picked up by the next connection.
fn load_cached<T, F>(
    cache: &Mutex<HashMap<PathBuf, Arc<T>>>,
    path: &Path,
    load: F,
) -> Result<Arc<T>, SecurityKeyError>
where
    F: FnOnce(&Path) -> Result<T, SecurityKeyError>,
{
    // `lib_contains_symbol` opens the configured path itself before
    // `sshsk_open` dlopens it, so a bare file name names a file relative to
    // the working directory, never one found through the loader search path.
    let canonical = std::fs::canonicalize(path).map_err(|error| SecurityKeyError::LoadFailed {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    let mut cache = cache.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(loaded) = cache.get(&canonical) {
        return Ok(Arc::clone(loaded));
    }
    let loaded = Arc::new(load(&canonical)?);
    cache.insert(canonical, Arc::clone(&loaded));
    Ok(loaded)
}

/// `dlopen(path, RTLD_NOW | RTLD_LOCAL)`.
#[cfg(unix)]
fn open_library(path: &Path) -> Result<Library, libloading::Error> {
    use libloading::os::unix::{Library as UnixLibrary, RTLD_LOCAL, RTLD_NOW};
    // SAFETY: loading a shared object runs its initializers. The path is the
    // user's own `SecurityKeyProvider` setting (or `$SSH_SK_PROVIDER`), the
    // same trust OpenSSH extends when `ssh-sk-helper` dlopens it.
    unsafe { UnixLibrary::open(Some(path), RTLD_NOW | RTLD_LOCAL) }.map(Library::from)
}

/// `LoadLibraryExW`, which resolves every import at load time.
#[cfg(not(unix))]
fn open_library(path: &Path) -> Result<Library, libloading::Error> {
    // SAFETY: as for the Unix variant; the path is the user's own setting.
    unsafe { Library::new(path) }
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
        request.validate()?;
        let application = CString::new(request.application)
            .map_err(|_| SecurityKeyError::InvalidRequest("application contains NUL"))?;
        let pin = pin.map(pin_buffer).transpose()?;
        let pin_ptr = pin
            .as_ref()
            .map_or(ptr::null(), |pin| pin.as_ptr().cast::<c_char>());
        let mut response: *mut RawSignResponse = ptr::null_mut();

        // SAFETY: every pointer is valid for the stated length for the whole
        // call: `data` and `key_handle` borrow the request, the C strings are
        // NUL-terminated and live until after the call, `options` is NULL as
        // in `sshsk_sign`, and `response` is a valid out-pointer the provider
        // fills with memory it allocated with malloc.
        let code = unsafe {
            (self.loaded.sign)(
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
        // Scrub the PIN as soon as the provider is done with it.
        drop(pin);
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
        // SAFETY: `response` is the non-null, provider-allocated struct read
        // above; `copy_response` copied out of it without keeping pointers,
        // and it is not touched again after this call.
        unsafe { free_response(response) };
        copied
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// The PIN as a NUL-terminated C string in memory that is wiped on drop.
///
/// The NUL check runs before anything is copied: `CString::new` would hand a
/// rejected PIN back inside its error, and that copy would be freed without
/// being wiped. The capacity is reserved up front so no reallocation leaves
/// an unwiped copy behind either.
fn pin_buffer(pin: &str) -> Result<Zeroizing<Vec<u8>>, SecurityKeyError> {
    if pin.as_bytes().contains(&0) {
        return Err(SecurityKeyError::InvalidRequest("PIN contains NUL"));
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(pin.len() + 1));
    buffer.extend_from_slice(pin.as_bytes());
    buffer.push(0);
    Ok(buffer)
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
    // SAFETY: the provider owns each component as `len` bytes at its pointer
    // (or NULL); `copy_component` validates the pair before reading.
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
#[path = "external_tests.rs"]
mod tests;
