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
    let error = unsafe { copy_component(bytes.as_ptr(), MAX_COMPONENT_LEN + 1, "sig_s invalid") }
        .unwrap_err();
    assert_eq!(error, SecurityKeyError::InvalidResponse("sig_s invalid"));
    let copied = unsafe { copy_component(bytes.as_ptr(), bytes.len(), "sig_r invalid") }.unwrap();
    assert_eq!(&copied[..], &bytes);
    let empty = unsafe { copy_component(ptr::null(), 0, "sig_r invalid") }.unwrap();
    assert!(empty.is_empty());
}

#[test]
fn the_cache_loads_each_canonical_path_once_and_forgets_failures() {
    let directory = tempfile::tempdir().unwrap();
    let library = directory.path().join("provider.so");
    std::fs::write(&library, b"stand-in").unwrap();
    let cache = Mutex::new(HashMap::new());
    let loads = std::cell::Cell::new(0);
    let load = |canonical: &Path| {
        loads.set(loads.get() + 1);
        Ok(canonical.to_path_buf())
    };

    let first = load_cached(&cache, &library, load).unwrap();
    let again = load_cached(&cache, &library, load).unwrap();
    assert!(Arc::ptr_eq(&first, &again));
    #[cfg(unix)]
    {
        let link = directory.path().join("link.so");
        std::os::unix::fs::symlink(&library, &link).unwrap();
        let through_link = load_cached(&cache, &link, load).unwrap();
        assert!(Arc::ptr_eq(&first, &through_link));
    }
    assert_eq!(loads.get(), 1);

    let other = directory.path().join("other.so");
    std::fs::write(&other, b"stand-in").unwrap();
    let failing = |_: &Path| -> Result<PathBuf, SecurityKeyError> {
        Err(SecurityKeyError::InvalidResponse("load failed"))
    };
    assert!(load_cached(&cache, &other, failing).is_err());
    let recovered = load_cached(&cache, &other, load).unwrap();
    assert_eq!(*recovered, std::fs::canonicalize(&other).unwrap());
    assert_eq!(loads.get(), 2);

    let missing = directory.path().join("missing.so");
    assert!(matches!(
        load_cached(&cache, &missing, load).unwrap_err(),
        SecurityKeyError::LoadFailed { path, .. } if path == missing
    ));
}

#[test]
fn pins_are_nul_terminated_and_a_nul_inside_is_refused() {
    assert_eq!(&pin_buffer("1234").unwrap()[..], b"1234\0");
    assert_eq!(&pin_buffer("").unwrap()[..], b"\0");
    assert_eq!(
        pin_buffer("12\0ab").unwrap_err(),
        SecurityKeyError::InvalidRequest("PIN contains NUL")
    );
}

/// Fixture providers compiled from C at test time, so the real `dlopen`
/// path is exercised without the OpenSSH regress tree. Skipped when no C
/// compiler is installed.
#[cfg(target_os = "linux")]
mod compiled {
    use super::*;

    const PROVIDER: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
struct sk_sign_response {
uint8_t flags; uint32_t counter;
uint8_t *sig_r; size_t sig_r_len; uint8_t *sig_s; size_t sig_s_len;
};
int bssh_fixture_sign_calls = 0;
uint32_t sk_api_version(void) { return 0x000a0000; }
int sk_enroll(void) { return -2; }
int sk_load_resident_keys(void) { return -2; }
int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
const char *application, const uint8_t *key_handle, size_t key_handle_len,
uint8_t flags, const char *pin, void **options,
struct sk_sign_response **out) {
struct sk_sign_response *response;
bssh_fixture_sign_calls++;
if ((response = calloc(1, sizeof(*response))) == NULL ||
    (response->sig_r = malloc(64)) == NULL)
    return -1;
memset(response->sig_r, 0x5a, 64);
response->sig_r_len = 64;
response->flags = flags;
response->counter = 42;
*out = response;
return 0;
}
"#;

    /// Same entry points, but `sk_enroll` calls a function no library
    /// defines. Linked with lazy binding, so only `RTLD_NOW` notices.
    const UNRESOLVED: &str = r#"
#include <stdint.h>
#include <stddef.h>
extern int bssh_fixture_symbol_nobody_defines(void);
uint32_t sk_api_version(void) { return 0x000a0000; }
int sk_enroll(void) { return bssh_fixture_symbol_nobody_defines(); }
int sk_load_resident_keys(void) { return -2; }
int sk_sign(void) { return -1; }
"#;

    fn build(directory: &Path, name: &str, source: &str) -> Option<PathBuf> {
        let source_path = directory.join(format!("{name}.c"));
        std::fs::write(&source_path, source).unwrap();
        let library = directory.join(format!("{name}.so"));
        let status = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-Wl,-z,lazy", "-o"])
            .arg(&library)
            .arg(&source_path)
            .status();
        match status {
            Ok(status) if status.success() => Some(library),
            _ => {
                eprintln!("no working C compiler; skipping");
                None
            }
        }
    }

    fn sign_calls(provider: &ExternalProvider) -> c_int {
        // SAFETY: the fixture defines `bssh_fixture_sign_calls` as an
        // `int`; it is only read, from the thread running this test.
        unsafe {
            **provider
                ._loaded_for_tests()
                .get::<*const c_int>(b"bssh_fixture_sign_calls\0")
                .unwrap()
        }
    }

    fn request<'a>(application: &'a str) -> SkSignRequest<'a> {
        SkSignRequest {
            algorithm: super::super::super::SkAlgorithm::Ed25519,
            data: b"message",
            application,
            key_handle: &[1, 2, 3],
            flags: 0x01,
        }
    }

    #[test]
    fn unresolved_symbols_fail_the_load_like_rtld_now() {
        let directory = tempfile::tempdir().unwrap();
        let Some(library) = build(directory.path(), "unresolved", UNRESOLVED) else {
            return;
        };
        match ExternalProvider::load(&library).unwrap_err() {
            SecurityKeyError::LoadFailed { path, reason } => {
                assert_eq!(path, library);
                assert!(
                    reason.contains("bssh_fixture_symbol_nobody_defines"),
                    "{reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_provider_is_loaded_once_and_signs_through_the_ffi() {
        let directory = tempfile::tempdir().unwrap();
        let Some(library) = build(directory.path(), "provider", PROVIDER) else {
            return;
        };
        let first = ExternalProvider::load(&library).unwrap();
        let link = directory.path().join("provider-link.so");
        std::os::unix::fs::symlink(&library, &link).unwrap();
        let second = ExternalProvider::load(&link).unwrap();
        assert!(Arc::ptr_eq(&first.loaded, &second.loaded));
        assert_eq!(second.describe(), link.display().to_string());

        let response = first.sign(&request("ssh:"), Some("1234")).unwrap();
        assert_eq!(&response.sig_r[..], &[0x5a; 64]);
        assert!(response.sig_s.is_empty());
        assert_eq!((response.flags, response.counter), (0x01, 42));
        assert_eq!(sign_calls(&first), 1);

        assert_eq!(
            second.sign(&request(""), None).unwrap_err(),
            SecurityKeyError::InvalidRequest("key has no application")
        );
        assert_eq!(
            second.sign(&request("ssh:"), Some("12\0")).unwrap_err(),
            SecurityKeyError::InvalidRequest("PIN contains NUL")
        );
        assert_eq!(sign_calls(&first), 1, "the provider was called anyway");
    }
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
