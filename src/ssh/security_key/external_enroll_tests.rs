// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn options_reject_nuls_before_calling_native_code() {
    assert!(Options::new(Some("device\0suffix"), None).is_err());
    assert!(Options::new(None, Some("user\0suffix")).is_err());
    assert!(Options::new(None, None).unwrap().as_ptr().is_null());
}

/// Compile independently declared C structs to test ABI layout, including
/// padding and the embedded enrollment response in resident credentials.
#[cfg(target_os = "linux")]
mod compiled {
    use super::*;
    use crate::ssh::security_key::SecurityKeyProvider;
    use crate::ssh::security_key::external::ExternalProvider;

    const PROVIDER: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef __GLIBC__
/* LD_PRELOAD in the cleanup subprocess intercepts Rust's libc::free too. */
extern void __libc_free(void *);
static _Thread_local void *watched[256];
static _Thread_local size_t watched_len[256];
static _Thread_local int dirty, live, freed;
static void watch(void *p, size_t n) {
    for (size_t i = 0; i < 256; i++) if (!watched[i]) {
        watched[i] = p; watched_len[i] = n; live++; return;
    }
    abort();
}
void free(void *p) {
    if (p) for (size_t i = 0; i < 256; i++) if (watched[i] == p) {
        for (size_t j = 0; j < watched_len[i]; j++)
            if (((uint8_t *)p)[j]) { dirty++; break; }
        watched[i] = NULL; live--; freed++; break;
    }
    __libc_free(p);
}
int bssh_fixture_live(void) { return live; }
int bssh_fixture_dirty(void) { return dirty; }
int bssh_fixture_freed(void) { return freed; }
#else
static void watch(void *p, size_t n) { (void)p; (void)n; }
#endif
struct sk_option { char *name; char *value; uint8_t required; };
struct sk_enroll_response {
    uint8_t flags;
    uint8_t *public_key; size_t public_key_len;
    uint8_t *key_handle; size_t key_handle_len;
    uint8_t *signature; size_t signature_len;
    uint8_t *attestation_cert; size_t attestation_cert_len;
    uint8_t *authdata; size_t authdata_len;
};
struct sk_resident_key {
    uint32_t alg; size_t slot; char *application;
    struct sk_enroll_response key;
    uint8_t flags; uint8_t *user_id; size_t user_id_len;
};
static const uint8_t p256[] = {
0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};
static const uint8_t ed25519[] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
static uint8_t *bytes(size_t size) {
    uint8_t *p = malloc(size); assert(p); memset(p, 0x5a, size); return p;
}
static void populate(struct sk_enroll_response *r, uint32_t alg) {
    r->flags = 0x25;
    r->public_key_len = alg == 0 ? 65 : 32;
    r->public_key = bytes(r->public_key_len);
    if (alg == 0) memcpy(r->public_key, p256, 65); else memcpy(r->public_key, ed25519, 32);
    r->key_handle = bytes(19); r->key_handle_len = 19; watch(r->key_handle, 19);
    r->signature = bytes(64); r->signature_len = 64;
    r->attestation_cert = bytes(100); r->attestation_cert_len = 100;
    r->authdata = bytes(37); r->authdata_len = 37;
}
static const char *options(struct sk_option **opts, int user) {
    if (!opts) return "default";
    assert(opts[0] && !strcmp(opts[0]->name, "device") && !opts[0]->required);
    if (user) {
        assert(opts[1] && !strcmp(opts[1]->name, "user") && !opts[1]->required);
        assert(!strcmp(opts[1]->value, "alice") && !opts[2]);
    } else assert(!opts[1]);
    return opts[0]->value;
}
static void corrupt(struct sk_enroll_response *r, const char *mode) {
    if (!strcmp(mode, "null-public")) { free(r->public_key); r->public_key = NULL; }
    if (!strcmp(mode, "oversize-handle")) r->key_handle_len = SIZE_MAX;
    if (!strcmp(mode, "empty-handle")) r->key_handle_len = 0;
    if (!strcmp(mode, "null-attestation")) { free(r->authdata); r->authdata = NULL; }
    if (!strcmp(mode, "oversize-attestation")) r->signature_len = SIZE_MAX;
    if (!strcmp(mode, "bad-point")) memset(r->public_key, 0, r->public_key_len);
}
uint32_t sk_api_version(void) { return 0x000a0000; }
int sk_sign(void) { return -2; }
int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **opts, struct sk_enroll_response **out) {
    const char *mode = options(opts, 1);
    assert(alg == 0 || alg == 1);
    assert(challenge_len == 9 && !memcmp(challenge, "challenge", 9));
    assert(!strcmp(application, "ssh:fixture") && flags == 0x21);
    assert(pin && !strcmp(pin, "1234")); watch((void *)pin, strlen(pin) + 1);
    if (!strcmp(mode, "missing")) return 0;
    *out = calloc(1, sizeof(**out)); assert(*out); populate(*out, alg);
    corrupt(*out, mode);
    return !strcmp(mode, "pin-error") ? -3 : 0;
}
int sk_load_resident_keys(const char *pin, struct sk_option **opts,
    struct sk_resident_key ***out, size_t *count) {
    const char *mode = options(opts, 0);
    assert(pin && !strcmp(pin, "1234")); watch((void *)pin, strlen(pin) + 1);
    if (!strcmp(mode, "empty")) return 0;
    if (!strcmp(mode, "null-array")) { *count = 1; return 0; }
    if (!strcmp(mode, "oversize-array")) {
        *out = calloc(1, sizeof(**out)); *count = SIZE_MAX; return 0;
    }
    *count = 2; *out = calloc(*count, sizeof(**out)); assert(*out);
    for (size_t i = 0; i < *count; i++) {
        if (!strcmp(mode, "null-entry") && i == 1) continue;
        struct sk_resident_key *r = calloc(1, sizeof(*r)); assert(r);
        (*out)[i] = r; r->alg = i; r->slot = 100 + i;
        r->application = strdup("ssh:fixture"); populate(&r->key, i);
        r->flags = i == 0 ? 4 : 0;
        r->key.flags = 0xff; /* Must use resident flags, not these flags. */
        r->user_id = bytes(5); r->user_id_len = 5;
        if (!strcmp(mode, "filtered")) {
            if (i == 0) { free(r->application); r->application = strdup("https:example"); }
            else r->alg = 99;
        }
        if (!strcmp(mode, "bad-user")) { free(r->user_id); r->user_id = NULL; }
        if (!strcmp(mode, "null-application")) { free(r->application); r->application = NULL; }
        if (!strcmp(mode, "long-application")) {
            free(r->application); r->application = (char *)bytes(4097); r->application[4096] = 0;
        }
        if (!strcmp(mode, "nonutf8-application")) r->application[4] = (char)0xff;
        corrupt(&r->key, mode);
    }
    return !strcmp(mode, "pin-error") ? -3 : 0;
}
"#;

    fn provider() -> Option<(tempfile::TempDir, ExternalProvider)> {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("enroll.c");
        let library = directory.path().join("enroll.so");
        std::fs::write(&source, PROVIDER).unwrap();
        let output = match std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&library)
            .arg(source)
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("C compiler unavailable; skipping compiled ABI test");
                return None;
            }
            Err(error) => panic!("could not run C compiler: {error}"),
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let provider = ExternalProvider::load(&library).unwrap();
        Some((directory, provider))
    }

    fn request(mode: &str, algorithm: SkAlgorithm) -> SkEnrollRequest<'_> {
        SkEnrollRequest {
            algorithm,
            challenge: b"challenge",
            application: "ssh:fixture",
            flags: 0x21,
            device: Some(mode),
            user: Some("alice"),
        }
    }

    #[test]
    fn enrolls_both_algorithms_and_downloads_resident_keys_through_real_abi() {
        let Some((_directory, provider)) = provider() else {
            return;
        };
        for algorithm in [SkAlgorithm::Ed25519, SkAlgorithm::EcdsaSha2NistP256] {
            let result = provider
                .enroll(&request("default", algorithm), Some("1234"))
                .unwrap();
            assert_eq!(result.flags, 0x25);
            assert_eq!(&result.key_handle[..], &[0x5a; 19]);
            assert_eq!(
                result.public_key.len(),
                if algorithm == SkAlgorithm::Ed25519 {
                    32
                } else {
                    65
                }
            );
        }
        let keys = provider
            .load_resident_keys(Some("1234"), Some("default"))
            .unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].algorithm, SkAlgorithm::EcdsaSha2NistP256);
        assert_eq!(keys[1].algorithm, SkAlgorithm::Ed25519);
        assert_eq!(keys[0].key.flags, 0x25);
        assert_eq!(keys[1].key.flags, 0x21);
        for key in keys {
            assert_eq!(key.application, "ssh:fixture");
            assert_eq!(&key.key.key_handle[..], &[0x5a; 19]);
            assert_eq!(key.user_id, [0x5a; 5]);
        }
        for device in [None, Some("default")] {
            assert_eq!(
                provider
                    .load_resident_keys(Some("1234"), device)
                    .unwrap()
                    .len(),
                2
            );
        }
        for mode in ["empty", "filtered"] {
            assert!(
                provider
                    .load_resident_keys(Some("1234"), Some(mode))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn rejects_malformed_enrollment_and_resident_responses() {
        let Some((_directory, provider)) = provider() else {
            return;
        };
        for mode in [
            "missing",
            "null-public",
            "oversize-handle",
            "empty-handle",
            "null-attestation",
            "oversize-attestation",
            "bad-point",
        ] {
            assert!(
                matches!(
                    provider.enroll(&request(mode, SkAlgorithm::EcdsaSha2NistP256), Some("1234")),
                    Err(SecurityKeyError::InvalidResponse(_))
                ),
                "{mode}"
            );
        }
        assert!(matches!(
            provider.enroll(&request("bad-point", SkAlgorithm::Ed25519), Some("1234")),
            Err(SecurityKeyError::InvalidResponse(_))
        ));
        for mode in [
            "null-array",
            "oversize-array",
            "null-entry",
            "null-public",
            "oversize-handle",
            "empty-handle",
            "null-attestation",
            "oversize-attestation",
            "bad-user",
            "null-application",
            "long-application",
            "nonutf8-application",
            "bad-point",
        ] {
            assert!(
                matches!(
                    provider.load_resident_keys(Some("1234"), Some(mode)),
                    Err(SecurityKeyError::InvalidResponse(_))
                ),
                "{mode}"
            );
        }
        assert_eq!(
            provider
                .enroll(&request("pin-error", SkAlgorithm::Ed25519), Some("1234"))
                .unwrap_err(),
            SecurityKeyError::PinRequired
        );
        assert_eq!(
            provider
                .load_resident_keys(Some("1234"), Some("pin-error"))
                .unwrap_err(),
            SecurityKeyError::PinRequired
        );
    }

    #[test]
    fn invalid_inputs_never_enter_the_provider() {
        let Some((_directory, provider)) = provider() else {
            return;
        };
        let mut request = request("default", SkAlgorithm::Ed25519);
        assert!(provider.enroll(&request, Some("12\0")).is_err());
        assert!(provider.load_resident_keys(Some("12\0"), None).is_err());
        assert!(
            provider
                .load_resident_keys(Some("1234"), Some("dev\0"))
                .is_err()
        );
        request.user = Some("alice\0");
        assert!(provider.enroll(&request, Some("1234")).is_err());
        request.user = Some("alice");
        request.challenge = b"";
        assert!(provider.enroll(&request, Some("1234")).is_err());
    }

    #[cfg(target_env = "gnu")]
    #[test]
    fn cleanup_zeroizes_handles_and_pins_on_success_and_error() {
        const CHILD: &str = "BSSH_SK_CLEANUP_FIXTURE";
        if let Some(path) = std::env::var_os(CHILD) {
            let provider = ExternalProvider::load(std::path::Path::new(&path)).unwrap();
            for mode in ["default", "pin-error", "bad-point", "null-attestation"] {
                let _ =
                    provider.enroll(&request(mode, SkAlgorithm::EcdsaSha2NistP256), Some("1234"));
                let _ = provider.load_resident_keys(Some("1234"), Some(mode));
                // SAFETY: fixture symbols have no-argument int prototypes;
                // provider lifetime keeps their library mapped.
                unsafe {
                    for symbol in [
                        b"bssh_fixture_live\0".as_slice(),
                        b"bssh_fixture_dirty\0".as_slice(),
                    ] {
                        let count = provider
                            ._loaded_for_tests()
                            .get::<unsafe extern "C" fn() -> c_int>(symbol)
                            .unwrap();
                        assert_eq!(count(), 0, "{mode}: {}", String::from_utf8_lossy(symbol));
                    }
                    let freed = provider
                        ._loaded_for_tests()
                        .get::<unsafe extern "C" fn() -> c_int>(b"bssh_fixture_freed\0")
                        .unwrap();
                    assert!(freed() >= 5, "free interposition did not run");
                }
            }
            return;
        }
        let Some((directory, _provider)) = provider() else {
            return;
        };
        let library = directory.path().join("enroll.so");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                concat!(
                    module_path!(),
                    "::cleanup_zeroizes_handles_and_pins_on_success_and_error"
                )
                .strip_prefix("bssh::")
                .unwrap(),
                "--nocapture",
            ])
            .env(CHILD, &library)
            .env("LD_PRELOAD", &library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "cleanup child did not run"
        );
    }
}
