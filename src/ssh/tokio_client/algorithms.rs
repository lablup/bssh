//! OpenSSH-style algorithm list resolution for the russh transport.

use std::sync::LazyLock;

use glob::Pattern;
use russh::{cipher, kex, mac};
use ssh_key::Algorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListMode {
    Replace,
    Append,
    Remove,
    Prepend,
}

fn list_mode(values: &[String]) -> (ListMode, Vec<&str>) {
    let Some((first, rest)) = values.split_first() else {
        return (ListMode::Replace, Vec::new());
    };
    let (mode, first) = match first.as_bytes().first() {
        Some(b'+') => (ListMode::Append, &first[1..]),
        Some(b'-') => (ListMode::Remove, &first[1..]),
        Some(b'^') => (ListMode::Prepend, &first[1..]),
        _ => (ListMode::Replace, first.as_str()),
    };
    let mut names = Vec::with_capacity(values.len());
    if !first.is_empty() {
        names.push(first);
    }
    names.extend(rest.iter().map(String::as_str));
    (mode, names)
}

fn expand_supported<T: Clone + PartialEq>(
    kind: &str,
    names: &[&str],
    supported: &[T],
    name: impl Fn(&T) -> &str,
) -> Result<Vec<T>, String> {
    let mut expanded = Vec::new();
    for configured in names {
        let pattern = Pattern::new(configured).map_err(|error| error.to_string())?;
        let matches = supported
            .iter()
            .filter(|algorithm| pattern.matches(name(algorithm)))
            .cloned()
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(unsupported(
                kind,
                configured,
                supported.iter().map(|value| name(value).to_string()),
            ));
        }
        for algorithm in matches {
            if !expanded.contains(&algorithm) {
                expanded.push(algorithm);
            }
        }
    }
    Ok(expanded)
}

fn combine<T: Clone + PartialEq>(defaults: &[T], configured: Vec<T>, mode: ListMode) -> Vec<T> {
    match mode {
        ListMode::Replace => configured,
        ListMode::Append => {
            defaults
                .iter()
                .cloned()
                .chain(configured)
                .fold(Vec::new(), |mut result, algorithm| {
                    if !result.contains(&algorithm) {
                        result.push(algorithm);
                    }
                    result
                })
        }
        ListMode::Prepend => configured.into_iter().chain(defaults.iter().cloned()).fold(
            Vec::new(),
            |mut result, algorithm| {
                if !result.contains(&algorithm) {
                    result.push(algorithm);
                }
                result
            },
        ),
        ListMode::Remove => unreachable!("remove is handled before conversion"),
    }
}

fn unsupported(kind: &str, name: &str, supported: impl Iterator<Item = String>) -> String {
    format!(
        "unsupported {kind} '{name}'; supported values: {}",
        supported.collect::<Vec<_>>().join(",")
    )
}

fn resolve_policy<T: Clone + PartialEq>(
    kind: &str,
    values: &[String],
    defaults: &[T],
    supported: &[T],
    name: impl Fn(&T) -> &str + Copy,
) -> Result<Vec<T>, String> {
    let (mode, names) = list_mode(values);
    if names.is_empty() {
        return Err(format!(
            "empty {kind} policy; supported values: {}",
            supported.iter().map(name).collect::<Vec<_>>().join(",")
        ));
    }
    let resolved = if mode == ListMode::Remove {
        let removed = expand_supported(kind, &names, supported, name)?;
        defaults
            .iter()
            .filter(|algorithm| !removed.contains(algorithm))
            .cloned()
            .collect()
    } else {
        let configured = expand_supported(kind, &names, supported, name)?;
        combine(defaults, configured, mode)
    };
    if resolved.is_empty() {
        return Err(format!("{kind} policy selects no supported algorithms"));
    }
    Ok(resolved)
}

fn selectable_ciphers() -> Vec<cipher::Name> {
    cipher::ALL_CIPHERS
        .iter()
        .map(|value| **value)
        .filter(|value| !matches!(value.as_ref(), "clear" | "none"))
        .collect()
}

fn selectable_macs() -> Vec<mac::Name> {
    mac::ALL_MAC_ALGORITHMS
        .iter()
        .map(|value| **value)
        .filter(|value| value.as_ref() != "none")
        .collect()
}

#[must_use]
pub fn supported_cipher_names() -> Vec<String> {
    selectable_ciphers()
        .iter()
        .map(|value| value.as_ref().to_string())
        .collect()
}

#[must_use]
pub fn supported_mac_names() -> Vec<String> {
    selectable_macs()
        .iter()
        .map(|value| value.as_ref().to_string())
        .collect()
}

pub(crate) fn resolve_ciphers(values: &[String]) -> Result<Vec<cipher::Name>, String> {
    let supported = selectable_ciphers();
    resolve_policy(
        "cipher",
        values,
        russh::Preferred::DEFAULT.cipher.as_ref(),
        &supported,
        AsRef::as_ref,
    )
}

pub(crate) fn resolve_macs(values: &[String]) -> Result<Vec<mac::Name>, String> {
    let supported = selectable_macs();
    resolve_policy(
        "MAC",
        values,
        russh::Preferred::DEFAULT.mac.as_ref(),
        &supported,
        AsRef::as_ref,
    )
}

pub(crate) fn resolve_kex(values: &[String]) -> Result<Vec<kex::Name>, String> {
    let extensions = [
        kex::EXTENSION_SUPPORT_AS_CLIENT,
        kex::EXTENSION_SUPPORT_AS_SERVER,
        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
    ];
    let defaults = russh::Preferred::DEFAULT
        .kex
        .iter()
        .filter(|value| !extensions.contains(value))
        .cloned()
        .collect::<Vec<_>>();
    let supported = kex::ALL_KEX_ALGORITHMS
        .iter()
        .map(|value| **value)
        .collect::<Vec<_>>();
    let mut resolved = resolve_policy(
        "key exchange algorithm",
        values,
        &defaults,
        &supported,
        AsRef::as_ref,
    )?;
    resolved.extend(extensions);
    Ok(resolved)
}

fn supported_key_algorithms() -> Vec<Algorithm> {
    let mut supported = default_host_key_algorithms().to_vec();
    for algorithm in russh::keys::key::ALL_KEY_TYPES {
        if !supported.contains(algorithm) {
            supported.push(algorithm.clone());
        }
    }
    supported
}

/// OpenSSH's default plain host-key order (`KEX_DEFAULT_PK_ALG` in
/// `myproposal.h`): Ed25519, the ECDSA curves, the FIDO `sk-*` types, then
/// the SHA-2 RSA signatures. The SHA-1 `ssh-rsa` signature is not offered;
/// `HostKeyAlgorithms +ssh-rsa` opts back in. bssh does not verify
/// `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, so that entry is absent.
pub(crate) fn default_host_key_algorithms() -> &'static [Algorithm] {
    static DEFAULTS: LazyLock<Vec<Algorithm>> = LazyLock::new(|| {
        vec![
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: russh::keys::ssh_key::EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: russh::keys::ssh_key::EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: russh::keys::ssh_key::EcdsaCurve::NistP521,
            },
            Algorithm::SkEd25519,
            Algorithm::SkEcdsaSha2NistP256,
            Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha512),
            },
            Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha256),
            },
        ]
    });
    &DEFAULTS
}

/// Host-key algorithm policy split into the plain and certificate lists
/// russh advertises separately. Certificate names are advertised ahead of
/// plain names, matching OpenSSH's default `HostKeyAlgorithms` order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct HostKeyAlgorithms {
    pub keys: Vec<Algorithm>,
    pub certificates: Vec<Algorithm>,
}

const CERTIFICATE_SUFFIX: &str = "-cert-v01@openssh.com";

/// Certificate names first, then plain names, as OpenSSH orders them.
fn host_key_names(algorithms: &[Algorithm]) -> Vec<String> {
    let mut names: Vec<String> = algorithms
        .iter()
        .map(|algorithm| algorithm.to_certificate_type().to_string())
        .collect();
    names.extend(algorithms.iter().map(ToString::to_string));
    names
}

/// Certificate algorithms advertised by default: the certificate form of
/// every default plain algorithm, as OpenSSH does.
pub(crate) fn default_host_key_certificates() -> &'static [Algorithm] {
    default_host_key_algorithms()
}

pub(crate) fn resolve_host_keys(values: &[String]) -> Result<HostKeyAlgorithms, String> {
    let defaults = host_key_names(default_host_key_algorithms());
    let supported = host_key_names(&supported_key_algorithms());
    let resolved = resolve_policy(
        "host key algorithm",
        values,
        &defaults,
        &supported,
        String::as_str,
    )?;
    let mut policy = HostKeyAlgorithms::default();
    for name in resolved {
        let (parsed, list) = if name.ends_with(CERTIFICATE_SUFFIX) {
            (certificate_algorithm(&name), &mut policy.certificates)
        } else {
            (Algorithm::new(&name), &mut policy.keys)
        };
        let algorithm =
            parsed.map_err(|error| format!("unsupported host key algorithm {name}: {error}"))?;
        if !list.contains(&algorithm) {
            list.push(algorithm);
        }
    }
    Ok(policy)
}

/// Parse a `*-cert-v01@openssh.com` name into the plain algorithm it wraps.
/// The SHA-2 RSA certificate names are not known to ssh-key's parser, and
/// the `sk-*@openssh.com` names share their `@openssh.com` suffix with the
/// certificate suffix, so this cannot be a plain suffix strip.
fn certificate_algorithm(name: &str) -> Result<Algorithm, ssh_key::Error> {
    match name {
        "rsa-sha2-256-cert-v01@openssh.com" => Ok(Algorithm::Rsa {
            hash: Some(russh::keys::HashAlg::Sha256),
        }),
        "rsa-sha2-512-cert-v01@openssh.com" => Ok(Algorithm::Rsa {
            hash: Some(russh::keys::HashAlg::Sha512),
        }),
        other => Algorithm::new_certificate(other),
    }
}

/// OpenSSH's default `CASignatureAlgorithms`.
pub(crate) const DEFAULT_CA_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Resolve `CASignatureAlgorithms` (with `+`, `-`, `^` modifiers) into the
/// signature algorithm names a certificate authority may use.
pub(crate) fn resolve_ca_signature_algorithms(values: &[String]) -> Result<Vec<String>, String> {
    let defaults: Vec<String> = DEFAULT_CA_SIGNATURE_ALGORITHMS
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    if values.is_empty() {
        return Ok(defaults);
    }
    let mut supported = defaults.clone();
    supported.push("ssh-rsa".to_string());
    resolve_policy(
        "CA signature algorithm",
        values,
        &defaults,
        &supported,
        String::as_str,
    )
}

fn public_key_names(algorithms: &[Algorithm]) -> Vec<String> {
    algorithms
        .iter()
        .flat_map(|algorithm| {
            [
                algorithm.to_certificate_type().to_string(),
                algorithm.to_string(),
            ]
        })
        .collect()
}

/// OpenSSH's default `PubkeyAcceptedAlgorithms`: every certificate name
/// first, then every plain name, in `KEX_DEFAULT_PK_ALG` order.
pub(crate) fn default_pubkey_algorithms() -> Vec<String> {
    host_key_names(default_host_key_algorithms())
}

pub(crate) fn resolve_pubkey_algorithms(values: &[String]) -> Result<Vec<String>, String> {
    let defaults = default_pubkey_algorithms();
    let supported = public_key_names(&supported_key_algorithms());
    resolve_policy(
        "public key signature algorithm",
        values,
        &defaults,
        &supported,
        String::as_str,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifiers_append_prepend_and_remove_against_transport_defaults() {
        let appended = resolve_ciphers(&[String::from("+aes128-cbc")]).unwrap();
        assert_eq!(appended.last(), Some(&cipher::AES_128_CBC));
        let prepended = resolve_macs(&[String::from("^hmac-sha1")]).unwrap();
        assert_eq!(prepended.first(), Some(&mac::HMAC_SHA1));
        let removed = resolve_kex(&[String::from("-*sha1")]).unwrap();
        assert!(removed.iter().all(|name| !name.as_ref().ends_with("sha1")));
    }

    #[test]
    fn wildcards_expand_and_empty_policies_fail_closed() {
        let ciphers = resolve_ciphers(&[String::from("aes*-ctr")]).unwrap();
        assert!(!ciphers.is_empty());
        assert!(
            ciphers
                .iter()
                .all(|algorithm| algorithm.as_ref().starts_with("aes")
                    && algorithm.as_ref().ends_with("-ctr"))
        );

        let error = resolve_macs(&[String::from("-*")]).unwrap_err();
        assert!(error.contains("selects no supported algorithms"));
    }

    #[test]
    fn removal_and_internal_algorithms_fail_closed() {
        for policy in ["-not-real", "+", "-", "^", "clear", "none"] {
            let error = resolve_ciphers(&[policy.to_string()]).unwrap_err();
            assert!(error.contains("supported values"), "{policy}: {error}");
        }
        assert!(resolve_macs(&["none".to_string()]).is_err());
        assert!(
            !supported_cipher_names()
                .iter()
                .any(|name| name == "clear" || name == "none")
        );
        assert!(!supported_mac_names().iter().any(|name| name == "none"));

        // A supported non-default removal is valid and simply leaves the
        // default preference unchanged.
        assert_eq!(
            resolve_ciphers(&["-aes128-cbc".to_string()]).unwrap(),
            russh::Preferred::DEFAULT.cipher.as_ref()
        );
    }

    #[test]
    fn configured_kex_preserves_protocol_extension_markers() {
        let resolved = resolve_kex(&[String::from("curve25519-sha256")]).unwrap();
        assert_eq!(resolved[0], kex::CURVE25519);
        assert!(resolved.contains(&kex::EXTENSION_SUPPORT_AS_CLIENT));
        assert!(resolved.contains(&kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT));
    }

    #[test]
    fn pubkey_policy_resolves_modifiers_for_authentication_follow_up() {
        let resolved = resolve_pubkey_algorithms(&[String::from("rsa-sha2-*")]).unwrap();
        assert_eq!(
            resolved,
            [
                "rsa-sha2-512-cert-v01@openssh.com",
                "rsa-sha2-512",
                "rsa-sha2-256-cert-v01@openssh.com",
                "rsa-sha2-256"
            ]
        );

        let defaults = default_pubkey_algorithms();
        assert!(defaults.contains(&"rsa-sha2-512".to_string()));
        assert!(defaults.contains(&"rsa-sha2-256".to_string()));
        assert!(!defaults.contains(&"ssh-rsa".to_string()));
        assert!(!defaults.contains(&"ssh-rsa-cert-v01@openssh.com".to_string()));

        let sha1_opt_in = resolve_pubkey_algorithms(&[String::from("+ssh-rsa")]).unwrap();
        assert_eq!(sha1_opt_in.last().map(String::as_str), Some("ssh-rsa"));
    }

    #[test]
    fn host_key_modifiers_use_defaults_as_the_base_and_all_supported_as_candidates() {
        let defaults = default_host_key_algorithms();

        let appended = resolve_host_keys(&[String::from("+ssh-rsa")]).unwrap();
        assert_eq!(
            appended.certificates, defaults,
            "certificate algorithms follow the default plain list"
        );
        let appended = appended.keys;
        assert!(
            defaults
                .iter()
                .all(|algorithm| algorithm.as_ref() != "ssh-rsa")
        );
        assert_eq!(&appended[..defaults.len()], defaults);
        assert_eq!(appended.last().map(AsRef::as_ref), Some("ssh-rsa"));
        assert_eq!(
            appended
                .iter()
                .filter(|algorithm| algorithm.as_ref() == "ssh-rsa")
                .count(),
            1
        );

        let removed = resolve_host_keys(&[String::from("-ssh-*")]).unwrap();
        assert!(
            removed
                .certificates
                .iter()
                .all(|algorithm| !algorithm.as_ref().starts_with("ssh-")),
            "the glob removes certificate forms too"
        );
        assert_eq!(
            removed.keys,
            defaults
                .iter()
                .filter(|algorithm| !algorithm.as_ref().starts_with("ssh-"))
                .cloned()
                .collect::<Vec<_>>()
        );

        let nondefault = Algorithm::Dsa;
        assert!(!defaults.contains(&nondefault));
        let prepended = resolve_host_keys(&[format!("^{}", nondefault.as_ref())])
            .unwrap()
            .keys;
        assert_eq!(prepended.first(), Some(&nondefault));
        assert_eq!(
            prepended
                .iter()
                .filter(|algorithm| **algorithm == nondefault)
                .count(),
            1
        );
        assert_eq!(&prepended[1..], defaults);
    }

    #[test]
    fn explicit_certificate_host_key_algorithms_are_split_from_plain_ones() {
        let only_cert =
            resolve_host_keys(&[String::from("ssh-ed25519-cert-v01@openssh.com")]).unwrap();
        assert!(only_cert.keys.is_empty());
        assert_eq!(only_cert.certificates, vec![Algorithm::Ed25519]);

        let mixed = resolve_host_keys(&[
            String::from("rsa-sha2-512-cert-v01@openssh.com"),
            String::from("ssh-ed25519"),
            String::from("rsa-sha2-256"),
        ])
        .unwrap();
        assert_eq!(
            mixed.certificates,
            vec![Algorithm::Rsa {
                hash: Some(russh::keys::HashAlg::Sha512)
            }]
        );
        assert_eq!(
            mixed.keys,
            vec![
                Algorithm::Ed25519,
                Algorithm::Rsa {
                    hash: Some(russh::keys::HashAlg::Sha256)
                }
            ]
        );
        assert!(resolve_host_keys(&[String::from("ssh-dss-cert-v02@openssh.com")]).is_err());

        let sk = resolve_host_keys(&[
            String::from("sk-ssh-ed25519-cert-v01@openssh.com"),
            String::from("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"),
        ])
        .unwrap();
        assert_eq!(
            sk.certificates,
            vec![Algorithm::SkEd25519, Algorithm::SkEcdsaSha2NistP256]
        );
        assert!(sk.keys.is_empty());
    }

    #[test]
    fn ca_signature_algorithms_default_and_modifiers() {
        let defaults = resolve_ca_signature_algorithms(&[]).unwrap();
        assert_eq!(defaults.first().map(String::as_str), Some("ssh-ed25519"));
        assert!(!defaults.iter().any(|name| name == "ssh-rsa"));
        let with_sha1 = resolve_ca_signature_algorithms(&[String::from("+ssh-rsa")]).unwrap();
        assert_eq!(with_sha1.last().map(String::as_str), Some("ssh-rsa"));
        let only = resolve_ca_signature_algorithms(&[String::from("ssh-ed25519")]).unwrap();
        assert_eq!(only, vec!["ssh-ed25519".to_string()]);
        assert!(resolve_ca_signature_algorithms(&[String::from("ssh-dss")]).is_err());
    }

    #[test]
    fn pubkey_modifiers_use_defaults_as_the_base_and_all_supported_as_candidates() {
        let defaults = default_pubkey_algorithms();

        let appended = resolve_pubkey_algorithms(&[String::from("+ssh-rsa")]).unwrap();
        assert!(!defaults.iter().any(|algorithm| algorithm == "ssh-rsa"));
        assert_eq!(&appended[..defaults.len()], defaults);
        assert_eq!(appended.last().map(String::as_str), Some("ssh-rsa"));
        assert_eq!(
            appended
                .iter()
                .filter(|algorithm| *algorithm == "ssh-rsa")
                .count(),
            1
        );

        let removed = resolve_pubkey_algorithms(&[String::from("-ssh-*")]).unwrap();
        assert_eq!(
            removed,
            defaults
                .iter()
                .filter(|algorithm| !algorithm.starts_with("ssh-"))
                .cloned()
                .collect::<Vec<_>>()
        );

        let nondefault = Algorithm::Dsa.to_string();
        assert!(!defaults.contains(&nondefault));
        let prepended = resolve_pubkey_algorithms(&[format!("^{nondefault}")]).unwrap();
        assert_eq!(prepended.first(), Some(&nondefault));
        assert_eq!(
            prepended
                .iter()
                .filter(|algorithm| **algorithm == nondefault)
                .count(),
            1
        );
        assert_eq!(&prepended[1..], defaults);
    }

    /// `ssh -G` from the pinned OpenSSH 10.3p1 prints these lists minus the
    /// `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` entries bssh cannot verify.
    #[test]
    fn default_host_key_and_pubkey_lists_follow_openssh_order_with_sk_types() {
        let expected_plain = [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "rsa-sha2-512",
            "rsa-sha2-256",
        ];
        let plain = default_host_key_algorithms()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(plain, expected_plain);

        let mut expected_pubkey = expected_plain
            .iter()
            .map(|name| match *name {
                "sk-ssh-ed25519@openssh.com" => "sk-ssh-ed25519-cert-v01@openssh.com".to_string(),
                "sk-ecdsa-sha2-nistp256@openssh.com" => {
                    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com".to_string()
                }
                other => format!("{other}-cert-v01@openssh.com"),
            })
            .collect::<Vec<_>>();
        expected_pubkey.extend(expected_plain.iter().map(ToString::to_string));
        assert_eq!(default_pubkey_algorithms(), expected_pubkey);
        assert_eq!(
            host_key_names(default_host_key_algorithms()),
            expected_pubkey
        );
    }

    #[test]
    fn sk_wildcards_expand_to_the_supported_fido_types() {
        let hosts = resolve_host_keys(&[String::from("sk-*")]).unwrap();
        assert_eq!(
            hosts.keys,
            vec![Algorithm::SkEd25519, Algorithm::SkEcdsaSha2NistP256]
        );
        assert_eq!(hosts.certificates, hosts.keys);
        let pubkey = resolve_pubkey_algorithms(&[String::from("sk-ssh-ed25519*")]).unwrap();
        assert_eq!(
            pubkey,
            [
                "sk-ssh-ed25519-cert-v01@openssh.com",
                "sk-ssh-ed25519@openssh.com"
            ]
        );
    }

    #[test]
    fn unknown_algorithm_reports_supported_values() {
        let error = resolve_ciphers(&[String::from("unknown-cipher")]).unwrap_err();
        assert!(error.contains("unknown-cipher"));
        assert!(error.contains("aes256-ctr"));
    }
}
