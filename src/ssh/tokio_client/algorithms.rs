//! OpenSSH-style algorithm list resolution for the russh transport.

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

fn remove_matching<T: Clone>(
    defaults: &[T],
    patterns: &[&str],
    name: impl Fn(&T) -> &str,
) -> Result<Vec<T>, String> {
    let patterns = patterns
        .iter()
        .map(|pattern| Pattern::new(pattern).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(defaults
        .iter()
        .filter(|algorithm| {
            !patterns
                .iter()
                .any(|pattern| pattern.matches(name(algorithm)))
        })
        .cloned()
        .collect())
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
    let resolved = if mode == ListMode::Remove {
        remove_matching(defaults, &names, name)?
    } else {
        let configured = expand_supported(kind, &names, supported, name)?;
        combine(defaults, configured, mode)
    };
    if resolved.is_empty() {
        return Err(format!("{kind} policy selects no supported algorithms"));
    }
    Ok(resolved)
}

pub(crate) fn resolve_ciphers(values: &[String]) -> Result<Vec<cipher::Name>, String> {
    let supported = cipher::ALL_CIPHERS
        .iter()
        .map(|value| **value)
        .collect::<Vec<_>>();
    resolve_policy(
        "cipher",
        values,
        russh::Preferred::DEFAULT.cipher.as_ref(),
        &supported,
        AsRef::as_ref,
    )
}

pub(crate) fn resolve_macs(values: &[String]) -> Result<Vec<mac::Name>, String> {
    let supported = mac::ALL_MAC_ALGORITHMS
        .iter()
        .map(|value| **value)
        .collect::<Vec<_>>();
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
    let mut supported = russh::Preferred::DEFAULT.key.to_vec();
    for algorithm in russh::keys::key::ALL_KEY_TYPES {
        if !supported.contains(algorithm) {
            supported.push(algorithm.clone());
        }
    }
    supported
}

pub(crate) fn resolve_host_keys(values: &[String]) -> Result<Vec<Algorithm>, String> {
    let defaults = russh::Preferred::DEFAULT.key.as_ref();
    let supported = supported_key_algorithms();
    resolve_policy(
        "host key algorithm",
        values,
        defaults,
        &supported,
        AsRef::as_ref,
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

pub(crate) fn resolve_pubkey_algorithms(values: &[String]) -> Result<Vec<String>, String> {
    let defaults = public_key_names(russh::Preferred::DEFAULT.key.as_ref());
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
    }

    #[test]
    fn host_key_modifiers_use_defaults_as_the_base_and_all_supported_as_candidates() {
        let defaults = russh::Preferred::DEFAULT.key.as_ref();

        let appended = resolve_host_keys(&[String::from("+ssh-rsa")]).unwrap();
        assert_eq!(appended, defaults);
        assert_eq!(
            appended
                .iter()
                .filter(|algorithm| algorithm.as_ref() == "ssh-rsa")
                .count(),
            1
        );

        let removed = resolve_host_keys(&[String::from("-ssh-*")]).unwrap();
        assert_eq!(
            removed,
            defaults
                .iter()
                .filter(|algorithm| !algorithm.as_ref().starts_with("ssh-"))
                .cloned()
                .collect::<Vec<_>>()
        );

        let nondefault = Algorithm::SkEd25519;
        assert!(!defaults.contains(&nondefault));
        let prepended = resolve_host_keys(&[format!("^{}", nondefault.as_ref())]).unwrap();
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
    fn pubkey_modifiers_use_defaults_as_the_base_and_all_supported_as_candidates() {
        let defaults = public_key_names(russh::Preferred::DEFAULT.key.as_ref());

        let appended = resolve_pubkey_algorithms(&[String::from("+ssh-rsa")]).unwrap();
        assert_eq!(appended, defaults);
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

        let nondefault = Algorithm::SkEd25519.to_string();
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

    #[test]
    fn unknown_algorithm_reports_supported_values() {
        let error = resolve_ciphers(&[String::from("unknown-cipher")]).unwrap_err();
        assert!(error.contains("unknown-cipher"));
        assert!(error.contains("aes256-ctr"));
    }
}
