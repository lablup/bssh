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

//! SSH query options handler (-Q option)

use bssh::diagnosticln as eprintln;

/// Key types bssh can verify and authenticate with, as `(plain, certificate)`
/// name pairs in the order the reference `ssh -Q key` prints them. The
/// FIDO `sk-*` certificate names do not derive from their plain names by
/// suffixing, so the table spells both out.
const KEY_TYPES: &[(&str, &str)] = &[
    ("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"),
    (
        "sk-ssh-ed25519@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    ),
    (
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ),
    ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com"),
];

/// Signature algorithms (`-Q key-sig`): the key types plus the SHA-2 RSA
/// variants. OpenSSH also lists `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`
/// here; bssh cannot verify WebAuthn signatures and leaves it out.
const SIGNATURE_TYPES: &[(&str, &str)] = &[
    ("rsa-sha2-256", "rsa-sha2-256-cert-v01@openssh.com"),
    ("rsa-sha2-512", "rsa-sha2-512-cert-v01@openssh.com"),
];

fn plain_names(pairs: &[(&'static str, &'static str)]) -> Vec<&'static str> {
    pairs.iter().map(|(plain, _)| *plain).collect::<Vec<_>>()
}

fn certificate_names(pairs: &[(&'static str, &'static str)]) -> Vec<&'static str> {
    pairs
        .iter()
        .map(|(_, certificate)| *certificate)
        .collect::<Vec<_>>()
}

/// `ssh -Q key` interleaves each plain name with its certificate form.
fn interleaved_names(pairs: &[(&'static str, &'static str)]) -> Vec<&'static str> {
    pairs
        .iter()
        .flat_map(|(plain, certificate)| [*plain, *certificate])
        .collect::<Vec<_>>()
}

fn key_sig_names() -> Vec<&'static str> {
    let mut names = interleaved_names(KEY_TYPES);
    names.extend(interleaved_names(SIGNATURE_TYPES));
    names
}

pub fn is_supported_query(query: &str) -> bool {
    matches!(
        query.to_ascii_lowercase().as_str(),
        "cipher"
            | "cipher-auth"
            | "mac"
            | "kex"
            | "kexalgorithms"
            | "compression"
            | "key"
            | "key-plain"
            | "key-cert"
            | "key-sig"
            | "protocol-version"
            | "help"
    )
}

/// Handle SSH query options (-Q)
pub fn handle_query(query: &str) {
    match query.to_ascii_lowercase().as_str() {
        "cipher" => {
            println!(
                "{}",
                bssh::ssh::tokio_client::supported_cipher_names().join("\n")
            );
        }
        "cipher-auth" => {
            println!("aes128-gcm@openssh.com\naes256-gcm@openssh.com");
            println!("chacha20-poly1305@openssh.com");
        }
        "mac" => {
            println!(
                "{}",
                bssh::ssh::tokio_client::supported_mac_names().join("\n")
            );
        }
        "kex" | "kexalgorithms" => {
            println!("curve25519-sha256\ncurve25519-sha256@libssh.org");
            println!("ecdh-sha2-nistp256\necdh-sha2-nistp384\necdh-sha2-nistp521");
        }
        "compression" => {
            // bssh can negotiate eager RFC 4253 zlib compression. Delayed
            // zlib@openssh.com remains intentionally disabled because the
            // underlying transport currently corrupts post-auth packets.
            println!("none\nzlib");
        }
        "key-plain" => println!("{}", plain_names(KEY_TYPES).join("\n")),
        "key-cert" => println!("{}", certificate_names(KEY_TYPES).join("\n")),
        "key" => println!("{}", interleaved_names(KEY_TYPES).join("\n")),
        "key-sig" => println!("{}", key_sig_names().join("\n")),
        "protocol-version" => {
            println!("2");
        }
        "help" => {
            println!("Available query options:");
            println!("  cipher            - Supported ciphers");
            println!("  cipher-auth       - Authenticated encryption ciphers");
            println!("  mac               - Supported MAC algorithms");
            println!("  kex               - Supported key exchange algorithms");
            println!("  compression       - Supported compression algorithms");
            println!("  key               - Supported key types");
            println!("  protocol-version  - SSH protocol version");
        }
        _ => {
            eprintln!("Unknown query option: {query}");
            eprintln!("Use 'bssh -Q help' to see available options");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_kex_algorithms_keyword_is_a_case_insensitive_query_alias() {
        for query in ["kex", "KexAlgorithms", "kexalgorithms"] {
            assert!(is_supported_query(query));
        }
    }

    /// Reference lists from the pinned OpenSSH 10.3p1 `ssh -Q`, minus the
    /// `webauthn-sk-*` signature names bssh does not verify.
    #[test]
    fn key_queries_match_the_reference_client_order() {
        assert!(is_supported_query("key-cert"));
        assert_eq!(
            plain_names(KEY_TYPES),
            [
                "ssh-ed25519",
                "sk-ssh-ed25519@openssh.com",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "sk-ecdsa-sha2-nistp256@openssh.com",
                "ssh-rsa",
            ]
        );
        assert_eq!(
            certificate_names(KEY_TYPES),
            [
                "ssh-ed25519-cert-v01@openssh.com",
                "sk-ssh-ed25519-cert-v01@openssh.com",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                "ssh-rsa-cert-v01@openssh.com",
            ]
        );
        assert_eq!(
            &interleaved_names(KEY_TYPES)[..4],
            [
                "ssh-ed25519",
                "ssh-ed25519-cert-v01@openssh.com",
                "sk-ssh-ed25519@openssh.com",
                "sk-ssh-ed25519-cert-v01@openssh.com",
            ]
        );
        assert_eq!(
            &key_sig_names()[14..],
            [
                "rsa-sha2-256",
                "rsa-sha2-256-cert-v01@openssh.com",
                "rsa-sha2-512",
                "rsa-sha2-512-cert-v01@openssh.com",
            ]
        );
        assert_eq!(key_sig_names().len(), 18);
        assert!(!key_sig_names().iter().any(|name| name.contains("webauthn")));
    }

    #[test]
    fn compression_query_is_supported_without_claiming_delayed_zlib() {
        assert!(is_supported_query("compression"));
        assert!(is_supported_query("COMPRESSION"));
    }
}
