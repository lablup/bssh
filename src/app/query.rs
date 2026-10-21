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

/// Plain host/user key types bssh can verify and authenticate with.
const PLAIN_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

/// Signature algorithm names, which add the SHA-2 RSA variants.
const SIGNATURE_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
];

fn certificate_names(plain: &[&str]) -> Vec<String> {
    plain
        .iter()
        .map(|name| format!("{name}-cert-v01@openssh.com"))
        .collect()
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
        "key-plain" => println!("{}", PLAIN_KEY_TYPES.join("\n")),
        "key-cert" => println!("{}", certificate_names(PLAIN_KEY_TYPES).join("\n")),
        "key" => {
            println!("{}", PLAIN_KEY_TYPES.join("\n"));
            println!("{}", certificate_names(PLAIN_KEY_TYPES).join("\n"));
        }
        "key-sig" => {
            println!("{}", SIGNATURE_KEY_TYPES.join("\n"));
            println!("{}", certificate_names(SIGNATURE_KEY_TYPES).join("\n"));
        }
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

    #[test]
    fn certificate_key_names_follow_openssh_naming() {
        assert_eq!(
            certificate_names(&["ssh-ed25519"]),
            vec!["ssh-ed25519-cert-v01@openssh.com".to_string()]
        );
        assert!(is_supported_query("key-cert"));
    }

    #[test]
    fn compression_query_is_supported_without_claiming_delayed_zlib() {
        assert!(is_supported_query("compression"));
        assert!(is_supported_query("COMPRESSION"));
    }
}
