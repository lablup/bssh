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

/// Handle SSH query options (-Q)
pub fn handle_query(query: &str) {
    match query {
        "cipher" => {
            println!("aes128-ctr\naes192-ctr\naes256-ctr");
            println!("aes128-gcm@openssh.com\naes256-gcm@openssh.com");
            println!("chacha20-poly1305@openssh.com");
        }
        "cipher-auth" => {
            println!("aes128-gcm@openssh.com\naes256-gcm@openssh.com");
            println!("chacha20-poly1305@openssh.com");
        }
        "mac" => {
            println!("hmac-sha2-256\nhmac-sha2-512\nhmac-sha1");
        }
        "kex" => {
            println!("curve25519-sha256\ncurve25519-sha256@libssh.org");
            println!("ecdh-sha2-nistp256\necdh-sha2-nistp384\necdh-sha2-nistp521");
        }
        "key" | "key-plain" | "key-cert" | "key-sig" => {
            println!("ssh-rsa\nssh-ed25519");
            println!("ecdsa-sha2-nistp256\necdsa-sha2-nistp384\necdsa-sha2-nistp521");
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
