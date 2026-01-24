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

//! SSH key generation module
//!
//! This module provides functionality for generating SSH key pairs in OpenSSH format,
//! supporting Ed25519 (recommended) and RSA algorithms.
//!
//! # Example
//!
//! ```no_run
//! use bssh::keygen::{generate_ed25519, generate_rsa};
//! use std::path::Path;
//!
//! // Generate an Ed25519 key
//! let result = generate_ed25519(Path::new("/tmp/id_ed25519"), Some("user@host")).unwrap();
//! println!("Fingerprint: {}", result.fingerprint);
//!
//! // Generate an RSA key
//! let result = generate_rsa(Path::new("/tmp/id_rsa"), 4096, Some("user@host")).unwrap();
//! println!("Fingerprint: {}", result.fingerprint);
//! ```

pub mod ed25519;
pub mod rsa;

use anyhow::Result;
use std::path::Path;

/// Result of key generation containing the key material and metadata
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// Private key in OpenSSH PEM format
    pub private_key_pem: String,
    /// Public key in OpenSSH format (type base64 comment)
    pub public_key_openssh: String,
    /// SHA256 fingerprint of the public key
    pub fingerprint: String,
    /// Key type (ed25519 or rsa-BITS)
    pub key_type: String,
}

/// Generate an Ed25519 key pair
///
/// Ed25519 keys are recommended for most use cases due to their:
/// - Strong security with compact key size
/// - Fast key generation and signing
/// - Resistance to side-channel attacks
///
/// # Arguments
///
/// * `output_path` - Path where the private key will be written (public key goes to path.pub)
/// * `comment` - Optional comment to include in the key (defaults to "bssh-keygen")
///
/// # Returns
///
/// Returns `GeneratedKey` containing the key material and fingerprint
pub fn generate_ed25519(output_path: &Path, comment: Option<&str>) -> Result<GeneratedKey> {
    ed25519::generate(output_path, comment)
}

/// Generate an RSA key pair
///
/// RSA keys are supported for compatibility with older systems.
/// Ed25519 is recommended for new deployments.
///
/// # Arguments
///
/// * `output_path` - Path where the private key will be written (public key goes to path.pub)
/// * `bits` - Key size in bits (minimum 2048, maximum 16384, recommended 4096)
/// * `comment` - Optional comment to include in the key (defaults to "bssh-keygen")
///
/// # Returns
///
/// Returns `GeneratedKey` containing the key material and fingerprint
///
/// # Errors
///
/// Returns an error if:
/// - Key size is less than 2048 bits
/// - Key size exceeds 16384 bits
/// - Key generation fails
pub fn generate_rsa(output_path: &Path, bits: u32, comment: Option<&str>) -> Result<GeneratedKey> {
    rsa::generate(output_path, bits, comment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_ed25519() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate_ed25519(&key_path, Some("test@example.com"));
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key
            .private_key_pem
            .contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(key.public_key_openssh.starts_with("ssh-ed25519 "));
        assert!(key.public_key_openssh.contains("test@example.com"));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.key_type, "ed25519");

        // Verify files were created
        assert!(key_path.exists());
        let pub_path = temp_dir.path().join("id_ed25519.pub");
        assert!(pub_path.exists());
    }

    #[test]
    fn test_generate_rsa() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate_rsa(&key_path, 2048, Some("test@example.com"));
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key
            .private_key_pem
            .contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(key.public_key_openssh.starts_with("ssh-rsa "));
        assert!(key.public_key_openssh.contains("test@example.com"));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.key_type, "rsa-2048");

        // Verify files were created
        assert!(key_path.exists());
        let pub_path = temp_dir.path().join("id_rsa.pub");
        assert!(pub_path.exists());
    }

    #[test]
    fn test_generate_rsa_invalid_bits() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        // Too small
        let result = generate_rsa(&key_path, 1024, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("2048"));

        // Too large
        let result = generate_rsa(&key_path, 32768, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("16384"));
    }

    #[test]
    fn test_default_comment() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate_ed25519(&key_path, None);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key.public_key_openssh.contains("bssh-keygen"));
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate_ed25519(&key_path, None);
        assert!(result.is_ok());

        // Private key should be 0600
        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }
}
