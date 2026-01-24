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

//! Ed25519 key generation
//!
//! Ed25519 is a modern elliptic curve signature algorithm that provides:
//! - 128-bit security level (equivalent to RSA-3072)
//! - Fast key generation and signing operations
//! - Compact key size (32 bytes public key, 64 bytes private key)
//! - Deterministic signatures (no random number needed for signing)
//! - Resistance to side-channel attacks

use super::GeneratedKey;
use anyhow::{Context, Result};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use ssh_key::LineEnding;
use std::io::Write;
use std::path::Path;

/// Generate an Ed25519 SSH key pair
///
/// # Arguments
///
/// * `output_path` - Path where the private key will be written
/// * `comment` - Optional comment to include in the public key
///
/// # Returns
///
/// Returns `GeneratedKey` containing the private key, public key, and fingerprint
pub fn generate(output_path: &Path, comment: Option<&str>) -> Result<GeneratedKey> {
    tracing::info!("Generating Ed25519 key pair");

    // Generate key pair using cryptographically secure RNG
    let keypair = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
        .context("Failed to generate Ed25519 key")?;

    // Get public key and fingerprint
    let public_key = keypair.public_key();
    let fingerprint = format!("{}", public_key.fingerprint(HashAlg::Sha256));

    // Format private key in OpenSSH format
    let private_key_pem = keypair
        .to_openssh(LineEnding::LF)
        .context("Failed to encode private key to OpenSSH format")?;

    // Format public key with comment
    let comment_str = comment.unwrap_or("bssh-keygen");
    let public_key_base64 = public_key
        .to_openssh()
        .context("Failed to encode public key to OpenSSH format")?;
    let public_key_openssh = format!("{} {}", public_key_base64, comment_str);

    // Write private key with secure permissions
    write_private_key(output_path, &private_key_pem)?;

    // Write public key
    let pub_path = format!("{}.pub", output_path.display());
    std::fs::write(&pub_path, format!("{}\n", public_key_openssh))
        .with_context(|| format!("Failed to write public key to {}", pub_path))?;

    tracing::info!(
        path = %output_path.display(),
        fingerprint = %fingerprint,
        "Generated Ed25519 key"
    );

    Ok(GeneratedKey {
        private_key_pem: private_key_pem.to_string(),
        public_key_openssh,
        fingerprint,
        key_type: "ed25519".to_string(),
    })
}

/// Write private key file with secure permissions (0600 on Unix)
fn write_private_key(path: &Path, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // -rw------- (owner read/write only)
            .open(path)
            .with_context(|| format!("Failed to create private key file: {}", path.display()))?;

        file.write_all(content.as_bytes())
            .with_context(|| format!("Failed to write private key: {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write private key: {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_ed25519_key() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate(&key_path, Some("test@example.com"));
        assert!(result.is_ok());

        let key = result.unwrap();

        // Verify private key format
        assert!(key
            .private_key_pem
            .contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(key
            .private_key_pem
            .contains("-----END OPENSSH PRIVATE KEY-----"));

        // Verify public key format
        assert!(key.public_key_openssh.starts_with("ssh-ed25519 "));
        assert!(key.public_key_openssh.ends_with("test@example.com"));

        // Verify fingerprint format
        assert!(key.fingerprint.starts_with("SHA256:"));

        // Verify key type
        assert_eq!(key.key_type, "ed25519");
    }

    #[test]
    fn test_files_created() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate(&key_path, None);
        assert!(result.is_ok());

        // Verify private key file exists
        assert!(key_path.exists());

        // Verify public key file exists
        let pub_path = temp_dir.path().join("id_ed25519.pub");
        assert!(pub_path.exists());

        // Verify public key file content ends with newline
        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(pub_content.ends_with('\n'));
    }

    #[test]
    fn test_default_comment() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate(&key_path, None);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key.public_key_openssh.ends_with("bssh-keygen"));
    }

    #[test]
    #[cfg(unix)]
    fn test_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate(&key_path, None);
        assert!(result.is_ok());

        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_unique_keys() {
        let temp_dir = tempdir().unwrap();

        // Generate two keys
        let key_path1 = temp_dir.path().join("id_ed25519_1");
        let key_path2 = temp_dir.path().join("id_ed25519_2");

        let result1 = generate(&key_path1, None).unwrap();
        let result2 = generate(&key_path2, None).unwrap();

        // Keys should be different
        assert_ne!(result1.private_key_pem, result2.private_key_pem);
        assert_ne!(result1.public_key_openssh, result2.public_key_openssh);
        assert_ne!(result1.fingerprint, result2.fingerprint);
    }

    #[test]
    fn test_key_can_be_read_back() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_ed25519");

        let result = generate(&key_path, Some("test")).unwrap();

        // Read the private key back and verify it's valid
        let private_key_content = fs::read_to_string(&key_path).unwrap();
        assert_eq!(private_key_content, result.private_key_pem);

        // Read the public key back
        let pub_path = temp_dir.path().join("id_ed25519.pub");
        let public_key_content = fs::read_to_string(&pub_path).unwrap();
        assert_eq!(public_key_content.trim(), result.public_key_openssh);
    }
}
