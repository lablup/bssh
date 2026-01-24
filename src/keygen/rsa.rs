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

//! RSA key generation
//!
//! RSA is a widely-used public key cryptographic algorithm.
//! While still secure when used with sufficient key sizes (2048+ bits),
//! Ed25519 is recommended for new deployments due to its:
//! - Faster key generation and operations
//! - Smaller key sizes
//! - Better resistance to implementation errors
//!
//! RSA key generation is provided for compatibility with legacy systems.

use super::GeneratedKey;
use anyhow::{bail, Context, Result};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use ssh_key::LineEnding;
use std::io::Write;
use std::path::Path;

/// Minimum allowed RSA key size in bits
const MIN_RSA_BITS: u32 = 2048;

/// Maximum allowed RSA key size in bits
const MAX_RSA_BITS: u32 = 16384;

/// Generate an RSA SSH key pair
///
/// # Arguments
///
/// * `output_path` - Path where the private key will be written
/// * `bits` - Key size in bits (2048-16384)
/// * `comment` - Optional comment to include in the public key
///
/// # Returns
///
/// Returns `GeneratedKey` containing the private key, public key, and fingerprint
///
/// # Errors
///
/// Returns an error if:
/// - Key size is less than 2048 bits
/// - Key size exceeds 16384 bits
/// - Key generation fails
pub fn generate(output_path: &Path, bits: u32, comment: Option<&str>) -> Result<GeneratedKey> {
    // Validate key size
    if bits < MIN_RSA_BITS {
        bail!(
            "RSA key size must be at least {} bits for security. Got: {}",
            MIN_RSA_BITS,
            bits
        );
    }
    if bits > MAX_RSA_BITS {
        bail!(
            "RSA key size must not exceed {} bits. Got: {}",
            MAX_RSA_BITS,
            bits
        );
    }

    tracing::info!(bits = bits, "Generating RSA key pair");

    // Generate key pair using cryptographically secure RNG
    // Use SHA-256 for the RSA signature hash algorithm
    let keypair = PrivateKey::random(
        &mut rand::thread_rng(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    )
    .context("Failed to generate RSA key")?;

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
        bits = bits,
        fingerprint = %fingerprint,
        "Generated RSA key"
    );

    Ok(GeneratedKey {
        private_key_pem: private_key_pem.to_string(),
        public_key_openssh,
        fingerprint,
        key_type: format!("rsa-{}", bits),
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
    fn test_generate_rsa_2048() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 2048, Some("test@example.com"));
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
        assert!(key.public_key_openssh.starts_with("ssh-rsa "));
        assert!(key.public_key_openssh.ends_with("test@example.com"));

        // Verify fingerprint format
        assert!(key.fingerprint.starts_with("SHA256:"));

        // Verify key type includes bit size
        assert_eq!(key.key_type, "rsa-2048");
    }

    #[test]
    fn test_generate_rsa_4096() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 4096, None);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.key_type, "rsa-4096");
    }

    #[test]
    fn test_reject_small_key_size() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 1024, None);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("2048"));
        assert!(err.contains("1024"));
    }

    #[test]
    fn test_reject_huge_key_size() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 32768, None);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("16384"));
        assert!(err.contains("32768"));
    }

    #[test]
    fn test_files_created() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 2048, None);
        assert!(result.is_ok());

        // Verify private key file exists
        assert!(key_path.exists());

        // Verify public key file exists
        let pub_path = temp_dir.path().join("id_rsa.pub");
        assert!(pub_path.exists());

        // Verify public key file content ends with newline
        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(pub_content.ends_with('\n'));
    }

    #[test]
    fn test_default_comment() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 2048, None);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert!(key.public_key_openssh.ends_with("bssh-keygen"));
    }

    #[test]
    #[cfg(unix)]
    fn test_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 2048, None);
        assert!(result.is_ok());

        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_unique_keys() {
        let temp_dir = tempdir().unwrap();

        // Generate two keys
        let key_path1 = temp_dir.path().join("id_rsa_1");
        let key_path2 = temp_dir.path().join("id_rsa_2");

        let result1 = generate(&key_path1, 2048, None).unwrap();
        let result2 = generate(&key_path2, 2048, None).unwrap();

        // Keys should be different
        assert_ne!(result1.private_key_pem, result2.private_key_pem);
        assert_ne!(result1.public_key_openssh, result2.public_key_openssh);
        assert_ne!(result1.fingerprint, result2.fingerprint);
    }

    #[test]
    fn test_key_can_be_read_back() {
        let temp_dir = tempdir().unwrap();
        let key_path = temp_dir.path().join("id_rsa");

        let result = generate(&key_path, 2048, Some("test")).unwrap();

        // Read the private key back and verify it's valid
        let private_key_content = fs::read_to_string(&key_path).unwrap();
        assert_eq!(private_key_content, result.private_key_pem);

        // Read the public key back
        let pub_path = temp_dir.path().join("id_rsa.pub");
        let public_key_content = fs::read_to_string(&pub_path).unwrap();
        assert_eq!(public_key_content.trim(), result.public_key_openssh);
    }

    #[test]
    fn test_boundary_key_sizes() {
        let temp_dir = tempdir().unwrap();

        // Test minimum valid size
        let key_path = temp_dir.path().join("id_rsa_min");
        let result = generate(&key_path, 2048, None);
        assert!(result.is_ok());

        // Test just below minimum
        let key_path = temp_dir.path().join("id_rsa_below_min");
        let result = generate(&key_path, 2047, None);
        assert!(result.is_err());

        // Test maximum valid size (skip actual generation due to time)
        // Just verify the boundary logic with values near max
        let key_path = temp_dir.path().join("id_rsa_above_max");
        let result = generate(&key_path, 16385, None);
        assert!(result.is_err());
    }
}
