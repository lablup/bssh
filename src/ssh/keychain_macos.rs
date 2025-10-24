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

//! macOS Keychain integration for SSH key passphrase management.
//!
//! This module provides secure storage and retrieval of SSH key passphrases
//! using the macOS Keychain Services API via the security-framework crate.
//!
//! # Security Considerations
//! - Passphrases are stored in the user's default keychain with appropriate access control
//! - All passphrase data is handled using `Zeroizing` to ensure secure memory cleanup
//! - Keychain items are keyed by the canonical path of the SSH key file
//! - Access to keychain items requires user authentication (managed by macOS)
//! - Passphrases are never logged or exposed in error messages
//!
//! # Implementation Notes
//! - This module is only compiled on macOS (`#[cfg(target_os = "macos")]`)
//! - Uses the Security Framework's GenericPassword API for storage
//! - Service name: "bssh-ssh-key-passphrase"
//! - Account name: canonical path of the SSH key file
//!
//! # Usage Example
//! ```no_run
//! use bssh::ssh::keychain_macos;
//!
//! # #[cfg(target_os = "macos")]
//! # async fn example() -> anyhow::Result<()> {
//! let key_path = "/Users/user/.ssh/id_ed25519";
//!
//! // Retrieve passphrase from Keychain
//! if let Some(passphrase) = keychain_macos::retrieve_passphrase(key_path).await? {
//!     println!("Found passphrase in Keychain");
//! }
//!
//! // Store passphrase in Keychain
//! keychain_macos::store_passphrase(key_path, "my-secret-passphrase").await?;
//!
//! // Delete passphrase from Keychain
//! keychain_macos::delete_passphrase(key_path).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use std::path::Path;
use zeroize::Zeroizing;

/// Service name used for storing SSH key passphrases in macOS Keychain.
/// This identifies all passphrase entries created by bssh.
const KEYCHAIN_SERVICE_NAME: &str = "bssh-ssh-key-passphrase";

/// Maximum passphrase length to prevent DoS attacks (8KB)
const MAX_PASSPHRASE_LENGTH: usize = 8192;

/// Store an SSH key passphrase in the macOS Keychain.
///
/// The passphrase is stored as a generic password with:
/// - Service: "bssh-ssh-key-passphrase"
/// - Account: canonical path of the SSH key file
/// - Password: the passphrase
///
/// If a passphrase already exists for the given key path, it will be updated.
///
/// # Arguments
/// * `key_path` - Path to the SSH key file (will be canonicalized)
/// * `passphrase` - The passphrase to store (will be zeroized after use)
///
/// # Security
/// - The passphrase is stored securely in the user's default keychain
/// - Access requires user authentication (managed by macOS)
/// - The passphrase is zeroized in memory after storage
///
/// # Errors
/// Returns an error if:
/// - The key path cannot be canonicalized
/// - The passphrase is too long (> 8KB)
/// - Keychain access is denied
/// - The Keychain service is unavailable
///
/// # Example
/// ```no_run
/// # #[cfg(target_os = "macos")]
/// # async fn example() -> anyhow::Result<()> {
/// use bssh::ssh::keychain_macos;
///
/// keychain_macos::store_passphrase(
///     "/Users/user/.ssh/id_ed25519",
///     "my-secret-passphrase"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn store_passphrase(key_path: impl AsRef<Path>, passphrase: &str) -> Result<()> {
    let key_path = key_path.as_ref();

    // Validate passphrase length
    if passphrase.len() > MAX_PASSPHRASE_LENGTH {
        anyhow::bail!(
            "Passphrase too long ({} bytes, max {} bytes)",
            passphrase.len(),
            MAX_PASSPHRASE_LENGTH
        );
    }

    // Canonicalize the key path to ensure consistency
    let canonical_path = tokio::fs::canonicalize(key_path)
        .await
        .with_context(|| format!("Failed to resolve SSH key path: {key_path:?}"))?;

    // SECURITY: Validate that the SSH key file is owned by the current user
    // This prevents storing passphrases for keys owned by other users
    let metadata = tokio::fs::metadata(&canonical_path)
        .await
        .with_context(|| format!("Failed to read SSH key file metadata: {canonical_path:?}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::getuid() };
        let file_uid = metadata.uid();

        if file_uid != current_uid {
            anyhow::bail!(
                "Security error: SSH key file is not owned by current user (file uid: {}, current uid: {}). \
                 Only the owner of an SSH key should be able to store its passphrase.",
                file_uid,
                current_uid
            );
        }

        // Also check that the file is not world-readable (common SSH security requirement)
        let mode = metadata.mode();
        if mode & 0o044 != 0 {
            tracing::warn!(
                "SSH key file has overly permissive permissions: {:o}. \
                 Consider restricting with: chmod 600 {}",
                mode & 0o777,
                canonical_path.display()
            );
        }
    }

    let account_name = canonical_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("SSH key path contains invalid UTF-8: {canonical_path:?}")
    })?;

    tracing::debug!("Storing passphrase in Keychain for key: {account_name}");

    // Use Zeroizing to ensure passphrase bytes are cleared from memory
    let passphrase_bytes = Zeroizing::new(passphrase.as_bytes().to_vec());

    // Perform Keychain operation in blocking task to avoid blocking async runtime
    let service_name = KEYCHAIN_SERVICE_NAME.to_string();
    let account_name_owned = account_name.to_string();

    tokio::task::spawn_blocking(move || -> Result<()> {
        // The security-framework crate will update the existing item if it exists
        set_generic_password(&service_name, &account_name_owned, &passphrase_bytes).with_context(
            || {
                "Failed to store passphrase in Keychain. \
             This may happen if Keychain access is denied or the Keychain is locked."
            },
        )?;

        tracing::info!("Successfully stored passphrase in Keychain for key: {account_name_owned}");
        Ok(())
    })
    .await
    .context("Keychain storage task panicked")??;

    Ok(())
}

/// Retrieve an SSH key passphrase from the macOS Keychain.
///
/// Searches for a passphrase stored with:
/// - Service: "bssh-ssh-key-passphrase"
/// - Account: canonical path of the SSH key file
///
/// # Arguments
/// * `key_path` - Path to the SSH key file (will be canonicalized)
///
/// # Returns
/// - `Ok(Some(passphrase))` if a passphrase was found
/// - `Ok(None)` if no passphrase is stored for this key
/// - `Err(...)` if an error occurred
///
/// # Security
/// - The returned passphrase is wrapped in `Zeroizing` for secure memory cleanup
/// - Access requires user authentication if the keychain is locked
/// - Passphrases are never logged
///
/// # Errors
/// Returns an error if:
/// - The key path cannot be canonicalized
/// - Keychain access is denied (after user authentication prompt)
/// - The Keychain service is unavailable
/// - An unexpected Keychain error occurs
///
/// # Example
/// ```no_run
/// # #[cfg(target_os = "macos")]
/// # async fn example() -> anyhow::Result<()> {
/// use bssh::ssh::keychain_macos;
///
/// if let Some(passphrase) = keychain_macos::retrieve_passphrase("/Users/user/.ssh/id_ed25519").await? {
///     println!("Found passphrase in Keychain");
///     // passphrase is automatically zeroized when dropped
/// }
/// # Ok(())
/// # }
/// ```
pub async fn retrieve_passphrase(key_path: impl AsRef<Path>) -> Result<Option<Zeroizing<String>>> {
    let key_path = key_path.as_ref();

    // Canonicalize the key path to match the storage format
    let canonical_path = tokio::fs::canonicalize(key_path)
        .await
        .with_context(|| format!("Failed to resolve SSH key path: {key_path:?}"))?;

    let account_name = canonical_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("SSH key path contains invalid UTF-8: {canonical_path:?}")
    })?;

    tracing::debug!("Retrieving passphrase from Keychain for key: {account_name}");

    // Perform Keychain operation in blocking task
    let service_name = KEYCHAIN_SERVICE_NAME.to_string();
    let account_name_owned = account_name.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<Option<Zeroizing<Vec<u8>>>> {
        match get_generic_password(&service_name, &account_name_owned) {
            Ok(passphrase_bytes) => {
                tracing::info!(
                    "Successfully retrieved passphrase from Keychain for key: {account_name_owned}"
                );
                Ok(Some(Zeroizing::new(passphrase_bytes)))
            }
            Err(err) => {
                // Check if it's a "not found" error vs. a real error
                let err_msg = format!("{err:?}");
                if err_msg.contains("errSecItemNotFound") || err_msg.contains("-25300") {
                    tracing::debug!(
                        "No passphrase found in Keychain for key: {account_name_owned}"
                    );
                    Ok(None)
                } else {
                    // Real error (access denied, keychain locked, etc.)
                    Err(anyhow::anyhow!(
                        "Failed to retrieve passphrase from Keychain: {err}\n\
                         This may happen if Keychain access is denied or the Keychain is locked."
                    ))
                }
            }
        }
    })
    .await
    .context("Keychain retrieval task panicked")??;

    // Convert bytes to string if found
    if let Some(passphrase_bytes) = result {
        let passphrase_str = Zeroizing::new(
            String::from_utf8(passphrase_bytes.to_vec())
                .context("Passphrase stored in Keychain is not valid UTF-8")?,
        );
        Ok(Some(passphrase_str))
    } else {
        Ok(None)
    }
}

/// Delete an SSH key passphrase from the macOS Keychain.
///
/// Removes a passphrase stored with:
/// - Service: "bssh-ssh-key-passphrase"
/// - Account: canonical path of the SSH key file
///
/// # Arguments
/// * `key_path` - Path to the SSH key file (will be canonicalized)
///
/// # Security
/// - Deletion requires user authentication (managed by macOS)
/// - If no passphrase exists for the key, this operation succeeds silently
///
/// # Errors
/// Returns an error if:
/// - The key path cannot be canonicalized
/// - Keychain access is denied
/// - The Keychain service is unavailable
/// - An unexpected Keychain error occurs
///
/// # Example
/// ```no_run
/// # #[cfg(target_os = "macos")]
/// # async fn example() -> anyhow::Result<()> {
/// use bssh::ssh::keychain_macos;
///
/// keychain_macos::delete_passphrase("/Users/user/.ssh/id_ed25519").await?;
/// # Ok(())
/// # }
/// ```
pub async fn delete_passphrase(key_path: impl AsRef<Path>) -> Result<()> {
    let key_path = key_path.as_ref();

    // Canonicalize the key path to match the storage format
    let canonical_path = tokio::fs::canonicalize(key_path)
        .await
        .with_context(|| format!("Failed to resolve SSH key path: {key_path:?}"))?;

    let account_name = canonical_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("SSH key path contains invalid UTF-8: {canonical_path:?}")
    })?;

    tracing::debug!("Deleting passphrase from Keychain for key: {account_name}");

    // Perform Keychain operation in blocking task
    let service_name = KEYCHAIN_SERVICE_NAME.to_string();
    let account_name_owned = account_name.to_string();

    tokio::task::spawn_blocking(move || -> Result<()> {
        match delete_generic_password(&service_name, &account_name_owned) {
            Ok(()) => {
                tracing::info!(
                    "Successfully deleted passphrase from Keychain for key: {account_name_owned}"
                );
                Ok(())
            }
            Err(err) => {
                // Check if it's a "not found" error vs. a real error
                let err_msg = format!("{err:?}");
                if err_msg.contains("errSecItemNotFound") || err_msg.contains("-25300") {
                    // Not found is not an error - succeed silently
                    tracing::debug!(
                        "No passphrase found in Keychain for key: {account_name_owned}"
                    );
                    Ok(())
                } else {
                    // Real error
                    Err(anyhow::anyhow!(
                        "Failed to delete passphrase from Keychain: {err}\n\
                         This may happen if Keychain access is denied."
                    ))
                }
            }
        }
    })
    .await
    .context("Keychain deletion task panicked")??;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_store_and_retrieve_passphrase() {
        // Create a temporary SSH key file
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        tokio::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nfake key\n-----END PRIVATE KEY-----",
        )
        .await
        .unwrap();

        let test_passphrase = "test-passphrase-12345";

        // Store passphrase
        store_passphrase(&key_path, test_passphrase)
            .await
            .expect("Failed to store passphrase");

        // Retrieve passphrase
        let retrieved = retrieve_passphrase(&key_path)
            .await
            .expect("Failed to retrieve passphrase");

        assert!(retrieved.is_some(), "Passphrase should be found");
        assert_eq!(
            retrieved.as_ref().unwrap().as_str(),
            test_passphrase,
            "Retrieved passphrase should match stored passphrase"
        );

        // Clean up
        delete_passphrase(&key_path)
            .await
            .expect("Failed to delete passphrase");

        // Verify deletion
        let after_delete = retrieve_passphrase(&key_path)
            .await
            .expect("Failed to check after deletion");
        assert!(after_delete.is_none(), "Passphrase should be deleted");
    }

    #[tokio::test]
    async fn test_retrieve_nonexistent_passphrase() {
        // Create a temporary SSH key file
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("nonexistent_key");
        tokio::fs::write(&key_path, "fake key content")
            .await
            .unwrap();

        // Try to retrieve non-existent passphrase
        let result = retrieve_passphrase(&key_path).await;

        assert!(
            result.is_ok(),
            "Should not error on non-existent passphrase"
        );
        assert!(
            result.unwrap().is_none(),
            "Should return None for non-existent passphrase"
        );
    }

    #[tokio::test]
    async fn test_delete_nonexistent_passphrase() {
        // Create a temporary SSH key file
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("nonexistent_key");
        tokio::fs::write(&key_path, "fake key content")
            .await
            .unwrap();

        // Try to delete non-existent passphrase (should succeed silently)
        let result = delete_passphrase(&key_path).await;

        assert!(
            result.is_ok(),
            "Deleting non-existent passphrase should succeed silently"
        );
    }

    #[tokio::test]
    async fn test_update_existing_passphrase() {
        // Create a temporary SSH key file
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("update_test_key");
        tokio::fs::write(&key_path, "fake key content")
            .await
            .unwrap();

        let first_passphrase = "first-passphrase";
        let second_passphrase = "second-passphrase";

        // Store first passphrase
        store_passphrase(&key_path, first_passphrase).await.unwrap();

        // Update with second passphrase
        store_passphrase(&key_path, second_passphrase)
            .await
            .unwrap();

        // Retrieve and verify it's the second passphrase
        let retrieved = retrieve_passphrase(&key_path).await.unwrap();
        assert_eq!(
            retrieved.as_ref().unwrap().as_str(),
            second_passphrase,
            "Should have updated to second passphrase"
        );

        // Clean up
        delete_passphrase(&key_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_passphrase_too_long() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key");
        tokio::fs::write(&key_path, "fake key content")
            .await
            .unwrap();

        // Create a passphrase that's too long
        let long_passphrase = "a".repeat(MAX_PASSPHRASE_LENGTH + 1);

        let result = store_passphrase(&key_path, &long_passphrase).await;

        assert!(result.is_err(), "Should error on too-long passphrase");
        assert!(
            result.unwrap_err().to_string().contains("too long"),
            "Error should mention passphrase length"
        );
    }

    #[tokio::test]
    async fn test_invalid_key_path() {
        // Try to store passphrase for non-existent key
        let result = store_passphrase("/nonexistent/path/to/key", "passphrase").await;

        assert!(result.is_err(), "Should error on non-existent key path");
    }

    #[tokio::test]
    async fn test_passphrase_zeroization() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("zeroize_test_key");
        tokio::fs::write(&key_path, "fake key content")
            .await
            .unwrap();

        let passphrase = "secret-passphrase";

        // Store and retrieve
        store_passphrase(&key_path, passphrase).await.unwrap();
        let retrieved = retrieve_passphrase(&key_path).await.unwrap().unwrap();

        // Verify passphrase is correct
        assert_eq!(retrieved.as_str(), passphrase);

        // Drop the passphrase (should be zeroized)
        drop(retrieved);

        // Clean up
        delete_passphrase(&key_path).await.unwrap();
    }
}
