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

//! Security validation for Include directive

use anyhow::{Context, Result};
use std::path::Path;
use tokio::io::AsyncReadExt as _;

use super::super::diagnostic::{escape_field, escape_path};

/// Validate a glob pattern for security
pub fn validate_glob_pattern(pattern: &str) -> Result<()> {
    // Check for dangerous glob patterns
    if pattern.contains("**") {
        anyhow::bail!("Recursive glob patterns (**) are not allowed for security reasons");
    }

    // Check for excessive wildcards that could cause exponential expansion
    let wildcard_count = pattern.chars().filter(|&c| c == '*').count();
    if wildcard_count > 5 {
        anyhow::bail!(
            "Too many wildcards in pattern '{}'. Maximum 5 wildcards allowed.",
            escape_field(pattern)
        );
    }

    // Check for overly broad patterns that could match system files
    // But allow common SSH config patterns like ~/.ssh/config.d/*
    if (pattern == "*" || pattern == "/*") && !pattern.contains("ssh") {
        anyhow::bail!(
            "Pattern '{}' is too broad and could match system files",
            escape_field(pattern)
        );
    }

    // Check pattern length
    if pattern.len() > 512 {
        anyhow::bail!("Pattern is too long (max 512 characters)");
    }

    Ok(())
}

fn validate_opened_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        anyhow::bail!("Include path is not a regular file: {}", escape_path(path));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::getuid() };
        if metadata.uid() != 0 && metadata.uid() != uid {
            anyhow::bail!("Bad owner for SSH config file {}", escape_path(path));
        }
        if metadata.mode() & 0o22 != 0 {
            anyhow::bail!("Bad permissions for SSH config file {}", escape_path(path));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn is_openssh_null_config(path: &Path, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt as _;

    path == Path::new("/dev/null") && metadata.file_type().is_char_device()
}

#[cfg(not(unix))]
fn is_openssh_null_config(_path: &Path, _metadata: &std::fs::Metadata) -> bool {
    false
}

/// Open, validate with `fstat`, and read from the same handle.
pub(crate) async fn read_config_file(
    path: &Path,
    check_permissions: bool,
    missing_ok: bool,
) -> Result<Option<String>> {
    read_config_file_with_hook(path, check_permissions, missing_ok, || {}).await
}

async fn read_config_file_with_hook<F>(
    path: &Path,
    check_permissions: bool,
    missing_ok: bool,
    after_open: F,
) -> Result<Option<String>>
where
    F: FnOnce(),
{
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if missing_ok && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open SSH config file: {}", escape_path(path)));
        }
    };
    after_open();
    let metadata = file.metadata().await.with_context(|| {
        format!(
            "Failed to inspect opened SSH config file: {}",
            escape_path(path)
        )
    })?;
    if check_permissions {
        validate_opened_metadata(path, &metadata)?;
    } else if !metadata.is_file() && !is_openssh_null_config(path, &metadata) {
        anyhow::bail!(
            "SSH config path is not a regular file: {}",
            escape_path(path)
        );
    }
    let mut content = String::new();
    file.read_to_string(&mut content)
        .await
        .with_context(|| format!("Failed to read SSH config file: {}", escape_path(path)))?;
    Ok(Some(content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_glob_pattern_security() {
        // Test recursive glob rejection
        let result = validate_glob_pattern("config.d/**/*.conf");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Recursive glob"));

        // Test too many wildcards
        let result = validate_glob_pattern("a*/b*/c*/d*/e*/f*");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Too many wildcards")
        );

        // Test too-long pattern
        let long_pattern = "a".repeat(600);
        let result = validate_glob_pattern(&long_pattern);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));

        // Test overly broad pattern
        let result = validate_glob_pattern("/*");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too broad"));

        // Test valid patterns
        assert!(validate_glob_pattern("~/.ssh/config.d/*.conf").is_ok());
        assert!(validate_glob_pattern("/etc/ssh/*.conf").is_ok());
        assert!(validate_glob_pattern("config.d/[0-9][0-9]-*.conf").is_ok());
        // Path with ../ is allowed in pattern validation (checked later by is_path_allowed)
        assert!(validate_glob_pattern("../../../etc/passwd").is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_swap_after_open_reads_and_checks_the_opened_target() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let safe = directory.path().join("safe.conf");
        let unsafe_file = directory.path().join("unsafe.conf");
        let link = directory.path().join("config");
        std::fs::write(&safe, "User safe\n").unwrap();
        std::fs::write(&unsafe_file, "User unsafe\n").unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&unsafe_file, std::fs::Permissions::from_mode(0o622)).unwrap();
        symlink(&safe, &link).unwrap();

        let content = read_config_file_with_hook(&link, true, false, || {
            std::fs::remove_file(&link).unwrap();
            symlink(&unsafe_file, &link).unwrap();
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(content, "User safe\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exact_null_device_is_an_empty_root_config_only() {
        let path = Path::new("/dev/null");

        assert_eq!(
            read_config_file(path, false, false).await.unwrap(),
            Some(String::new())
        );
        assert!(read_config_file(path, true, false).await.is_err());
    }
}
