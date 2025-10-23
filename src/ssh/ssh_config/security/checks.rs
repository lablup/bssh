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

//! Security checks for different file types

use anyhow::Result;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Validate security properties of identity files
pub fn validate_identity_file_security(path: &Path, line_number: usize) -> Result<()> {
    // Check for sensitive system paths
    let path_str = path.to_string_lossy();

    // Block access to critical system files
    let sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\",
        "\\System32\\",
        "\\Program Files\\",
    ];

    for pattern in &sensitive_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: Identity file path '{path_str}' at line {line_number} points to sensitive system location. \
                 Access to system files is not allowed for security reasons."
            );
        }
    }

    // On Unix systems, check file permissions if the file exists
    #[cfg(unix)]
    if path.exists() && path.is_file() {
        if let Ok(metadata) = std::fs::metadata(path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check if file is world-readable (dangerous for private keys)
            if mode & 0o004 != 0 {
                tracing::warn!(
                    "Security warning: Identity file '{}' at line {} is world-readable. \
                     Private SSH keys should not be readable by other users (chmod 600 recommended).",
                    path_str,
                    line_number
                );
            }

            // Check if file is group-readable (also not ideal for private keys)
            if mode & 0o040 != 0 {
                tracing::warn!(
                    "Security warning: Identity file '{}' at line {} is group-readable. \
                     Private SSH keys should only be readable by the owner (chmod 600 recommended).",
                    path_str,
                    line_number
                );
            }

            // Check if file is world-writable (very dangerous)
            if mode & 0o002 != 0 {
                anyhow::bail!(
                    "Security violation: Identity file '{path_str}' at line {line_number} is world-writable. \
                     This is extremely dangerous and must be fixed immediately."
                );
            }
        }
    }

    Ok(())
}

/// Validate security properties of known_hosts files
pub fn validate_known_hosts_file_security(path: &Path, line_number: usize) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Block access to critical system files
    let sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\",
        "\\System32\\",
        "\\Program Files\\",
    ];

    for pattern in &sensitive_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: Known hosts file path '{path_str}' at line {line_number} points to sensitive system location. \
                 Access to system files is not allowed for security reasons."
            );
        }
    }

    // Ensure known_hosts files are in reasonable locations
    let path_lower = path_str.to_lowercase();
    if !path_lower.contains("ssh")
        && !path_lower.contains("known")
        && !path_str.contains("/.")
        && !path_str.starts_with("/etc/ssh/")
        && !path_str.starts_with("/usr/")
        && !path_str.contains("/home/")
        && !path_str.contains("/Users/")
    {
        tracing::warn!(
            "Security warning: Known hosts file '{}' at line {} is in an unusual location. \
             Ensure this is intentional and the file is trustworthy.",
            path_str,
            line_number
        );
    }

    Ok(())
}

/// Validate security properties of certificate files
pub fn validate_certificate_file_security(path: &Path, line_number: usize) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Block access to critical system files that should never be certificates
    let forbidden_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/master.passwd", // BSD systems
        "/etc/security/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\System32\\",
        "\\Windows\\SysWOW64\\",
        "\\SAM", // Windows SAM database
        ".bash_history",
        ".zsh_history",
        ".mysql_history",
        ".psql_history",
        "id_rsa", // Private keys should not be used as certificates
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    ];

    for pattern in &forbidden_patterns {
        if path_str.contains(pattern) {
            // Special handling for SSH key patterns
            if pattern.starts_with("id_") {
                // Check if this looks like a private key (not a certificate)
                // Allow: id_rsa-cert.pub, id_rsa_cert.pub, etc.
                // Block: id_rsa, id_rsa.pub (regular public key, not certificate)
                if path_str.ends_with("-cert.pub")
                    || path_str.ends_with("_cert.pub")
                    || path_str.ends_with("-cert.pem")
                {
                    continue; // This is a certificate file, allow it
                }

                // Check if it's exactly the private key name without certificate suffix
                if path_str.ends_with(pattern) || path_str.ends_with(&format!("{}.pub", pattern)) {
                    anyhow::bail!(
                        "Security violation: Certificate file path '{path_str}' at line {line_number} appears to be a private key or regular public key. \
                         SSH certificate files should end with '-cert.pub' or similar suffix. Use CertificateFile for certificates, not regular keys."
                    );
                }
                continue; // For other cases with id_* in path, allow them
            }

            anyhow::bail!(
                "Security violation: Certificate file path '{path_str}' at line {line_number} points to forbidden system location. \
                 System files and sensitive locations cannot be used as SSH certificates."
            );
        }
    }

    // Warn about unusual certificate file extensions
    if !path_str.ends_with(".pub")
        && !path_str.ends_with(".pem")
        && !path_str.ends_with(".crt")
        && !path_str.ends_with(".cert")
    {
        tracing::warn!(
            "Security warning: Certificate file '{}' at line {} has an unusual extension. \
             SSH certificates typically end with '.pub', '-cert.pub', '.pem', or '.crt'.",
            path_str,
            line_number
        );
    }

    // Ensure certificate files are in reasonable locations
    let path_lower = path_str.to_lowercase();
    if !path_lower.contains("ssh")
        && !path_lower.contains("cert")
        && !path_str.contains("/.")  // Hidden directories like ~/.ssh
        && !path_str.starts_with("/etc/ssh/")
        && !path_str.starts_with("/usr/")
        && !path_str.contains("/home/")
        && !path_str.contains("/Users/")  // macOS
        && !path_str.contains("/var/lib/")
    // System service directories
    {
        tracing::warn!(
            "Security warning: Certificate file '{}' at line {} is in an unusual location. \
             Ensure this is intentional and the file is a valid SSH certificate.",
            path_str,
            line_number
        );
    }

    Ok(())
}

/// Validate security properties of general files
pub fn validate_general_file_security(path: &Path, line_number: usize) -> Result<()> {
    let path_str = path.to_string_lossy();

    // Block access to the most critical system files
    let forbidden_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/proc/",
        "/sys/",
        "/dev/random",
        "/dev/urandom",
        "/boot/",
        "/usr/bin/",
        "/bin/",
        "/sbin/",
        "\\Windows\\System32\\",
        "\\Windows\\SysWOW64\\",
    ];

    for pattern in &forbidden_patterns {
        if path_str.contains(pattern) {
            anyhow::bail!(
                "Security violation: File path '{path_str}' at line {line_number} points to forbidden system location. \
                 Access to this location is not allowed for security reasons."
            );
        }
    }

    Ok(())
}
