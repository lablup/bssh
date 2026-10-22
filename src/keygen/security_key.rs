// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

//! Authenticator enrollment and OpenSSH security-key serialization.

use anyhow::{Context, Result, bail, ensure};
use rand::RngExt;
use ssh_key::{HashAlg, LineEnding, PrivateKey, private, public};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::ssh::security_key::{
    SK_FLAG_RESIDENT_KEY, SK_FLAG_USER_PRESENCE_REQUIRED, SK_FLAG_USER_VERIFICATION_REQUIRED,
    SecurityKeyProvider, SkAlgorithm, SkEnrollRequest, SkEnrollResponse, SkResidentKey,
};

#[path = "sk_files.rs"]
mod files;
pub use files::{check_output, public_path};

/// Parsed OpenSSH `-O` security-key options.
#[derive(Debug, Clone)]
pub struct EnrollmentOptions {
    pub application: String,
    pub flags: u8,
    pub user: Option<String>,
    pub device: Option<String>,
    pub challenge: Option<PathBuf>,
}

impl Default for EnrollmentOptions {
    fn default() -> Self {
        Self {
            application: "ssh:".into(),
            flags: SK_FLAG_USER_PRESENCE_REQUIRED,
            user: None,
            device: None,
            challenge: None,
        }
    }
}

impl EnrollmentOptions {
    /// Reject unknown options before opening or touching an authenticator.
    pub fn parse(options: &[String]) -> Result<Self> {
        let mut result = Self::default();
        let mut seen = std::collections::HashSet::new();
        for option in options {
            let (name, value) = option
                .split_once('=')
                .map_or((option.as_str(), None), |(n, v)| (n, Some(v)));
            ensure!(seen.insert(name), "Duplicate security-key option: {name}");
            match (name, value) {
                ("resident", None) => result.flags |= SK_FLAG_RESIDENT_KEY,
                ("verify-required", None) => result.flags |= SK_FLAG_USER_VERIFICATION_REQUIRED,
                ("no-touch-required", None) => result.flags &= !SK_FLAG_USER_PRESENCE_REQUIRED,
                ("application", Some(value))
                    if value.starts_with("ssh:") && !value.contains('\0') =>
                {
                    result.application = value.into()
                }
                ("user", Some(value)) if !value.is_empty() && !value.contains('\0') => {
                    result.user = Some(value.into())
                }
                ("device", Some(value)) if !value.is_empty() && !value.contains('\0') => {
                    result.device = Some(value.into())
                }
                ("challenge", Some(value)) if !value.is_empty() => {
                    result.challenge = Some(value.into())
                }
                ("write-attestation", _) => {
                    bail!("Security-key option write-attestation is not supported")
                }
                _ => bail!("Invalid or unsupported security-key option: {name}"),
            }
        }
        Ok(result)
    }

    /// Read at most 1 MiB of challenge data, or generate a random challenge.
    pub fn challenge_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut challenge = Zeroizing::new(Vec::new());
        if let Some(path) = &self.challenge {
            let mut open = std::fs::OpenOptions::new();
            open.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.custom_flags(libc::O_NONBLOCK);
            }
            let file = open
                .open(path)
                .context("Cannot open security-key challenge file")?;
            ensure!(
                file.metadata()?.is_file(),
                "Challenge must be a regular file"
            );
            file.take(1024 * 1024 + 1).read_to_end(&mut challenge)?;
            ensure!(
                !challenge.is_empty() && challenge.len() <= 1024 * 1024,
                "Challenge must contain 1 to 1048576 bytes"
            );
        } else {
            challenge.resize(32, 0);
            rand::rng().fill(challenge.as_mut_slice());
        }
        Ok(challenge)
    }

    pub fn request<'a>(
        &'a self,
        algorithm: SkAlgorithm,
        challenge: &'a [u8],
    ) -> SkEnrollRequest<'a> {
        SkEnrollRequest {
            algorithm,
            challenge,
            application: &self.application,
            flags: self.flags,
            user: self.user.as_deref(),
            device: self.device.as_deref(),
        }
    }
}

/// Saved credential metadata. Private handles and PEM are deliberately not returned.
#[derive(Debug, Clone)]
pub struct SavedSecurityKey {
    pub path: PathBuf,
    pub fingerprint: String,
    pub public_key_openssh: String,
}

/// Enroll with an already opened provider, then save the OpenSSH credential.
pub fn generate(
    provider: &dyn SecurityKeyProvider,
    request: &SkEnrollRequest<'_>,
    pin: Option<&str>,
    output: &Path,
    comment: Option<&str>,
    overwrite: bool,
) -> Result<SavedSecurityKey> {
    request.validate()?;
    check_output(output, overwrite)?;
    let response = provider.enroll(request, pin)?;
    save(
        request.algorithm,
        request.application,
        response,
        output,
        comment.unwrap_or("bssh-keygen"),
        overwrite,
    )
}

/// Save one resident credential with its application as the default comment.
pub fn save_resident(
    key: SkResidentKey,
    directory: &Path,
    overwrite: bool,
) -> Result<SavedSecurityKey> {
    let path = directory.join(resident_filename(&key));
    save_resident_at(key, &path, overwrite)
}

/// Save a resident credential to a caller-selected, collision-free output path.
pub fn save_resident_at(
    key: SkResidentKey,
    output: &Path,
    overwrite: bool,
) -> Result<SavedSecurityKey> {
    save(
        key.algorithm,
        &key.application,
        key.key,
        output,
        &key.application,
        overwrite,
    )
}

/// Match OpenSSH's resident key names; hex-escape unsafe device-supplied components.
pub fn resident_filename(key: &SkResidentKey) -> String {
    let application = key
        .application
        .strip_prefix("ssh://")
        .or_else(|| key.application.strip_prefix("ssh:"))
        .unwrap_or(&key.application);
    let mut suffix = safe_component(application.as_bytes());
    let user_length = key
        .user_id
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    if user_length > 0 {
        suffix.push('_');
        suffix.push_str(&safe_component(&key.user_id[..user_length]));
    }
    // Bound untrusted device data to a portable filename length. A digest also
    // prevents different truncated applications/user IDs from sharing a path.
    if suffix.len() > 180 {
        use sha2::{Digest, Sha256};
        suffix = Sha256::digest(suffix.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
    }
    let algorithm = match key.algorithm {
        SkAlgorithm::Ed25519 => "ed25519",
        SkAlgorithm::EcdsaSha2NistP256 => "ecdsa",
    };
    format!(
        "id_{algorithm}_sk_rk{}{}",
        if suffix.is_empty() { "" } else { "_" },
        suffix
    )
}

/// Allocate one portable filename per credential, reserving both private and
/// public names under case-insensitive comparison. Numeric suffixes retain the
/// OpenSSH basename while avoiding aliases on macOS and Windows filesystems.
pub fn resident_filenames(keys: &[SkResidentKey]) -> Vec<String> {
    let mut used = std::collections::HashSet::new();
    keys.iter()
        .map(|key| {
            let base = resident_filename(key);
            let mut name = base.clone();
            let mut suffix = 2_u64;
            loop {
                let normalized = name.to_ascii_lowercase();
                let public = format!("{normalized}.pub");
                if !used.contains(&normalized) && !used.contains(&public) {
                    used.insert(normalized);
                    used.insert(public);
                    return name;
                }
                name = format!("{base}_{suffix}");
                suffix += 1;
            }
        })
        .collect()
}

fn safe_component(bytes: &[u8]) -> String {
    // ASCII eliminates Unicode normalization aliases; no colon, whitespace or
    // terminal dot can become a Windows stream name or normalized path alias.
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte))
        && !bytes.windows(2).any(|pair| pair == b"..")
        && !bytes.ends_with(b".")
    {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

fn save(
    algorithm: SkAlgorithm,
    application: &str,
    response: SkEnrollResponse,
    output: &Path,
    comment: &str,
    overwrite: bool,
) -> Result<SavedSecurityKey> {
    ensure!(
        application.starts_with("ssh:") && !application.contains('\0'),
        "Invalid security-key application"
    );
    ensure!(
        !comment.contains(['\n', '\r', '\0']),
        "Key comment contains control characters"
    );
    ensure!(
        !response.key_handle.is_empty() && response.key_handle.len() <= 255,
        "Security-key handle must contain 1 to 255 bytes (ssh-key serialization limit)"
    );
    let key_data = match algorithm {
        SkAlgorithm::Ed25519 => {
            let bytes: [u8; 32] = response
                .public_key
                .as_slice()
                .try_into()
                .context("Invalid Ed25519 security-key public key")?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .context("Invalid Ed25519 security-key public key")?;
            ensure!(
                !verifying_key.is_weak(),
                "Weak Ed25519 security-key public key"
            );
            let public = public::SkEd25519::new(public::Ed25519PublicKey(bytes), application);
            private::KeypairData::SkEd25519(private::SkEd25519::new(
                public,
                response.flags,
                response.key_handle.to_vec(),
            )?)
        }
        SkAlgorithm::EcdsaSha2NistP256 => {
            ensure!(
                response.public_key.len() == 65 && response.public_key[0] == 4,
                "Invalid P-256 security-key public key"
            );
            let public::EcdsaPublicKey::NistP256(point) =
                public::EcdsaPublicKey::from_sec1_bytes(&response.public_key)?
            else {
                bail!("Invalid P-256 security-key public key")
            };
            let public = public::SkEcdsaSha2NistP256::new(point, application);
            private::KeypairData::SkEcdsaSha2NistP256(private::SkEcdsaSha2NistP256::new(
                public,
                response.flags,
                response.key_handle.to_vec(),
            )?)
        }
    };
    // ssh-key owns its internal handle copy; all buffers owned by this module
    // remain zeroizing and no credential/private key is exposed in Debug.
    let private = PrivateKey::new(key_data, comment)?;
    let pem = private.to_openssh(LineEnding::LF)?;
    let public = private.public_key();
    let result = SavedSecurityKey {
        path: output.into(),
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        public_key_openssh: public.to_openssh()?,
    };
    files::write_pair(
        output,
        pem.as_bytes(),
        result.public_key_openssh.as_bytes(),
        overwrite,
    )?;
    Ok(result)
}

#[cfg(test)]
#[path = "sk_tests.rs"]
mod tests;
