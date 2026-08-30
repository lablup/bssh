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

//! Verified OpenSSH host-key rotation and atomic known_hosts updates.

#[cfg(unix)]
use std::fs::File;
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::PublicKey;
use sha1::Sha1;
use ssh_key::{Algorithm as SshAlgorithm, HashAlg, Signature};

use super::host_verification::{KNOWN_HOSTS_LOCK, acquire_known_hosts_file_lock, glob_match};

const HOSTKEYS_PROVE_DOMAIN: &[u8] = b"hostkeys-prove-00@openssh.com";
pub(crate) const MAX_ANNOUNCED_KEYS: usize = 64;

pub(crate) fn verify_hostkeys_proof(
    keys: &[PublicKey],
    proof: &russh::client::HostKeysProof,
    negotiated_host_key_algorithm: Option<&SshAlgorithm>,
) -> Result<Vec<PublicKey>, String> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    if keys.len() > MAX_ANNOUNCED_KEYS {
        return Err(format!(
            "server announced {} host keys, exceeding the {MAX_ANNOUNCED_KEYS}-key limit",
            keys.len()
        ));
    }
    if proof.signatures.len() != keys.len() {
        return Err(format!(
            "server returned {} proofs for {} announced keys",
            proof.signatures.len(),
            keys.len()
        ));
    }

    let mut seen = HashSet::new();
    let mut verified = Vec::with_capacity(keys.len());
    for (key, encoded_signature) in keys.iter().zip(&proof.signatures) {
        let key_blob = key
            .to_bytes()
            .map_err(|error| format!("could not encode announced key: {error}"))?;
        if !seen.insert(key_blob.clone()) {
            return Err("server announced a duplicate host key".to_string());
        }
        let signature = Signature::try_from(encoded_signature.as_slice())
            .map_err(|error| format!("malformed host-key proof signature: {error}"))?;
        if let Err(error) =
            enforce_rsa_proof_algorithm(key, &signature, negotiated_host_key_algorithm)
        {
            tracing::debug!("Skipping untrusted announced host key: {error}");
            continue;
        }
        let message = hostkeys_proof_message(&proof.session_id, &key_blob)?;
        signature::Verifier::verify(key, &message, &signature)
            .map_err(|_| "host-key proof signature did not verify".to_string())?;
        verified.push(key.clone());
    }
    Ok(verified)
}

fn enforce_rsa_proof_algorithm(
    key: &PublicKey,
    signature: &Signature,
    negotiated_host_key_algorithm: Option<&SshAlgorithm>,
) -> Result<(), String> {
    if !matches!(key.algorithm(), SshAlgorithm::Rsa { .. }) {
        return Ok(());
    }

    let signature_algorithm = signature.algorithm();
    let allowed = match negotiated_host_key_algorithm {
        Some(algorithm @ SshAlgorithm::Rsa { .. }) => signature_algorithm == *algorithm,
        _ => matches!(
            signature_algorithm,
            SshAlgorithm::Rsa {
                hash: Some(HashAlg::Sha256 | HashAlg::Sha512)
            }
        ),
    };
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "untrusted RSA host-key proof signature algorithm '{}'",
            signature_algorithm.as_str()
        ))
    }
}

pub(crate) async fn apply_hostkeys_proof(
    known_hosts_paths: &[String],
    identities: &[(&str, u16)],
    current_key: &PublicKey,
    announced_keys: &[PublicKey],
    proof: &russh::client::HostKeysProof,
    negotiated_host_key_algorithm: Option<&SshAlgorithm>,
    hash_known_hosts: bool,
) -> Result<(), String> {
    let proven = verify_hostkeys_proof(announced_keys, proof, negotiated_host_key_algorithm)?;
    rotate_proven_host_keys(
        known_hosts_paths,
        identities,
        current_key,
        &proven,
        hash_known_hosts,
    )
    .await
}

fn hostkeys_proof_message(session_id: &[u8], key_blob: &[u8]) -> Result<Vec<u8>, String> {
    let mut message =
        Vec::with_capacity(HOSTKEYS_PROVE_DOMAIN.len() + session_id.len() + key_blob.len() + 12);
    encode_ssh_string(&mut message, HOSTKEYS_PROVE_DOMAIN)?;
    encode_ssh_string(&mut message, session_id)?;
    encode_ssh_string(&mut message, key_blob)?;
    Ok(message)
}

fn encode_ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "SSH string is too large".to_string())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) async fn rotate_proven_host_keys(
    known_hosts_paths: &[String],
    identities: &[(&str, u16)],
    current_key: &PublicKey,
    proven_keys: &[PublicKey],
    hash_known_hosts: bool,
) -> Result<(), String> {
    if known_hosts_paths.is_empty() {
        return Err("no writable user known_hosts file is configured".to_string());
    }
    if identities.is_empty() {
        return Err("no known-host identity is available for rotation".to_string());
    }

    let identities = identities
        .iter()
        .map(|(hostname, port)| known_hosts_identity(&hostname.to_ascii_lowercase(), *port))
        .collect::<Vec<_>>();
    let mut desired = Vec::with_capacity(proven_keys.len() + 1);
    desired.push(current_key.clone());
    for key in proven_keys {
        if !desired.iter().any(|existing| existing == key) {
            desired.push(key.clone());
        }
    }

    let mut unique_paths = Vec::new();
    for path in known_hosts_paths {
        if !unique_paths.contains(path) {
            unique_paths.push(path.clone());
        }
    }
    let mut lock_paths = unique_paths.clone();
    lock_paths.sort();

    let _process_guard = KNOWN_HOSTS_LOCK.lock().await;
    let mut file_guards = Vec::with_capacity(lock_paths.len());
    for path in &lock_paths {
        file_guards.push(
            acquire_known_hosts_file_lock(path)
                .map_err(|error| format!("could not lock known_hosts '{path}': {error}"))?,
        );
    }

    let plans = plan_rewrites(&unique_paths, &identities, &desired, hash_known_hosts)?;
    commit_rewrites(plans)
}

#[derive(Debug)]
struct RewritePlan {
    path: PathBuf,
    existed: bool,
    original: Vec<u8>,
    rewritten: Vec<u8>,
}

fn plan_rewrites(
    paths: &[String],
    identities: &[String],
    desired_keys: &[PublicKey],
    hash_known_hosts: bool,
) -> Result<Vec<RewritePlan>, String> {
    let desired_blobs = desired_keys
        .iter()
        .map(PublicKey::to_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not encode desired host key: {error}"))?;
    let mut originals = Vec::with_capacity(paths.len());
    let mut obsolete = Vec::<Vec<u8>>::new();

    for path in paths {
        let path = PathBuf::from(path);
        let (existed, bytes) = match std::fs::read(&path) {
            Ok(bytes) => (true, bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (false, Vec::new()),
            Err(error) => return Err(format!("could not read {}: {error}", path.display())),
        };
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        for (line_number, line) in text.lines().enumerate() {
            let Some(parsed) = parse_known_hosts_line(line) else {
                continue;
            };
            let relation = host_field_relation(parsed.hosts, identities);
            if relation.matches {
                if parsed.marker.is_some() {
                    return Err(format!(
                        "refusing host-key update: marker at {}:{}",
                        path.display(),
                        line_number + 1
                    ));
                }
                if relation.complex {
                    return Err(format!(
                        "refusing host-key update: complex host specification at {}:{}",
                        path.display(),
                        line_number + 1
                    ));
                }
                if parsed.key_blob.is_none() {
                    return Err(format!(
                        "refusing host-key update: malformed matching entry at {}:{}",
                        path.display(),
                        line_number + 1
                    ));
                }
                if let Some(blob) = parsed.key_blob
                    && !desired_blobs.contains(&blob)
                    && !obsolete.contains(&blob)
                {
                    obsolete.push(blob);
                }
            } else if let Some(blob) = parsed.key_blob
                && desired_blobs.contains(&blob)
            {
                return Err(format!(
                    "refusing host-key update: an announced key is shared by another identity at {}:{}",
                    path.display(),
                    line_number + 1
                ));
            }
        }
        originals.push((path, existed, bytes));
    }

    if !obsolete.is_empty() {
        for (path, _, bytes) in &originals {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
            for (line_number, line) in text.lines().enumerate() {
                let Some(parsed) = parse_known_hosts_line(line) else {
                    continue;
                };
                if !host_field_relation(parsed.hosts, identities).matches
                    && parsed
                        .key_blob
                        .as_ref()
                        .is_some_and(|blob| obsolete.contains(blob))
                {
                    return Err(format!(
                        "refusing host-key update: an obsolete key is shared by another identity at {}:{}",
                        path.display(),
                        line_number + 1
                    ));
                }
            }
        }
    }

    let mut plans = Vec::with_capacity(originals.len());
    for (index, (path, existed, original)) in originals.into_iter().enumerate() {
        let text = std::str::from_utf8(&original)
            .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        let mut rewritten = Vec::<String>::new();
        for line in text.lines() {
            let remove = parse_known_hosts_line(line)
                .is_some_and(|parsed| host_field_relation(parsed.hosts, identities).matches);
            if !remove {
                rewritten.push(line.to_string());
            }
        }

        if index == 0 {
            let host_fields = if hash_known_hosts {
                identities
                    .iter()
                    .map(|identity| hash_host_pattern(identity))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                vec![identities.join(",")]
            };
            for host_field in host_fields {
                for key in desired_keys {
                    let openssh = key
                        .to_openssh()
                        .map_err(|error| format!("could not format host key: {error}"))?;
                    rewritten.push(format!("{host_field} {openssh}"));
                }
            }
        }

        let mut bytes = rewritten.join("\n").into_bytes();
        if !bytes.is_empty() {
            bytes.push(b'\n');
        }
        plans.push(RewritePlan {
            path,
            existed,
            original,
            rewritten: bytes,
        });
    }
    Ok(plans)
}

#[derive(Debug, Clone, Copy)]
struct HostFieldRelation {
    matches: bool,
    complex: bool,
}

fn host_field_relation(host_field: &str, identities: &[String]) -> HostFieldRelation {
    let patterns = host_field.split(',').map(str::trim).collect::<Vec<_>>();
    let matches = identities
        .iter()
        .any(|identity| host_field_matches(host_field, identity));
    let syntactically_complex = patterns.len() > 2
        || patterns.iter().any(|pattern| {
            pattern.starts_with('!')
                || (!pattern.starts_with("|1|") && (pattern.contains('*') || pattern.contains('?')))
        });
    let pair_is_exact = patterns.len() != 2
        || (identities.len() == 2
            && patterns.iter().all(|pattern| {
                identities
                    .iter()
                    .any(|identity| pattern_matches(pattern, identity))
            })
            && identities.iter().all(|identity| {
                patterns
                    .iter()
                    .any(|pattern| pattern_matches(pattern, identity))
            }));
    HostFieldRelation {
        matches,
        complex: syntactically_complex || !pair_is_exact,
    }
}

fn host_field_matches(host_field: &str, identity: &str) -> bool {
    let mut positive = false;
    for raw_pattern in host_field.split(',') {
        let raw_pattern = raw_pattern.trim();
        let (negated, pattern) = match raw_pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, raw_pattern),
        };
        if pattern_matches(pattern, identity) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn pattern_matches(pattern: &str, identity: &str) -> bool {
    if pattern.starts_with("|1|") {
        host_pattern_matches(pattern, identity)
    } else {
        glob_match(identity, pattern)
    }
}

struct ParsedKnownHostsLine<'a> {
    marker: Option<&'a str>,
    hosts: &'a str,
    key_blob: Option<Vec<u8>>,
}

fn parse_known_hosts_line(line: &str) -> Option<ParsedKnownHostsLine<'_>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields = trimmed.split_whitespace().collect::<Vec<_>>();
    let (marker, hosts, declared, encoded) =
        if fields.first().is_some_and(|field| field.starts_with('@')) {
            (
                fields.first().copied(),
                *fields.get(1)?,
                fields.get(2).copied(),
                fields.get(3).copied(),
            )
        } else {
            (
                None,
                *fields.first()?,
                fields.get(1).copied(),
                fields.get(2).copied(),
            )
        };
    let key_blob = declared.zip(encoded).and_then(|(declared, encoded)| {
        let key = russh::keys::parse_public_key_base64(encoded).ok()?;
        let algorithm = key.algorithm();
        (algorithm.as_str() == declared)
            .then(|| key.to_bytes().ok())
            .flatten()
    });
    Some(ParsedKnownHostsLine {
        marker,
        hosts,
        key_blob,
    })
}

fn commit_rewrites(plans: Vec<RewritePlan>) -> Result<(), String> {
    let mut committed = Vec::<RewritePlan>::new();
    for plan in plans {
        if plan.original == plan.rewritten {
            continue;
        }
        if let Err(error) = atomic_replace(&plan.path, &plan.rewritten) {
            let rollback_errors = rollback_rewrites(&committed);
            return if rollback_errors.is_empty() {
                Err(error)
            } else {
                Err(format!(
                    "{error}; rollback also failed: {}",
                    rollback_errors.join("; ")
                ))
            };
        }
        committed.push(plan);
    }
    Ok(())
}

fn rollback_rewrites(committed: &[RewritePlan]) -> Vec<String> {
    let mut errors = Vec::new();
    for plan in committed.iter().rev() {
        let result = if plan.existed {
            atomic_replace(&plan.path, &plan.original)
        } else {
            match std::fs::remove_file(&plan.path) {
                Ok(()) => {
                    #[cfg(unix)]
                    if let Err(error) = sync_parent_directory(&plan.path) {
                        errors.push(error);
                    }
                    Ok(())
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!("could not remove {}: {error}", plan.path.display())),
            }
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }
    errors
}

pub(crate) fn hash_host_pattern(identity: &str) -> Result<String, String> {
    let mut salt = [0_u8; 20];
    rand::fill(&mut salt);
    let mut hmac =
        Hmac::<Sha1>::new_from_slice(&salt).map_err(|_| "invalid HMAC salt".to_string())?;
    hmac.update(identity.as_bytes());
    let digest = hmac.finalize().into_bytes();
    Ok(format!(
        "|1|{}|{}",
        BASE64.encode(salt),
        BASE64.encode(digest)
    ))
}

pub(crate) fn host_pattern_matches(pattern: &str, identity: &str) -> bool {
    if let Some(encoded) = pattern.strip_prefix("|1|") {
        let mut parts = encoded.split('|');
        let (Some(salt), Some(expected), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        let (Ok(salt), Ok(expected)) = (BASE64.decode(salt), BASE64.decode(expected)) else {
            return false;
        };
        let Ok(mut hmac) = Hmac::<Sha1>::new_from_slice(&salt) else {
            return false;
        };
        hmac.update(identity.as_bytes());
        hmac.verify_slice(&expected).is_ok()
    } else {
        pattern.eq_ignore_ascii_case(identity)
    }
}

fn known_hosts_identity(hostname: &str, port: u16) -> String {
    if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    }
}

fn create_private_parent(parent: &Path) -> Result<(), std::io::Error> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)
}

pub(super) fn atomic_replace(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_parent(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "known_hosts filename is not valid UTF-8".to_string())?;
    let mut random = [0_u8; 8];
    rand::fill(&mut random);
    let temporary = parent.join(format!(
        ".{filename}.bssh.{}.{:016x}.tmp",
        std::process::id(),
        u64::from_ne_bytes(random)
    ));

    let result = write_temporary(&temporary, path, contents);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn write_temporary(temporary: &Path, destination: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    file.write_all(contents)
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    file.sync_all()
        .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
    drop(file);

    replace_file(temporary, destination)?;
    #[cfg(unix)]
    sync_parent_directory(destination)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), String> {
    std::fs::rename(temporary, destination).map_err(|error| {
        format!(
            "could not atomically replace {} with {}: {error}",
            destination.display(),
            temporary.display()
        )
    })
}

#[cfg(windows)]
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both pointers refer to NUL-terminated UTF-16 buffers that remain alive for the call.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(format!(
            "could not atomically replace {}: {}",
            destination.display(),
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(destination: &Path) -> Result<(), String> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync {}: {error}", parent.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};
    use tempfile::tempdir;

    fn private_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    fn proof_for(keys: &[PrivateKey], session_id: &[u8]) -> russh::client::HostKeysProof {
        let signatures = keys
            .iter()
            .map(|key| {
                let blob = key.public_key().to_bytes().unwrap();
                let message = hostkeys_proof_message(session_id, &blob).unwrap();
                let signature: Signature = signature::Signer::try_sign(key, &message).unwrap();
                Vec::<u8>::try_from(signature).unwrap()
            })
            .collect();
        russh::client::HostKeysProof {
            session_id: session_id.to_vec(),
            signatures,
        }
    }

    #[test]
    fn verifies_every_signature_and_rejects_malicious_announcements() {
        let keys = [private_key(), private_key()];
        let public = keys
            .iter()
            .map(|key| key.public_key().clone())
            .collect::<Vec<_>>();
        let proof = proof_for(&keys, b"session");
        assert_eq!(
            verify_hostkeys_proof(&public, &proof, Some(&SshAlgorithm::Ed25519)).unwrap(),
            public
        );

        let mut malicious = proof;
        malicious.signatures[1][0] ^= 0x80;
        assert!(verify_hostkeys_proof(&public, &malicious, Some(&SshAlgorithm::Ed25519)).is_err());
    }

    #[test]
    fn skips_legacy_rsa_sha1_proof_without_rsa_negotiation() {
        let rsa = PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap();
        let signature = Signature::new(SshAlgorithm::Rsa { hash: None }, vec![0_u8; 256]).unwrap();
        let proof = russh::client::HostKeysProof {
            session_id: b"session".to_vec(),
            signatures: vec![Vec::<u8>::try_from(signature).unwrap()],
        };
        assert!(
            verify_hostkeys_proof(
                &[rsa.public_key().clone()],
                &proof,
                Some(&SshAlgorithm::Ed25519),
            )
            .unwrap()
            .is_empty()
        );
    }

    #[tokio::test]
    async fn proven_rotation_adds_removes_hashes_and_relooks_up() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let old = private_key().public_key().clone();
        let new = private_key().public_key().clone();
        std::fs::write(
            &path,
            format!(
                "node.example {}\nnode.example {}\nother.example {}\n",
                current.to_openssh().unwrap(),
                old.to_openssh().unwrap(),
                private_key().public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();

        rotate_proven_host_keys(
            &[path.to_string_lossy().into_owned()],
            &[("node.example", 22)],
            &current,
            std::slice::from_ref(&new),
            true,
        )
        .await
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("node.example "));
        assert!(contents.contains("other.example "));
        assert_eq!(contents.matches("|1|").count(), 2);
        let found =
            russh::keys::known_hosts::known_host_keys_path("node.example", 22, &path).unwrap();
        assert!(found.iter().any(|(_, key)| key == &current));
        assert!(found.iter().any(|(_, key)| key == &new));
        assert!(!found.iter().any(|(_, key)| key == &old));
    }

    #[tokio::test]
    async fn multi_file_rotation_updates_host_and_address_without_stale_keys() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("known_hosts");
        let second = directory.path().join("known_hosts.extra");
        let current = private_key().public_key().clone();
        let old = private_key().public_key().clone();
        let new = private_key().public_key().clone();
        let old_line = format!("node.example,192.0.2.10 {}\n", old.to_openssh().unwrap());
        std::fs::write(
            &first,
            format!(
                "node.example,192.0.2.10 {}\n{old_line}",
                current.to_openssh().unwrap()
            ),
        )
        .unwrap();
        std::fs::write(&second, &old_line).unwrap();

        rotate_proven_host_keys(
            &[
                first.to_string_lossy().into_owned(),
                second.to_string_lossy().into_owned(),
            ],
            &[("node.example", 22), ("192.0.2.10", 22)],
            &current,
            std::slice::from_ref(&new),
            false,
        )
        .await
        .unwrap();

        let first_contents = std::fs::read_to_string(&first).unwrap();
        let second_contents = std::fs::read_to_string(&second).unwrap();
        assert_eq!(first_contents.lines().count(), 2);
        assert!(
            first_contents
                .lines()
                .all(|line| line.starts_with("node.example,192.0.2.10 "))
        );
        assert!(!first_contents.contains(&old.to_openssh().unwrap()));
        assert!(second_contents.is_empty());
        for identity in ["node.example", "192.0.2.10"] {
            let found =
                russh::keys::known_hosts::known_host_keys_path(identity, 22, &first).unwrap();
            assert!(found.iter().any(|(_, key)| key == &current));
            assert!(found.iter().any(|(_, key)| key == &new));
        }
    }

    #[tokio::test]
    async fn complex_or_shared_entries_skip_the_entire_update() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("known_hosts");
        let second = directory.path().join("known_hosts.extra");
        let current = private_key().public_key().clone();
        let old = private_key().public_key().clone();
        let new = private_key().public_key().clone();
        let first_original = format!(
            "*.example {}\nnode.example {}\n",
            old.to_openssh().unwrap(),
            current.to_openssh().unwrap()
        );
        let second_original = format!("other.example {}\n", old.to_openssh().unwrap());
        std::fs::write(&first, &first_original).unwrap();
        std::fs::write(&second, &second_original).unwrap();

        assert!(
            rotate_proven_host_keys(
                &[
                    first.to_string_lossy().into_owned(),
                    second.to_string_lossy().into_owned(),
                ],
                &[("node.example", 22)],
                &current,
                std::slice::from_ref(&new),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(first).unwrap(), first_original);
        assert_eq!(std::fs::read_to_string(second).unwrap(), second_original);
    }

    #[tokio::test]
    async fn marker_entry_aborts_the_entire_update() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let next = private_key().public_key().clone();
        let original = format!(
            "@revoked node.example {}\nnode.example {}\n",
            current.to_openssh().unwrap(),
            current.to_openssh().unwrap()
        );
        std::fs::write(&path, &original).unwrap();

        assert!(
            rotate_proven_host_keys(
                &[path.to_string_lossy().into_owned()],
                &[("node.example", 22)],
                &current,
                std::slice::from_ref(&next),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[tokio::test]
    async fn obsolete_key_shared_by_another_identity_aborts_the_entire_update() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let obsolete = private_key().public_key().clone();
        let next = private_key().public_key().clone();
        let original = format!(
            "node.example {}\nnode.example {}\nother.example {}\n",
            current.to_openssh().unwrap(),
            obsolete.to_openssh().unwrap(),
            obsolete.to_openssh().unwrap()
        );
        std::fs::write(&path, &original).unwrap();

        assert!(
            rotate_proven_host_keys(
                &[path.to_string_lossy().into_owned()],
                &[("node.example", 22)],
                &current,
                std::slice::from_ref(&next),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[tokio::test]
    async fn malicious_unproven_announcement_leaves_every_file_unchanged() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("known_hosts");
        let second = directory.path().join("known_hosts.extra");
        let current = private_key();
        let announced = private_key();
        let original = format!(
            "node.example {}\n",
            current.public_key().to_openssh().unwrap()
        );
        std::fs::write(&first, &original).unwrap();
        std::fs::write(&second, &original).unwrap();
        let mut proof = proof_for(std::slice::from_ref(&announced), b"session");
        proof.signatures[0][0] ^= 0x80;

        assert!(
            apply_hostkeys_proof(
                &[
                    first.to_string_lossy().into_owned(),
                    second.to_string_lossy().into_owned(),
                ],
                &[("node.example", 22)],
                current.public_key(),
                std::slice::from_ref(announced.public_key()),
                &proof,
                Some(&SshAlgorithm::Ed25519),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(first).unwrap(), original);
        assert_eq!(std::fs::read_to_string(second).unwrap(), original);
    }

    #[tokio::test]
    async fn concurrent_rotations_leave_one_complete_parseable_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let next = private_key().public_key().clone();
        std::fs::write(
            &path,
            format!("node.example {}\n", current.to_openssh().unwrap()),
        )
        .unwrap();
        let paths = vec![path.to_string_lossy().into_owned()];

        let first = rotate_proven_host_keys(
            &paths,
            &[("node.example", 22)],
            &current,
            std::slice::from_ref(&next),
            false,
        );
        let second = rotate_proven_host_keys(
            &paths,
            &[("node.example", 22)],
            &current,
            std::slice::from_ref(&next),
            false,
        );
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();

        let found =
            russh::keys::known_hosts::known_host_keys_path("node.example", 22, &path).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|(_, key)| key == &current));
        assert!(found.iter().any(|(_, key)| key == &next));
    }
    #[tokio::test]
    async fn hashed_host_and_address_are_written_as_separate_openssh_rows() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let next = private_key().public_key().clone();
        std::fs::write(
            &path,
            format!(
                "node.example,192.0.2.10 {}\n",
                current.to_openssh().unwrap()
            ),
        )
        .unwrap();

        rotate_proven_host_keys(
            &[path.to_string_lossy().into_owned()],
            &[("node.example", 22), ("192.0.2.10", 22)],
            &current,
            std::slice::from_ref(&next),
            true,
        )
        .await
        .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 4);
        assert!(contents.lines().all(|line| line.starts_with("|1|")
            && !line.split_whitespace().next().unwrap().contains(',')));
        for identity in ["node.example", "192.0.2.10"] {
            let found =
                russh::keys::known_hosts::known_host_keys_path(identity, 22, &path).unwrap();
            assert!(found.iter().any(|(_, key)| key == &current));
            assert!(found.iter().any(|(_, key)| key == &next));
        }
    }

    #[tokio::test]
    async fn malformed_matching_entry_aborts_but_unrelated_malformed_entry_is_preserved() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let current = private_key().public_key().clone();
        let next = private_key().public_key().clone();
        let malformed = "node.example ssh-ed25519 not-base64\n";
        std::fs::write(&path, malformed).unwrap();

        assert!(
            rotate_proven_host_keys(
                &[path.to_string_lossy().into_owned()],
                &[("node.example", 22)],
                &current,
                std::slice::from_ref(&next),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), malformed);

        let unrelated = format!(
            "other.example ssh-ed25519 not-base64\nnode.example {}\n",
            current.to_openssh().unwrap()
        );
        std::fs::write(&path, &unrelated).unwrap();
        rotate_proven_host_keys(
            &[path.to_string_lossy().into_owned()],
            &[("node.example", 22)],
            &current,
            std::slice::from_ref(&next),
            false,
        )
        .await
        .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("other.example ssh-ed25519 not-base64\n"));
    }
}
