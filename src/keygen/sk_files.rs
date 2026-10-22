// Copyright 2026 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, ensure};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".pub");
    name.into()
}

/// Refuse non-regular destinations and check both halves before enrollment.
pub fn check_output(path: &Path, overwrite: bool) -> Result<()> {
    for path in [path.to_path_buf(), public_path(path)] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "Refusing non-regular key destination: {}",
                    path.display()
                );
                ensure!(overwrite, "Key file already exists: {}", path.display());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Cannot inspect key destination"),
        }
    }
    Ok(())
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn stage(path: &Path, content: &[u8], public: bool) -> Result<Temporary> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".bssh-keygen-{:032x}", rand::random::<u128>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if public { 0o644 } else { 0o600 });
    }
    let mut file = options
        .open(&temporary)
        .context("Cannot create temporary key file")?;
    let temporary = Temporary(temporary);
    file.write_all(content)?;
    if public {
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    Ok(temporary)
}

pub(super) fn write_pair(
    path: &Path,
    private: &[u8],
    public: &[u8],
    overwrite: bool,
) -> Result<()> {
    check_output(path, overwrite)?;
    let pub_path = public_path(path);
    let private_temp = stage(path, private, false)?;
    let public_temp = stage(&pub_path, public, true)?;
    // Rename replaces the directory entry, never follows a symlink or writes
    // through a hard link. For no-overwrite, hard_link atomically refuses a
    // destination introduced after the preflight check.
    if overwrite {
        check_output(path, true)?;
        fs::rename(&private_temp.0, path)?;
        fs::rename(&public_temp.0, &pub_path)?;
    } else {
        fs::hard_link(&private_temp.0, path)?;
        // Do not unlink a published private path on failure: another writer
        // could have replaced that directory entry in the meantime.
        fs::hard_link(&public_temp.0, &pub_path).with_context(|| {
            format!(
                "Cannot save public key; private key retained at {}",
                path.display()
            )
        })?;
    }
    Ok(())
}
