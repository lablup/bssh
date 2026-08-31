// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Secure publication and cleanup of a Unix control socket.

#[cfg(unix)]
mod unix {
    use std::fs::{self, Metadata};
    use std::io;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use tokio::net::{UnixListener, UnixStream};

    use super::super::validate_control_socket_path;

    #[derive(Debug)]
    pub struct ControlSocketGuard {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    struct TemporarySocketGuard(Option<PathBuf>);

    impl TemporarySocketGuard {
        fn new(path: PathBuf) -> Self {
            Self(Some(path))
        }

        fn disarm(&mut self) {
            self.0 = None;
        }
    }

    impl Drop for TemporarySocketGuard {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = fs::remove_file(path);
            }
        }
    }

    impl ControlSocketGuard {
        fn published(path: PathBuf, metadata: &Metadata) -> Self {
            Self {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }

        fn still_owns_path(&self) -> bool {
            fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode
            })
        }
    }

    impl Drop for ControlSocketGuard {
        fn drop(&mut self) {
            if self.still_owns_path()
                && let Err(error) = fs::remove_file(&self.path)
                && error.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!(
                    path = %self.path.display(),
                    "Could not remove owned control socket: {error}"
                );
            }
        }
    }

    pub async fn connect_control_socket(path: &Path) -> io::Result<UnixStream> {
        validate_control_socket_path(path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let stream = UnixStream::connect(path).await?;
        verify_same_user(&stream)?;
        Ok(stream)
    }

    pub fn verify_same_user(stream: &UnixStream) -> io::Result<()> {
        let peer_uid = stream.peer_cred()?.uid();
        // SAFETY: geteuid() has no preconditions and only reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        if peer_uid != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "control socket peer uid {peer_uid} does not match current uid {effective_uid}"
                ),
            ));
        }
        Ok(())
    }

    /// Remove a refused socket only when it is still the exact same socket owned
    /// by this uid. Regular files, symlinks, replacement sockets, and foreign
    /// sockets are never removed.
    pub fn remove_stale_control_socket(path: &Path) -> Result<bool> {
        let first = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("Could not inspect stale control socket"),
        };
        // SAFETY: geteuid() has no preconditions and only reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        if !first.file_type().is_socket() || first.uid() != effective_uid {
            return Ok(false);
        }
        let second = fs::symlink_metadata(path)
            .with_context(|| format!("Could not re-check control socket '{}'", path.display()))?;
        if !second.file_type().is_socket()
            || second.uid() != effective_uid
            || first.dev() != second.dev()
            || first.ino() != second.ino()
        {
            return Ok(false);
        }
        fs::remove_file(path).with_context(|| {
            format!("Could not remove stale control socket '{}'", path.display())
        })?;
        Ok(true)
    }

    /// Bind with a private temporary pathname, chmod it before publication, and
    /// hard-link it into place. No client can reach the socket while its mode is
    /// broader than 0600.
    pub fn bind_control_socket(path: &Path) -> Result<(UnixListener, ControlSocketGuard)> {
        validate_control_socket_path(path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut last_collision = None;
        for attempt in 0..32_u32 {
            let temporary = parent.join(format!(".bssh-mux-{}-{attempt}", std::process::id()));
            if validate_control_socket_path(&temporary).is_err() {
                anyhow::bail!(
                    "ControlPath directory '{}' leaves no room for a safe temporary socket; shorten it or use %C",
                    parent.display()
                );
            }
            let listener = match std::os::unix::net::UnixListener::bind(&temporary) {
                Ok(listener) => listener,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    last_collision = Some(error);
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Could not bind control socket '{}'", temporary.display())
                    });
                }
            };
            let mut cleanup_temporary = TemporarySocketGuard::new(temporary.clone());
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
                .context("Could not restrict control socket permissions")?;
            fs::hard_link(&temporary, path).with_context(|| {
                format!(
                    "Could not publish control socket '{}'; another master may already own it",
                    path.display()
                )
            })?;
            let metadata =
                fs::symlink_metadata(path).context("Could not inspect published control socket")?;
            fs::remove_file(&temporary)
                .context("Could not remove temporary control socket link")?;
            cleanup_temporary.disarm();
            listener
                .set_nonblocking(true)
                .context("Could not make control socket nonblocking")?;
            let listener = UnixListener::from_std(listener)
                .context("Could not register control socket with Tokio")?;
            return Ok((
                listener,
                ControlSocketGuard::published(path.to_path_buf(), &metadata),
            ));
        }
        Err(last_collision.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrInUse, "temporary socket collision")
        }))
        .context("Could not allocate a temporary control socket")
    }
}

#[cfg(unix)]
pub use unix::{
    ControlSocketGuard, bind_control_socket, connect_control_socket, remove_stale_control_socket,
    verify_same_user,
};

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn published_socket_is_private_same_user_and_owned_cleanup_is_exact() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("control");
        let (listener, guard) = bind_control_socket(&path).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let connect = connect_control_socket(&path);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        client.unwrap();
        verify_same_user(&accepted.unwrap().0).unwrap();

        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn stale_cleanup_preserves_regular_files_and_symlinks() {
        let directory = TempDir::new().unwrap();
        let regular = directory.path().join("regular");
        fs::write(&regular, b"do not remove").unwrap();
        assert!(!remove_stale_control_socket(&regular).unwrap());
        assert_eq!(fs::read(&regular).unwrap(), b"do not remove");

        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&regular, &symlink).unwrap();
        assert!(!remove_stale_control_socket(&symlink).unwrap());
        assert!(
            fs::symlink_metadata(&symlink)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn stale_owned_socket_is_removed() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("stale");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);
        assert!(remove_stale_control_socket(&path).unwrap());
        assert!(!path.exists());
    }
}

#[cfg(not(unix))]
mod unsupported {
    use std::io;
    use std::path::Path;

    use anyhow::Result;

    #[derive(Debug)]
    pub struct ControlSocketGuard;

    pub async fn connect_control_socket(_path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "connection multiplexing requires Unix-domain sockets",
        ))
    }

    pub fn bind_control_socket(_path: &Path) -> Result<((), ControlSocketGuard)> {
        anyhow::bail!("connection multiplexing requires Unix-domain sockets")
    }

    pub fn remove_stale_control_socket(_path: &Path) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(not(unix))]
pub use unsupported::{
    ControlSocketGuard, bind_control_socket, connect_control_socket, remove_stale_control_socket,
};
