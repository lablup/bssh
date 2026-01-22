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

//! SFTP server handler implementation.
//!
//! This module provides the SFTP subsystem handler for the bssh server,
//! implementing the `russh_sftp::server::Handler` trait.
//!
//! # Security
//!
//! The handler implements path traversal prevention to ensure clients
//! cannot access files outside their designated root directory.
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::sftp::SftpHandler;
//! use bssh::shared::auth_types::UserInfo;
//! use std::path::PathBuf;
//!
//! let user = UserInfo::new("testuser");
//! let handler = SftpHandler::new(user, Some(PathBuf::from("/home/testuser")));
//! ```

use std::collections::HashMap;
use std::io::SeekFrom;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::shared::auth_types::UserInfo;

/// Error type for SFTP operations.
///
/// This wrapper type converts to `StatusCode` for the SFTP handler trait.
#[derive(Debug, Clone)]
pub struct SftpError {
    /// The status code for the error.
    pub code: StatusCode,
    /// Human-readable error message.
    pub message: String,
}

impl SftpError {
    /// Create a new SFTP error.
    pub fn new(code: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Create an "operation not supported" error.
    pub fn not_supported() -> Self {
        Self::new(StatusCode::OpUnsupported, "Operation not supported")
    }

    /// Create a "no such file" error.
    pub fn no_such_file(path: &Path) -> Self {
        Self::new(
            StatusCode::NoSuchFile,
            format!("No such file: {}", path.display()),
        )
    }

    /// Create a "permission denied" error.
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PermissionDenied, message)
    }

    /// Create an "invalid handle" error.
    pub fn invalid_handle() -> Self {
        Self::new(StatusCode::Failure, "Invalid handle")
    }

    /// Create a generic failure error.
    #[allow(dead_code)]
    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(StatusCode::Failure, message)
    }

    /// Create an EOF error.
    pub fn eof() -> Self {
        Self::new(StatusCode::Eof, "End of file")
    }
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SftpError {}

impl From<std::io::Error> for SftpError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let code = match err.kind() {
            ErrorKind::NotFound => StatusCode::NoSuchFile,
            ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
            ErrorKind::UnexpectedEof => StatusCode::Eof,
            _ => StatusCode::Failure,
        };
        Self::new(code, err.to_string())
    }
}

impl From<SftpError> for StatusCode {
    fn from(err: SftpError) -> Self {
        err.code
    }
}

/// An open file or directory handle.
enum OpenHandle {
    /// An open file.
    File {
        file: File,
        path: PathBuf,
        #[allow(dead_code)]
        flags: OpenFlags,
    },
    /// An open directory listing.
    Dir {
        path: PathBuf,
        entries: Vec<DirEntryInfo>,
        position: usize,
    },
}

/// Directory entry information for readdir.
struct DirEntryInfo {
    filename: String,
    attrs: FileAttributes,
}

/// SFTP server handler.
///
/// Implements the SFTP protocol for file transfer operations with
/// security controls to prevent path traversal attacks.
pub struct SftpHandler {
    /// Current user information.
    user_info: UserInfo,

    /// Root directory for SFTP operations (chroot-like behavior).
    root_dir: PathBuf,

    /// Open file and directory handles (shared for async access).
    handles: Arc<Mutex<HashMap<String, OpenHandle>>>,

    /// Counter for generating unique handle IDs.
    handle_counter: u64,
}

impl SftpHandler {
    /// Create a new SFTP handler.
    ///
    /// # Arguments
    ///
    /// * `user_info` - Information about the authenticated user
    /// * `root_dir` - Optional root directory for chroot-like behavior.
    ///   If None, defaults to filesystem root ("/").
    pub fn new(user_info: UserInfo, root_dir: Option<PathBuf>) -> Self {
        let root_dir = root_dir.unwrap_or_else(|| PathBuf::from("/"));

        tracing::debug!(
            user = %user_info.username,
            root = %root_dir.display(),
            "Creating SFTP handler"
        );

        Self {
            user_info,
            root_dir,
            handles: Arc::new(Mutex::new(HashMap::new())),
            handle_counter: 0,
        }
    }

    /// Generate a new unique handle ID.
    fn new_handle(&mut self) -> String {
        self.handle_counter += 1;
        format!("h{}", self.handle_counter)
    }

    /// Resolve a client path to an absolute filesystem path.
    ///
    /// This method prevents path traversal attacks by:
    /// 1. Joining the path with the root directory
    /// 2. Normalizing the path (resolving "." and ".." components)
    /// 3. Verifying the result is within the root directory
    ///
    /// # Security
    ///
    /// This is critical for security. The resolved path must always
    /// start with the root directory to prevent access to files
    /// outside the allowed area.
    pub fn resolve_path(&self, path: &str) -> Result<PathBuf, SftpError> {
        let path = Path::new(path);

        // Normalize the path manually without following symlinks
        let normalized = if path.is_absolute() {
            // Strip the leading "/" and join with root
            let stripped = path.strip_prefix("/").unwrap_or(path);
            self.root_dir.join(stripped)
        } else {
            self.root_dir.join(path)
        };

        // Normalize path components (handle ".." and ".")
        let mut resolved = PathBuf::new();
        for component in normalized.components() {
            use std::path::Component;
            match component {
                Component::Normal(c) => resolved.push(c),
                Component::CurDir => {} // Skip "."
                Component::ParentDir => {
                    // Go up but don't go above root
                    if resolved.starts_with(&self.root_dir) && resolved != self.root_dir {
                        resolved.pop();
                    }
                    // If we can't go up, stay at root
                    if !resolved.starts_with(&self.root_dir) {
                        resolved = self.root_dir.clone();
                    }
                }
                Component::RootDir => resolved.push("/"),
                Component::Prefix(p) => resolved.push(p.as_os_str()),
            }
        }

        // Ensure the resolved path is within the root
        if !resolved.starts_with(&self.root_dir) {
            tracing::warn!(
                user = %self.user_info.username,
                requested = %path.display(),
                resolved = %resolved.display(),
                root = %self.root_dir.display(),
                "Path traversal attempt detected"
            );
            return Err(SftpError::permission_denied(
                "Access denied: path outside root",
            ));
        }

        tracing::trace!(
            requested = %path.display(),
            resolved = %resolved.display(),
            "Resolved path"
        );

        Ok(resolved)
    }

    /// Convert file metadata to SFTP FileAttributes.
    fn metadata_to_attrs(metadata: &std::fs::Metadata) -> FileAttributes {
        FileAttributes {
            size: Some(metadata.len()),
            uid: Some(metadata.uid()),
            user: None,
            gid: Some(metadata.gid()),
            group: None,
            permissions: Some(metadata.permissions().mode()),
            atime: Some(
                metadata
                    .accessed()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0),
            ),
            mtime: Some(
                metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0),
            ),
        }
    }

    /// Build a long name string for directory listing (like "ls -l").
    fn build_longname(filename: &str, attrs: &FileAttributes) -> String {
        let perms = attrs.permissions.unwrap_or(0);
        let is_dir = (perms & 0o40000) != 0;
        let is_link = (perms & 0o120000) == 0o120000;

        let file_type = if is_link {
            'l'
        } else if is_dir {
            'd'
        } else {
            '-'
        };

        let perm_str = format!(
            "{}{}{}{}{}{}{}{}{}",
            if perms & 0o400 != 0 { 'r' } else { '-' },
            if perms & 0o200 != 0 { 'w' } else { '-' },
            if perms & 0o100 != 0 { 'x' } else { '-' },
            if perms & 0o040 != 0 { 'r' } else { '-' },
            if perms & 0o020 != 0 { 'w' } else { '-' },
            if perms & 0o010 != 0 { 'x' } else { '-' },
            if perms & 0o004 != 0 { 'r' } else { '-' },
            if perms & 0o002 != 0 { 'w' } else { '-' },
            if perms & 0o001 != 0 { 'x' } else { '-' },
        );

        let size = attrs.size.unwrap_or(0);
        let uid = attrs.uid.unwrap_or(0);
        let gid = attrs.gid.unwrap_or(0);

        format!("{file_type}{perm_str}  1 {uid:5} {gid:5} {size:10} Jan  1 00:00 {filename}")
    }
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::not_supported()
    }

    /// Handle SFTP version negotiation.
    fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<Version, Self::Error>> + Send {
        tracing::info!(
            user = %self.user_info.username,
            version = version,
            "SFTP session initialized"
        );

        async move { Ok(Version::new()) }
    }

    /// Open a file.
    fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> impl std::future::Future<Output = Result<Handle, Self::Error>> + Send {
        let path_result = self.resolve_path(&filename);
        let handle_id = self.new_handle();
        let handles = Arc::clone(&self.handles);

        tracing::debug!(
            user = %self.user_info.username,
            path = %filename,
            flags = ?pflags,
            handle = %handle_id,
            "Opening file"
        );

        async move {
            let path = path_result?;

            // Build open options from flags
            let mut opts = OpenOptions::new();

            if pflags.contains(OpenFlags::READ) {
                opts.read(true);
            }
            if pflags.contains(OpenFlags::WRITE) {
                opts.write(true);
            }
            if pflags.contains(OpenFlags::CREATE) {
                opts.create(true);
            }
            if pflags.contains(OpenFlags::TRUNCATE) {
                opts.truncate(true);
            }
            if pflags.contains(OpenFlags::APPEND) {
                opts.append(true);
            }
            if pflags.contains(OpenFlags::EXCLUDE) {
                opts.create_new(true);
            }

            let file = opts.open(&path).await?;

            // Store the handle
            handles.lock().await.insert(
                handle_id.clone(),
                OpenHandle::File {
                    file,
                    path,
                    flags: pflags,
                },
            );

            Ok(Handle {
                id,
                handle: handle_id,
            })
        }
    }

    /// Read data from an open file.
    fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> impl std::future::Future<Output = Result<Data, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);

        async move {
            let mut handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get_mut(&handle);

            let file = match handle_entry {
                Some(OpenHandle::File { file, .. }) => file,
                _ => return Err(SftpError::invalid_handle()),
            };

            // Seek to offset
            file.seek(SeekFrom::Start(offset)).await?;

            // Read data
            let mut buffer = vec![0u8; len as usize];
            let bytes_read = file.read(&mut buffer).await?;

            if bytes_read == 0 {
                return Err(SftpError::eof());
            }

            buffer.truncate(bytes_read);

            tracing::trace!(
                handle = %handle,
                offset = offset,
                requested = len,
                read = bytes_read,
                "Read data from file"
            );

            Ok(Data { id, data: buffer })
        }
    }

    /// Write data to an open file.
    fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);
        let data_len = data.len();

        async move {
            let mut handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get_mut(&handle);

            let file = match handle_entry {
                Some(OpenHandle::File { file, .. }) => file,
                _ => return Err(SftpError::invalid_handle()),
            };

            // Seek to offset
            file.seek(SeekFrom::Start(offset)).await?;

            // Write data
            file.write_all(&data).await?;

            tracing::trace!(
                handle = %handle,
                offset = offset,
                written = data_len,
                "Wrote data to file"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Close an open file or directory handle.
    fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);
        let user = self.user_info.username.clone();

        tracing::debug!(
            user = %user,
            handle = %handle,
            "Closing handle"
        );

        async move {
            let removed = handles.lock().await.remove(&handle);

            match removed {
                Some(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: String::new(),
                    language_tag: "en".to_string(),
                }),
                None => Err(SftpError::invalid_handle()),
            }
        }
    }

    /// Open a directory for listing.
    fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Handle, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);
        let handle_id = self.new_handle();
        let handles = Arc::clone(&self.handles);

        tracing::debug!(
            user = %self.user_info.username,
            path = %path,
            handle = %handle_id,
            "Opening directory"
        );

        async move {
            let resolved_path = resolved?;

            // Read directory entries
            let mut entries = Vec::new();
            let mut read_dir = fs::read_dir(&resolved_path).await?;

            // Add "." and ".." entries
            if let Ok(meta) = fs::metadata(&resolved_path).await {
                entries.push(DirEntryInfo {
                    filename: ".".to_string(),
                    attrs: SftpHandler::metadata_to_attrs(&meta),
                });
            }
            if let Some(parent) = resolved_path.parent() {
                if let Ok(meta) = fs::metadata(parent).await {
                    entries.push(DirEntryInfo {
                        filename: "..".to_string(),
                        attrs: SftpHandler::metadata_to_attrs(&meta),
                    });
                }
            }

            // Read actual entries
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    entries.push(DirEntryInfo {
                        filename: entry.file_name().to_string_lossy().to_string(),
                        attrs: SftpHandler::metadata_to_attrs(&meta),
                    });
                }
            }

            // Store the directory handle
            handles.lock().await.insert(
                handle_id.clone(),
                OpenHandle::Dir {
                    path: resolved_path,
                    entries,
                    position: 0,
                },
            );

            Ok(Handle {
                id,
                handle: handle_id,
            })
        }
    }

    /// Read entries from an open directory.
    fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl std::future::Future<Output = Result<Name, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);

        async move {
            let mut handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get_mut(&handle);

            let (entries, position) = match handle_entry {
                Some(OpenHandle::Dir {
                    entries, position, ..
                }) => (entries, position),
                _ => return Err(SftpError::invalid_handle()),
            };

            // Check if we've read all entries
            if *position >= entries.len() {
                return Err(SftpError::eof());
            }

            // Return a batch of entries (up to 100 at a time)
            const BATCH_SIZE: usize = 100;
            let end = (*position + BATCH_SIZE).min(entries.len());

            let files: Vec<_> = entries[*position..end]
                .iter()
                .map(|e| {
                    let longname = SftpHandler::build_longname(&e.filename, &e.attrs);
                    russh_sftp::protocol::File {
                        filename: e.filename.clone(),
                        longname,
                        attrs: e.attrs.clone(),
                    }
                })
                .collect();

            let remaining = entries.len() - end;
            *position = end;

            tracing::trace!(
                handle = %handle,
                returned = files.len(),
                remaining = remaining,
                "Read directory entries"
            );

            Ok(Name { id, files })
        }
    }

    /// Get file attributes by path (follows symlinks).
    fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Attrs, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);

        async move {
            let path = resolved?;
            let metadata = fs::metadata(&path).await?;
            let attrs = SftpHandler::metadata_to_attrs(&metadata);

            Ok(Attrs { id, attrs })
        }
    }

    /// Get file attributes by path (does not follow symlinks).
    fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Attrs, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);

        async move {
            let path = resolved?;
            let metadata = fs::symlink_metadata(&path).await?;
            let attrs = SftpHandler::metadata_to_attrs(&metadata);

            Ok(Attrs { id, attrs })
        }
    }

    /// Get file attributes by handle.
    fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl std::future::Future<Output = Result<Attrs, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);

        async move {
            let handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get(&handle);

            let path = match handle_entry {
                Some(OpenHandle::File { path, .. }) => path.clone(),
                Some(OpenHandle::Dir { path, .. }) => path.clone(),
                None => return Err(SftpError::invalid_handle()),
            };

            drop(handles_guard); // Release lock before async I/O

            let metadata = fs::metadata(&path).await?;
            let attrs = SftpHandler::metadata_to_attrs(&metadata);

            Ok(Attrs { id, attrs })
        }
    }

    /// Resolve the real/canonical path.
    fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Name, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);
        let root_dir = self.root_dir.clone();

        async move {
            let full_path = resolved?;

            // Return path relative to root (as client sees it)
            let display_path = if full_path == root_dir {
                "/".to_string()
            } else {
                full_path
                    .strip_prefix(&root_dir)
                    .map(|p| format!("/{}", p.display()))
                    .unwrap_or_else(|_| full_path.display().to_string())
            };

            // Get attributes if the path exists
            let attrs = match fs::metadata(&full_path).await {
                Ok(meta) => SftpHandler::metadata_to_attrs(&meta),
                Err(_) => FileAttributes {
                    size: None,
                    uid: None,
                    user: None,
                    gid: None,
                    group: None,
                    permissions: None,
                    atime: None,
                    mtime: None,
                },
            };

            tracing::trace!(
                requested = %path,
                resolved = %display_path,
                "Resolved real path"
            );

            Ok(Name {
                id,
                files: vec![russh_sftp::protocol::File {
                    filename: display_path,
                    longname: String::new(),
                    attrs,
                }],
            })
        }
    }

    /// Create a directory.
    fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);
        let user = self.user_info.username.clone();

        async move {
            let path = resolved?;

            fs::create_dir(&path).await?;

            // Set permissions if specified
            if let Some(perms) = attrs.permissions {
                fs::set_permissions(&path, std::fs::Permissions::from_mode(perms)).await?;
            }

            tracing::info!(
                user = %user,
                path = %path.display(),
                "Created directory"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Remove a directory.
    fn rmdir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);
        let user = self.user_info.username.clone();

        async move {
            let path = resolved?;

            fs::remove_dir(&path).await?;

            tracing::info!(
                user = %user,
                path = %path.display(),
                "Removed directory"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Remove a file.
    fn remove(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);
        let user = self.user_info.username.clone();

        async move {
            let path = resolved?;

            fs::remove_file(&path).await?;

            tracing::info!(
                user = %user,
                path = %path.display(),
                "Removed file"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Rename a file or directory.
    fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let old_resolved = self.resolve_path(&oldpath);
        let new_resolved = self.resolve_path(&newpath);
        let user = self.user_info.username.clone();

        async move {
            let old_path = old_resolved?;
            let new_path = new_resolved?;

            fs::rename(&old_path, &new_path).await?;

            tracing::info!(
                user = %user,
                from = %old_path.display(),
                to = %new_path.display(),
                "Renamed file/directory"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Set file attributes by path.
    fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);

        async move {
            let path = resolved?;

            // Set permissions if specified
            if let Some(perms) = attrs.permissions {
                fs::set_permissions(&path, std::fs::Permissions::from_mode(perms)).await?;
            }

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Set file attributes by handle.
    fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let handles = Arc::clone(&self.handles);

        async move {
            let handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get(&handle);

            let path = match handle_entry {
                Some(OpenHandle::File { path, .. }) => path.clone(),
                Some(OpenHandle::Dir { path, .. }) => path.clone(),
                None => return Err(SftpError::invalid_handle()),
            };

            drop(handles_guard); // Release lock before async I/O

            // Set permissions if specified
            if let Some(perms) = attrs.permissions {
                fs::set_permissions(&path, std::fs::Permissions::from_mode(perms)).await?;
            }

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }

    /// Read a symbolic link.
    fn readlink(
        &mut self,
        id: u32,
        path: String,
    ) -> impl std::future::Future<Output = Result<Name, Self::Error>> + Send {
        let resolved = self.resolve_path(&path);

        async move {
            let path = resolved?;
            let target = fs::read_link(&path).await?;

            let attrs = FileAttributes {
                size: None,
                uid: None,
                user: None,
                gid: None,
                group: None,
                permissions: None,
                atime: None,
                mtime: None,
            };

            Ok(Name {
                id,
                files: vec![russh_sftp::protocol::File {
                    filename: target.display().to_string(),
                    longname: String::new(),
                    attrs,
                }],
            })
        }
    }

    /// Create a symbolic link.
    fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
        let link_resolved = self.resolve_path(&linkpath);
        let user = self.user_info.username.clone();

        async move {
            let link_path = link_resolved?;

            // Create symbolic link (target is used as-is, not resolved)
            #[cfg(unix)]
            tokio::fs::symlink(&targetpath, &link_path).await?;

            #[cfg(not(unix))]
            return Err(SftpError::not_supported());

            tracing::info!(
                user = %user,
                link = %link_path.display(),
                target = %targetpath,
                "Created symbolic link"
            );

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handler() -> SftpHandler {
        let user = UserInfo::new("testuser");
        SftpHandler::new(user, Some(PathBuf::from("/home/testuser")))
    }

    #[test]
    fn test_resolve_path_basic() {
        let handler = test_handler();

        // Basic path resolution
        let result = handler.resolve_path("documents/file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn test_resolve_path_absolute() {
        let handler = test_handler();

        // Absolute path should be relative to root
        let result = handler.resolve_path("/documents/file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn test_resolve_path_traversal_blocked() {
        let handler = test_handler();

        // Path traversal attempts are clamped to root (security measure)
        // "../etc/passwd" -> trying to escape, clamped to root, then "etc/passwd"
        // Results in "/home/testuser/etc/passwd" - stays within jail
        let result = handler.resolve_path("../etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));

        // "documents/../../etc/passwd" -> go into docs, up twice (clamped at root), then etc/passwd
        let result = handler.resolve_path("documents/../../etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));

        // All paths stay within the root directory (the security guarantee)
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn test_resolve_path_double_dots() {
        let handler = test_handler();

        // ".." that doesn't escape should work
        let result = handler.resolve_path("a/b/../c").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/a/c"));
    }

    #[test]
    fn test_resolve_path_root() {
        let handler = test_handler();

        // Root path
        let result = handler.resolve_path("/").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));

        let result = handler.resolve_path(".").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    #[test]
    fn test_resolve_path_many_parent_refs() {
        let handler = test_handler();

        // Many ".." are clamped to stay within root - security is maintained
        let result = handler
            .resolve_path("../../../../../../../etc/passwd")
            .unwrap();
        // All the ".." attempts are stopped at root, then "etc/passwd" is appended
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));

        // The security guarantee: path never escapes root
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn test_sftp_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let sftp_err: SftpError = io_err.into();
        assert_eq!(sftp_err.code, StatusCode::NoSuchFile);

        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let sftp_err: SftpError = io_err.into();
        assert_eq!(sftp_err.code, StatusCode::PermissionDenied);
    }

    #[test]
    fn test_new_handle_uniqueness() {
        let mut handler = test_handler();

        let h1 = handler.new_handle();
        let h2 = handler.new_handle();
        let h3 = handler.new_handle();

        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_build_longname() {
        let attrs = FileAttributes {
            size: Some(1024),
            uid: Some(1000),
            user: None,
            gid: Some(1000),
            group: None,
            permissions: Some(0o100644), // Regular file with rw-r--r--
            atime: None,
            mtime: None,
        };

        let longname = SftpHandler::build_longname("test.txt", &attrs);
        assert!(longname.contains("test.txt"));
        assert!(longname.contains("rw-r--r--"));
        assert!(longname.contains("1024"));
    }

    #[test]
    fn test_build_longname_directory() {
        let attrs = FileAttributes {
            size: Some(4096),
            uid: Some(1000),
            user: None,
            gid: Some(1000),
            group: None,
            permissions: Some(0o40755), // Directory with rwxr-xr-x
            atime: None,
            mtime: None,
        };

        let longname = SftpHandler::build_longname("mydir", &attrs);
        assert!(longname.starts_with('d'));
        assert!(longname.contains("rwxr-xr-x"));
    }
}
