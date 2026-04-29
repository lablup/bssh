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
//! // Without chroot (OpenSSH-compatible behavior):
//! let handler = SftpHandler::new(user.clone(), None, PathBuf::from("/home/testuser"));
//!
//! // With chroot:
//! let handler = SftpHandler::new(
//!     user,
//!     Some(PathBuf::from("/srv/sftp")),
//!     PathBuf::from("/home/testuser"),
//! );
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

/// Maximum number of open handles per session to prevent resource exhaustion.
const MAX_HANDLES: usize = 1000;

/// Maximum read buffer size (64KB) to prevent memory exhaustion.
const MAX_READ_SIZE: u32 = 65536;

/// Normalize a path's `..` and `.` components without touching the filesystem.
///
/// This is a logical normalization that does not follow symlinks. Used as
/// a building block for both chrooted and non-chrooted resolution.
fn normalize_components(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop only normal components; never above the root prefix.
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::RootDir => out.push("/"),
            Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    out
}

/// Resolve a client-supplied path against a chroot root.
///
/// - Plain `/` (the chroot's pseudo-root in the client's view, also returned
///   by `realpath`) maps to `root`.
/// - Absolute paths inside `root` are honored as-is (no doubling).
/// - Absolute paths outside `root` are rejected.
/// - Relative paths are joined with `root` and normalized.
/// - `..` traversal is clamped to `root`.
fn resolve_chroot(requested: &Path, root: &Path) -> Result<PathBuf, SftpError> {
    use std::path::Component;

    // Treat empty path the same as "." to keep parity with no-chroot mode.
    let requested = if requested.as_os_str().is_empty() {
        Path::new(".")
    } else {
        requested
    };

    if requested.is_absolute() {
        // Plain "/" is the client's view of the chroot root (returned by
        // `realpath`). Map it back to the actual chroot directory so the
        // realpath-roundtrip stays consistent.
        if requested == Path::new("/") {
            return Ok(root.to_path_buf());
        }

        // Absolute paths inside the chroot are honored verbatim. Anything
        // outside is rejected so the chroot enforces a containment boundary
        // rather than silently re-rooting the path.
        let normalized = normalize_components(requested);
        if normalized == root || normalized.starts_with(root) {
            tracing::trace!(
                requested = %requested.display(),
                resolved = %normalized.display(),
                "Resolved absolute path inside chroot"
            );
            return Ok(normalized);
        }
        tracing::warn!(
            event = "chroot_escape_blocked",
            requested = %requested.display(),
            root = %root.display(),
            "Absolute path outside chroot rejected"
        );
        return Err(SftpError::permission_denied(
            "Access denied: path outside root",
        ));
    }

    // Relative path: join with root, then walk components clamping `..`
    // so traversal cannot escape the chroot. This preserves the original
    // security guarantee.
    let mut resolved = root.to_path_buf();
    for component in requested.components() {
        match component {
            Component::Normal(c) => resolved.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                if resolved != root {
                    resolved.pop();
                }
                if !resolved.starts_with(root) {
                    resolved = root.to_path_buf();
                }
            }
            // Relative paths shouldn't carry these, but ignore safely.
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    if !resolved.starts_with(root) {
        tracing::warn!(
            event = "path_traversal_blocked",
            requested = %requested.display(),
            resolved = %resolved.display(),
            root = %root.display(),
            "Resolved path escaped chroot"
        );
        return Err(SftpError::permission_denied(
            "Access denied: path outside root",
        ));
    }

    tracing::trace!(
        requested = %requested.display(),
        resolved = %resolved.display(),
        "Resolved relative path under chroot"
    );
    Ok(resolved)
}

/// Find the closest existing ancestor of `path` and return both the ancestor
/// and its canonicalized form.
///
/// Walks up `path` (popping one component at a time) until a path that exists
/// on the filesystem is found, then canonicalizes it. Used by chroot
/// resolution to detect intermediate-directory symlinks pointing outside the
/// chroot — without this check, `open(...)` / `create_dir(...)` etc. on a
/// non-existent final path would happily follow a parent-symlink and operate
/// outside the chroot.
///
/// Returns `None` when no ancestor exists or canonicalization fails for every
/// candidate.
fn closest_existing_canonical(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut cur = path.to_path_buf();
    loop {
        if cur.exists() {
            if let Ok(canonical) = std::fs::canonicalize(&cur) {
                return Some((cur, canonical));
            }
            return None;
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// Resolve a client-supplied path without a chroot.
///
/// - Absolute paths are used verbatim, after normalizing `.` and `..`.
/// - Relative paths join with `cwd` (the user's home directory by default)
///   and are normalized the same way.
///
/// This matches OpenSSH `sftp-server` semantics: filesystem permissions are
/// the only access boundary.
fn resolve_no_chroot(requested: &Path, cwd: &Path) -> PathBuf {
    let requested = if requested.as_os_str().is_empty() {
        Path::new(".")
    } else {
        requested
    };

    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        cwd.join(requested)
    };
    let normalized = normalize_components(&joined);
    tracing::trace!(
        requested = %requested.display(),
        resolved = %normalized.display(),
        "Resolved path (no chroot)"
    );
    normalized
}

/// SFTP server handler.
///
/// Implements the SFTP protocol for file transfer operations with
/// security controls to prevent path traversal attacks.
pub struct SftpHandler {
    /// Current user information.
    user_info: UserInfo,

    /// Optional chroot root for SFTP operations.
    ///
    /// When `Some(path)`, all client paths are confined to this directory.
    /// When `None`, the handler runs without chroot (OpenSSH-compatible),
    /// using `cwd` as the base for relative paths and honoring absolute
    /// client paths verbatim.
    root_dir: Option<PathBuf>,

    /// Base directory for resolving relative client paths.
    ///
    /// When `root_dir` is `Some(_)`, this is set to the chroot root.
    /// When `root_dir` is `None`, this is the user's home directory and
    /// matches OpenSSH's `chdir` behavior on session start.
    cwd: PathBuf,

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
    /// * `root_dir` - Optional chroot root. When `None`, no chroot is applied.
    /// * `home_dir` - The user's home directory; used as the base for relative
    ///   paths when chroot is disabled.
    pub fn new(user_info: UserInfo, root_dir: Option<PathBuf>, home_dir: PathBuf) -> Self {
        let cwd = root_dir.clone().unwrap_or_else(|| home_dir.clone());

        tracing::debug!(
            user = %user_info.username,
            chroot = ?root_dir.as_ref().map(|p| p.display().to_string()),
            cwd = %cwd.display(),
            "Creating SFTP handler"
        );

        Self {
            user_info,
            root_dir,
            cwd,
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
    /// Behavior depends on whether a chroot `root_dir` is configured.
    ///
    /// ## With chroot (`root_dir = Some(root)`):
    /// - Absolute client paths inside `root` are honored as-is.
    /// - Absolute client paths outside `root` are rejected with
    ///   `permission_denied` (matching OpenSSH `ChrootDirectory` semantics).
    /// - Relative paths are joined with `root`.
    /// - `..` traversal is clamped to `root` (cannot escape).
    ///
    /// ## Without chroot (`root_dir = None`):
    /// - Absolute paths are used verbatim.
    /// - Relative paths are joined with `cwd` (the user's home directory).
    /// - `..` traversal is normalized but not clamped (filesystem permissions
    ///   remain the access boundary, matching OpenSSH).
    fn resolve_path_static(
        path: &str,
        root_dir: Option<&Path>,
        cwd: &Path,
    ) -> Result<PathBuf, SftpError> {
        let requested = Path::new(path);

        let resolved = match root_dir {
            Some(root) => resolve_chroot(requested, root)?,
            None => return Ok(resolve_no_chroot(requested, cwd)),
        };

        // Chroot mode: also verify the closest existing ancestor canonicalizes
        // inside the chroot. This catches intermediate-directory symlinks
        // pointing outside the chroot. Without this, a chroot-internal symlink
        // such as `chroot/escape -> /etc` would let a client target
        // `chroot/escape/passwd` and have `open(...)` follow the symlink to
        // write `/etc/passwd`. Lexical `starts_with(root)` alone cannot
        // detect this; we need filesystem-level canonicalization.
        //
        // Compare canonical-vs-canonical: an unresolved root might itself
        // contain symlinks, so we canonicalize both sides. If the chroot
        // root does not exist on disk, the operator config is bad and we
        // can only fall back to the lexical check (skip enforcement here).
        let root = root_dir.expect("chroot branch implies Some(root)");
        if let Some(canonical_root) = std::fs::canonicalize(root).ok()
            && let Some((ancestor, canonical_ancestor)) = closest_existing_canonical(&resolved)
            && !canonical_ancestor.starts_with(&canonical_root)
        {
            tracing::warn!(
                event = "symlink_escape_attempt",
                requested = %path,
                resolved = %resolved.display(),
                ancestor = %ancestor.display(),
                canonical_ancestor = %canonical_ancestor.display(),
                canonical_root = %canonical_root.display(),
                "Security: parent-directory symlink escape blocked"
            );
            return Err(SftpError::permission_denied(
                "Access denied: path outside root",
            ));
        }

        Ok(resolved)
    }

    /// Resolve a client path to an absolute filesystem path.
    ///
    /// See [`Self::resolve_path_static`] for the full semantics. This is the
    /// instance-method wrapper used throughout the handler trait impl.
    pub fn resolve_path(&self, path: &str) -> Result<PathBuf, SftpError> {
        Self::resolve_path_static(path, self.root_dir.as_deref(), &self.cwd)
    }

    /// Validate that a symlink's resolved target stays inside the chroot, if
    /// chroot is enabled.
    ///
    /// Returns `Ok(())` when:
    /// - chroot is disabled (no enforcement applies), or
    /// - the resolved target lives under `root_dir`.
    ///
    /// Returns `permission_denied` when the target escapes a configured chroot.
    fn ensure_target_in_root(
        root_dir: Option<&Path>,
        resolved_target: &Path,
    ) -> Result<(), SftpError> {
        match root_dir {
            Some(root) if !resolved_target.starts_with(root) => Err(SftpError::permission_denied(
                "Symlink target outside allowed directory",
            )),
            _ => Ok(()),
        }
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
        let root_dir = self.root_dir.clone();
        let cwd = self.cwd.clone();

        tracing::debug!(
            user = %self.user_info.username,
            path = %filename,
            flags = ?pflags,
            handle = %handle_id,
            "Opening file"
        );

        async move {
            // Check handle limit before acquiring lock
            {
                let handles_guard = handles.lock().await;
                if handles_guard.len() >= MAX_HANDLES {
                    return Err(SftpError::new(StatusCode::Failure, "Too many open handles"));
                }
            }

            let path = path_result?;

            // Check if the path is a symlink and validate the target
            let metadata = fs::symlink_metadata(&path).await;
            if let Ok(meta) = metadata
                && meta.is_symlink()
            {
                // Follow the symlink and ensure target is within root (if any)
                let target = fs::read_link(&path).await?;
                let resolved_target = if target.is_absolute() {
                    target
                } else {
                    // Resolve relative symlink from the symlink's directory.
                    // Fall back to cwd when the parent isn't accessible.
                    let base = path.parent().unwrap_or(&cwd);
                    let joined = base.join(&target);
                    // Use tokio's canonicalize for async operation
                    tokio::fs::canonicalize(&joined).await.unwrap_or(target)
                };

                if let Err(e) =
                    SftpHandler::ensure_target_in_root(root_dir.as_deref(), &resolved_target)
                {
                    tracing::warn!(
                        path = %path.display(),
                        target = %resolved_target.display(),
                        "Symlink target outside root directory"
                    );
                    return Err(e);
                }
            }

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
            // Cap read size to prevent memory exhaustion
            let capped_len = len.min(MAX_READ_SIZE);
            if len > MAX_READ_SIZE {
                tracing::warn!(
                    handle = %handle,
                    requested = len,
                    capped = capped_len,
                    "Read size exceeds maximum, capping to MAX_READ_SIZE"
                );
            }

            let mut handles_guard = handles.lock().await;
            let handle_entry = handles_guard.get_mut(&handle);

            let file = match handle_entry {
                Some(OpenHandle::File { file, .. }) => file,
                _ => return Err(SftpError::invalid_handle()),
            };

            // Seek to offset
            file.seek(SeekFrom::Start(offset)).await?;

            // Read data
            let mut buffer = vec![0u8; capped_len as usize];
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
        let root_dir = self.root_dir.clone();

        tracing::debug!(
            user = %self.user_info.username,
            path = %path,
            handle = %handle_id,
            "Opening directory"
        );

        async move {
            // Check handle limit before acquiring lock
            {
                let handles_guard = handles.lock().await;
                if handles_guard.len() >= MAX_HANDLES {
                    return Err(SftpError::new(StatusCode::Failure, "Too many open handles"));
                }
            }

            let resolved_path = resolved?;

            // Read directory entries
            let mut entries = Vec::new();
            let mut read_dir = fs::read_dir(&resolved_path).await?;

            // Add "." entry
            if let Ok(meta) = fs::symlink_metadata(&resolved_path).await {
                entries.push(DirEntryInfo {
                    filename: ".".to_string(),
                    attrs: SftpHandler::metadata_to_attrs(&meta),
                });
            }

            // Add ".." entry. With chroot, only include the parent if it
            // remains inside the chroot; otherwise reuse the directory's own
            // metadata so the listing doesn't leak the chroot boundary.
            // Without chroot, fall back to ordinary parent semantics.
            if let Some(parent) = resolved_path.parent() {
                let parent_inside_root = root_dir
                    .as_ref()
                    .map(|root| parent.starts_with(root))
                    .unwrap_or(true);
                let at_root_boundary = root_dir
                    .as_ref()
                    .map(|root| resolved_path == *root)
                    .unwrap_or(false);

                if parent_inside_root {
                    if let Ok(meta) = fs::symlink_metadata(parent).await {
                        entries.push(DirEntryInfo {
                            filename: "..".to_string(),
                            attrs: SftpHandler::metadata_to_attrs(&meta),
                        });
                    }
                } else if at_root_boundary {
                    // At chroot boundary, mirror the directory's own metadata.
                    if let Ok(meta) = fs::symlink_metadata(&resolved_path).await {
                        entries.push(DirEntryInfo {
                            filename: "..".to_string(),
                            attrs: SftpHandler::metadata_to_attrs(&meta),
                        });
                    }
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
        let root_dir = self.root_dir.clone();
        let cwd = self.cwd.clone();

        async move {
            let path = resolved?;

            // Use symlink_metadata first to check if it's a symlink
            let symlink_meta = fs::symlink_metadata(&path).await?;

            if symlink_meta.is_symlink() {
                // Follow the symlink and validate the target is within root
                // (when chroot is enabled).
                let target = fs::read_link(&path).await?;
                let resolved_target = if target.is_absolute() {
                    target
                } else {
                    let base = path.parent().unwrap_or(&cwd);
                    let joined = base.join(&target);
                    tokio::fs::canonicalize(&joined).await.unwrap_or(target)
                };

                if let Err(e) =
                    SftpHandler::ensure_target_in_root(root_dir.as_deref(), &resolved_target)
                {
                    tracing::warn!(
                        path = %path.display(),
                        target = %resolved_target.display(),
                        "stat: Symlink target outside root directory"
                    );
                    return Err(e);
                }
            }

            // Now get the metadata (following symlinks)
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

            // Return path the way the client should see it. With chroot,
            // strip the root prefix so the client sees a path rooted at "/".
            // Without chroot, expose the resolved absolute path verbatim.
            let display_path = match root_dir.as_ref() {
                Some(root) if full_path == *root => "/".to_string(),
                Some(root) => full_path
                    .strip_prefix(root)
                    .map(|p| format!("/{}", p.display()))
                    .unwrap_or_else(|_| full_path.display().to_string()),
                None => full_path.display().to_string(),
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
        let root_dir = self.root_dir.clone();

        async move {
            let path = resolved?;
            let target = fs::read_link(&path).await?;

            // With chroot: redact targets outside the chroot and rewrite
            // in-chroot targets to a chroot-relative path.
            // Without chroot: pass the link target through verbatim, the same
            // way OpenSSH does.
            let safe_target = match (root_dir.as_ref(), target.is_absolute()) {
                (Some(root), true) => {
                    let resolved_target =
                        if let Ok(canonical) = tokio::fs::canonicalize(&target).await {
                            canonical
                        } else {
                            target.clone()
                        };

                    if !resolved_target.starts_with(root) {
                        tracing::warn!(
                            symlink = %path.display(),
                            target = %resolved_target.display(),
                            "readlink: Symlink target outside root, redacting"
                        );
                        PathBuf::from("[target outside root]")
                    } else {
                        resolved_target
                            .strip_prefix(root)
                            .map(PathBuf::from)
                            .unwrap_or(target)
                    }
                }
                // Without chroot, or for relative targets: pass the link
                // target through unchanged (matches OpenSSH behavior).
                _ => target,
            };

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
                    filename: safe_target.display().to_string(),
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
        let root_dir = self.root_dir.clone();
        let cwd = self.cwd.clone();

        async move {
            let link_path = link_resolved?;

            // Validate the symlink target. With chroot, both absolute and
            // relative targets must resolve inside the chroot. Without chroot,
            // mirror OpenSSH and let the kernel + filesystem permissions
            // enforce access; we still create the link with the target as-is.
            let target = Path::new(&targetpath);

            if let Some(root) = root_dir.as_deref() {
                if target.is_absolute() {
                    let resolved_target = resolve_chroot(target, root).inspect_err(|_| {
                        tracing::warn!(
                            user = %user,
                            link = %link_path.display(),
                            target = %targetpath,
                            "Rejected symlink with absolute target outside chroot"
                        );
                    })?;
                    if !resolved_target.starts_with(root) {
                        tracing::warn!(
                            user = %user,
                            link = %link_path.display(),
                            target = %targetpath,
                            resolved = %resolved_target.display(),
                            "Symlink target resolves outside chroot"
                        );
                        return Err(SftpError::permission_denied(
                            "Symlink target must be within root directory",
                        ));
                    }
                } else {
                    // Relative target: combine with the link's parent directory
                    // (or fall back to cwd) and ensure the result stays in
                    // the chroot.
                    let link_parent = link_path.parent().unwrap_or(&cwd);
                    let mut resolved = link_parent.to_path_buf();
                    for component in target.components() {
                        use std::path::Component;
                        match component {
                            Component::Normal(c) => resolved.push(c),
                            Component::CurDir => {}
                            Component::ParentDir
                                if (!resolved.pop() || !resolved.starts_with(root)) =>
                            {
                                tracing::warn!(
                                    user = %user,
                                    link = %link_path.display(),
                                    target = %targetpath,
                                    "Relative symlink target escapes chroot"
                                );
                                return Err(SftpError::permission_denied(
                                    "Symlink target must be within root directory",
                                ));
                            }
                            _ => {}
                        }
                    }
                    if !resolved.starts_with(root) {
                        tracing::warn!(
                            user = %user,
                            link = %link_path.display(),
                            target = %targetpath,
                            resolved = %resolved.display(),
                            "Relative symlink resolves outside chroot"
                        );
                        return Err(SftpError::permission_denied(
                            "Symlink target must be within root directory",
                        ));
                    }
                }
            }

            // Create symbolic link (target is stored as-is, validation above)
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

    /// Build a handler with chroot enabled at `/home/testuser`.
    fn chroot_handler() -> SftpHandler {
        let user = UserInfo::new("testuser");
        SftpHandler::new(
            user,
            Some(PathBuf::from("/home/testuser")),
            PathBuf::from("/home/testuser"),
        )
    }

    /// Build a handler with no chroot, home dir at `/home/testuser`.
    fn no_chroot_handler() -> SftpHandler {
        let user = UserInfo::new("testuser");
        SftpHandler::new(user, None, PathBuf::from("/home/testuser"))
    }

    // --- Chroot mode tests --------------------------------------------------

    #[test]
    fn chroot_relative_path_resolves_under_root() {
        let handler = chroot_handler();
        let result = handler.resolve_path("documents/file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn chroot_absolute_inside_root_is_returned_verbatim() {
        // The bug fix: an absolute client path inside the chroot must NOT be
        // re-rooted (no path doubling). /home/testuser/file.bin must resolve
        // to /home/testuser/file.bin, not /home/testuser/home/testuser/file.bin.
        let handler = chroot_handler();
        let result = handler.resolve_path("/home/testuser/file.bin").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/file.bin"));
    }

    #[test]
    fn chroot_absolute_at_root_resolves_to_root() {
        let handler = chroot_handler();
        let result = handler.resolve_path("/home/testuser").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    #[test]
    fn chroot_absolute_outside_root_is_rejected() {
        let handler = chroot_handler();
        let err = handler.resolve_path("/etc/passwd").unwrap_err();
        assert_eq!(err.code, StatusCode::PermissionDenied);

        let err = handler.resolve_path("/tmp/file.bin").unwrap_err();
        assert_eq!(err.code, StatusCode::PermissionDenied);
    }

    #[test]
    fn chroot_relative_traversal_is_clamped_to_root() {
        let handler = chroot_handler();
        // "../etc/passwd" tries to escape, gets clamped at root, then etc/passwd
        let result = handler.resolve_path("../etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));
        assert!(result.starts_with("/home/testuser"));

        // Multiple parent refs all get clamped
        let result = handler
            .resolve_path("../../../../../../../etc/passwd")
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn chroot_relative_in_bounds_double_dots_work() {
        let handler = chroot_handler();
        let result = handler.resolve_path("a/b/../c").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/a/c"));
    }

    #[test]
    fn chroot_root_path_resolves_to_chroot() {
        let handler = chroot_handler();
        let result = handler.resolve_path("/").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
        let result = handler.resolve_path(".").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    // --- No-chroot mode tests -----------------------------------------------

    #[test]
    fn no_chroot_absolute_path_used_verbatim() {
        // OpenSSH-compatible: absolute paths are not re-rooted.
        let handler = no_chroot_handler();
        let result = handler.resolve_path("/etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/etc/passwd"));

        let result = handler.resolve_path("/tmp/file.bin").unwrap();
        assert_eq!(result, PathBuf::from("/tmp/file.bin"));

        let result = handler.resolve_path("/home/testuser/file.bin").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/file.bin"));
    }

    #[test]
    fn no_chroot_relative_path_resolves_from_home() {
        let handler = no_chroot_handler();
        let result = handler.resolve_path("documents/file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn no_chroot_relative_double_dots_normalize() {
        // Without chroot, `..` normalizes against the cwd (home directory)
        // exactly as the kernel would. This matches OpenSSH's sftp-server.
        let handler = no_chroot_handler();
        let result = handler.resolve_path("../testuser/file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/file.txt"));
    }

    #[test]
    fn no_chroot_dot_resolves_to_home() {
        let handler = no_chroot_handler();
        let result = handler.resolve_path(".").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
        let result = handler.resolve_path("").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    #[test]
    fn no_chroot_handler_creates_with_explicit_home() {
        let user = UserInfo::new("alice");
        let handler = SftpHandler::new(user, None, PathBuf::from("/home/alice"));
        let result = handler.resolve_path("file.txt").unwrap();
        assert_eq!(result, PathBuf::from("/home/alice/file.txt"));
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
        let mut handler = chroot_handler();

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

    #[test]
    fn test_build_longname_symlink() {
        let attrs = FileAttributes {
            size: Some(20),
            uid: Some(1000),
            user: None,
            gid: Some(1000),
            group: None,
            permissions: Some(0o120777), // Symlink with lrwxrwxrwx
            atime: None,
            mtime: None,
        };

        let longname = SftpHandler::build_longname("link", &attrs);
        assert!(longname.starts_with('l'));
        assert!(longname.contains("rwxrwxrwx"));
    }

    #[test]
    fn test_build_longname_no_permissions() {
        let attrs = FileAttributes {
            size: Some(0),
            uid: None,
            user: None,
            gid: None,
            group: None,
            permissions: None,
            atime: None,
            mtime: None,
        };

        let longname = SftpHandler::build_longname("unknown", &attrs);
        // Should handle missing permissions gracefully
        assert!(longname.contains("unknown"));
        // With no permissions, defaults to 0, so all dashes
        assert!(longname.starts_with('-'));
    }

    #[test]
    fn test_resolve_path_empty_string() {
        let handler = chroot_handler();

        // Empty string should resolve to root
        let result = handler.resolve_path("").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    #[test]
    fn test_resolve_path_special_characters() {
        let handler = chroot_handler();

        // Path with spaces
        let result = handler.resolve_path("my documents/file name.txt").unwrap();
        assert_eq!(
            result,
            PathBuf::from("/home/testuser/my documents/file name.txt")
        );

        // Path with unicode characters
        let result = handler.resolve_path("documents/test-file.txt").unwrap();
        assert_eq!(
            result,
            PathBuf::from("/home/testuser/documents/test-file.txt")
        );
    }

    #[test]
    fn test_resolve_path_encoded_traversal() {
        let handler = chroot_handler();

        // Encoded patterns should be treated as literal path components
        // (the path component itself is ".." not percent encoding)
        let result = handler.resolve_path("%2e%2e/etc/passwd").unwrap();
        // %2e%2e is treated as a literal directory name, not decoded
        assert_eq!(result, PathBuf::from("/home/testuser/%2e%2e/etc/passwd"));
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn test_resolve_path_multiple_slashes() {
        let handler = chroot_handler();

        // Relative path with consecutive slashes - normalization collapses them.
        let result = handler.resolve_path("documents///file.txt").unwrap();
        assert!(result.starts_with("/home/testuser"));
        assert!(result.to_string_lossy().contains("documents"));
        assert!(result.to_string_lossy().contains("file.txt"));

        // An absolute path with multiple slashes that lands inside the chroot.
        let result = handler
            .resolve_path("/home/testuser///documents///file.txt")
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn test_resolve_path_dot_only() {
        let handler = chroot_handler();

        // Single dot
        let result = handler.resolve_path(".").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));

        // Double dot clamped to root
        let result = handler.resolve_path("..").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser"));
    }

    #[test]
    fn test_resolve_path_alternating_dots() {
        let handler = chroot_handler();

        // Alternating . and ..
        let result = handler.resolve_path("./a/../b/./c/../d").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/b/d"));
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn test_sftp_error_helpers() {
        // Test all error helper methods
        let err = SftpError::not_supported();
        assert_eq!(err.code, StatusCode::OpUnsupported);

        let err = SftpError::no_such_file(Path::new("/test/path"));
        assert_eq!(err.code, StatusCode::NoSuchFile);
        assert!(err.message.contains("/test/path"));

        let err = SftpError::permission_denied("custom message");
        assert_eq!(err.code, StatusCode::PermissionDenied);
        assert_eq!(err.message, "custom message");

        let err = SftpError::invalid_handle();
        assert_eq!(err.code, StatusCode::Failure);

        let err = SftpError::failure("generic failure");
        assert_eq!(err.code, StatusCode::Failure);
        assert_eq!(err.message, "generic failure");

        let err = SftpError::eof();
        assert_eq!(err.code, StatusCode::Eof);
    }

    #[test]
    fn test_sftp_error_display() {
        let err = SftpError::new(StatusCode::NoSuchFile, "test error message");
        let display = format!("{}", err);
        assert!(display.contains("test error message"));
    }

    #[test]
    fn test_sftp_error_to_status_code() {
        let err = SftpError::permission_denied("test");
        let code: StatusCode = err.into();
        assert_eq!(code, StatusCode::PermissionDenied);
    }

    #[test]
    fn test_sftp_error_from_io_eof() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let sftp_err: SftpError = io_err.into();
        assert_eq!(sftp_err.code, StatusCode::Eof);
    }

    #[test]
    fn test_sftp_error_from_io_other() {
        let io_err = std::io::Error::other("other error");
        let sftp_err: SftpError = io_err.into();
        assert_eq!(sftp_err.code, StatusCode::Failure);
    }

    #[test]
    fn no_chroot_handler_treats_relative_under_home() {
        // With no chroot, relative paths resolve from the home directory.
        let user = UserInfo::new("testuser");
        let handler = SftpHandler::new(user, None, PathBuf::from("/home/testuser"));

        let result = handler.resolve_path("etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));

        // Absolute paths are honored verbatim.
        let result = handler.resolve_path("/etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn resolve_path_static_chroot_mode() {
        let root = PathBuf::from("/chroot/jail");
        let cwd = root.clone();

        // Relative path joined with chroot root.
        let result = SftpHandler::resolve_path_static("test.txt", Some(&root), &cwd).unwrap();
        assert_eq!(result, PathBuf::from("/chroot/jail/test.txt"));

        // Relative `..` clamped to chroot root.
        let result = SftpHandler::resolve_path_static("../escape", Some(&root), &cwd).unwrap();
        assert_eq!(result, PathBuf::from("/chroot/jail/escape"));

        // Absolute inside chroot honored as-is.
        let result =
            SftpHandler::resolve_path_static("/chroot/jail/absolute/path", Some(&root), &cwd)
                .unwrap();
        assert_eq!(result, PathBuf::from("/chroot/jail/absolute/path"));

        // Absolute outside chroot rejected.
        let err = SftpHandler::resolve_path_static("/etc/passwd", Some(&root), &cwd).unwrap_err();
        assert_eq!(err.code, StatusCode::PermissionDenied);
    }

    #[test]
    fn resolve_path_static_no_chroot_mode() {
        let cwd = PathBuf::from("/home/alice");

        // Relative path joined with cwd.
        let result = SftpHandler::resolve_path_static("test.txt", None, &cwd).unwrap();
        assert_eq!(result, PathBuf::from("/home/alice/test.txt"));

        // Absolute path honored verbatim.
        let result = SftpHandler::resolve_path_static("/etc/passwd", None, &cwd).unwrap();
        assert_eq!(result, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn ensure_target_in_root_allows_no_chroot() {
        // No chroot: every target is allowed; filesystem permissions apply.
        SftpHandler::ensure_target_in_root(None, Path::new("/anywhere/at/all")).unwrap();
    }

    #[test]
    fn ensure_target_in_root_rejects_chroot_escape() {
        let root = PathBuf::from("/chroot/jail");
        let err =
            SftpHandler::ensure_target_in_root(Some(&root), Path::new("/etc/passwd")).unwrap_err();
        assert_eq!(err.code, StatusCode::PermissionDenied);
    }

    #[test]
    fn ensure_target_in_root_allows_inside_chroot() {
        let root = PathBuf::from("/chroot/jail");
        SftpHandler::ensure_target_in_root(Some(&root), Path::new("/chroot/jail/file")).unwrap();
    }

    #[test]
    fn test_metadata_to_attrs() {
        // Create a temporary file to get real metadata
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        {
            let mut file = File::create(&file_path).unwrap();
            writeln!(file, "test content").unwrap();
        }

        let metadata = std::fs::metadata(&file_path).unwrap();
        let attrs = SftpHandler::metadata_to_attrs(&metadata);

        assert!(attrs.size.is_some());
        assert!(attrs.uid.is_some());
        assert!(attrs.gid.is_some());
        assert!(attrs.permissions.is_some());
        assert!(attrs.mtime.is_some());
        assert!(attrs.atime.is_some());
    }
}
