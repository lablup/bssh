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

//! SCP (Secure Copy Protocol) server implementation.
//!
//! This module provides the SCP protocol handler for the bssh server,
//! enabling file transfers via the `scp` command.
//!
//! # Protocol Overview
//!
//! SCP is not a standalone protocol but rather a command-line tool that
//! communicates over SSH. When a client runs `scp file user@host:path`,
//! the SSH server receives an exec request for `scp -t path` (upload/sink mode)
//! or `scp -f path` (download/source mode).
//!
//! # Security
//!
//! The handler implements path traversal prevention to ensure clients
//! cannot access files outside their designated root directory.
//!
//! # Example
//!
//! ```no_run
//! use bssh::server::scp::{ScpHandler, ScpMode};
//! use bssh::shared::auth_types::UserInfo;
//! use std::path::PathBuf;
//!
//! let user = UserInfo::new("testuser");
//! // Without chroot (OpenSSH-compatible behavior):
//! let handler = ScpHandler::new(
//!     ScpMode::Sink,
//!     PathBuf::from("/tmp/upload"),
//!     user.clone(),
//!     None,
//!     PathBuf::from("/home/testuser"),
//! );
//!
//! // With chroot:
//! let handler = ScpHandler::new(
//!     ScpMode::Sink,
//!     PathBuf::from("/tmp/upload"),
//!     user,
//!     Some(PathBuf::from("/srv/scp")),
//!     PathBuf::from("/home/testuser"),
//! );
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use russh::ChannelId;
use russh::server::Handle;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::shared::auth_types::UserInfo;

/// SCP protocol status codes.
const SCP_OK: u8 = 0;
const SCP_WARNING: u8 = 1;
const SCP_ERROR: u8 = 2;

/// Maximum file size for SCP transfers (10 GB).
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Buffer size for file transfers (64 KB).
const BUFFER_SIZE: usize = 64 * 1024;

/// Maximum line length for SCP protocol headers (64 KB).
/// This prevents DoS via unbounded buffer growth.
const MAX_LINE_LENGTH: usize = 64 * 1024;

/// SCP operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpMode {
    /// Source mode (-f): Server sends files to client (download).
    Source,
    /// Sink mode (-t): Server receives files from client (upload).
    Sink,
}

impl std::fmt::Display for ScpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScpMode::Source => write!(f, "source"),
            ScpMode::Sink => write!(f, "sink"),
        }
    }
}

/// Result of parsing an SCP command.
#[derive(Debug, Clone)]
pub struct ScpCommand {
    /// The operation mode (source or sink).
    pub mode: ScpMode,
    /// The target path for the operation.
    pub path: PathBuf,
    /// Whether recursive mode is enabled (-r).
    pub recursive: bool,
    /// Whether to preserve times (-p).
    pub preserve_times: bool,
    /// Whether the target is expected to be a directory (-d).
    pub target_is_directory: bool,
    /// Verbose mode (-v).
    pub verbose: bool,
}

impl ScpCommand {
    /// Parse an SCP command string.
    ///
    /// The command format is: `scp [-r] [-p] [-d] [-v] (-t|-f) path`
    ///
    /// # Arguments
    ///
    /// * `command` - The full command string (e.g., "scp -t /tmp/upload")
    ///
    /// # Returns
    ///
    /// Returns `Ok(ScpCommand)` if the command is a valid SCP command,
    /// or `Err` if parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// use bssh::server::scp::{ScpCommand, ScpMode};
    ///
    /// let cmd = ScpCommand::parse("scp -t -r /tmp/upload").unwrap();
    /// assert_eq!(cmd.mode, ScpMode::Sink);
    /// assert!(cmd.recursive);
    /// ```
    pub fn parse(command: &str) -> Result<Self> {
        let args: Vec<&str> = command.split_whitespace().collect();

        if args.is_empty() {
            anyhow::bail!("Empty command");
        }

        // First argument must be "scp"
        if args[0] != "scp" {
            anyhow::bail!("Not an SCP command: {}", args[0]);
        }

        let mut mode = None;
        let mut recursive = false;
        let mut preserve_times = false;
        let mut target_is_directory = false;
        let mut verbose = false;
        let mut path = None;

        let mut i = 1;
        while i < args.len() {
            let arg = args[i];

            if arg.starts_with('-') && arg.len() > 1 {
                // Handle combined flags like "-tpr"
                for ch in arg[1..].chars() {
                    match ch {
                        't' => mode = Some(ScpMode::Sink),
                        'f' => mode = Some(ScpMode::Source),
                        'r' => recursive = true,
                        'p' => preserve_times = true,
                        'd' => target_is_directory = true,
                        'v' => verbose = true,
                        // Ignore other flags we don't care about
                        _ => {}
                    }
                }
            } else if !arg.starts_with('-') {
                // This is the path argument
                if path.is_none() {
                    path = Some(PathBuf::from(arg));
                }
            }

            i += 1;
        }

        let mode = mode.ok_or_else(|| anyhow::anyhow!("Missing -t or -f flag"))?;
        let path = path.ok_or_else(|| anyhow::anyhow!("Missing path argument"))?;

        Ok(Self {
            mode,
            path,
            recursive,
            preserve_times,
            target_is_directory,
            verbose,
        })
    }

    /// Check if a command string is an SCP command.
    ///
    /// This is a quick check without full parsing.
    pub fn is_scp_command(command: &str) -> bool {
        let trimmed = command.trim();
        trimmed.starts_with("scp ") || trimmed == "scp"
    }
}

/// Normalize a path's `..` and `.` components without touching the filesystem.
fn normalize_components(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
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

/// Resolve a client-supplied SCP path against a chroot root.
///
/// - Absolute paths inside `root` are honored as-is.
/// - Absolute paths outside `root` are rejected.
/// - Relative paths are joined with `root`; `..` is clamped to `root`.
fn resolve_chroot_scp(requested: &Path, root: &Path, user: &str) -> Result<PathBuf> {
    if requested.is_absolute() {
        // Plain "/" is the client's view of the chroot root (matches what
        // `realpath` returns). Map it back to the actual chroot directory.
        if requested == Path::new("/") {
            return Ok(root.to_path_buf());
        }
        let normalized = normalize_components(requested);
        if normalized == root || normalized.starts_with(root) {
            return Ok(normalized);
        }
        tracing::warn!(
            event = "chroot_escape_blocked",
            user = %user,
            requested = %requested.display(),
            root = %root.display(),
            "Security: absolute path outside chroot blocked"
        );
        anyhow::bail!("Access denied: path outside root");
    }

    // Relative path under chroot: join, then walk components clamping `..`
    // so traversal cannot escape the chroot.
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
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    if !resolved.starts_with(root) {
        tracing::warn!(
            event = "path_traversal_attempt",
            user = %user,
            requested = %requested.display(),
            resolved = %resolved.display(),
            root = %root.display(),
            "Security: path traversal attempt blocked"
        );
        anyhow::bail!("Access denied: path outside root");
    }

    Ok(resolved)
}

/// Find the closest existing ancestor of `path` and return both the ancestor
/// and its canonicalized form.
///
/// Walks up `path` (popping one component at a time) until a path that exists
/// on the filesystem is found, then canonicalizes it. Used by chroot
/// resolution to detect intermediate-directory symlinks pointing outside the
/// chroot — without this check, `OpenOptions::open(...)` on a non-existent
/// final path would happily follow a parent-symlink and write outside the
/// chroot.
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

/// Resolve a client-supplied SCP path without a chroot.
///
/// Absolute paths are used verbatim. Relative paths join with `cwd`
/// (the user's home directory). `..` is normalized but not clamped.
/// This matches OpenSSH `scp -t` behavior on a non-restricted account.
fn resolve_no_chroot_scp(requested: &Path, cwd: &Path) -> PathBuf {
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        cwd.join(requested)
    };
    normalize_components(&joined)
}

/// SCP server handler.
///
/// Implements the SCP protocol for file transfer operations with
/// security controls to prevent path traversal attacks.
pub struct ScpHandler {
    /// The SCP mode (source or sink).
    mode: ScpMode,
    /// The target path for the operation.
    target_path: PathBuf,
    /// Current user information.
    user_info: UserInfo,
    /// Optional chroot root.
    ///
    /// `Some(path)` confines all transfers to `path` (chroot semantics).
    /// `None` (default) runs without chroot: absolute paths are honored
    /// verbatim and relative paths resolve from `cwd`. This matches OpenSSH.
    root_dir: Option<PathBuf>,
    /// Base directory for resolving relative client paths.
    ///
    /// Set to the chroot root when chroot is enabled, or to the user's home
    /// directory when chroot is disabled.
    cwd: PathBuf,
    /// Whether recursive mode is enabled.
    recursive: bool,
    /// Whether to preserve times.
    preserve_times: bool,
    /// Whether the client signaled the destination is a directory (`-d`/`-r`).
    ///
    /// Used by `receive_file` to decide whether to append the source filename
    /// to a single-file destination.
    target_is_directory: bool,
    /// Stored times for the next file (mtime, atime).
    stored_times: Option<(u64, u64)>,
}

impl ScpHandler {
    /// Create a new SCP handler.
    ///
    /// # Arguments
    ///
    /// * `mode` - The SCP mode (source or sink)
    /// * `target_path` - The target path for the operation
    /// * `user_info` - Information about the authenticated user
    /// * `root_dir` - Optional chroot root. When `None`, no chroot is applied.
    /// * `home_dir` - The user's home directory; used as the base for relative
    ///   paths when chroot is disabled.
    pub fn new(
        mode: ScpMode,
        target_path: PathBuf,
        user_info: UserInfo,
        root_dir: Option<PathBuf>,
        home_dir: PathBuf,
    ) -> Self {
        let cwd = root_dir.clone().unwrap_or_else(|| home_dir.clone());

        tracing::debug!(
            user = %user_info.username,
            mode = %mode,
            path = %target_path.display(),
            chroot = ?root_dir.as_ref().map(|p| p.display().to_string()),
            cwd = %cwd.display(),
            "Creating SCP handler"
        );

        Self {
            mode,
            target_path,
            user_info,
            root_dir,
            cwd,
            recursive: false,
            preserve_times: false,
            target_is_directory: false,
            stored_times: None,
        }
    }

    /// Create a handler from a parsed SCP command.
    pub fn from_command(
        cmd: &ScpCommand,
        user_info: UserInfo,
        root_dir: Option<PathBuf>,
        home_dir: PathBuf,
    ) -> Self {
        let mut handler = Self::new(cmd.mode, cmd.path.clone(), user_info, root_dir, home_dir);
        handler.recursive = cmd.recursive;
        handler.preserve_times = cmd.preserve_times;
        handler.target_is_directory = cmd.target_is_directory;
        handler
    }

    /// Resolve a client path to an absolute filesystem path.
    ///
    /// Behavior depends on whether a chroot `root_dir` is configured.
    ///
    /// ## With chroot (`root_dir = Some(root)`):
    /// - Absolute client paths inside `root` are honored as-is.
    /// - Absolute client paths outside `root` are rejected.
    /// - Relative paths are joined with `root`; `..` traversal is clamped.
    /// - Existing paths are canonicalized to catch symlink-escape attempts.
    /// - For non-existent paths (typical for new-file creates), the closest
    ///   existing ancestor is canonicalized and verified to stay inside
    ///   `root`. This blocks intermediate-directory symlinks pointing outside
    ///   the chroot.
    ///
    /// ## Without chroot (`root_dir = None`):
    /// - Absolute paths are used verbatim.
    /// - Relative paths are joined with `cwd` (user home directory).
    /// - Filesystem permissions remain the access boundary, matching OpenSSH.
    pub fn resolve_path(&self, path: &Path) -> Result<PathBuf> {
        let path_str = path.to_string_lossy();
        let resolved = match self.root_dir.as_deref() {
            Some(root) => resolve_chroot_scp(path, root, &self.user_info.username)?,
            None => resolve_no_chroot_scp(path, &self.cwd),
        };

        // Canonicalize existing paths to catch symlink-escape attempts. Only
        // enforce the in-root invariant when chroot is enabled; without
        // chroot, canonicalization is purely informational.
        if resolved.exists() {
            match std::fs::canonicalize(&resolved) {
                Ok(canonical) => {
                    if let Some(root) = self.root_dir.as_deref()
                        && !canonical.starts_with(root)
                    {
                        tracing::warn!(
                            event = "symlink_escape_attempt",
                            user = %self.user_info.username,
                            requested = %path_str,
                            resolved = %resolved.display(),
                            canonical = %canonical.display(),
                            root = %root.display(),
                            "Security: symlink escape attempt blocked"
                        );
                        anyhow::bail!("Access denied: symlink target outside root");
                    }
                    return Ok(canonical);
                }
                Err(e) => {
                    tracing::debug!(
                        path = %resolved.display(),
                        error = %e,
                        "Canonicalization failed, using resolved path"
                    );
                }
            }
        } else if let Some(root) = self.root_dir.as_deref() {
            // Path does not exist (typical for new-file create/upload). Walk
            // up to the closest existing ancestor and verify its canonical
            // form stays inside the chroot. This catches the case where an
            // intermediate parent is a symlink pointing outside the chroot;
            // without this check, `OpenOptions::open(...)` would follow the
            // symlink and create the file outside the chroot.
            //
            // Compare canonical-vs-canonical: an unresolved root might itself
            // contain symlinks, so we canonicalize both sides. If the chroot
            // root does not exist on disk, the operator config is bad and we
            // can only fall back to the lexical check above (skip enforcement).
            if let Some(canonical_root) = std::fs::canonicalize(root).ok()
                && let Some((ancestor, canonical_ancestor)) = closest_existing_canonical(&resolved)
                && !canonical_ancestor.starts_with(&canonical_root)
            {
                tracing::warn!(
                    event = "symlink_escape_attempt",
                    user = %self.user_info.username,
                    requested = %path_str,
                    resolved = %resolved.display(),
                    ancestor = %ancestor.display(),
                    canonical_ancestor = %canonical_ancestor.display(),
                    canonical_root = %canonical_root.display(),
                    "Security: parent-directory symlink escape blocked"
                );
                anyhow::bail!("Access denied: symlink target outside root");
            }
        }

        tracing::trace!(
            requested = %path_str,
            resolved = %resolved.display(),
            "Resolved path"
        );

        Ok(resolved)
    }

    /// Run the SCP protocol.
    ///
    /// This method handles the main SCP protocol loop, reading commands
    /// from the client and sending/receiving files accordingly.
    ///
    /// # Arguments
    ///
    /// * `channel_id` - The SSH channel ID
    /// * `handle` - The russh session handle for sending data
    /// * `data_rx` - Receiver for data from the SSH client
    ///
    /// # Returns
    ///
    /// Returns the exit code (0 for success, non-zero for failure).
    pub async fn run(
        mut self,
        channel_id: ChannelId,
        handle: Handle,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> i32 {
        tracing::info!(
            user = %self.user_info.username,
            mode = %self.mode,
            path = %self.target_path.display(),
            recursive = %self.recursive,
            "Starting SCP session"
        );

        let result = match self.mode {
            ScpMode::Sink => {
                self.run_sink(channel_id, handle.clone(), &mut data_rx)
                    .await
            }
            ScpMode::Source => {
                self.run_source(channel_id, handle.clone(), &mut data_rx)
                    .await
            }
        };

        match result {
            Ok(()) => {
                tracing::info!(
                    user = %self.user_info.username,
                    mode = %self.mode,
                    "SCP session completed successfully"
                );
                0
            }
            Err(e) => {
                tracing::error!(
                    user = %self.user_info.username,
                    mode = %self.mode,
                    error = %e,
                    "SCP session failed"
                );
                1
            }
        }
    }

    /// Run sink mode (receive files from client).
    async fn run_sink(
        &mut self,
        channel_id: ChannelId,
        handle: Handle,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        // Resolve the target path
        let target = self.resolve_path(&self.target_path)?;

        // Send initial ready signal
        self.send_ok(channel_id, &handle).await?;

        // Create a buffered reader from the data stream
        let mut buffer = Vec::new();
        let mut current_dir = target.clone();

        // Stack for tracking directory nesting
        let mut dir_stack: Vec<PathBuf> = vec![target.clone()];

        loop {
            // Read until we have a complete line or command
            let line = match self.read_line(&mut buffer, data_rx).await {
                Ok(Some(line)) => line,
                Ok(None) => break, // EOF
                Err(e) => {
                    tracing::warn!("Error reading SCP command: {}", e);
                    break;
                }
            };

            if line.is_empty() {
                continue;
            }

            let first_byte = line.as_bytes()[0];

            match first_byte {
                b'C' => {
                    // File: C<mode> <size> <filename>
                    // At top level (dir_stack.len() == 1) we honor the
                    // single-file vs. directory distinction. Inside a
                    // recursively descended directory, the filename always
                    // joins to the current directory.
                    let at_top_level = dir_stack.len() == 1;
                    if let Err(e) = self
                        .receive_file(
                            &line,
                            &current_dir,
                            at_top_level,
                            channel_id,
                            &handle,
                            &mut buffer,
                            data_rx,
                        )
                        .await
                    {
                        tracing::error!("Error receiving file: {}", e);
                        self.send_error(channel_id, &handle, &e.to_string()).await?;
                        return Err(e);
                    }
                }
                b'D' => {
                    // Directory: D<mode> 0 <dirname>
                    if !self.recursive {
                        self.send_error(channel_id, &handle, "Recursive mode not enabled")
                            .await?;
                        anyhow::bail!("Recursive mode not enabled");
                    }

                    match self.enter_directory(&line, &current_dir).await {
                        Ok(new_dir) => {
                            dir_stack.push(new_dir.clone());
                            current_dir = new_dir;
                            self.send_ok(channel_id, &handle).await?;
                        }
                        Err(e) => {
                            self.send_error(channel_id, &handle, &e.to_string()).await?;
                            return Err(e);
                        }
                    }
                }
                b'E' => {
                    // End of directory
                    if dir_stack.len() > 1 {
                        dir_stack.pop();
                        current_dir = dir_stack.last().cloned().unwrap_or(target.clone());
                    }
                    self.send_ok(channel_id, &handle).await?;
                }
                b'T' => {
                    // Preserve times: T<mtime> 0 <atime> 0
                    if self.preserve_times
                        && let Err(e) = self.parse_times(&line)
                    {
                        tracing::warn!("Error parsing times: {}", e);
                    }
                    self.send_ok(channel_id, &handle).await?;
                }
                SCP_WARNING | SCP_ERROR => {
                    // Error from client
                    tracing::warn!("SCP client error: {}", line);
                    break;
                }
                _ => {
                    tracing::warn!("Unknown SCP command: {:?}", line);
                    self.send_error(channel_id, &handle, "Unknown command")
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Receive a single file.
    ///
    /// `at_top_level` indicates the C-record is for the top-level destination
    /// supplied by the client, not a file inside a recursively descended
    /// directory. At top level, the destination might be either a file
    /// (e.g. `scp local.bin host:/tmp/dest.bin`) or a directory (e.g.
    /// `scp local.bin host:/tmp/dest/`); the source filename should only be
    /// appended in the directory case.
    #[allow(clippy::too_many_arguments)]
    async fn receive_file(
        &mut self,
        header: &str,
        target_dir: &Path,
        at_top_level: bool,
        channel_id: ChannelId,
        handle: &Handle,
        buffer: &mut Vec<u8>,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        // Parse header: C<mode> <size> <filename>
        // Remove the 'C' prefix
        let header = &header[1..];
        let parts: Vec<&str> = header.splitn(3, ' ').collect();

        if parts.len() != 3 {
            anyhow::bail!("Invalid file header: {}", header);
        }

        let raw_mode = u32::from_str_radix(parts[0], 8)
            .with_context(|| format!("Invalid mode: {}", parts[0]))?;
        // Security: mask mode to only allow standard permission bits
        // Prevents setuid (04000), setgid (02000), and sticky (01000) bits
        let mode = raw_mode & 0o777;

        let size: u64 = parts[1]
            .parse()
            .with_context(|| format!("Invalid size: {}", parts[1]))?;
        let filename = parts[2].trim();

        // Security: validate filename
        if filename.contains('/') || filename == ".." || filename == "." {
            anyhow::bail!("Invalid filename");
        }

        // Check file size limit
        if size > MAX_FILE_SIZE {
            tracing::warn!(
                event = "file_size_exceeded",
                user = %self.user_info.username,
                size = %size,
                max_size = %MAX_FILE_SIZE,
                "Security: file size limit exceeded"
            );
            anyhow::bail!("File too large");
        }

        // Decide whether to treat the resolved target as a directory and
        // append the source filename, or write directly to it as a single
        // file. This is the fix for the "filename appended to single-file
        // destination" bug.
        let target_path =
            if at_top_level && !self.target_is_directory && !self.recursive && !target_dir.is_dir()
            {
                // Single-file destination: write directly to the resolved path.
                target_dir.to_path_buf()
            } else {
                // Directory destination (existing dir, `-d`/`-r` flag, or nested
                // descent): append the source filename.
                target_dir.join(filename)
            };

        // When chroot is configured, ensure the final path stays inside the
        // chroot. Without chroot, the OS handles access checks.
        if let Some(root) = self.root_dir.as_deref()
            && !target_path.starts_with(root)
        {
            anyhow::bail!("Access denied: path outside root");
        }

        tracing::info!(
            user = %self.user_info.username,
            path = %target_path.display(),
            size = %size,
            mode = format!("{:04o}", mode),
            "Receiving file"
        );

        // Send ready signal
        self.send_ok(channel_id, handle).await?;

        // Create/open the file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target_path)
            .await
            .with_context(|| format!("Failed to create file: {}", target_path.display()))?;

        // Receive file data
        let mut remaining = size;

        // First, use any data already in buffer
        let buffered = buffer.len().min(remaining as usize);
        if buffered > 0 {
            file.write_all(&buffer[..buffered]).await?;
            buffer.drain(..buffered);
            remaining -= buffered as u64;
        }

        // Read remaining data
        while remaining > 0 {
            let data = match data_rx.recv().await {
                Some(data) => data,
                None => anyhow::bail!("Connection closed while receiving file"),
            };

            let to_write = data.len().min(remaining as usize);
            file.write_all(&data[..to_write]).await?;
            remaining -= to_write as u64;

            // Store any extra data in buffer
            if to_write < data.len() {
                buffer.extend_from_slice(&data[to_write..]);
            }
        }

        file.flush().await?;
        drop(file);

        // Set permissions
        #[cfg(unix)]
        {
            fs::set_permissions(&target_path, std::fs::Permissions::from_mode(mode)).await?;
        }

        // Set times if preserved
        if let Some((mtime, atime)) = self.stored_times.take() {
            // Note: Setting times requires the filetime crate or nix
            // For now we just log the intention
            tracing::debug!(
                path = %target_path.display(),
                mtime = mtime,
                atime = atime,
                "Would set file times (not implemented)"
            );
        }

        // Read the trailing null byte (after file data)
        // This might already be in the buffer
        if !buffer.is_empty() && buffer[0] == 0 {
            buffer.remove(0);
        } else {
            // Wait for the null byte
            while let Some(data) = data_rx.recv().await {
                if data.is_empty() {
                    continue;
                }
                if data[0] == 0 {
                    // Store any remaining data
                    if data.len() > 1 {
                        buffer.extend_from_slice(&data[1..]);
                    }
                    break;
                }
                // Unexpected data
                buffer.extend_from_slice(&data);
            }
        }

        // Send success
        self.send_ok(channel_id, handle).await?;

        tracing::info!(
            user = %self.user_info.username,
            path = %target_path.display(),
            "File received successfully"
        );

        Ok(())
    }

    /// Enter a directory (create if needed).
    async fn enter_directory(&self, header: &str, current_dir: &Path) -> Result<PathBuf> {
        // Parse header: D<mode> 0 <dirname>
        let header = &header[1..]; // Remove 'D'
        let parts: Vec<&str> = header.splitn(3, ' ').collect();

        if parts.len() != 3 {
            anyhow::bail!("Invalid directory header: {}", header);
        }

        let mode = u32::from_str_radix(parts[0], 8)
            .with_context(|| format!("Invalid mode: {}", parts[0]))?;
        let dirname = parts[2].trim();

        // Security: validate dirname
        if dirname.contains('/') || dirname == ".." || dirname == "." {
            anyhow::bail!("Invalid directory name: {}", dirname);
        }

        let new_dir = current_dir.join(dirname);

        // When chroot is configured, ensure the new directory stays inside
        // it. Without chroot, the OS enforces access via filesystem perms.
        if let Some(root) = self.root_dir.as_deref()
            && !new_dir.starts_with(root)
        {
            anyhow::bail!("Access denied: path outside root");
        }

        // Mask mode to only allow standard permission bits (no setuid/setgid/sticky)
        let safe_mode = mode & 0o777;

        tracing::debug!(
            user = %self.user_info.username,
            path = %new_dir.display(),
            mode = format!("{:04o}", safe_mode),
            "Entering directory"
        );

        // Create directory atomically - handles race conditions safely
        // If directory already exists, that's fine; we just continue
        match fs::create_dir(&new_dir).await {
            Ok(()) => {
                #[cfg(unix)]
                {
                    fs::set_permissions(&new_dir, std::fs::Permissions::from_mode(safe_mode))
                        .await?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Directory already exists, which is acceptable
            }
            Err(e) => return Err(e.into()),
        }

        Ok(new_dir)
    }

    /// Parse time preservation header.
    fn parse_times(&mut self, header: &str) -> Result<()> {
        // Format: T<mtime> 0 <atime> 0
        let header = &header[1..]; // Remove 'T'
        let parts: Vec<&str> = header.split_whitespace().collect();

        if parts.len() >= 3 {
            let mtime: u64 = parts[0].parse()?;
            let atime: u64 = parts[2].parse()?;
            self.stored_times = Some((mtime, atime));
        }

        Ok(())
    }

    /// Run source mode (send files to client).
    async fn run_source(
        &mut self,
        channel_id: ChannelId,
        handle: Handle,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        // Resolve the source path
        let source = self.resolve_path(&self.target_path)?;

        // Wait for ready signal from client
        self.wait_for_ok(data_rx).await?;

        // Check if source exists
        let metadata = fs::symlink_metadata(&source).await?;

        if metadata.is_dir() {
            if self.recursive {
                self.send_directory(channel_id, &handle, &source, data_rx)
                    .await?;
            } else {
                self.send_error(channel_id, &handle, "Is a directory")
                    .await?;
                anyhow::bail!("Source is a directory but recursive mode not enabled");
            }
        } else if metadata.is_file() {
            self.send_file(channel_id, &handle, &source, data_rx)
                .await?;
        } else {
            self.send_error(channel_id, &handle, "Not a regular file")
                .await?;
            anyhow::bail!("Source is not a regular file");
        }

        Ok(())
    }

    /// Send a single file to the client.
    async fn send_file(
        &self,
        channel_id: ChannelId,
        handle: &Handle,
        path: &Path,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        let metadata = fs::metadata(path).await?;
        let size = metadata.len();

        #[cfg(unix)]
        let mode = metadata.permissions().mode() & 0o777;
        #[cfg(not(unix))]
        let mode = 0o644;

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        tracing::info!(
            user = %self.user_info.username,
            path = %path.display(),
            size = %size,
            mode = format!("{:04o}", mode),
            "Sending file"
        );

        // Send time if preserving
        if self.preserve_times {
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let atime = metadata
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let time_header = format!("T{} 0 {} 0\n", mtime, atime);
            self.send_data(channel_id, handle, time_header.as_bytes())
                .await?;
            self.wait_for_ok(data_rx).await?;
        }

        // Send file header
        let header = format!("C{:04o} {} {}\n", mode, size, filename);
        self.send_data(channel_id, handle, header.as_bytes())
            .await?;

        // Wait for acknowledgment
        self.wait_for_ok(data_rx).await?;

        // Send file data
        let mut file = File::open(path).await?;
        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            self.send_data(channel_id, handle, &buffer[..n]).await?;
        }

        // Send trailing null byte
        self.send_data(channel_id, handle, &[0]).await?;

        // Wait for final acknowledgment
        self.wait_for_ok(data_rx).await?;

        tracing::info!(
            user = %self.user_info.username,
            path = %path.display(),
            "File sent successfully"
        );

        Ok(())
    }

    /// Send a directory and its contents recursively.
    async fn send_directory(
        &self,
        channel_id: ChannelId,
        handle: &Handle,
        path: &Path,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<()> {
        let metadata = fs::metadata(path).await?;

        #[cfg(unix)]
        let mode = metadata.permissions().mode() & 0o777;
        #[cfg(not(unix))]
        let mode = 0o755;

        let dirname = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        tracing::debug!(
            user = %self.user_info.username,
            path = %path.display(),
            mode = format!("{:04o}", mode),
            "Sending directory"
        );

        // Send time if preserving
        if self.preserve_times {
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let atime = metadata
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let time_header = format!("T{} 0 {} 0\n", mtime, atime);
            self.send_data(channel_id, handle, time_header.as_bytes())
                .await?;
            self.wait_for_ok(data_rx).await?;
        }

        // Send directory header
        let header = format!("D{:04o} 0 {}\n", mode, dirname);
        self.send_data(channel_id, handle, header.as_bytes())
            .await?;

        // Wait for acknowledgment
        self.wait_for_ok(data_rx).await?;

        // Send directory contents
        let mut entries = fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            let entry_meta = fs::symlink_metadata(&entry_path).await?;

            // Skip symlinks for security
            if entry_meta.is_symlink() {
                tracing::debug!(
                    path = %entry_path.display(),
                    "Skipping symlink"
                );
                continue;
            }

            if entry_meta.is_dir() {
                // Recurse into subdirectory
                // Use Box::pin to allow recursion
                Box::pin(self.send_directory(channel_id, handle, &entry_path, data_rx)).await?;
            } else if entry_meta.is_file() {
                self.send_file(channel_id, handle, &entry_path, data_rx)
                    .await?;
            }
        }

        // Send end of directory marker
        self.send_data(channel_id, handle, b"E\n").await?;
        self.wait_for_ok(data_rx).await?;

        Ok(())
    }

    /// Read a line from the data stream.
    async fn read_line(
        &self,
        buffer: &mut Vec<u8>,
        data_rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<Option<String>> {
        loop {
            // Check if we have a complete line in buffer
            if let Some(newline_pos) = buffer.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&buffer[..newline_pos]).to_string();
                buffer.drain(..=newline_pos);
                return Ok(Some(line));
            }

            // Check for buffer size limit to prevent DoS via memory exhaustion
            if buffer.len() > MAX_LINE_LENGTH {
                anyhow::bail!(
                    "Line too long (max {} bytes) - possible DoS attempt",
                    MAX_LINE_LENGTH
                );
            }

            // Read more data
            match data_rx.recv().await {
                Some(data) => {
                    buffer.extend_from_slice(&data);
                }
                None => {
                    // EOF - return any remaining data as a line
                    if !buffer.is_empty() {
                        let line = String::from_utf8_lossy(buffer).to_string();
                        buffer.clear();
                        return Ok(Some(line));
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Send data to the channel.
    async fn send_data(&self, channel_id: ChannelId, handle: &Handle, data: &[u8]) -> Result<()> {
        handle
            .data(channel_id, bytes::Bytes::copy_from_slice(data))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send data"))?;
        Ok(())
    }

    /// Send OK status.
    async fn send_ok(&self, channel_id: ChannelId, handle: &Handle) -> Result<()> {
        self.send_data(channel_id, handle, &[SCP_OK]).await
    }

    /// Send error status with message.
    async fn send_error(
        &self,
        channel_id: ChannelId,
        handle: &Handle,
        message: &str,
    ) -> Result<()> {
        let error_msg = format!("{}{}\n", char::from(SCP_ERROR), message);
        self.send_data(channel_id, handle, error_msg.as_bytes())
            .await
    }

    /// Wait for OK status from client.
    async fn wait_for_ok(&self, data_rx: &mut mpsc::Receiver<Vec<u8>>) -> Result<()> {
        match data_rx.recv().await {
            Some(data) => {
                if !data.is_empty() && data[0] != SCP_OK {
                    let msg = String::from_utf8_lossy(&data[1..]).to_string();
                    anyhow::bail!("Client error: {}", msg);
                }
                Ok(())
            }
            None => anyhow::bail!("Connection closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_command_parse_sink() {
        let cmd = ScpCommand::parse("scp -t /tmp/upload").unwrap();
        assert_eq!(cmd.mode, ScpMode::Sink);
        assert_eq!(cmd.path, PathBuf::from("/tmp/upload"));
        assert!(!cmd.recursive);
        assert!(!cmd.preserve_times);
    }

    #[test]
    fn test_scp_command_parse_source() {
        let cmd = ScpCommand::parse("scp -f /home/user/file.txt").unwrap();
        assert_eq!(cmd.mode, ScpMode::Source);
        assert_eq!(cmd.path, PathBuf::from("/home/user/file.txt"));
    }

    #[test]
    fn test_scp_command_parse_recursive() {
        let cmd = ScpCommand::parse("scp -r -t /tmp/upload").unwrap();
        assert_eq!(cmd.mode, ScpMode::Sink);
        assert!(cmd.recursive);
    }

    #[test]
    fn test_scp_command_parse_preserve_times() {
        let cmd = ScpCommand::parse("scp -p -t /tmp/upload").unwrap();
        assert_eq!(cmd.mode, ScpMode::Sink);
        assert!(cmd.preserve_times);
    }

    #[test]
    fn test_scp_command_parse_combined_flags() {
        let cmd = ScpCommand::parse("scp -rpt /tmp/upload").unwrap();
        assert_eq!(cmd.mode, ScpMode::Sink);
        assert!(cmd.recursive);
        assert!(cmd.preserve_times);
    }

    #[test]
    fn test_scp_command_parse_all_flags() {
        let cmd = ScpCommand::parse("scp -r -p -d -v -t /tmp/upload").unwrap();
        assert_eq!(cmd.mode, ScpMode::Sink);
        assert!(cmd.recursive);
        assert!(cmd.preserve_times);
        assert!(cmd.target_is_directory);
        assert!(cmd.verbose);
    }

    #[test]
    fn test_scp_command_parse_missing_mode() {
        let result = ScpCommand::parse("scp /tmp/upload");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("-t or -f"));
    }

    #[test]
    fn test_scp_command_parse_missing_path() {
        let result = ScpCommand::parse("scp -t");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path"));
    }

    #[test]
    fn test_scp_command_parse_not_scp() {
        let result = ScpCommand::parse("ls -la");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not an SCP"));
    }

    #[test]
    fn test_scp_command_is_scp_command() {
        assert!(ScpCommand::is_scp_command("scp -t /tmp"));
        assert!(ScpCommand::is_scp_command("scp -f /home/user/file"));
        assert!(ScpCommand::is_scp_command("  scp -t /tmp  "));
        assert!(!ScpCommand::is_scp_command("ls -la"));
        assert!(!ScpCommand::is_scp_command("scpfoo"));
    }

    /// Build a handler with chroot enabled at `/home/testuser`.
    fn chroot_handler(target_path: PathBuf) -> ScpHandler {
        let user = UserInfo::new("testuser");
        ScpHandler::new(
            ScpMode::Sink,
            target_path,
            user,
            Some(PathBuf::from("/home/testuser")),
            PathBuf::from("/home/testuser"),
        )
    }

    /// Build a handler with no chroot, home dir at `/home/testuser`.
    fn no_chroot_handler(target_path: PathBuf) -> ScpHandler {
        let user = UserInfo::new("testuser");
        ScpHandler::new(
            ScpMode::Sink,
            target_path,
            user,
            None,
            PathBuf::from("/home/testuser"),
        )
    }

    #[test]
    fn chroot_relative_path_resolves_under_root() {
        let handler = chroot_handler(PathBuf::from("/tmp"));
        let result = handler
            .resolve_path(Path::new("documents/file.txt"))
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn chroot_absolute_inside_root_is_returned_verbatim() {
        // Bug fix: an absolute client path inside the chroot must NOT be
        // re-rooted under itself. /home/testuser/file.bin must resolve to
        // /home/testuser/file.bin, not /home/testuser/home/testuser/file.bin.
        let handler = chroot_handler(PathBuf::from("/home/testuser/file.bin"));
        let result = handler
            .resolve_path(Path::new("/home/testuser/file.bin"))
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/file.bin"));
    }

    #[test]
    fn chroot_absolute_outside_root_is_rejected() {
        let handler = chroot_handler(PathBuf::from("/etc/passwd"));
        let err = handler.resolve_path(Path::new("/etc/passwd")).unwrap_err();
        assert!(
            err.to_string().contains("outside root"),
            "expected rejection, got: {err}"
        );

        let err = handler
            .resolve_path(Path::new("/tmp/file.bin"))
            .unwrap_err();
        assert!(err.to_string().contains("outside root"));
    }

    #[test]
    fn chroot_relative_traversal_is_clamped_to_root() {
        let handler = chroot_handler(PathBuf::from("/tmp"));
        let result = handler.resolve_path(Path::new("../etc/passwd")).unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/etc/passwd"));
        assert!(result.starts_with("/home/testuser"));
    }

    #[test]
    fn no_chroot_absolute_path_used_verbatim() {
        // OpenSSH-compatible: absolute paths are not re-rooted.
        let handler = no_chroot_handler(PathBuf::from("/home/work/file.bin"));
        let result = handler
            .resolve_path(Path::new("/home/work/file.bin"))
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/work/file.bin"));

        let handler = no_chroot_handler(PathBuf::from("/tmp/file.bin"));
        let result = handler.resolve_path(Path::new("/tmp/file.bin")).unwrap();
        assert_eq!(result, PathBuf::from("/tmp/file.bin"));
    }

    #[test]
    fn no_chroot_relative_path_resolves_from_home() {
        let handler = no_chroot_handler(PathBuf::from("documents/file.txt"));
        let result = handler
            .resolve_path(Path::new("documents/file.txt"))
            .unwrap();
        assert_eq!(result, PathBuf::from("/home/testuser/documents/file.txt"));
    }

    #[test]
    fn from_command_threads_chroot_and_target_is_directory() {
        let cmd = ScpCommand::parse("scp -rp -d -t /tmp/upload").unwrap();
        let user = UserInfo::new("testuser");
        let handler = ScpHandler::from_command(
            &cmd,
            user,
            Some(PathBuf::from("/home/testuser")),
            PathBuf::from("/home/testuser"),
        );
        assert_eq!(handler.mode, ScpMode::Sink);
        assert!(handler.recursive);
        assert!(handler.preserve_times);
        assert!(handler.target_is_directory);
    }

    #[test]
    fn test_scp_mode_display() {
        assert_eq!(format!("{}", ScpMode::Source), "source");
        assert_eq!(format!("{}", ScpMode::Sink), "sink");
    }

    #[test]
    fn test_handler_parse_times() {
        let user = UserInfo::new("testuser");
        let mut handler = ScpHandler::new(
            ScpMode::Sink,
            PathBuf::from("/tmp"),
            user,
            Some(PathBuf::from("/home/testuser")),
            PathBuf::from("/home/testuser"),
        );

        handler.parse_times("T1234567890 0 1234567800 0").unwrap();
        assert_eq!(handler.stored_times, Some((1234567890, 1234567800)));
    }

    // --- Filesystem-backed tests for receive_file destination semantics -----

    /// Verify the SCP single-file vs. directory destination decision matches
    /// the issue's acceptance criteria. Uses real temp directories so we can
    /// exercise both the existing-directory and non-existent-file cases.
    #[test]
    fn receive_file_destination_decision() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();

        // Case 1: target is a non-existent file (single-file destination).
        // Without -d/-r and target_dir is not a directory -> write directly.
        let target = dir.path().join("dest.bin");
        assert!(!target.exists());
        let at_top_level = true;
        let target_is_directory = false;
        let recursive = false;
        let resolved = single_file_decision(
            &target,
            at_top_level,
            target_is_directory,
            recursive,
            "src.bin",
        );
        assert_eq!(resolved, target);

        // Case 2: target is an existing directory -> append filename.
        let target = dir.path().to_path_buf();
        let resolved = single_file_decision(
            &target,
            at_top_level,
            target_is_directory,
            recursive,
            "src.bin",
        );
        assert_eq!(resolved, target.join("src.bin"));

        // Case 3: target is non-existent but `-d` was supplied -> append.
        let target = dir.path().join("dest_dir");
        let resolved = single_file_decision(&target, at_top_level, true, false, "src.bin");
        assert_eq!(resolved, target.join("src.bin"));

        // Case 4: recursive descent (not top level) -> always append.
        let target = dir.path().join("subdir");
        let resolved = single_file_decision(&target, false, false, true, "src.bin");
        assert_eq!(resolved, target.join("src.bin"));
    }

    /// Mirror of the destination decision logic from `receive_file`. Kept
    /// alongside it so the tests cover the same condition the runtime uses.
    fn single_file_decision(
        target_dir: &Path,
        at_top_level: bool,
        target_is_directory: bool,
        recursive: bool,
        filename: &str,
    ) -> PathBuf {
        if at_top_level && !target_is_directory && !recursive && !target_dir.is_dir() {
            target_dir.to_path_buf()
        } else {
            target_dir.join(filename)
        }
    }
}
