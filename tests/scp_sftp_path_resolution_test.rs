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

//! Integration tests for the SCP/SFTP path-resolution and chroot-mode fixes
//! introduced for issue #186.
//!
//! These tests validate the public API of `ScpHandler` and `SftpHandler`
//! against the acceptance criteria in the issue:
//!
//! - Without chroot, absolute client paths are honored verbatim and relative
//!   paths resolve from the user's home directory (OpenSSH-compatible).
//! - With chroot, absolute client paths inside the chroot are honored
//!   verbatim (no path doubling); paths outside are rejected.
//! - Path-traversal and symlink-escape protections continue to hold under
//!   the new logic.
//!
//! End-to-end tests with a running `bssh-server` and a real `scp` or
//! `bssh upload` client are out of scope for this file (they require host
//! key generation and process spawning), but the path-resolution layer
//! covered here is the one the issue identifies as defective. Bug-fix
//! coverage starts here and is supplemented by the unit tests inside the
//! `scp` and `sftp` modules.

use std::path::{Path, PathBuf};

use bssh::server::scp::{ScpHandler, ScpMode};
use bssh::server::sftp::SftpHandler;
use bssh::shared::auth_types::UserInfo;
use tempfile::tempdir;

fn user() -> UserInfo {
    UserInfo::new("work")
}

// ---------------------------------------------------------------------------
// SCP path resolution
// ---------------------------------------------------------------------------

#[test]
fn scp_no_chroot_accepts_absolute_client_path() {
    // Reproduction of the Backend.AI bug: client sends `/home/work/file.bin`
    // and the server must write to exactly `/home/work/file.bin`. Previously
    // the path got doubled to `/home/work/home/work/file.bin`.
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("/home/work/file.bin"),
        user(),
        None, // no chroot — the recommended default after this fix.
        PathBuf::from("/home/work"),
    );
    let resolved = handler
        .resolve_path(Path::new("/home/work/file.bin"))
        .expect("absolute path inside home dir should resolve");
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn scp_no_chroot_accepts_path_outside_home() {
    // Without chroot, `/tmp/foo` is just `/tmp/foo`. Filesystem permissions
    // are the only access boundary, matching OpenSSH `scp`.
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("/tmp/foo.bin"),
        user(),
        None,
        PathBuf::from("/home/work"),
    );
    let resolved = handler
        .resolve_path(Path::new("/tmp/foo.bin"))
        .expect("absolute path should resolve");
    assert_eq!(resolved, PathBuf::from("/tmp/foo.bin"));
}

#[test]
fn scp_no_chroot_relative_path_lands_in_home() {
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("file.bin"),
        user(),
        None,
        PathBuf::from("/home/work"),
    );
    let resolved = handler
        .resolve_path(Path::new("file.bin"))
        .expect("relative path should resolve");
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn scp_chroot_inside_root_no_doubling() {
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("/home/work/file.bin"),
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let resolved = handler
        .resolve_path(Path::new("/home/work/file.bin"))
        .expect("absolute inside chroot should resolve verbatim");
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn scp_chroot_rejects_paths_outside_root() {
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("/etc/passwd"),
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let err = handler
        .resolve_path(Path::new("/etc/passwd"))
        .expect_err("absolute outside chroot must be rejected");
    assert!(
        err.to_string().contains("outside root"),
        "expected access-denied error, got: {err}"
    );
}

#[test]
fn scp_chroot_relative_traversal_clamped() {
    let handler = ScpHandler::new(
        ScpMode::Sink,
        PathBuf::from("../etc/passwd"),
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    // The traversal-protection invariant: `..` cannot escape the chroot.
    let resolved = handler
        .resolve_path(Path::new("../etc/passwd"))
        .expect("relative traversal should be clamped, not rejected");
    assert!(resolved.starts_with("/home/work"));
    assert_eq!(resolved, PathBuf::from("/home/work/etc/passwd"));
}

// ---------------------------------------------------------------------------
// SFTP path resolution
// ---------------------------------------------------------------------------

#[test]
fn sftp_no_chroot_accepts_absolute_client_path() {
    // Reproduction of the SFTP variant of the Backend.AI bug: `bssh upload`
    // sending an absolute path to `bssh-server` previously failed with
    // "No such file" because of path doubling.
    let handler = SftpHandler::new(user(), None, PathBuf::from("/home/work"));
    let resolved = handler
        .resolve_path("/home/work/file.bin")
        .expect("absolute path inside home dir should resolve");
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn sftp_no_chroot_accepts_path_outside_home() {
    let handler = SftpHandler::new(user(), None, PathBuf::from("/home/work"));
    let resolved = handler
        .resolve_path("/tmp/foo.bin")
        .expect("absolute path should resolve");
    assert_eq!(resolved, PathBuf::from("/tmp/foo.bin"));
}

#[test]
fn sftp_no_chroot_relative_path_lands_in_home() {
    let handler = SftpHandler::new(user(), None, PathBuf::from("/home/work"));
    let resolved = handler.resolve_path("file.bin").unwrap();
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn sftp_chroot_inside_root_no_doubling() {
    let handler = SftpHandler::new(
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let resolved = handler.resolve_path("/home/work/file.bin").unwrap();
    assert_eq!(resolved, PathBuf::from("/home/work/file.bin"));
}

#[test]
fn sftp_chroot_rejects_paths_outside_root() {
    let handler = SftpHandler::new(
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let err = handler
        .resolve_path("/etc/passwd")
        .expect_err("absolute outside chroot must be rejected");
    // The exact code is PermissionDenied; we verify by checking the message.
    assert!(
        err.to_string().contains("outside root"),
        "expected permission-denied, got: {err}"
    );
}

#[test]
fn sftp_chroot_relative_traversal_clamped() {
    let handler = SftpHandler::new(
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let resolved = handler.resolve_path("../../etc/passwd").unwrap();
    assert!(resolved.starts_with("/home/work"));
    assert_eq!(resolved, PathBuf::from("/home/work/etc/passwd"));
}

#[test]
fn sftp_chroot_root_path_returns_chroot() {
    // The realpath roundtrip: `realpath(".")` returns "/" to the client, and
    // a subsequent client request for "/" must resolve back to the chroot
    // directory, not get rejected as "outside root".
    let handler = SftpHandler::new(
        user(),
        Some(PathBuf::from("/home/work")),
        PathBuf::from("/home/work"),
    );
    let resolved = handler.resolve_path("/").unwrap();
    assert_eq!(resolved, PathBuf::from("/home/work"));
}

// ---------------------------------------------------------------------------
// Symlink-escape protection
// ---------------------------------------------------------------------------

/// Create a symlink pointing outside the chroot and ensure the SCP resolver
/// blocks it via canonicalization.
#[test]
#[cfg(unix)]
fn scp_chroot_blocks_symlink_escape() {
    let dir = tempdir().expect("tempdir");
    let chroot = dir.path().join("chroot");
    std::fs::create_dir(&chroot).unwrap();

    // Create a target file outside the chroot and a symlink inside that
    // points at it. Resolving the symlink path must canonicalize and reject.
    let outside_target = dir.path().join("outside.txt");
    std::fs::write(&outside_target, b"secret").unwrap();
    let escape_link = chroot.join("escape");
    std::os::unix::fs::symlink(&outside_target, &escape_link).unwrap();

    let handler = ScpHandler::new(
        ScpMode::Source,
        escape_link.clone(),
        user(),
        Some(chroot.clone()),
        chroot.clone(),
    );
    let err = handler
        .resolve_path(&escape_link)
        .expect_err("symlink escape must be blocked");
    assert!(
        err.to_string().contains("symlink target outside root"),
        "expected symlink-escape error, got: {err}"
    );
}

/// Verify that the SCP resolver still rejects a symlink-escape attempt when
/// the user supplies a path *inside* the chroot but the resolved canonical
/// path lands outside, even if the symlink is reached through a relative
/// client path.
#[test]
#[cfg(unix)]
fn scp_chroot_blocks_relative_symlink_escape() {
    let dir = tempdir().unwrap();
    let chroot = dir.path().join("chroot");
    std::fs::create_dir(&chroot).unwrap();

    let outside_target = dir.path().join("outside.txt");
    std::fs::write(&outside_target, b"secret").unwrap();
    std::os::unix::fs::symlink(&outside_target, chroot.join("link")).unwrap();

    let handler = ScpHandler::new(
        ScpMode::Source,
        PathBuf::from("link"),
        user(),
        Some(chroot.clone()),
        chroot.clone(),
    );
    let err = handler
        .resolve_path(Path::new("link"))
        .expect_err("relative symlink escape must be blocked");
    assert!(err.to_string().contains("symlink target outside root"));
}
