// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Safe background-process supervision for SSH-compatible invocations.
//!
//! Tokio and russh may own worker threads by the time authentication finishes,
//! so calling `fork(2)` at that point would leave the child with an invalid
//! snapshot of their synchronization state. The foreground process instead
//! resolves enough configuration to decide whether detachment is needed, then
//! re-executes bssh before creating the SSH transport. The worker authenticates;
//! the supervisor either waits for its exit or becomes the foreground passenger
//! of a persistent control master.

use std::path::PathBuf;

#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::{ExitStatus, Stdio};

use anyhow::{Context, Result};
use bssh::ssh::{SessionPolicy, control::SessionOpenRequest};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use bssh::ssh::control::{AttachOutcome, attach_session, verify_same_user};
#[cfg(unix)]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

const WORKER_SOCKET_ENV: &str = "BSSH_INTERNAL_BACKGROUND_SOCKET";
const WORKER_PARENT_ENV: &str = "BSSH_INTERNAL_BACKGROUND_PARENT";
#[cfg(unix)]
const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// A lifecycle transition sent by the authenticated worker to its supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BackgroundEvent {
    /// `-f`: authentication and forwarding setup completed successfully.
    Detached { exit_code: i32 },
    /// A ControlPersist master is ready; the supervisor owns the initial
    /// foreground session while the worker keeps the authenticated transport.
    PersistentMaster {
        control_path: PathBuf,
        session_request: Box<SessionOpenRequest>,
        invoking_policy: SessionPolicy,
    },
}

/// Worker-side notification channel, present only in the re-executed process.
#[derive(Debug, Clone)]
pub struct BackgroundWorker {
    socket_path: PathBuf,
}

impl BackgroundWorker {
    /// Discover a worker launched by this process's direct parent.
    ///
    /// Checking the recorded parent PID prevents LocalCommand, ProxyCommand,
    /// and other descendants from accidentally inheriting the internal role.
    pub fn from_environment() -> Result<Option<Self>> {
        let Some(socket_path) = std::env::var_os(WORKER_SOCKET_ENV) else {
            return Ok(None);
        };
        let recorded_parent = std::env::var(WORKER_PARENT_ENV)
            .context("Background worker is missing its parent PID")?
            .parse::<u32>()
            .context("Background worker parent PID is invalid")?;
        if recorded_parent != parent_process_id() {
            return Ok(None);
        }
        Ok(Some(Self {
            socket_path: PathBuf::from(socket_path),
        }))
    }

    /// Detach the authenticated worker and report readiness to the supervisor.
    #[cfg(unix)]
    pub async fn detach(&self, event: &BackgroundEvent) -> Result<()> {
        // Connect before detaching so setup errors remain visible on the
        // foreground terminal and an absent supervisor is never mistaken for
        // successful backgrounding.
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "Could not connect to background supervisor '{}'",
                    self.socket_path.display()
                )
            })?;
        detach_process()?;
        write_event(&mut stream, event).await?;
        stream.shutdown().await?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub async fn detach(&self, _event: &BackgroundEvent) -> Result<()> {
        let _ = &self.socket_path;
        anyhow::bail!("background-after-authentication currently requires Unix")
    }
}

/// Re-execute a single-destination SSH invocation and proxy its lifecycle.
#[cfg(unix)]
pub async fn supervise(args: &[String]) -> Result<i32> {
    let socket_dir = create_socket_directory()?;
    let socket_path = socket_dir.join("ready.sock");
    let listener = UnixListener::bind(&socket_path).with_context(|| {
        format!(
            "Could not bind background supervisor socket '{}'",
            socket_path.display()
        )
    })?;
    set_owner_only(&socket_path, 0o600)?;
    let _cleanup = SocketDirectoryGuard {
        socket_path: socket_path.clone(),
        directory: socket_dir,
    };

    let executable = std::env::current_exe().context("Could not locate the bssh executable")?;
    let mut command = tokio::process::Command::new(executable);
    command
        .args(args.iter().skip(1))
        .env(WORKER_SOCKET_ENV, &socket_path)
        .env(WORKER_PARENT_ENV, std::process::id().to_string())
        // The worker remains the foreground SSH client for ordinary calls, so
        // piped input must survive the re-exec. `-f` replaces this descriptor
        // with /dev/null only after authentication has completed.
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(false);
    let mut child = command
        .spawn()
        .context("Could not start background worker")?;

    tokio::select! {
        status = child.wait() => exit_status_code(status.context("Could not wait for bssh worker")?),
        accepted = listener.accept() => {
            let (mut stream, _) = accepted.context("Could not accept background worker readiness")?;
            verify_same_user(&stream).context("Rejected background worker owned by another user")?;
            let event = read_event(&mut stream).await?;
            match event {
                BackgroundEvent::Detached { exit_code } => Ok(exit_code),
                BackgroundEvent::PersistentMaster {
                    control_path,
                    session_request,
                    invoking_policy,
                } => match attach_session(&control_path, *session_request, &invoking_policy).await? {
                    AttachOutcome::ExitStatus(status) => Ok(i32::try_from(status).unwrap_or(255)),
                    AttachOutcome::NoMaster => anyhow::bail!(
                        "Persistent control master disappeared before the initial session attached"
                    ),
                },
            }
        }
    }
}

#[cfg(not(unix))]
pub async fn supervise(_args: &[String]) -> Result<i32> {
    anyhow::bail!("background-after-authentication currently requires Unix")
}

#[cfg(unix)]
async fn write_event(stream: &mut UnixStream, event: &BackgroundEvent) -> Result<()> {
    let payload = serde_json::to_vec(event).context("Could not encode background event")?;
    anyhow::ensure!(
        payload.len() <= MAX_EVENT_BYTES,
        "Background event exceeds {MAX_EVENT_BYTES} bytes"
    );
    let length = u32::try_from(payload.len()).context("Background event length overflow")?;
    stream.write_u32(length).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

#[cfg(unix)]
async fn read_event(stream: &mut UnixStream) -> Result<BackgroundEvent> {
    let length = usize::try_from(stream.read_u32().await?)
        .context("Background event length is not representable")?;
    anyhow::ensure!(
        length <= MAX_EVENT_BYTES,
        "Background event exceeds {MAX_EVENT_BYTES} bytes"
    );
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).context("Could not decode background event")
}

#[cfg(unix)]
fn create_socket_directory() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;

    let directory = std::env::temp_dir().join(format!(
        "bssh-background-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&directory)
        .with_context(|| format!("Could not create '{}'", directory.display()))?;
    Ok(directory)
}

#[cfg(unix)]
fn set_owner_only(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("Could not restrict permissions on '{}'", path.display()))
}

#[cfg(unix)]
fn detach_process() -> Result<()> {
    use std::os::fd::AsRawFd as _;

    nix::unistd::setsid().context("Could not create background process session")?;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .context("Could not open /dev/null for background process")?;
    for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `null` remains open for the entire loop, and each target is a
        // conventional process-owned standard descriptor. `dup2` atomically
        // replaces only that descriptor and does not copy Tokio/russh memory.
        if unsafe { libc::dup2(null.as_raw_fd(), descriptor) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("Could not redirect background process standard I/O");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn exit_status_code(status: ExitStatus) -> Result<i32> {
    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;

        if let Some(signal) = status.signal() {
            return Ok(128 + signal);
        }
    }
    anyhow::bail!("bssh worker terminated without an exit status")
}

#[cfg(unix)]
fn parent_process_id() -> u32 {
    u32::try_from(nix::unistd::getppid().as_raw()).unwrap_or_default()
}

#[cfg(not(unix))]
fn parent_process_id() -> u32 {
    0
}

#[cfg(unix)]
struct SocketDirectoryGuard {
    socket_path: PathBuf,
    directory: PathBuf,
}

#[cfg(unix)]
impl Drop for SocketDirectoryGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.socket_path.display(), "Could not remove supervisor socket: {error}");
        }
        if let Err(error) = std::fs::remove_dir(&self.directory)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.directory.display(), "Could not remove supervisor directory: {error}");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use bssh::ssh::SessionRequest;

    #[tokio::test]
    async fn event_frame_round_trips_and_preserves_session_policy() {
        let (mut writer, mut reader) = UnixStream::pair().expect("unix stream pair");
        let event = BackgroundEvent::PersistentMaster {
            control_path: PathBuf::from("/tmp/control-test"),
            session_request: Box::new(
                SessionOpenRequest::new(
                    SessionPolicy {
                        environment: vec![("LANG".into(), "C".into())],
                        local_command: None,
                        forward_agent: false,
                        request_pty: false,
                        stdin_null: true,
                        request: SessionRequest::Exec("true".into()),
                    },
                    None,
                )
                .expect("valid session request"),
            ),
            invoking_policy: SessionPolicy {
                environment: Vec::new(),
                local_command: Some("true".into()),
                forward_agent: false,
                request_pty: false,
                stdin_null: false,
                request: SessionRequest::Exec("true".into()),
            },
        };
        let expected = event.clone();
        let write = tokio::spawn(async move { write_event(&mut writer, &event).await });
        assert_eq!(read_event(&mut reader).await.unwrap(), expected);
        write.await.unwrap().unwrap();
    }
}
