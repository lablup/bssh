//! OpenSSH-compatible `ProxyCommand` transport support.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::process::{ChildStderr, Command};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::Error;

const MAX_CAPTURED_STDERR: usize = 64 * 1024;

/// A proxy decision resolved from command-line, ssh_config, and YAML inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMode {
    /// An explicit `ProxyCommand none` or `ProxyJump none` disables fallback.
    Direct,
    /// Connect through an ssh_config `ProxyCommand` child process.
    Command(ProxyCommandConfig),
    /// Connect through one or more jump hosts.
    Jump(String),
}

/// The unexpanded `ProxyCommand` and the context needed by its percent tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCommandConfig {
    pub command: String,
    pub original_host: String,
    pub host_key_alias: Option<String>,
    pub use_fdpass: bool,
}

impl ProxyCommandConfig {
    #[must_use]
    pub fn new(command: impl Into<String>, original_host: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            original_host: original_host.into(),
            host_key_alias: None,
            use_fdpass: false,
        }
    }

    #[must_use]
    pub fn with_host_key_alias(mut self, alias: Option<String>) -> Self {
        self.host_key_alias = alias;
        self
    }

    #[must_use]
    pub fn with_fdpass(mut self, enabled: bool) -> Self {
        self.use_fdpass = enabled;
        self
    }

    pub fn expand(&self, host: &str, port: u16, remote_user: &str) -> Result<String, Error> {
        let key_alias = self
            .host_key_alias
            .as_deref()
            .unwrap_or(&self.original_host);
        let port = port.to_string();
        let mut expanded = String::with_capacity(self.command.len());
        let mut chars = self.command.chars();

        while let Some(ch) = chars.next() {
            if ch != '%' {
                expanded.push(ch);
                continue;
            }

            let Some(token) = chars.next() else {
                return Err(Error::InvalidProxyCommandToken {
                    command: self.command.clone(),
                    token: "%".to_string(),
                });
            };
            match token {
                '%' => expanded.push('%'),
                'h' => expanded.push_str(host),
                'k' => expanded.push_str(key_alias),
                'n' => expanded.push_str(&self.original_host),
                'p' => expanded.push_str(&port),
                'r' => expanded.push_str(remote_user),
                other => {
                    return Err(Error::InvalidProxyCommandToken {
                        command: self.command.clone(),
                        token: format!("%{other}"),
                    });
                }
            }
        }

        Ok(expanded)
    }
}

/// The split stdout/stdin pair presented to russh as one duplex stream.
pub(crate) struct ProxyCommandStream {
    stdout: tokio::process::ChildStdout,
    stdin: tokio::process::ChildStdin,
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct ProxyCompletion {
    status: Result<ExitStatus, String>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct ProxyProcessState {
    command: String,
    completion: Mutex<Option<ProxyCompletion>>,
    completed: Notify,
}

impl ProxyProcessState {
    fn record(&self, status: io::Result<ExitStatus>, stderr: Vec<u8>) {
        let completion = ProxyCompletion {
            status: status.map_err(|error| error.to_string()),
            stderr,
        };
        *self
            .completion
            .lock()
            .expect("proxy completion mutex poisoned") = Some(completion);
        self.completed.notify_waiters();
    }

    fn failure(&self) -> Option<ProxyFailure> {
        let completion = self
            .completion
            .lock()
            .expect("proxy completion mutex poisoned");
        let completion = completion.as_ref()?;
        let status = match &completion.status {
            Ok(status) if status.success() => return None,
            Ok(status) => status.to_string(),
            Err(error) => format!("could not read exit status: {error}"),
        };
        let stderr = String::from_utf8_lossy(&completion.stderr)
            .trim()
            .to_string();

        Some(ProxyFailure {
            command: self.command.clone(),
            status,
            stderr: if stderr.is_empty() {
                "no stderr output".to_string()
            } else {
                stderr
            },
        })
    }

    async fn wait_for_failure(&self, wait: Duration) -> Option<ProxyFailure> {
        if self
            .completion
            .lock()
            .expect("proxy completion mutex poisoned")
            .is_none()
        {
            let notified = self.completed.notified();
            if self
                .completion
                .lock()
                .expect("proxy completion mutex poisoned")
                .is_none()
            {
                let _ = tokio::time::timeout(wait, notified).await;
            }
        }
        self.failure()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyFailure {
    pub command: String,
    pub status: String,
    pub stderr: String,
}

/// Keeps the proxy child monitor alive for exactly as long as the SSH client.
pub(crate) struct ProxyCommandProcess {
    state: Arc<ProxyProcessState>,
    monitor: AbortHandle,
}

impl ProxyCommandProcess {
    pub(crate) async fn wait_for_failure(&self, wait: Duration) -> Option<ProxyFailure> {
        self.state.wait_for_failure(wait).await
    }

    pub(crate) fn terminate(&self) {
        self.monitor.abort();
    }
}

impl fmt::Debug for ProxyCommandProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCommandProcess")
            .field("command", &self.state.command)
            .finish_non_exhaustive()
    }
}

impl Drop for ProxyCommandProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(crate) struct ProxyCommandSession {
    pub stream: ProxyCommandStream,
    pub process: Arc<ProxyCommandProcess>,
}

/// Spawn a proxy via the user's shell, matching OpenSSH's `exec <command>` form.
pub(crate) fn spawn_proxy_command(
    config: &ProxyCommandConfig,
    host: &str,
    port: u16,
    remote_user: &str,
) -> Result<ProxyCommandSession, Error> {
    if config.use_fdpass {
        return Err(Error::ProxyUseFdpassUnsupported {
            command: config.command.clone(),
        });
    }

    let expanded = config.expand(host, port, remote_user)?;
    let mut command = shell_command(&expanded);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|source| Error::ProxyCommandSpawn {
        command: expanded.clone(),
        source,
    })?;
    let stdin = child.stdin.take().ok_or_else(|| Error::ProxyCommandSpawn {
        command: expanded.clone(),
        source: io::Error::other("proxy child stdin was not captured"),
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::ProxyCommandSpawn {
            command: expanded.clone(),
            source: io::Error::other("proxy child stdout was not captured"),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::ProxyCommandSpawn {
            command: expanded.clone(),
            source: io::Error::other("proxy child stderr was not captured"),
        })?;

    let state = Arc::new(ProxyProcessState {
        command: expanded,
        completion: Mutex::new(None),
        completed: Notify::new(),
    });
    let monitor_state = Arc::clone(&state);
    let monitor = tokio::spawn(async move {
        let stderr_task = tokio::spawn(drain_stderr(stderr));
        let status = child.wait().await;
        let stderr = stderr_task.await.unwrap_or_default();
        monitor_state.record(status, stderr);
    });
    let monitor = monitor.abort_handle();

    Ok(ProxyCommandSession {
        stream: ProxyCommandStream { stdout, stdin },
        process: Arc::new(ProxyCommandProcess { state, monitor }),
    })
}

async fn drain_stderr(mut stderr: ChildStderr) -> Vec<u8> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;

    while let Ok(read) = stderr.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURED_STDERR.saturating_sub(captured.len());
        if remaining > 0 {
            captured.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        truncated |= read > remaining;
    }

    if truncated {
        captured.extend_from_slice(b"\n[proxy stderr truncated]");
    }
    captured
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let shell = std::env::var_os("SHELL")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("/bin/sh"));
    let mut process = Command::new(shell);
    process.arg("-c").arg(format!("exec {command}"));
    process
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let shell = std::env::var_os("COMSPEC")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("cmd.exe"));
    let mut process = Command::new(shell);
    process.arg("/C").arg(command);
    process
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn expands_all_openssh_proxy_tokens() {
        let config = ProxyCommandConfig::new("echo %% %h %k %n %p %r", "original.example.com")
            .with_host_key_alias(Some("key-alias.example.com".to_string()));

        assert_eq!(
            config.expand("target.internal", 2200, "alice").unwrap(),
            "echo % target.internal key-alias.example.com original.example.com 2200 alice"
        );
    }

    #[test]
    fn rejects_unknown_proxy_tokens() {
        let config = ProxyCommandConfig::new("echo %x", "target");
        let error = config.expand("target", 22, "alice").unwrap_err();
        assert!(matches!(error, Error::InvalidProxyCommandToken { .. }));
        assert!(error.to_string().contains("%x"));
    }

    #[tokio::test]
    async fn shell_pipeline_is_preserved() {
        let config = ProxyCommandConfig::new("printf PROXY | tr A-Z a-z", "target");
        let mut session = spawn_proxy_command(&config, "target", 22, "alice").unwrap();
        let mut output = String::new();
        session.stream.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "proxy");
        assert!(
            session
                .process
                .wait_for_failure(Duration::from_secs(1))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn failure_captures_exit_status_and_stderr() {
        let config =
            ProxyCommandConfig::new("sh -c 'printf proxy\\ exploded >&2; exit 42'", "target");
        let session = spawn_proxy_command(&config, "target", 22, "alice").unwrap();
        let failure = session
            .process
            .wait_for_failure(Duration::from_secs(1))
            .await
            .expect("proxy must fail");
        assert!(failure.status.contains("42"));
        assert_eq!(failure.stderr, "proxy exploded");
        assert!(failure.command.contains("exit 42"));
    }

    #[test]
    fn fdpass_is_rejected_before_spawn() {
        let config = ProxyCommandConfig::new("echo unused", "target").with_fdpass(true);
        let error = match spawn_proxy_command(&config, "target", 22, "alice") {
            Ok(_) => panic!("ProxyUseFdpass must be rejected before spawn"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::ProxyUseFdpassUnsupported { .. }));
    }
}
