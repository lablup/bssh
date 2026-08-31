// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Live bssh control-master runtime.

#[cfg(unix)]
mod unix {
    use std::io::{self, BufRead as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{Mutex, Semaphore, mpsc, watch};
    use tokio::task::{JoinHandle, JoinSet};

    use crate::forwarding::ForwardingPlan;
    use crate::ssh::tokio_client::{Client, CommandOutput};

    use super::super::{
        CONTROL_PROTOCOL_VERSION, ControlCommand, ControlData, ControlDataStream, ControlMessage,
        ControlOperation, ControlPersist, ControlRequest, ControlResponse, ControlResponseKind,
        MAX_CONTROL_DATA_BYTES, SessionOpenRequest, bind_control_socket, connect_control_socket,
        read_control_message, verify_same_user, write_control_message,
    };

    const HELLO_REQUEST_ID: u64 = 0;
    const OPERATION_REQUEST_ID: u64 = 1;
    const SESSION_PIPE_CAPACITY: usize = 256 * 1024;
    const CONTROL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
    const CONTROL_CONFIRM_TIMEOUT_MILLIS: libc::c_int = 30_000;
    const MAX_CONTROL_CLIENTS: usize = 128;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AttachOutcome {
        NoMaster,
        ExitStatus(u32),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MasterSignal {
        Exit,
        Stop,
    }

    pub struct RunningControlMaster {
        signal: mpsc::Sender<MasterSignal>,
        active_sessions: watch::Receiver<usize>,
        task: JoinHandle<Result<()>>,
    }

    impl RunningControlMaster {
        pub async fn shutdown_immediately(self) -> Result<()> {
            let _ = self.signal.send(MasterSignal::Exit).await;
            join_master(self.task).await
        }

        /// Apply ControlPersist after the initial invocation finishes.
        pub async fn finish_after_initial(
            mut self,
            persist: ControlPersist,
            initial_request_was_none: bool,
        ) -> Result<()> {
            if matches!(persist, ControlPersist::Disabled) && !initial_request_was_none {
                let _ = self.signal.send(MasterSignal::Stop).await;
                return join_master(self.task).await;
            }
            let Some(timeout) = persist.timeout() else {
                return join_master(self.task).await;
            };
            loop {
                if *self.active_sessions.borrow() != 0 {
                    tokio::select! {
                        result = &mut self.task => return flatten_master_join(result),
                        changed = self.active_sessions.changed() => {
                            if changed.is_err() {
                                return join_master(self.task).await;
                            }
                        }
                    }
                    continue;
                }
                let idle = tokio::time::sleep(timeout);
                tokio::pin!(idle);
                tokio::select! {
                    result = &mut self.task => return flatten_master_join(result),
                    changed = self.active_sessions.changed() => {
                        if changed.is_err() {
                            return join_master(self.task).await;
                        }
                    }
                    () = &mut idle => {
                        let _ = self.signal.send(MasterSignal::Stop).await;
                        return join_master(self.task).await;
                    }
                }
            }
        }
    }

    async fn join_master(task: JoinHandle<Result<()>>) -> Result<()> {
        flatten_master_join(task.await)
    }

    fn flatten_master_join(result: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
        result.context("Control master task failed to join")?
    }

    pub fn start_control_master(
        path: &Path,
        client: Client,
        require_confirmation: bool,
    ) -> Result<RunningControlMaster> {
        let (listener, guard) = bind_control_socket(path)?;
        let (signal_tx, signal_rx) = mpsc::channel(8);
        let (active_tx, active_rx) = watch::channel(0usize);
        let task_signal = signal_tx.clone();
        let task = tokio::spawn(async move {
            serve_control_master(
                listener,
                guard,
                client,
                require_confirmation,
                signal_rx,
                task_signal,
                active_tx,
            )
            .await
        });
        Ok(RunningControlMaster {
            signal: signal_tx,
            active_sessions: active_rx,
            task,
        })
    }

    pub async fn attach_session(
        path: &Path,
        session: SessionOpenRequest,
        invoking_policy: &crate::ssh::SessionPolicy,
    ) -> Result<AttachOutcome> {
        let mut stream = match tokio::time::timeout(
            CONTROL_HANDSHAKE_TIMEOUT,
            connect_control_socket(path),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Err(_) => {
                tracing::debug!(path = %path.display(), "Control master connect timed out; falling back");
                return Ok(AttachOutcome::NoMaster);
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(AttachOutcome::NoMaster);
            }
            Ok(Err(error)) => {
                return Err(error).with_context(|| {
                    format!("Could not connect to control master '{}'", path.display())
                });
            }
        };
        match tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, perform_hello(&mut stream)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(path = %path.display(), "Control master handshake failed; falling back: {error:#}");
                return Ok(AttachOutcome::NoMaster);
            }
            Err(_) => {
                tracing::debug!(path = %path.display(), "Control master handshake timed out; falling back");
                return Ok(AttachOutcome::NoMaster);
            }
        }
        invoking_policy.run_local_command().await?;
        run_attached_session(stream, session)
            .await
            .map(AttachOutcome::ExitStatus)
    }

    pub async fn send_control_command(
        path: &Path,
        command: ControlCommand,
        forwards: Vec<crate::forwarding::ForwardingDirective>,
        address_family: crate::ssh::tokio_client::AddressFamily,
    ) -> Result<ControlResponseKind> {
        let mut stream =
            tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, connect_control_socket(path))
                .await
                .context("Timed out connecting to control master")?
                .with_context(|| format!("No control master is running at '{}'", path.display()))?;
        tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, perform_hello(&mut stream))
            .await
            .context("Timed out negotiating with control master")??;
        write_control_message(
            &mut stream,
            &ControlMessage::Request(ControlRequest {
                request_id: OPERATION_REQUEST_ID,
                operation: ControlOperation::Command {
                    command,
                    forwards,
                    address_family,
                },
            }),
        )
        .await?;
        let response = read_response(&mut stream, OPERATION_REQUEST_ID).await?;
        match response {
            ControlResponseKind::Error { code, message } => {
                anyhow::bail!("control command failed ({code}): {message}")
            }
            response => Ok(response),
        }
    }

    async fn run_attached_session(
        mut stream: UnixStream,
        session: SessionOpenRequest,
    ) -> Result<u32> {
        write_control_message(
            &mut stream,
            &ControlMessage::Request(ControlRequest {
                request_id: OPERATION_REQUEST_ID,
                operation: ControlOperation::OpenSession(session.clone()),
            }),
        )
        .await?;
        let opened = read_response(&mut stream, OPERATION_REQUEST_ID).await?;
        let session_id = match opened {
            ControlResponseKind::SessionOpened { session_id } => session_id,
            ControlResponseKind::Error { code, message } => {
                anyhow::bail!("control master rejected session ({code}): {message}")
            }
            response => {
                anyhow::bail!("unexpected control response while opening session: {response:?}")
            }
        };
        let (mut reader, mut writer) = stream.into_split();
        let stdin_null = session.policy.stdin_null;
        let input = tokio::spawn(async move {
            let mut sequence = 0u64;
            if !stdin_null {
                let mut stdin = tokio::io::stdin();
                let mut buffer = vec![0u8; MAX_CONTROL_DATA_BYTES];
                loop {
                    let count = stdin.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    write_control_message(
                        &mut writer,
                        &ControlMessage::Data(ControlData {
                            session_id,
                            stream: ControlDataStream::Stdin,
                            sequence,
                            payload: buffer[..count].to_vec(),
                            eof: false,
                        }),
                    )
                    .await
                    .map_err(io::Error::other)?;
                    sequence = sequence.saturating_add(1);
                }
            }
            write_control_message(
                &mut writer,
                &ControlMessage::Data(ControlData {
                    session_id,
                    stream: ControlDataStream::Stdin,
                    sequence,
                    payload: Vec::new(),
                    eof: true,
                }),
            )
            .await
            .map_err(io::Error::other)
        });

        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let mut stdout_open = true;
        let mut stderr_open = true;
        let status = loop {
            match read_control_message(&mut reader).await? {
                ControlMessage::Data(data) if data.session_id == session_id => match data.stream {
                    ControlDataStream::Stdout if stdout_open => {
                        if stdout.write_all(&data.payload).await.is_err() {
                            stdout_open = false;
                        } else {
                            stdout.flush().await.ok();
                        }
                    }
                    ControlDataStream::Stderr if stderr_open => {
                        if stderr.write_all(&data.payload).await.is_err() {
                            stderr_open = false;
                        } else {
                            stderr.flush().await.ok();
                        }
                    }
                    _ => {}
                },
                ControlMessage::Response(ControlResponse {
                    request_id: OPERATION_REQUEST_ID,
                    kind:
                        ControlResponseKind::ExitStatus {
                            session_id: response_session,
                            status,
                        },
                }) if response_session == session_id => break status,
                ControlMessage::Response(ControlResponse {
                    request_id: OPERATION_REQUEST_ID,
                    kind: ControlResponseKind::Error { code, message },
                }) => anyhow::bail!("control session failed ({code}): {message}"),
                message => anyhow::bail!("unexpected control session message: {message:?}"),
            }
        };
        input.abort();
        let _ = input.await;
        Ok(status)
    }

    async fn perform_hello(stream: &mut UnixStream) -> Result<()> {
        write_control_message(
            stream,
            &ControlMessage::Request(ControlRequest {
                request_id: HELLO_REQUEST_ID,
                operation: ControlOperation::Hello {
                    version: CONTROL_PROTOCOL_VERSION,
                },
            }),
        )
        .await?;
        match read_response(stream, HELLO_REQUEST_ID).await? {
            ControlResponseKind::Ok => Ok(()),
            ControlResponseKind::Error { code, message } => {
                anyhow::bail!("control protocol handshake failed ({code}): {message}")
            }
            response => anyhow::bail!("unexpected control handshake response: {response:?}"),
        }
    }

    async fn read_response(
        stream: &mut UnixStream,
        request_id: u64,
    ) -> Result<ControlResponseKind> {
        match read_control_message(stream).await? {
            ControlMessage::Response(response) if response.request_id == request_id => {
                Ok(response.kind)
            }
            message => anyhow::bail!("unexpected control response: {message:?}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_control_master(
        listener: UnixListener,
        guard: super::super::ControlSocketGuard,
        client: Client,
        require_confirmation: bool,
        mut signal_rx: mpsc::Receiver<MasterSignal>,
        signal_tx: mpsc::Sender<MasterSignal>,
        active_tx: watch::Sender<usize>,
    ) -> Result<()> {
        let next_session = Arc::new(AtomicU64::new(1));
        let active = Arc::new(AtomicUsize::new(0));
        let confirmation = Arc::new(Mutex::new(()));
        let handler_slots = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
        let mut handlers = JoinSet::new();
        let immediate = loop {
            tokio::select! {
                signal = signal_rx.recv() => match signal {
                    Some(MasterSignal::Exit) => break true,
                    Some(MasterSignal::Stop) | None => break false,
                },
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("Control socket accept failed")?;
                    if let Err(error) = verify_same_user(&stream) {
                        tracing::warn!("Rejected control client: {error}");
                        continue;
                    }
                    let Ok(handler_slot) = Arc::clone(&handler_slots).try_acquire_owned() else {
                        tracing::warn!("Rejected control client: {MAX_CONTROL_CLIENTS} handlers are already active");
                        continue;
                    };
                    let handler_client = client.clone();
                    let handler_signal = signal_tx.clone();
                    let handler_active = Arc::clone(&active);
                    let handler_active_tx = active_tx.clone();
                    let handler_next_session = Arc::clone(&next_session);
                    let handler_confirmation = Arc::clone(&confirmation);
                    handlers.spawn(async move {
                        let _handler_slot = handler_slot;
                        if let Err(error) = handle_control_connection(
                            stream,
                            handler_client,
                            require_confirmation,
                            handler_confirmation,
                            handler_signal,
                            handler_active,
                            handler_active_tx,
                            handler_next_session,
                        )
                        .await
                        {
                            tracing::debug!("Control client disconnected with error: {error:#}");
                        }
                    });
                }
                Some(joined) = handlers.join_next(), if !handlers.is_empty() => {
                    if let Err(error) = joined {
                        tracing::warn!("Control client task failed to join: {error}");
                    }
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    if client.is_closed() {
                        break true;
                    }
                }
            }
        };
        drop(listener);
        drop(guard);
        if immediate {
            handlers.abort_all();
        }
        while let Some(result) = handlers.join_next().await {
            if !immediate && let Err(error) = result {
                tracing::warn!("Control client task failed while draining: {error}");
            }
        }
        client
            .disconnect()
            .await
            .context("Could not disconnect control-master SSH transport")
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_control_connection(
        mut stream: UnixStream,
        client: Client,
        require_confirmation: bool,
        confirmation: Arc<Mutex<()>>,
        signal: mpsc::Sender<MasterSignal>,
        active: Arc<AtomicUsize>,
        active_tx: watch::Sender<usize>,
        next_session: Arc<AtomicU64>,
    ) -> Result<()> {
        let hello = read_initial_control_message(&mut stream, "hello").await?;
        let request_id = match hello {
            ControlMessage::Request(ControlRequest {
                request_id,
                operation: ControlOperation::Hello { version },
            }) if version == CONTROL_PROTOCOL_VERSION => request_id,
            message => anyhow::bail!("expected protocol hello, received {message:?}"),
        };
        send_response(&mut stream, request_id, ControlResponseKind::Ok).await?;
        let request = match read_initial_control_message(&mut stream, "request").await? {
            ControlMessage::Request(request) => request,
            message => anyhow::bail!("expected control request, received {message:?}"),
        };
        match request.operation {
            ControlOperation::Hello { .. } => {
                send_error(
                    &mut stream,
                    request.request_id,
                    "duplicate_hello",
                    "hello was already completed",
                )
                .await
            }
            ControlOperation::OpenSession(session) => {
                if require_confirmation {
                    let approved = confirm_attach(Arc::clone(&confirmation)).await?;
                    if !approved {
                        return send_error(
                            &mut stream,
                            request.request_id,
                            "permission_denied",
                            "control master did not approve the shared session",
                        )
                        .await;
                    }
                }
                handle_remote_session(
                    stream,
                    request.request_id,
                    session,
                    client,
                    active,
                    active_tx,
                    next_session.fetch_add(1, Ordering::Relaxed),
                )
                .await
            }
            ControlOperation::Command {
                command,
                forwards,
                address_family,
            } => {
                let plan = ForwardingPlan {
                    directives: forwards,
                    clear_all: false,
                    exit_on_failure: true,
                    address_family,
                };
                let result = match command {
                    ControlCommand::Check => {
                        return send_response(
                            &mut stream,
                            request.request_id,
                            ControlResponseKind::Alive {
                                pid: std::process::id(),
                            },
                        )
                        .await;
                    }
                    ControlCommand::Forward => client.add_control_forwardings(&plan).await,
                    ControlCommand::Cancel => client.cancel_control_forwardings(&plan).await,
                    ControlCommand::Exit | ControlCommand::Stop => Ok(()),
                };
                if let Err(error) = result {
                    return send_error(
                        &mut stream,
                        request.request_id,
                        "forwarding_failed",
                        &error.to_string(),
                    )
                    .await;
                }
                send_response(&mut stream, request.request_id, ControlResponseKind::Ok).await?;
                match command {
                    ControlCommand::Exit => {
                        let _ = signal.send(MasterSignal::Exit).await;
                    }
                    ControlCommand::Stop => {
                        let _ = signal.send(MasterSignal::Stop).await;
                    }
                    _ => {}
                }
                Ok(())
            }
        }
    }

    async fn read_initial_control_message(
        stream: &mut UnixStream,
        phase: &str,
    ) -> Result<ControlMessage> {
        tokio::time::timeout(CONTROL_HANDSHAKE_TIMEOUT, read_control_message(stream))
            .await
            .with_context(|| format!("Control client timed out during {phase}"))?
            .map_err(anyhow::Error::from)
    }

    async fn confirm_attach(lock: Arc<Mutex<()>>) -> Result<bool> {
        let _guard = lock.lock().await;
        tokio::task::spawn_blocking(|| -> Result<bool> {
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .context("ControlMaster ask mode requires /dev/tty")?;
            let mut writer = tty.try_clone().context("Could not clone /dev/tty")?;
            writer.write_all(b"Allow shared SSH session? [y/N] ")?;
            writer.flush()?;
            let mut descriptor = libc::pollfd {
                fd: tty.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `descriptor` points to one initialized pollfd whose file
            // descriptor remains owned by `tty` for the duration of this call.
            let ready = unsafe {
                libc::poll(
                    std::ptr::from_mut(&mut descriptor),
                    1,
                    CONTROL_CONFIRM_TIMEOUT_MILLIS,
                )
            };
            if ready < 0 {
                return Err(io::Error::last_os_error()).context("Could not poll /dev/tty");
            }
            if ready == 0 || descriptor.revents & libc::POLLIN == 0 {
                return Ok(false);
            }
            let mut answer = String::new();
            io::BufReader::new(tty).read_line(&mut answer)?;
            Ok(matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "y" | "yes"
            ))
        })
        .await
        .context("Control-master confirmation task failed")?
    }

    struct ActiveSessionGuard {
        active: Arc<AtomicUsize>,
        updates: watch::Sender<usize>,
    }

    impl ActiveSessionGuard {
        fn new(active: Arc<AtomicUsize>, updates: watch::Sender<usize>) -> Self {
            let count = active.fetch_add(1, Ordering::AcqRel) + 1;
            updates.send_replace(count);
            Self { active, updates }
        }
    }

    impl Drop for ActiveSessionGuard {
        fn drop(&mut self) {
            let count = self.active.fetch_sub(1, Ordering::AcqRel) - 1;
            self.updates.send_replace(count);
        }
    }

    async fn handle_remote_session(
        mut stream: UnixStream,
        request_id: u64,
        session: SessionOpenRequest,
        client: Client,
        active: Arc<AtomicUsize>,
        active_tx: watch::Sender<usize>,
        session_id: u64,
    ) -> Result<()> {
        let _active = ActiveSessionGuard::new(active, active_tx);
        send_response(
            &mut stream,
            request_id,
            ControlResponseKind::SessionOpened { session_id },
        )
        .await?;
        let (mut reader, mut writer) = stream.into_split();
        let (input_reader, mut input_writer) = tokio::io::duplex(SESSION_PIPE_CAPACITY);
        let input = tokio::spawn(async move {
            loop {
                match read_control_message(&mut reader).await? {
                    ControlMessage::Data(data)
                        if data.session_id == session_id
                            && matches!(data.stream, ControlDataStream::Stdin) =>
                    {
                        if !data.payload.is_empty() {
                            input_writer.write_all(&data.payload).await?;
                        }
                        if data.eof {
                            input_writer.shutdown().await?;
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                    message => anyhow::bail!("unexpected session input message: {message:?}"),
                }
            }
        });
        let (output_tx, mut output_rx) = mpsc::channel(128);
        let policy = session.policy;
        let terminal = session.terminal;
        let execution_client = client.clone();
        let mut execution = tokio::spawn(async move {
            execution_client
                .execute_session_streaming_with_input_and_terminal(
                    &policy,
                    terminal.as_deref(),
                    output_tx,
                    input_reader,
                )
                .await
        });
        let mut status = None;
        let mut execution_joined = false;
        let mut output_open = true;
        let mut sequence = 0u64;
        let relay_result = async {
            loop {
                if status.is_some() && !output_open {
                    break;
                }
                tokio::select! {
                    result = &mut execution, if !execution_joined => {
                        execution_joined = true;
                        status = Some(result.context("Remote session task failed to join")??);
                    }
                    output = output_rx.recv(), if output_open => match output {
                        Some(CommandOutput::StdOut(payload)) => {
                            write_control_message(
                                &mut writer,
                                &ControlMessage::Data(ControlData {
                                    session_id,
                                    stream: ControlDataStream::Stdout,
                                    sequence,
                                    payload: payload.to_vec(),
                                    eof: false,
                                }),
                            ).await?;
                            sequence = sequence.saturating_add(1);
                        }
                        Some(CommandOutput::StdErr(payload)) => {
                            write_control_message(
                                &mut writer,
                                &ControlMessage::Data(ControlData {
                                    session_id,
                                    stream: ControlDataStream::Stderr,
                                    sequence,
                                    payload: payload.to_vec(),
                                    eof: false,
                                }),
                            ).await?;
                            sequence = sequence.saturating_add(1);
                        }
                        Some(CommandOutput::ExitCode(_)) => {}
                        None => output_open = false,
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        input.abort();
        let _ = input.await;
        if !execution_joined {
            execution.abort();
            let _ = execution.await;
        }
        relay_result?;
        send_response(
            &mut writer,
            request_id,
            ControlResponseKind::ExitStatus {
                session_id,
                status: status.context("remote session ended without exit status")?,
            },
        )
        .await
    }

    async fn send_response<W>(
        writer: &mut W,
        request_id: u64,
        kind: ControlResponseKind,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        write_control_message(
            writer,
            &ControlMessage::Response(ControlResponse { request_id, kind }),
        )
        .await?;
        Ok(())
    }

    async fn send_error<W>(writer: &mut W, request_id: u64, code: &str, message: &str) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        send_response(
            writer,
            request_id,
            ControlResponseKind::Error {
                code: code.to_string(),
                message: message.to_string(),
            },
        )
        .await
    }

    #[cfg(test)]
    mod tests {
        use tempfile::TempDir;

        use crate::ssh::{SessionPolicy, SessionRequest};

        use super::*;

        fn no_session_request() -> SessionOpenRequest {
            SessionOpenRequest::new(
                SessionPolicy {
                    environment: Vec::new(),
                    local_command: None,
                    request_pty: false,
                    stdin_null: true,
                    request: SessionRequest::None,
                },
                None,
            )
            .expect("valid session request")
        }

        #[tokio::test(start_paused = true)]
        async fn silent_control_socket_falls_back_after_bounded_handshake() {
            let directory = TempDir::new().expect("temporary directory");
            let path = directory.path().join("silent-control");
            let (listener, _guard) = bind_control_socket(&path).expect("control listener");
            let silent = tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.expect("accepted control client");
                std::future::pending::<()>().await;
            });

            let request = no_session_request();
            let outcome = attach_session(&path, request.clone(), &request.policy)
                .await
                .expect("silent master should fall back");
            assert_eq!(outcome, AttachOutcome::NoMaster);
            silent.abort();
            let _ = silent.await;
        }

        #[tokio::test]
        async fn master_dying_during_hello_falls_back_without_replaying_a_session() {
            let directory = TempDir::new().expect("temporary directory");
            let path = directory.path().join("dead-control");
            let (listener, _guard) = bind_control_socket(&path).expect("control listener");
            let dying = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accepted control client");
                drop(stream);
            });

            let request = no_session_request();
            let outcome = attach_session(&path, request.clone(), &request.policy)
                .await
                .expect("dead master should fall back");
            assert_eq!(outcome, AttachOutcome::NoMaster);
            dying.await.expect("dying listener task");
        }
    }
}

#[cfg(unix)]
pub use unix::{
    AttachOutcome, RunningControlMaster, attach_session, send_control_command, start_control_master,
};

#[cfg(not(unix))]
mod unsupported {
    use std::path::Path;

    use anyhow::Result;

    use crate::forwarding::ForwardingDirective;
    use crate::ssh::tokio_client::{AddressFamily, Client};

    use super::super::{ControlCommand, ControlPersist, ControlResponseKind, SessionOpenRequest};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AttachOutcome {
        NoMaster,
        ExitStatus(u32),
    }

    pub struct RunningControlMaster;

    impl RunningControlMaster {
        pub async fn shutdown_immediately(self) -> Result<()> {
            anyhow::bail!("connection multiplexing requires Unix-domain sockets")
        }

        pub async fn finish_after_initial(
            self,
            _persist: ControlPersist,
            _initial_request_was_none: bool,
        ) -> Result<()> {
            anyhow::bail!("connection multiplexing requires Unix-domain sockets")
        }
    }

    pub fn start_control_master(
        _path: &Path,
        _client: Client,
        _require_confirmation: bool,
    ) -> Result<RunningControlMaster> {
        anyhow::bail!("connection multiplexing requires Unix-domain sockets")
    }

    pub async fn attach_session(
        _path: &Path,
        _session: SessionOpenRequest,
        _invoking_policy: &crate::ssh::SessionPolicy,
    ) -> Result<AttachOutcome> {
        Ok(AttachOutcome::NoMaster)
    }

    pub async fn send_control_command(
        _path: &Path,
        _command: ControlCommand,
        _forwards: Vec<ForwardingDirective>,
        _address_family: AddressFamily,
    ) -> Result<ControlResponseKind> {
        anyhow::bail!("connection multiplexing requires Unix-domain sockets")
    }
}

#[cfg(not(unix))]
pub use unsupported::{
    AttachOutcome, RunningControlMaster, attach_session, send_control_command, start_control_master,
};
