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

//! SFTP server request loop with read-ahead and sequential write coalescing.
//!
//! This replaces `russh_sftp::server::run`, whose serial
//! read -> process -> write -> flush loop leaves the transport idle while the
//! handler waits on file I/O. It drives any [`russh_sftp::server::Handler`]
//! using only russh-sftp's public protocol types.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;

use bytes::Bytes;
use russh_sftp::protocol::{Packet, Status, StatusCode};
use russh_sftp::server::{Handler, StatusReply};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, warn};

macro_rules! into_wrap {
    ($id:expr, $handler:expr, $var:ident; $($arg:ident),*) => {
        match $handler.$var($($var.$arg),*).await {
            Err(err) => {
                let StatusReply { status_code, error_message, language_tag } = err.into();
                Packet::Status(Status {
                    id: $id,
                    status_code,
                    error_message: error_message.unwrap_or_else(|| status_code.to_string()),
                    language_tag: language_tag.unwrap_or_else(|| "en-US".to_string()),
                })
            },
            Ok(packet) => packet.into(),
        }
    };
}

/// Configuration for the SFTP server.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum allowed size of SFTP packets sent by clients. Default: 256 KiB.
    pub max_client_packet_len: u32,

    /// Request bytes the intake reads ahead of the processor before it pauses.
    /// Read-ahead lets the transport keep delivering (and decrypting) requests
    /// while the handler is blocked on file I/O, and it feeds the
    /// sequential-write coalescer.
    ///
    /// At this level the intake stops reading, which pushes back on the client
    /// through the transport (the SSH channel window, or the pipe in tests),
    /// the same way OpenSSH's `sftp-server` stops reading its input. Pausing
    /// is only safe while responses are flowing: if request intake stalls
    /// while a response write waits for channel window, the russh session
    /// loop can block on delivering channel data and stop processing the very
    /// `SSH_MSG_CHANNEL_WINDOW_ADJUST` that would free the response side
    /// (issue lablup/bssh#227, paramiko's unbounded READ prefetch). So the
    /// intake ignores this limit whenever a response write is blocked, and
    /// [`Self::max_buffered_request_bytes`] bounds memory in that state.
    /// Default: 8 MiB.
    pub read_ahead_bytes: usize,

    /// Hard ceiling on buffered request bytes. The intake only grows past
    /// [`Self::read_ahead_bytes`] while a response write is blocked, so a
    /// client reaching this ceiling keeps sending without reading its replies
    /// and its session is terminated. Default: 64 MiB.
    pub max_buffered_request_bytes: usize,

    /// Maximum number of bytes merged into a single coalesced `SSH_FXP_WRITE`
    /// handler call. Consecutive queued WRITE requests targeting the same
    /// handle at strictly sequential offsets are merged into one handler
    /// invocation (one seek + one write instead of one per request), and every
    /// merged request id still receives its own status reply. Set to 0 to
    /// disable coalescing. Default: 256 KiB.
    pub max_write_coalesce_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_client_packet_len: 262144,
            read_ahead_bytes: 8 * 1024 * 1024,
            max_buffered_request_bytes: 64 * 1024 * 1024,
            max_write_coalesce_len: 262144,
        }
    }
}

/// Why the intake side stopped producing a frame.
#[derive(Debug)]
enum ReadError {
    /// The client closed the stream.
    Eof,
    /// The request backlog exceeded `Config::max_buffered_request_bytes`.
    BacklogExceeded(usize),
    /// Any other framing or I/O failure; the session keeps reading.
    Other(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => f.write_str("unexpected EOF on stream"),
            Self::BacklogExceeded(budget) => {
                write!(f, "request backlog exceeded {budget} buffered bytes")
            }
            Self::Other(message) => f.write_str(message),
        }
    }
}

/// Read one length-prefixed SFTP frame, rejecting frames above `max_length`.
async fn read_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_length: u32,
) -> Result<Bytes, ReadError> {
    let io_error = |error: io::Error| match error.kind() {
        io::ErrorKind::UnexpectedEof => ReadError::Eof,
        _ => ReadError::Other(format!("I/O: {error}")),
    };
    let length = stream.read_u32().await.map_err(io_error)?;
    if length > max_length {
        return Err(ReadError::Other(
            "Bad message: packet length limit exceeded".to_owned(),
        ));
    }

    let mut buf = vec![0; length as usize];
    stream.read_exact(&mut buf).await.map_err(io_error)?;

    Ok(Bytes::from(buf))
}

async fn process_request<H>(packet: Packet, handler: &mut H) -> Packet
where
    H: Handler + Send,
{
    let id = packet.get_request_id();

    match packet {
        Packet::Init(init) => into_wrap!(id, handler, init; version, extensions),
        Packet::Open(open) => into_wrap!(id, handler, open; id, filename, pflags, attrs),
        Packet::Close(close) => into_wrap!(id, handler, close; id, handle),
        Packet::Read(read) => into_wrap!(id, handler, read; id, handle, offset, len),
        Packet::Write(write) => into_wrap!(id, handler, write; id, handle, offset, data),
        Packet::Lstat(lstat) => into_wrap!(id, handler, lstat; id, path),
        Packet::Fstat(fstat) => into_wrap!(id, handler, fstat; id, handle),
        Packet::SetStat(setstat) => into_wrap!(id, handler, setstat; id, path, attrs),
        Packet::FSetStat(fsetstat) => into_wrap!(id, handler, fsetstat; id, handle, attrs),
        Packet::OpenDir(opendir) => into_wrap!(id, handler, opendir; id, path),
        Packet::ReadDir(readdir) => into_wrap!(id, handler, readdir; id, handle),
        Packet::Remove(remove) => into_wrap!(id, handler, remove; id, filename),
        Packet::MkDir(mkdir) => into_wrap!(id, handler, mkdir; id, path, attrs),
        Packet::RmDir(rmdir) => into_wrap!(id, handler, rmdir; id, path),
        Packet::RealPath(realpath) => into_wrap!(id, handler, realpath; id, path),
        Packet::Stat(stat) => into_wrap!(id, handler, stat; id, path),
        Packet::Rename(rename) => into_wrap!(id, handler, rename; id, oldpath, newpath),
        Packet::ReadLink(readlink) => into_wrap!(id, handler, readlink; id, path),
        Packet::Symlink(symlink) => into_wrap!(id, handler, symlink; id, linkpath, targetpath),
        Packet::Extended(extended) => into_wrap!(id, handler, extended; id, request, data),
        _ => Packet::error(0, StatusCode::BadMessage),
    }
}

/// A client packet after framing and decoding, as seen by the processor loop.
enum Queued {
    /// A well-formed request.
    Request(Packet),
    /// A frame that could not be decoded; answered with `SSH_FXP_STATUS`
    /// `BadMessage` (id 0), matching the previous serial-loop behavior.
    Malformed,
    /// The reader failed to obtain a frame (I/O error or EOF).
    ReadError(ReadError),
}

fn decode(item: Result<Bytes, ReadError>) -> Queued {
    match item {
        Ok(mut bytes) => match Packet::try_from(&mut bytes) {
            Ok(packet) => Queued::Request(packet),
            Err(_) => Queued::Malformed,
        },
        Err(err) => Queued::ReadError(err),
    }
}

/// Shared state between the intake task and the processor loop.
#[derive(Default)]
struct IntakeGate {
    /// Framed bytes read from the client and not yet dequeued.
    queued: AtomicUsize,
    /// True while a response write or flush is waiting on the transport.
    output_blocked: AtomicBool,
    /// Wakes a paused intake when either value above changes.
    wake: Notify,
    /// Set by the intake when the backlog ceiling is reached.
    terminated: AtomicBool,
    /// Wakes a response write blocked when `terminated` is set.
    abort: Notify,
}

impl IntakeGate {
    fn release(&self, len: usize) {
        self.queued.fetch_sub(len, Ordering::SeqCst);
        self.wake.notify_one();
    }

    fn set_output_blocked(&self, blocked: bool) {
        self.output_blocked.store(blocked, Ordering::SeqCst);
        if blocked {
            self.wake.notify_one();
        }
    }

    /// End the session from the intake side. A response write blocked on a
    /// client that stopped reading would otherwise never observe the queued
    /// termination behind it.
    fn terminate(&self) {
        self.terminated.store(true, Ordering::SeqCst);
        self.abort.notify_one();
    }

    fn is_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }

    async fn aborted(&self) {
        loop {
            let notified = self.abort.notified();
            if self.is_terminated() {
                return;
            }
            notified.await;
        }
    }

    /// Wait until the backlog is under `read_ahead`, or a response write is
    /// blocked (pausing then could deadlock the session, see [`Config`]).
    async fn wait_for_room(&self, read_ahead: usize) {
        loop {
            // Created before the check so a notification in between is kept.
            let notified = self.wake.notified();
            if self.queued.load(Ordering::SeqCst) < read_ahead
                || self.output_blocked.load(Ordering::SeqCst)
            {
                return;
            }
            notified.await;
        }
    }
}

/// Response side of the session. It reports to the [`IntakeGate`] whenever a
/// write or flush cannot complete immediately.
struct ResponseWriter<W> {
    inner: W,
    gate: Arc<IntakeGate>,
}

impl<W: AsyncWrite + Unpin> ResponseWriter<W> {
    async fn track<F, T>(gate: &IntakeGate, future: F) -> io::Result<T>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        let mut future = std::pin::pin!(future);
        if let Poll::Ready(result) = futures::poll!(future.as_mut()) {
            return result;
        }
        gate.set_output_blocked(true);
        let result = tokio::select! {
            result = &mut future => result,
            () = gate.aborted() => Err(io::Error::other(
                "session terminated: request backlog ceiling reached",
            )),
        };
        gate.set_output_blocked(false);
        result
    }

    /// Encode and send one response packet without flushing. Flushing is
    /// deferred to the moment the request queue runs empty so a burst of
    /// pipelined requests is answered with one flush instead of one per
    /// request.
    async fn send(&mut self, response: Packet) -> io::Result<()> {
        let bytes =
            Bytes::try_from(response).map_err(|error| io::Error::other(error.to_string()))?;
        Self::track(&self.gate, self.inner.write_all(&bytes)).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        Self::track(&self.gate, self.inner.flush()).await
    }
}

/// Drive one SFTP session over `stream` until EOF.
///
/// Architecture: a reader task frames client packets and feeds a queue that
/// is unbounded in request count and bounded in bytes, so the transport keeps
/// delivering requests while the handler is busy with file I/O. Once
/// `Config::read_ahead_bytes` are queued the reader pauses, which throttles
/// the client through the transport. It keeps reading while a response write
/// is blocked: stalling intake then lets the russh session loop block on
/// channel data delivery, which stops WINDOW_ADJUST processing and deadlocks
/// the session (issue lablup/bssh#227). In that state only
/// `Config::max_buffered_request_bytes` bounds the queue, and exceeding it
/// terminates the session. The processor loop consumes the queue
/// strictly in order: requests are handled one at a time against
/// `&mut handler` and responses are written in request order, so response
/// ordering and error semantics are identical to the previous serial
/// read -> process -> write -> flush loop. Two optimizations apply on top:
///
/// - **Deferred flush**: responses are flushed only when the queue is
///   momentarily empty (or the session ends) instead of after every request.
/// - **Sequential write coalescing**: consecutive queued `SSH_FXP_WRITE`
///   requests for the same handle at strictly contiguous offsets are merged
///   into a single handler call (bounded by
///   `Config::max_write_coalesce_len`). Every merged request id receives its
///   own status reply carrying the outcome of the merged write; on failure
///   all merged ids receive the same error, which is the conservative
///   superset of what a partially-failed serial sequence would report.
async fn process_stream<S, H>(stream: S, handler: &mut H, cfg: &Config)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send,
{
    let (mut read_half, write_half) = tokio::io::split(stream);

    let (tx, mut rx) = mpsc::unbounded_channel::<Result<Bytes, ReadError>>();
    let gate = Arc::new(IntakeGate::default());
    let max_packet_len = cfg.max_client_packet_len;
    let read_ahead = cfg.read_ahead_bytes;
    let budget = cfg.max_buffered_request_bytes;
    let reader_gate = Arc::clone(&gate);
    let reader = tokio::spawn(async move {
        loop {
            reader_gate.wait_for_room(read_ahead).await;
            let item = read_packet(&mut read_half, max_packet_len).await;
            // Stop on EOF; keep reading after other errors to preserve the
            // previous loop's behavior (it warned and retried).
            let stop = matches!(item, Err(ReadError::Eof));
            let len = item.as_ref().map_or(0, Bytes::len);
            if reader_gate.queued.fetch_add(len, Ordering::SeqCst) + len > budget {
                // Only reachable while responses are blocked: the client
                // keeps sending without reading its replies.
                reader_gate.terminate();
                let _ = tx.send(Err(ReadError::BacklogExceeded(budget)));
                break;
            }
            if tx.send(item).is_err() || stop {
                break;
            }
        }
    });

    // Return a dequeued item's framed length to the byte budget.
    let release = |item: &Result<Bytes, ReadError>| {
        if let Ok(bytes) = item {
            gate.release(bytes.len());
        }
    };
    let mut write_half = ResponseWriter {
        inner: write_half,
        gate: Arc::clone(&gate),
    };

    // Holds a packet dequeued by the coalescer that did not merge into the
    // current write; it must be processed next to preserve ordering.
    let mut pending: Option<Queued> = None;

    'session: loop {
        if gate.is_terminated() {
            warn!(
                "sftp: terminating session: {}",
                ReadError::BacklogExceeded(budget)
            );
            break 'session;
        }
        let queued = match pending.take() {
            Some(queued) => queued,
            None => match rx.try_recv() {
                Ok(item) => {
                    release(&item);
                    decode(item)
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No request ready: flush buffered responses before
                    // blocking so the client is never left waiting on
                    // replies we already produced.
                    if let Err(err) = write_half.flush().await {
                        warn!("sftp: flush failed: {err}");
                        break 'session;
                    }
                    match rx.recv().await {
                        Some(item) => {
                            release(&item);
                            decode(item)
                        }
                        None => break 'session,
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => break 'session,
            },
        };

        match queued {
            Queued::ReadError(ReadError::Eof) => break 'session,
            Queued::ReadError(err @ ReadError::BacklogExceeded(_)) => {
                // Hard ceiling reached while responses were blocked.
                warn!("sftp: terminating session: {err}");
                break 'session;
            }
            Queued::ReadError(err) => {
                warn!("{}", err);
            }
            Queued::Malformed => {
                if let Err(err) = write_half
                    .send(Packet::error(0, StatusCode::BadMessage))
                    .await
                {
                    warn!("{}", err);
                }
            }
            Queued::Request(Packet::Write(mut write)) => {
                // Coalesce strictly sequential queued writes to the same
                // handle into one handler call.
                let mut ids = vec![write.id];
                while write.data.len() < cfg.max_write_coalesce_len {
                    let Ok(item) = rx.try_recv() else {
                        // Empty or disconnected: nothing more to merge now.
                        // A disconnect is surfaced by the next dequeue.
                        break;
                    };
                    release(&item);
                    match decode(item) {
                        Queued::Request(Packet::Write(next))
                            if next.handle == write.handle
                                && write.offset.checked_add(write.data.len() as u64)
                                    == Some(next.offset)
                                && write.data.len() + next.data.len()
                                    <= cfg.max_write_coalesce_len =>
                        {
                            ids.push(next.id);
                            write.data.extend_from_slice(&next.data);
                        }
                        other => {
                            pending = Some(other);
                            break;
                        }
                    }
                }

                let reply: StatusReply = match handler
                    .write(write.id, write.handle, write.offset, write.data)
                    .await
                {
                    Ok(status) => StatusReply {
                        status_code: status.status_code,
                        error_message: Some(status.error_message),
                        language_tag: Some(status.language_tag),
                    },
                    Err(err) => err.into(),
                };

                for id in ids {
                    let response = Packet::Status(Status {
                        id,
                        status_code: reply.status_code,
                        error_message: reply
                            .error_message
                            .clone()
                            .unwrap_or_else(|| reply.status_code.to_string()),
                        language_tag: reply
                            .language_tag
                            .clone()
                            .unwrap_or_else(|| "en-US".to_string()),
                    });
                    if let Err(err) = write_half.send(response).await {
                        warn!("{}", err);
                    }
                }
            }
            Queued::Request(request) => {
                let response = process_request(request, handler).await;
                if let Err(err) = write_half.send(response).await {
                    warn!("{}", err);
                }
            }
        }
    }

    if let Err(err) = write_half.flush().await {
        debug!("sftp: final flush failed: {err}");
    }
    reader.abort();

    debug!("sftp stream ended");
}

/// Serve SFTP on `stream` with the default [`Config`].
pub async fn run<S, H>(stream: S, handler: H)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    run_with_config(stream, handler, Config::default()).await
}

/// Serve SFTP on `stream`. The session runs on a spawned task.
pub async fn run_with_config<S, H>(stream: S, mut handler: H, cfg: Config)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    tokio::spawn(async move {
        process_stream(stream, &mut handler, &cfg).await;
    });
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::{Buf, BytesMut};
    use tokio::io::AsyncReadExt;

    use super::*;
    use russh_sftp::protocol::{Handle, OpenFlags, Write};

    /// Call log entry for the mock handler's write method.
    #[derive(Debug, Clone, PartialEq)]
    struct WriteCall {
        handle: String,
        offset: u64,
        len: usize,
    }

    /// State shared between the test body and the mock handler.
    #[derive(Debug, Default)]
    struct Shared {
        /// Sparse file image keyed by handle.
        files: HashMap<String, Vec<u8>>,
        /// Every write call the handler received, in order.
        write_calls: Vec<WriteCall>,
        /// Offsets whose writes must fail with `StatusCode::Failure`.
        fail_offsets: Vec<u64>,
        /// Simulated storage latency per write call.
        write_delay: Option<Duration>,
    }

    /// Mock handler. `open` sleeps 50 ms before replying, which gives the
    /// reader task ample time to enqueue every already-sent request. Tests
    /// exploit this: sending OPEN followed by a burst of WRITEs makes the
    /// queue state during write processing deterministic, so coalescing
    /// expectations can be exact instead of timing-tolerant.
    #[derive(Debug, Clone, Default)]
    struct MockHandler {
        shared: Arc<Mutex<Shared>>,
    }

    impl Handler for MockHandler {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        fn open(
            &mut self,
            id: u32,
            filename: String,
            _pflags: OpenFlags,
            _attrs: russh_sftp::protocol::FileAttributes,
        ) -> impl std::future::Future<Output = Result<Handle, Self::Error>> + Send {
            let shared = Arc::clone(&self.shared);
            async move {
                // Let the reader task queue all pipelined requests sent
                // after this OPEN before the processor resumes.
                tokio::time::sleep(Duration::from_millis(50)).await;
                shared
                    .lock()
                    .unwrap()
                    .files
                    .insert(filename.clone(), Vec::new());
                Ok(Handle {
                    id,
                    handle: filename,
                })
            }
        }

        fn write(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            data: Vec<u8>,
        ) -> impl std::future::Future<Output = Result<Status, Self::Error>> + Send {
            let shared = Arc::clone(&self.shared);
            async move {
                let delay = shared.lock().unwrap().write_delay;
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                let mut shared = shared.lock().unwrap();
                if shared.fail_offsets.contains(&offset) {
                    return Err(StatusCode::Failure);
                }
                shared.write_calls.push(WriteCall {
                    handle: handle.clone(),
                    offset,
                    len: data.len(),
                });
                let file = shared.files.entry(handle).or_default();
                let end = offset as usize + data.len();
                if file.len() < end {
                    file.resize(end, 0);
                }
                file[offset as usize..end].copy_from_slice(&data);
                Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: String::new(),
                    language_tag: "en".to_string(),
                })
            }
        }

        async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: "en".to_string(),
            })
        }

        async fn read(
            &mut self,
            id: u32,
            _handle: String,
            _offset: u64,
            len: u32,
        ) -> Result<russh_sftp::protocol::Data, Self::Error> {
            Ok(russh_sftp::protocol::Data {
                id,
                data: vec![0u8; len as usize],
            })
        }
    }

    fn encode(packet: Packet) -> Bytes {
        Bytes::try_from(packet).expect("packet must encode")
    }

    /// OPEN request used as a queue-priming barrier (see [`MockHandler`]).
    fn open_packet(id: u32, filename: &str) -> Bytes {
        encode(Packet::Open(russh_sftp::protocol::Open {
            id,
            filename: filename.to_string(),
            pflags: OpenFlags::WRITE,
            attrs: russh_sftp::protocol::FileAttributes::default(),
        }))
    }

    fn write_packet(id: u32, handle: &str, offset: u64, data: Vec<u8>) -> Bytes {
        encode(Packet::Write(Write {
            id,
            handle: handle.to_string(),
            offset,
            data,
        }))
    }

    fn read_request_packet(id: u32, handle: &str, offset: u64, len: u32) -> Bytes {
        encode(Packet::Read(russh_sftp::protocol::Read {
            id,
            handle: handle.to_string(),
            offset,
            len,
        }))
    }

    /// Feed `requests` into a session and collect one decoded response per
    /// request.
    async fn run_session(
        requests: Vec<Bytes>,
        expected_responses: usize,
        shared: Arc<Mutex<Shared>>,
        cfg: Config,
    ) -> Vec<Packet> {
        let (client, server) = tokio::io::duplex(1 << 20);

        let session = tokio::spawn(async move {
            let mut handler = MockHandler { shared };
            process_stream(server, &mut handler, &cfg).await;
        });

        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        for request in &requests {
            client_wr.write_all(request).await.unwrap();
        }
        client_wr.shutdown().await.unwrap();

        let mut responses = Vec::new();
        let mut buf = BytesMut::new();
        while responses.len() < expected_responses {
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), client_rd.read(&mut chunk))
                .await
                .expect("timed out waiting for responses")
                .expect("read must succeed");
            assert!(n > 0, "stream closed before all responses arrived");
            buf.extend_from_slice(&chunk[..n]);

            loop {
                if buf.len() < 4 {
                    break;
                }
                let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() < 4 + length {
                    break;
                }
                buf.advance(4);
                let mut frame = buf.split_to(length).freeze();
                responses.push(Packet::try_from(&mut frame).expect("response must decode"));
            }
        }

        session.await.unwrap();
        responses
    }

    fn status_of(packet: &Packet) -> (u32, StatusCode) {
        match packet {
            Packet::Status(status) => (status.id, status.status_code),
            other => panic!("expected status packet, got {other:?}"),
        }
    }

    fn response_id(packet: &Packet) -> u32 {
        match packet {
            Packet::Status(status) => status.id,
            Packet::Handle(handle) => handle.id,
            other => panic!("unexpected response packet: {other:?}"),
        }
    }

    #[tokio::test]
    async fn sequential_writes_coalesce_into_one_handler_call() {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let payload: Vec<u8> = (0..128u32).flat_map(|i| i.to_be_bytes()).collect();
        let chunk = payload.len() / 4;

        // OPEN primes the queue: while its handler sleeps, the reader
        // enqueues all four WRITEs, so they coalesce into one handler call.
        let mut requests = vec![open_packet(10, "h")];
        for (index, part) in payload.chunks(chunk).enumerate() {
            requests.push(write_packet(
                index as u32 + 1,
                "h",
                (index * chunk) as u64,
                part.to_vec(),
            ));
        }
        requests.push(encode(Packet::Close(russh_sftp::protocol::Close {
            id: 99,
            handle: "h".to_string(),
        })));

        let responses = run_session(requests, 6, Arc::clone(&shared), Config::default()).await;

        // Every request id gets a reply, in request order.
        let ids: Vec<u32> = responses.iter().map(response_id).collect();
        assert_eq!(ids, vec![10, 1, 2, 3, 4, 99]);
        for response in &responses[1..] {
            assert_eq!(status_of(response).1, StatusCode::Ok);
        }

        let shared = shared.lock().unwrap();
        // Coalescing must not change the file image.
        assert_eq!(shared.files.get("h"), Some(&payload));
        // All four queued sequential writes merge into a single call.
        assert_eq!(
            shared.write_calls,
            vec![WriteCall {
                handle: "h".into(),
                offset: 0,
                len: payload.len()
            }]
        );
    }

    #[tokio::test]
    async fn non_contiguous_writes_are_not_merged() {
        let shared = Arc::new(Mutex::new(Shared::default()));
        // Two queued writes with a hole between them must stay two calls.
        let requests = vec![
            open_packet(10, "h"),
            write_packet(1, "h", 0, vec![0xAA; 16]),
            write_packet(2, "h", 64, vec![0xBB; 16]),
        ];

        let responses = run_session(requests, 3, Arc::clone(&shared), Config::default()).await;
        assert_eq!(
            responses[1..].iter().map(status_of).collect::<Vec<_>>(),
            vec![(1, StatusCode::Ok), (2, StatusCode::Ok)]
        );

        let shared = shared.lock().unwrap();
        assert_eq!(
            shared.write_calls,
            vec![
                WriteCall {
                    handle: "h".into(),
                    offset: 0,
                    len: 16
                },
                WriteCall {
                    handle: "h".into(),
                    offset: 64,
                    len: 16
                },
            ]
        );
    }

    #[tokio::test]
    async fn different_handles_are_not_merged() {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let requests = vec![
            open_packet(10, "a"),
            write_packet(1, "a", 0, vec![0xAA; 16]),
            write_packet(2, "b", 16, vec![0xBB; 16]),
        ];

        let responses = run_session(requests, 3, Arc::clone(&shared), Config::default()).await;
        assert_eq!(
            responses[1..].iter().map(status_of).collect::<Vec<_>>(),
            vec![(1, StatusCode::Ok), (2, StatusCode::Ok)]
        );

        let shared = shared.lock().unwrap();
        assert_eq!(shared.write_calls.len(), 2);
        assert_eq!(shared.write_calls[0].handle, "a");
        assert_eq!(shared.write_calls[1].handle, "b");
    }

    #[tokio::test]
    async fn coalesce_respects_byte_budget() {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config {
            max_write_coalesce_len: 32,
            ..Config::default()
        };
        // Three queued sequential 16-byte writes with a 32-byte budget merge
        // as [32, 16].
        let requests = vec![
            open_packet(10, "h"),
            write_packet(1, "h", 0, vec![1; 16]),
            write_packet(2, "h", 16, vec![2; 16]),
            write_packet(3, "h", 32, vec![3; 16]),
        ];

        let responses = run_session(requests, 4, Arc::clone(&shared), cfg).await;
        for (index, response) in responses[1..].iter().enumerate() {
            assert_eq!(status_of(response), (index as u32 + 1, StatusCode::Ok));
        }

        let shared = shared.lock().unwrap();
        assert_eq!(
            shared.write_calls,
            vec![
                WriteCall {
                    handle: "h".into(),
                    offset: 0,
                    len: 32
                },
                WriteCall {
                    handle: "h".into(),
                    offset: 32,
                    len: 16
                },
            ]
        );
        let mut expected = vec![1u8; 16];
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&[3; 16]);
        assert_eq!(shared.files.get("h"), Some(&expected));
    }

    #[tokio::test]
    async fn merged_write_failure_reports_error_to_every_merged_id() {
        let shared = Arc::new(Mutex::new(Shared {
            fail_offsets: vec![0],
            ..Shared::default()
        }));
        let requests = vec![
            open_packet(10, "h"),
            write_packet(1, "h", 0, vec![1; 16]),
            write_packet(2, "h", 16, vec![2; 16]),
        ];

        let responses = run_session(requests, 3, Arc::clone(&shared), Config::default()).await;
        for (index, response) in responses[1..].iter().enumerate() {
            let (id, code) = status_of(response);
            assert_eq!(id, index as u32 + 1);
            assert_eq!(
                code,
                StatusCode::Failure,
                "every merged id must observe the write failure"
            );
        }

        let shared = shared.lock().unwrap();
        assert!(shared.write_calls.is_empty());
    }

    #[tokio::test]
    async fn coalescing_disabled_with_zero_budget() {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config {
            max_write_coalesce_len: 0,
            ..Config::default()
        };
        let requests = vec![
            open_packet(10, "h"),
            write_packet(1, "h", 0, vec![1; 16]),
            write_packet(2, "h", 16, vec![2; 16]),
        ];

        let responses = run_session(requests, 3, Arc::clone(&shared), cfg).await;
        assert_eq!(responses.len(), 3);

        let shared = shared.lock().unwrap();
        assert_eq!(shared.write_calls.len(), 2, "no merging with zero budget");
    }

    /// Regression test for the paramiko prefetch deadlock (lablup/bssh#227).
    ///
    /// The client sends a burst of READ requests and reads no responses until
    /// every request has been written, over a transport with a tiny buffer so
    /// the server's response writes block almost immediately. The old
    /// count-bounded intake queue stopped draining the stream once full,
    /// which left the client's send side blocked too: a mutual stall, and at
    /// the russh layer the same coupling froze WINDOW_ADJUST processing. The
    /// byte-budgeted intake must keep draining, letting the client finish
    /// sending and then collect every response.
    #[tokio::test]
    async fn pipelined_read_burst_drains_while_response_path_blocked() {
        const READS: usize = 300;
        const READ_LEN: u32 = 1024;

        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config::default();
        // Tiny per-direction buffer: response writes block after ~4 frames,
        // and the request burst does not fit in the transport either.
        let (client, server) = tokio::io::duplex(4096);

        let session = tokio::spawn(async move {
            let mut handler = MockHandler { shared };
            process_stream(server, &mut handler, &cfg).await;
        });

        let (mut client_rd, mut client_wr) = tokio::io::split(client);

        let send_all = async move {
            client_wr.write_all(&open_packet(0, "h")).await.unwrap();
            for i in 0..READS {
                client_wr
                    .write_all(&read_request_packet(
                        i as u32 + 1,
                        "h",
                        u64::from(READ_LEN) * i as u64,
                        READ_LEN,
                    ))
                    .await
                    .unwrap();
            }
            client_wr.shutdown().await.unwrap();
        };
        let send_all = tokio::time::timeout(Duration::from_secs(10), send_all);

        let recv_all = async move {
            let mut responses = 0usize;
            let mut buf = BytesMut::new();
            loop {
                let mut chunk = [0u8; 4096];
                let n = client_rd.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                loop {
                    if buf.len() < 4 {
                        break;
                    }
                    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    if buf.len() < 4 + length {
                        break;
                    }
                    buf.advance(4);
                    let mut frame = buf.split_to(length).freeze();
                    Packet::try_from(&mut frame).expect("response must decode");
                    responses += 1;
                }
            }
            responses
        };
        let recv_all = tokio::time::timeout(Duration::from_secs(10), recv_all);

        // The send side must complete even though nothing reads responses
        // concurrently; only then does the receive side start.
        send_all.await.expect("request burst must not deadlock");
        let responses = recv_all.await.expect("responses must not deadlock");
        assert_eq!(responses, READS + 1, "one HANDLE plus one DATA per READ");

        session.await.unwrap();
    }

    /// A client that sends far beyond `read_ahead_bytes` while the handler
    /// is busy is throttled through the transport, not disconnected: every
    /// request is still answered.
    #[tokio::test]
    async fn request_burst_beyond_read_ahead_is_throttled_not_terminated() {
        const READS: usize = 100;

        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config {
            // Far below the ~4 KiB the burst below sends while the OPEN
            // handler sleeps.
            read_ahead_bytes: 512,
            max_buffered_request_bytes: 1024,
            ..Config::default()
        };
        let mut requests = vec![open_packet(0, "h")];
        for i in 0..READS {
            requests.push(read_request_packet(i as u32 + 1, "h", 0, 64));
        }

        let responses = run_session(requests, READS + 1, shared, cfg).await;
        assert_eq!(responses.len(), READS + 1);
    }

    /// Pipelined uploads faster than storage, over a transport with no flow
    /// control of its own (the in-process case that used to hit the backlog
    /// ceiling): the intake must pause at `read_ahead_bytes` so the client is
    /// throttled, and the whole upload must succeed.
    #[tokio::test]
    async fn pipelined_writes_faster_than_storage_complete_under_backpressure() {
        const WRITES: usize = 64;
        const CHUNK: usize = 32 * 1024;

        let shared = Arc::new(Mutex::new(Shared {
            write_delay: Some(Duration::from_millis(2)),
            ..Shared::default()
        }));
        let cfg = Config {
            read_ahead_bytes: 64 * 1024,
            // Below the 2 MiB upload, so terminating at the ceiling would
            // fail this test.
            max_buffered_request_bytes: 1024 * 1024,
            ..Config::default()
        };
        let mut requests = vec![open_packet(0, "h")];
        let mut expected = Vec::with_capacity(WRITES * CHUNK);
        for i in 0..WRITES {
            let data = vec![i as u8; CHUNK];
            expected.extend_from_slice(&data);
            requests.push(write_packet(i as u32 + 1, "h", (i * CHUNK) as u64, data));
        }

        let responses = run_session(requests, WRITES + 1, Arc::clone(&shared), cfg).await;
        for response in &responses[1..] {
            assert_eq!(status_of(response).1, StatusCode::Ok);
        }
        assert_eq!(shared.lock().unwrap().files.get("h"), Some(&expected));
    }

    /// The deadlock shape of lablup/bssh#227 with a tiny read-ahead: the
    /// client writes a READ burst without reading replies over a small pipe,
    /// so response writes block. The intake must keep draining past
    /// `read_ahead_bytes` while output is blocked, or both sides stall.
    #[tokio::test]
    async fn blocked_responses_keep_intake_draining_past_read_ahead() {
        const READS: usize = 300;
        const READ_LEN: u32 = 1024;

        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config {
            read_ahead_bytes: 256,
            ..Config::default()
        };
        let (client, server) = tokio::io::duplex(4096);

        let session = tokio::spawn(async move {
            let mut handler = MockHandler { shared };
            process_stream(server, &mut handler, &cfg).await;
        });

        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        let send_all = async move {
            client_wr.write_all(&open_packet(0, "h")).await.unwrap();
            for i in 0..READS {
                client_wr
                    .write_all(&read_request_packet(
                        i as u32 + 1,
                        "h",
                        u64::from(READ_LEN) * i as u64,
                        READ_LEN,
                    ))
                    .await
                    .unwrap();
            }
            client_wr.shutdown().await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(10), send_all)
            .await
            .expect("request burst must not deadlock behind blocked responses");

        let recv_all = async move {
            let mut total = 0usize;
            let mut chunk = [0u8; 4096];
            loop {
                let n = client_rd.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break total;
                }
                total += n;
            }
        };
        let total = tokio::time::timeout(Duration::from_secs(10), recv_all)
            .await
            .expect("responses must drain");
        assert!(
            total > READS * READ_LEN as usize,
            "every READ must be answered"
        );

        session.await.unwrap();
    }

    /// A client that keeps sending while never reading its replies blocks the
    /// response side, so the intake reads past `read_ahead_bytes`; once the
    /// backlog reaches `max_buffered_request_bytes` the session is terminated
    /// instead of growing without bound.
    #[tokio::test]
    async fn backlog_ceiling_terminates_a_client_that_never_reads() {
        const READS: usize = 2000;

        let shared = Arc::new(Mutex::new(Shared::default()));
        let cfg = Config {
            read_ahead_bytes: 256,
            max_buffered_request_bytes: 16 * 1024,
            ..Config::default()
        };
        // A small pipe so the unread 4 KiB DATA replies block the server.
        let (client, server) = tokio::io::duplex(8192);

        let session = tokio::spawn(async move {
            let mut handler = MockHandler { shared };
            process_stream(server, &mut handler, &cfg).await;
        });

        let (mut client_rd, mut client_wr) = tokio::io::split(client);
        let flood = tokio::spawn(async move {
            if client_wr.write_all(&open_packet(0, "h")).await.is_err() {
                return;
            }
            for i in 0..READS {
                let request = read_request_packet(i as u32 + 1, "h", 0, 4096);
                if client_wr.write_all(&request).await.is_err() {
                    return;
                }
            }
        });

        tokio::time::timeout(Duration::from_secs(10), session)
            .await
            .expect("a client that never reads must be terminated, not hang")
            .unwrap();
        // The server side is gone: the flood stops and the reply stream ends.
        tokio::time::timeout(Duration::from_secs(10), flood)
            .await
            .expect("the flood must stop once the session is gone")
            .unwrap();
        let mut answered = 0usize;
        let mut chunk = [0u8; 8192];
        while let Ok(n) = client_rd.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            answered += n;
        }
        assert!(
            answered < READS * 4096,
            "expected termination before every READ was answered, got {answered} bytes"
        );
    }
}
