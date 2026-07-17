mod handler;
mod reply;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub use self::handler::Handler;
pub use self::reply::StatusReply;

use crate::{
    error::Error,
    protocol::{Packet, Status, StatusCode},
    utils::read_packet,
};

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

    /// Maximum number of client requests read ahead of the one currently
    /// being processed. Read-ahead lets the transport keep delivering (and
    /// decrypting) requests while the handler is blocked on file I/O, and it
    /// feeds the sequential-write coalescer. Bounded so a client cannot make
    /// the server buffer unlimited data; the worst-case buffered bytes are
    /// `max_read_ahead * max_client_packet_len` per session. Default: 16.
    pub max_read_ahead: usize,

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
            max_read_ahead: 16,
            max_write_coalesce_len: 262144,
        }
    }
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
    ReadError(Error),
}

fn decode(item: Result<Bytes, Error>) -> Queued {
    match item {
        Ok(mut bytes) => match Packet::try_from(&mut bytes) {
            Ok(packet) => Queued::Request(packet),
            Err(_) => Queued::Malformed,
        },
        Err(err) => Queued::ReadError(err),
    }
}

/// Encode and send one response packet without flushing. Flushing is deferred
/// to the moment the request queue runs empty so a burst of pipelined
/// requests is answered with one flush instead of one per request.
async fn send_response<W>(writer: &mut W, response: Packet) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let bytes = Bytes::try_from(response)?;
    writer.write_all(&bytes).await?;
    Ok(())
}

/// Drive one SFTP session over `stream` until EOF.
///
/// Architecture: a reader task frames client packets and feeds a bounded
/// queue (`Config::max_read_ahead`), so the transport keeps delivering
/// requests while the handler is busy with file I/O. The processor loop
/// consumes the queue strictly in order: requests are handled one at a time
/// against `&mut handler` and responses are written in request order, so
/// response ordering and error semantics are identical to the previous
/// serial read -> process -> write -> flush loop. Two optimizations apply on
/// top:
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
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let (tx, mut rx) = mpsc::channel::<Result<Bytes, Error>>(cfg.max_read_ahead.max(1));
    let max_packet_len = cfg.max_client_packet_len;
    let reader = tokio::spawn(async move {
        loop {
            let item = read_packet(&mut read_half, max_packet_len).await;
            // Stop on EOF; keep reading after other errors to preserve the
            // previous loop's behavior (it warned and retried).
            let stop = matches!(item, Err(Error::UnexpectedEof));
            if tx.send(item).await.is_err() || stop {
                break;
            }
        }
    });

    // Holds a packet dequeued by the coalescer that did not merge into the
    // current write; it must be processed next to preserve ordering.
    let mut pending: Option<Queued> = None;

    'session: loop {
        let queued = match pending.take() {
            Some(queued) => queued,
            None => match rx.try_recv() {
                Ok(item) => decode(item),
                Err(mpsc::error::TryRecvError::Empty) => {
                    // No request ready: flush buffered responses before
                    // blocking so the client is never left waiting on
                    // replies we already produced.
                    if let Err(err) = write_half.flush().await {
                        warn!("sftp: flush failed: {err}");
                        break 'session;
                    }
                    match rx.recv().await {
                        Some(item) => decode(item),
                        None => break 'session,
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => break 'session,
            },
        };

        match queued {
            Queued::ReadError(Error::UnexpectedEof) => break 'session,
            Queued::ReadError(err) => {
                warn!("{}", err);
            }
            Queued::Malformed => {
                if let Err(err) =
                    send_response(&mut write_half, Packet::error(0, StatusCode::BadMessage)).await
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
                    if let Err(err) = send_response(&mut write_half, response).await {
                        warn!("{}", err);
                    }
                }
            }
            Queued::Request(request) => {
                let response = process_request(request, handler).await;
                if let Err(err) = send_response(&mut write_half, response).await {
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

/// Run processing stream as SFTP
pub async fn run<S, H>(stream: S, handler: H)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
{
    run_with_config(stream, handler, Config::default()).await
}

/// Run processing stream as SFTP with custom configuration
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
    use crate::protocol::{Handle, OpenFlags, Write};

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
            _attrs: crate::protocol::FileAttributes,
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
    }

    fn encode(packet: Packet) -> Bytes {
        Bytes::try_from(packet).expect("packet must encode")
    }

    /// OPEN request used as a queue-priming barrier (see [`MockHandler`]).
    fn open_packet(id: u32, filename: &str) -> Bytes {
        encode(Packet::Open(crate::protocol::Open {
            id,
            filename: filename.to_string(),
            pflags: OpenFlags::WRITE,
            attrs: crate::protocol::FileAttributes::default(),
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
        requests.push(encode(Packet::Close(crate::protocol::Close {
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
}
