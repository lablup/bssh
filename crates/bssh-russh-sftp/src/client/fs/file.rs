use std::{
    future::Future,
    io::{self, SeekFrom},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf},
    runtime::Handle,
};

use super::Metadata;
use crate::{
    client::{error::Error, rawsession::SftpResult, session::Extensions, RawSftpSession},
    protocol::StatusCode,
};

type StateFn<T> = Option<Pin<Box<dyn Future<Output = io::Result<T>> + Send + Sync + 'static>>>;

const MAX_READ_LENGTH: u64 = 261120;
const MAX_WRITE_LENGTH: u64 = 261120;

fn bounded_chunk_size(limit: Option<u64>, default_limit: u64) -> usize {
    limit.map_or(default_limit, |n| n.min(default_limit)) as usize
}

struct FileState {
    f_read: StateFn<Option<Vec<u8>>>,
    f_seek: StateFn<u64>,
    f_write: StateFn<usize>,
    f_flush: StateFn<()>,
    f_shutdown: StateFn<()>,
}

/// Provides high-level methods for interaction with a remote file.
///
/// In order to properly close the handle, [`shutdown`] on a file should be called.
/// Also implement [`AsyncSeek`] and other async i/o implementations.
///
/// # Weakness
/// Using [`SeekFrom::End`] is costly and time-consuming because we need to
/// request the actual file size from the remote server.
pub struct File {
    session: Arc<RawSftpSession>,
    handle: String,
    state: FileState,
    pos: u64,
    closed: bool,
    extensions: Arc<Extensions>,
}

impl File {
    pub(crate) fn new(
        session: Arc<RawSftpSession>,
        handle: String,
        extensions: Arc<Extensions>,
    ) -> Self {
        Self {
            session,
            handle,
            state: FileState {
                f_read: None,
                f_seek: None,
                f_write: None,
                f_flush: None,
                f_shutdown: None,
            },
            pos: 0,
            closed: false,
            extensions,
        }
    }

    /// Queries metadata about the remote file.
    pub async fn metadata(&self) -> SftpResult<Metadata> {
        Ok(self.session.fstat(self.handle.as_str()).await?.attrs)
    }

    /// Sets metadata for a remote file.
    pub async fn set_metadata(&self, metadata: Metadata) -> SftpResult<()> {
        self.session
            .fsetstat(self.handle.as_str(), metadata)
            .await
            .map(|_| ())
    }

    /// Attempts to sync all data.
    ///
    /// If the server does not support `fsync@openssh.com` sending the request will
    /// be omitted, but will still pseudo-successfully
    pub async fn sync_all(&self) -> SftpResult<()> {
        if !self.extensions.fsync {
            return Ok(());
        }

        self.session.fsync(self.handle.as_str()).await.map(|_| ())
    }

    /// Streams `reader` to this remote file with up to `max_inflight` concurrent
    /// SFTP `WRITE` requests in flight. Each request carries up to the negotiated
    /// `write_len` (or [`MAX_WRITE_LENGTH`] when no limit is advertised).
    ///
    /// The high-level [`AsyncWrite`] impl issues one `WRITE` at a time and waits
    /// for its `STATUS` reply before sending the next, so sustained throughput is
    /// bounded by `chunk_size / RTT`.  This helper hides the per-request RTT by
    /// keeping multiple in-flight, mirroring how OpenSSH's `sftp` client behaves
    /// (~64 outstanding requests by default).
    ///
    /// On success returns the number of bytes streamed.  Updates `self.pos` to
    /// the new write offset.  Reading from `reader` and dispatching writes are
    /// interleaved, so memory usage is bounded by `max_inflight * chunk_size`.
    pub async fn write_all_pipelined<R>(
        &mut self,
        reader: &mut R,
        max_inflight: usize,
    ) -> SftpResult<u64>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use futures::stream::{FuturesUnordered, StreamExt};
        use tokio::io::AsyncReadExt;

        if max_inflight == 0 {
            return Err(Error::UnexpectedBehavior(
                "max_inflight must be at least 1".to_owned(),
            ));
        }

        let chunk_size = bounded_chunk_size(
            self.extensions.limits.as_ref().and_then(|l| l.write_len),
            MAX_WRITE_LENGTH,
        );

        let mut total: u64 = 0;
        let mut offset = self.pos;
        let mut in_flight = FuturesUnordered::new();
        let mut eof = false;

        loop {
            // Top up the pipeline with new chunks until we hit the cap or EOF.
            while !eof && in_flight.len() < max_inflight {
                let mut buf = vec![0u8; chunk_size];
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    eof = true;
                    break;
                }
                buf.truncate(n);

                let session = self.session.clone();
                let handle = self.handle.clone();
                let off = offset;

                in_flight.push(async move {
                    session.write(handle, off, buf).await?;
                    SftpResult::Ok(n as u64)
                });

                offset += n as u64;
                total += n as u64;
            }

            // Drain at least one in-flight write before reading more, otherwise
            // we busy-loop the read path while writes never get a chance to make
            // progress.
            match in_flight.next().await {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => break, // pipeline drained and no more data -> done
            }
        }

        self.pos = offset;
        Ok(total)
    }

    /// Streams the remote file from the current position to `writer` using up to
    /// `max_inflight` concurrent SFTP `READ` requests.  Each request asks for up
    /// to the negotiated `read_len`, capped at [`MAX_READ_LENGTH`].
    ///
    /// Like [`Self::write_all_pipelined`], this hides per-request RTT.  Chunks
    /// are reassembled in offset order before being written to `writer`, so the
    /// output is identical to a sequential read.  For regular files, the current
    /// file size is used to avoid speculative reads beyond EOF; if the size is
    /// unavailable, the transfer stops on EOF or the first short read.
    ///
    /// Returns the number of bytes streamed.  Updates `self.pos`.
    pub async fn read_to_writer_pipelined<W>(
        &mut self,
        writer: &mut W,
        max_inflight: usize,
    ) -> SftpResult<u64>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use futures::stream::{FuturesUnordered, StreamExt};
        use std::collections::BTreeMap;
        use tokio::io::AsyncWriteExt;

        if max_inflight == 0 {
            return Err(Error::UnexpectedBehavior(
                "max_inflight must be at least 1".to_owned(),
            ));
        }

        let chunk_size = bounded_chunk_size(
            self.extensions.limits.as_ref().and_then(|l| l.read_len),
            MAX_READ_LENGTH,
        );
        let file_end = self
            .metadata()
            .await
            .ok()
            .and_then(|m| m.size)
            .filter(|&size| size >= self.pos);

        let mut total: u64 = 0;
        let mut next_offset = self.pos;
        let mut next_to_write = self.pos;
        let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut in_flight = FuturesUnordered::new();
        let mut eof = false;

        loop {
            // Keep the total reorder buffer bounded. A slow early read can make
            // later replies arrive first; counting both pending and in-flight
            // chunks prevents unbounded memory growth in that case.
            while !eof
                && in_flight.len() + pending.len() < max_inflight
                && file_end.is_none_or(|end| next_offset < end)
            {
                let session = self.session.clone();
                let handle = self.handle.clone();
                let off = next_offset;
                let len = file_end.map_or(chunk_size as u64, |end| {
                    (end - next_offset).min(chunk_size as u64)
                }) as u32;

                in_flight.push(async move {
                    match session.read(handle, off, len).await {
                        Ok(data) => SftpResult::Ok((off, len, Some(data.data))),
                        Err(Error::Status(s)) if s.status_code == StatusCode::Eof => {
                            SftpResult::Ok((off, len, None))
                        }
                        Err(e) => Err(e),
                    }
                });

                next_offset += u64::from(len);
            }

            match in_flight.next().await {
                Some(Ok((off, len, Some(data)))) => {
                    if data.is_empty() {
                        eof = true;
                    } else {
                        if let Some(end) = file_end {
                            let got_end = off.saturating_add(data.len() as u64);
                            if data.len() != len as usize || got_end > end {
                                return Err(Error::UnexpectedBehavior(format!(
                                    "short read before EOF at offset {off}: requested {len} bytes, received {} bytes",
                                    data.len()
                                )));
                            }
                        } else if data.len() < len as usize {
                            eof = true;
                        }

                        pending.insert(off, data);
                    }
                }
                Some(Ok((off, _, None))) => {
                    if file_end.is_some_and(|end| off < end) {
                        return Err(Error::UnexpectedBehavior(format!(
                            "unexpected EOF before file size at offset {off}"
                        )));
                    }
                    eof = true;
                }
                Some(Err(e)) => return Err(e),
                None => break,
            }

            // Flush in-order chunks to writer as they become available.
            while let Some(chunk) = pending.remove(&next_to_write) {
                let n = chunk.len() as u64;
                writer.write_all(&chunk).await?;
                next_to_write += n;
                total += n;
            }
        }

        self.pos = next_to_write;
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{Arc, Mutex},
    };

    use tokio::io::duplex;

    use super::*;
    use crate::{
        client::SftpSession,
        protocol::{Attrs, Data, FileAttributes, Handle, OpenFlags, Status, Version},
        server,
        server::Handler,
    };

    struct MemoryHandler {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl MemoryHandler {
        fn ok_status(id: u32) -> Status {
            Status {
                id,
                status_code: StatusCode::Ok,
                error_message: String::new(),
                language_tag: String::new(),
            }
        }
    }

    impl Handler for MemoryHandler {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        fn init(
            &mut self,
            _version: u32,
            _extensions: std::collections::HashMap<String, String>,
        ) -> impl Future<Output = Result<Version, Self::Error>> + Send {
            async { Ok(Version::new()) }
        }

        fn open(
            &mut self,
            id: u32,
            _filename: String,
            _pflags: OpenFlags,
            _attrs: FileAttributes,
        ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
            async move {
                Ok(Handle {
                    id,
                    handle: "memory".to_owned(),
                })
            }
        }

        fn close(
            &mut self,
            id: u32,
            _handle: String,
        ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
            async move { Ok(Self::ok_status(id)) }
        }

        fn fstat(
            &mut self,
            id: u32,
            _handle: String,
        ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
            let data = self.data.clone();

            async move {
                let mut attrs = FileAttributes::empty();
                attrs.size = Some(data.lock().expect("memory file lock poisoned").len() as u64);
                Ok(Attrs { id, attrs })
            }
        }

        fn read(
            &mut self,
            id: u32,
            _handle: String,
            offset: u64,
            len: u32,
        ) -> impl Future<Output = Result<Data, Self::Error>> + Send {
            let data = self.data.clone();

            async move {
                let data = data.lock().expect("memory file lock poisoned");
                let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
                if offset >= data.len() {
                    return Err(StatusCode::Eof);
                }
                let end = offset.saturating_add(len as usize).min(data.len());

                Ok(Data {
                    id,
                    data: data[offset..end].to_vec(),
                })
            }
        }

        fn write(
            &mut self,
            id: u32,
            _handle: String,
            offset: u64,
            bytes: Vec<u8>,
        ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
            let data = self.data.clone();

            async move {
                let mut data = data.lock().expect("memory file lock poisoned");
                let offset = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
                let end = offset.checked_add(bytes.len()).ok_or(StatusCode::Failure)?;
                if data.len() < end {
                    data.resize(end, 0);
                }
                data[offset..end].copy_from_slice(&bytes);

                Ok(Self::ok_status(id))
            }
        }
    }

    async fn memory_session(data: Arc<Mutex<Vec<u8>>>) -> SftpSession {
        let (client, server_stream) = duplex(64 * 1024);
        server::run(server_stream, MemoryHandler { data }).await;
        SftpSession::new(client).await.expect("memory SFTP init")
    }

    #[test]
    fn advertised_chunk_sizes_are_capped() {
        assert_eq!(
            bounded_chunk_size(None, MAX_READ_LENGTH),
            MAX_READ_LENGTH as usize
        );
        assert_eq!(bounded_chunk_size(Some(1024), MAX_READ_LENGTH), 1024);
        assert_eq!(
            bounded_chunk_size(Some(MAX_READ_LENGTH * 4), MAX_READ_LENGTH),
            MAX_READ_LENGTH as usize
        );
    }

    #[tokio::test]
    async fn write_all_pipelined_streams_all_bytes() {
        let remote_data = Arc::new(Mutex::new(Vec::new()));
        let sftp = memory_session(remote_data.clone()).await;
        let input: Vec<u8> = (0..(MAX_WRITE_LENGTH as usize * 2 + 123))
            .map(|n| (n % 251) as u8)
            .collect();
        let mut reader = &input[..];
        let mut file = sftp
            .open_with_flags(
                "ignored",
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .expect("open memory file");

        let written = file
            .write_all_pipelined(&mut reader, 4)
            .await
            .expect("pipelined write");

        assert_eq!(written as usize, input.len());
        assert_eq!(
            *remote_data.lock().expect("memory file lock poisoned"),
            input
        );
    }

    #[tokio::test]
    async fn read_to_writer_pipelined_streams_all_bytes() {
        let input: Vec<u8> = (0..(MAX_READ_LENGTH as usize * 2 + 123))
            .map(|n| (n % 251) as u8)
            .collect();
        let remote_data = Arc::new(Mutex::new(input.clone()));
        let sftp = memory_session(remote_data).await;
        let mut file = sftp.open("ignored").await.expect("open memory file");
        let mut output = Vec::new();

        let read = file
            .read_to_writer_pipelined(&mut output, 4)
            .await
            .expect("pipelined read");

        assert_eq!(read as usize, input.len());
        assert_eq!(output, input);
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if self.closed {
            return;
        }

        if let Ok(handle) = Handle::try_current() {
            let session = self.session.clone();
            let file_handle = self.handle.clone();

            handle.spawn(async move {
                let _ = session.close(file_handle).await;
            });
        }
    }
}

impl AsyncRead for File {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let poll = Pin::new(match self.state.f_read.as_mut() {
            Some(f) => f,
            None => {
                let session = self.session.clone();
                let max_read_len = self
                    .extensions
                    .limits
                    .as_ref()
                    .and_then(|l| l.read_len)
                    .unwrap_or(MAX_READ_LENGTH) as usize;

                let file_handle = self.handle.clone();

                let offset = self.pos;
                let len = if buf.remaining() > max_read_len {
                    max_read_len
                } else {
                    buf.remaining()
                };

                self.state.f_read.get_or_insert(Box::pin(async move {
                    let result = session.read(file_handle, offset, len as u32).await;

                    match result {
                        Ok(data) => Ok(Some(data.data)),
                        Err(Error::Status(status)) if status.status_code == StatusCode::Eof => {
                            Ok(None)
                        }
                        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
                    }
                }))
            }
        })
        .poll(cx);

        if poll.is_ready() {
            self.state.f_read = None;
        }

        match poll {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(Some(data))) => {
                self.pos += data.len() as u64;
                buf.put_slice(&data[..]);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncSeek for File {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        match self.state.f_seek {
            Some(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "other file operation is pending, call poll_complete before start_seek",
            )),
            None => {
                let session = self.session.clone();
                let file_handle = self.handle.clone();
                let cur_pos = self.pos as i64;

                self.state.f_seek = Some(Box::pin(async move {
                    let new_pos = match position {
                        SeekFrom::Start(pos) => pos as i64,
                        SeekFrom::Current(pos) => cur_pos + pos,
                        SeekFrom::End(pos) => {
                            let result = session
                                .fstat(file_handle)
                                .await
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                            match result.attrs.size {
                                Some(size) => size as i64 + pos,
                                None => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        "file size unknown",
                                    ))
                                }
                            }
                        }
                    };

                    if new_pos < 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "cannot move file pointer before the beginning",
                        ));
                    }

                    Ok(new_pos as u64)
                }));

                Ok(())
            }
        }
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match self.state.f_seek.as_mut() {
            None => Poll::Ready(Ok(self.pos)),
            Some(f) => {
                self.pos = ready!(Pin::new(f).poll(cx))?;
                self.state.f_seek = None;
                Poll::Ready(Ok(self.pos))
            }
        }
    }
}

impl AsyncWrite for File {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let poll = Pin::new(match self.state.f_write.as_mut() {
            Some(f) => f,
            None => {
                let session = self.session.clone();
                let max_write_len = self
                    .extensions
                    .limits
                    .as_ref()
                    .and_then(|l| l.write_len)
                    .unwrap_or(MAX_WRITE_LENGTH) as usize;

                let file_handle = self.handle.clone();
                let data = buf.to_vec();

                let offset = self.pos;
                let len = if data.len() > max_write_len {
                    max_write_len
                } else {
                    data.len()
                };

                self.state.f_write.get_or_insert(Box::pin(async move {
                    session
                        .write(file_handle, offset, data[..len].to_vec())
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    Ok(len)
                }))
            }
        })
        .poll(cx);

        if poll.is_ready() {
            self.state.f_write = None;
        }

        if let Poll::Ready(Ok(len)) = poll {
            self.pos += len as u64;
        }

        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if !self.extensions.fsync {
            return Poll::Ready(Ok(()));
        }

        let poll = Pin::new(match self.state.f_flush.as_mut() {
            Some(f) => f,
            None => {
                let session = self.session.clone();
                let file_handle = self.handle.clone();

                self.state.f_flush.get_or_insert(Box::pin(async move {
                    session
                        .fsync(file_handle)
                        .await
                        .map(|_| ())
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
                }))
            }
        })
        .poll(cx);

        if poll.is_ready() {
            self.state.f_flush = None;
        }

        poll
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let poll = Pin::new(match self.state.f_shutdown.as_mut() {
            Some(f) => f,
            None => {
                let session = self.session.clone();
                let file_handle = self.handle.clone();

                self.state.f_shutdown.get_or_insert(Box::pin(async move {
                    session
                        .close(file_handle)
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    Ok(())
                }))
            }
        })
        .poll(cx);

        if poll.is_ready() {
            self.state.f_shutdown = None;
            self.closed = true;
        }

        poll
    }
}
