use std::{
    collections::VecDeque,
    future::{self, Future},
    io::{self, SeekFrom},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf},
    sync::oneshot,
};

use super::Metadata;
use crate::{
    client::{error::Error, rawsession::SftpResult, session::Features, RawSftpSession},
    protocol::{Packet, StatusCode},
};

type StateFn<T> = Option<Pin<Box<dyn Future<Output = io::Result<T>> + Send + Sync + 'static>>>;

// read packet overhead: type(1) + id(4) + data_len(4)
const READ_OVERHEAD_LENGTH: u32 = 9;
// write packet overhead excluding handle: type(1) + id(4) + handle_len(4) + offset(8) + data_len(4)
const WRITE_OVERHEAD_LENGTH: u32 = 21;

struct FileState {
    f_read: StateFn<Option<Vec<u8>>>,
    f_seek: StateFn<u64>,
    f_flush: StateFn<()>,
    f_shutdown: StateFn<()>,
    write_acks: VecDeque<oneshot::Receiver<SftpResult<Packet>>>,
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
    features: Features,
}

impl File {
    pub(crate) fn new(session: Arc<RawSftpSession>, handle: String, features: Features) -> Self {
        Self {
            session,
            handle,
            state: FileState {
                f_read: None,
                f_seek: None,
                f_flush: None,
                f_shutdown: None,
                write_acks: VecDeque::with_capacity(features.max_concurrent_writes),
            },
            pos: 0,
            closed: false,
            features,
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
        if !self.features.fsync {
            return Ok(());
        }

        self.session.fsync(self.handle.as_str()).await.map(|_| ())
    }

    /// Streams `reader` to this remote file with up to `max_inflight` concurrent
    /// SFTP `WRITE` requests in flight. Each request carries up to the negotiated
    /// `write_len` (or the per-handle packet ceiling when no limit is advertised).
    ///
    /// The high-level [`AsyncWrite`] impl can pipeline writes via the file's
    /// `write_acks` ring, but that path requires the caller to feed bytes via
    /// repeated `poll_write` calls. This helper hides the per-request RTT by
    /// driving the reader and dispatching WRITEs in lockstep, mirroring how
    /// OpenSSH's `sftp` client behaves (~64 outstanding requests by default).
    ///
    /// On success returns the number of bytes streamed. Updates `self.pos` to
    /// the new write offset. Reading from `reader` and dispatching writes are
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

        let chunk_size = self
            .features
            .limits
            .and_then(|l| l.write_len)
            .unwrap_or_else(|| {
                let overhead = WRITE_OVERHEAD_LENGTH + self.handle.len() as u32;
                self.features.max_packet_len.saturating_sub(overhead) as u64
            }) as usize;

        let mut total: u64 = 0;
        let mut offset = self.pos;
        let mut in_flight = FuturesUnordered::new();
        let mut eof = false;

        loop {
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

            match in_flight.next().await {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => break,
            }
        }

        self.pos = offset;
        Ok(total)
    }

    /// Streams the remote file from the current position to `writer` using up to
    /// `max_inflight` concurrent SFTP `READ` requests. Each request asks for up
    /// to the negotiated `read_len`, capped at the packet ceiling.
    ///
    /// Like [`Self::write_all_pipelined`], this hides per-request RTT. Chunks
    /// are reassembled in offset order before being written to `writer`, so the
    /// output is identical to a sequential read. For regular files, the current
    /// file size is used to avoid speculative reads beyond EOF; if the size is
    /// unavailable, the transfer stops on EOF or the first short read.
    ///
    /// Returns the number of bytes streamed. Updates `self.pos`.
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

        let chunk_size = self
            .features
            .limits
            .and_then(|l| l.read_len)
            .unwrap_or_else(|| {
                self.features
                    .max_packet_len
                    .saturating_sub(READ_OVERHEAD_LENGTH) as u64
            }) as usize;
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

fn check_write_result(
    result: Result<SftpResult<Packet>, oneshot::error::RecvError>,
) -> io::Result<()> {
    match result {
        Err(_) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "write channel closed",
        )),
        Ok(Ok(Packet::Status(s))) if s.status_code == StatusCode::Ok => Ok(()),
        Ok(Ok(Packet::Status(s))) => Err(io::Error::other(s.error_message)),
        Ok(Ok(_)) => Err(io::Error::other("unexpected response packet")),
        Ok(Err(e)) => Err(io::Error::other(e.to_string())),
    }
}

fn poll_oldest_write(
    pending: &mut VecDeque<oneshot::Receiver<SftpResult<Packet>>>,
    cx: &mut Context<'_>,
) -> Option<Poll<io::Result<()>>> {
    let rx = pending.front_mut()?;
    Some(match Pin::new(rx).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(r) => {
            pending.pop_front();
            Poll::Ready(check_write_result(r))
        }
    })
}

fn poll_drain_writes(
    pending: &mut VecDeque<oneshot::Receiver<SftpResult<Packet>>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while let Some(poll) = poll_oldest_write(pending, cx) {
        ready!(poll)?;
    }
    Poll::Ready(Ok(()))
}

impl Drop for File {
    fn drop(&mut self) {
        if self.closed {
            return;
        }

        let _ = self.session.close_nowait(std::mem::take(&mut self.handle));
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
                    .features
                    .limits
                    .and_then(|l| l.read_len)
                    .unwrap_or_else(|| {
                        self.features
                            .max_packet_len
                            .saturating_sub(READ_OVERHEAD_LENGTH) as u64
                    }) as usize;

                let file_handle = self.handle.clone();

                let offset = self.pos;
                let len = usize::min(buf.remaining(), max_read_len);

                self.state.f_read.get_or_insert(Box::pin(async move {
                    let result = session.read(file_handle, offset, len as u32).await;
                    match result {
                        Ok(data) => Ok(Some(data.data)),
                        Err(Error::Status(status)) if status.status_code == StatusCode::Eof => {
                            Ok(None)
                        }
                        Err(e) => Err(io::Error::other(e.to_string())),
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
        if self.state.f_seek.is_some() {
            return Err(io::Error::other(
                "other file operation is pending, call poll_complete before start_seek",
            ));
        }

        self.state.f_seek = Some(match position {
            SeekFrom::Start(pos) => Box::pin(future::ready(Ok(pos))),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::other(
                        "cannot move file pointer before the beginning",
                    ));
                }
                Box::pin(future::ready(Ok(new_pos as u64)))
            }
            SeekFrom::End(pos) => {
                let session = self.session.clone();
                let file_handle = self.handle.clone();

                Box::pin(async move {
                    let result = session
                        .fstat(file_handle)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    match result.attrs.size {
                        Some(size) => {
                            let new_pos = size as i64 + pos;
                            if new_pos < 0 {
                                return Err(io::Error::other(
                                    "cannot move file pointer before the beginning",
                                ));
                            }
                            Ok(new_pos as u64)
                        }
                        None => Err(io::Error::other("file size unknown")),
                    }
                })
            }
        });

        Ok(())
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
        if self.state.write_acks.len() >= self.features.max_concurrent_writes {
            if let Some(poll) = poll_oldest_write(&mut self.state.write_acks, cx) {
                ready!(poll)?;
            }
        }

        let max_write_len = self
            .features
            .limits
            .and_then(|l| l.write_len)
            .unwrap_or_else(|| {
                let overhead = WRITE_OVERHEAD_LENGTH + self.handle.len() as u32;
                self.features.max_packet_len.saturating_sub(overhead) as u64
            }) as usize;

        let len = usize::min(buf.len(), max_write_len);
        let data = buf[..len].to_vec();
        let handle = self.handle.clone();
        let offset = self.pos;

        match self.session.write_nowait(handle, offset, data) {
            Ok(rx) => {
                self.pos += len as u64;
                self.state.write_acks.push_back(rx);
                Poll::Ready(Ok(len))
            }
            Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        ready!(poll_drain_writes(&mut self.state.write_acks, cx))?;

        if !self.features.fsync {
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
                        .map_err(|e| io::Error::other(e.to_string()))
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
        ready!(poll_drain_writes(&mut self.state.write_acks, cx))?;

        let poll = Pin::new(match self.state.f_shutdown.as_mut() {
            Some(f) => f,
            None => {
                let session = self.session.clone();
                let file_handle = self.handle.clone();

                self.state.f_shutdown.get_or_insert(Box::pin(async move {
                    session
                        .close(file_handle)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))?;
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
