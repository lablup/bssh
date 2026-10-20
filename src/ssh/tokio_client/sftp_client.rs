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

//! Pipelined SFTP client used by bssh's file transfers.
//!
//! Built on russh-sftp's public [`RawSftpSession`], so bssh controls how many
//! requests stay in flight and how large each one is. russh-sftp's own `File`
//! pipelines too, but with a small default window (16 requests of up to
//! 32 KiB writes) that leaves WAN transfers latency-bound; these helpers keep
//! a caller-chosen depth of full-size requests outstanding instead.

use std::collections::BTreeMap;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use russh_sftp::client::Config;
use russh_sftp::client::RawSftpSession;
use russh_sftp::client::error::Error;
use russh_sftp::client::rawsession::{Limits, SftpResult};
use russh_sftp::extensions;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// READ reply framing: packet_len(4) + type(1) + id(4) + data_len(4).
const READ_OVERHEAD_LENGTH: u32 = 13;
/// WRITE request framing without the handle bytes: packet_len(4) + type(1) +
/// id(4) + handle_len(4) + offset(8) + data_len(4).
const WRITE_OVERHEAD_LENGTH: u32 = 25;

/// Transfer parameters negotiated when the session starts.
#[derive(Debug, Clone, Copy)]
struct Negotiated {
    max_packet_len: u32,
    limits: Option<Limits>,
    /// Whether the server offers `fsync@openssh.com` version 1.
    fsync: bool,
}

/// An SFTP session with pipelined file transfers.
pub struct SftpClient {
    session: Arc<RawSftpSession>,
    negotiated: Negotiated,
}

/// One entry returned by [`SftpClient::read_dir`], excluding `.` and `..`.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub attrs: FileAttributes,
}

impl SftpClient {
    /// Start an SFTP session on `stream` with russh-sftp's default client config.
    pub async fn new<S>(stream: S) -> SftpResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_with_config(stream, Config::default()).await
    }

    /// Start an SFTP session, negotiating `limits@openssh.com` and
    /// `fsync@openssh.com` when offered.
    pub async fn new_with_config<S>(stream: S, cfg: Config) -> SftpResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let max_packet_len = cfg.max_packet_len;
        let mut session = RawSftpSession::new_with_config(stream, cfg);
        let version = session.init().await?;
        let has_extension =
            |name: &str, ver: &str| version.extensions.get(name).is_some_and(|v| v == ver);
        let mut negotiated = Negotiated {
            max_packet_len,
            limits: None,
            fsync: has_extension(extensions::FSYNC, "1"),
        };

        if has_extension(extensions::LIMITS, "1") {
            let limits = Limits::from(session.limits().await?);
            session.set_limits(limits);
            negotiated.limits = Some(limits);
            if let Some(packet_len) = limits.packet_len {
                negotiated.max_packet_len = u32::try_from(packet_len)
                    .map_or(negotiated.max_packet_len, |len| {
                        len.min(negotiated.max_packet_len)
                    });
            }
        }

        Ok(Self {
            session: Arc::new(session),
            negotiated,
        })
    }

    /// Set the per-request response timeout in seconds.
    pub fn set_timeout(&self, secs: u64) {
        self.session.set_timeout(secs);
    }

    /// Open `path` read-only.
    pub async fn open(&self, path: impl Into<String>) -> SftpResult<RemoteFile> {
        self.open_with_flags(path, OpenFlags::READ).await
    }

    /// Create or truncate `path` for writing.
    pub async fn create(&self, path: impl Into<String>) -> SftpResult<RemoteFile> {
        self.open_with_flags(
            path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
    }

    /// Open `path` with explicit flags.
    pub async fn open_with_flags(
        &self,
        path: impl Into<String>,
        flags: OpenFlags,
    ) -> SftpResult<RemoteFile> {
        let handle = self
            .session
            .open(path, flags, FileAttributes::empty())
            .await?
            .handle;
        Ok(RemoteFile {
            session: Arc::clone(&self.session),
            handle,
            negotiated: self.negotiated,
            pos: 0,
            closed: false,
        })
    }

    /// Upload `reader` to `remote` opened with `flags`: pipelined WRITEs, then
    /// `fsync@openssh.com` when the server offers it, then a confirmed close.
    /// Returns the number of bytes written.
    pub async fn upload_from<R>(
        &self,
        reader: &mut R,
        remote: impl Into<String>,
        flags: OpenFlags,
        max_inflight: usize,
    ) -> SftpResult<u64>
    where
        R: AsyncRead + Unpin,
    {
        let mut file = self.open_with_flags(remote, flags).await?;
        let written = file.write_all_pipelined(reader, max_inflight).await?;
        file.sync_all().await?;
        file.close().await?;
        Ok(written)
    }

    /// Create a remote directory.
    pub async fn create_dir(&self, path: impl Into<String>) -> SftpResult<()> {
        self.session
            .mkdir(path, FileAttributes::empty())
            .await
            .map(|_| ())
    }

    /// List a remote directory, excluding `.` and `..`.
    pub async fn read_dir(&self, path: impl Into<String>) -> SftpResult<Vec<DirEntry>> {
        let handle = self.session.opendir(path).await?.handle;
        let mut entries = Vec::new();
        let listing = loop {
            match self.session.readdir(handle.as_str()).await {
                Ok(name) => entries.extend(
                    name.files
                        .into_iter()
                        .filter(|file| file.filename != "." && file.filename != "..")
                        .map(|file| DirEntry {
                            name: file.filename,
                            attrs: file.attrs,
                        }),
                ),
                Err(Error::Status(status)) if status.status_code == StatusCode::Eof => {
                    break Ok(entries);
                }
                Err(error) => break Err(error),
            }
        };
        let closed = self.session.close(handle).await;
        let entries = listing?;
        closed?;
        Ok(entries)
    }

    /// Close the SFTP channel stream.
    pub async fn close(&self) -> SftpResult<()> {
        self.session.close_session()
    }
}

/// An open remote file handle with pipelined transfer helpers.
///
/// Call [`RemoteFile::close`] to release the handle and observe the server's
/// reply. A handle dropped without it is closed in the background.
pub struct RemoteFile {
    session: Arc<RawSftpSession>,
    handle: String,
    negotiated: Negotiated,
    pos: u64,
    closed: bool,
}

impl RemoteFile {
    fn effective_read_len(&self) -> SftpResult<usize> {
        let packet_payload = self
            .negotiated
            .max_packet_len
            .saturating_sub(READ_OVERHEAD_LENGTH);
        let advertised = self
            .negotiated
            .limits
            .and_then(|limits| limits.read_len)
            .unwrap_or(u64::from(packet_payload));
        let effective = advertised
            .min(u64::from(packet_payload))
            .min(u64::from(u32::MAX));

        if effective == 0 {
            return Err(Error::UnexpectedBehavior(
                "effective SFTP read payload length is zero".to_owned(),
            ));
        }

        Ok(effective as usize)
    }

    fn effective_write_len(&self) -> SftpResult<usize> {
        let handle_len = u32::try_from(self.handle.len()).map_err(|_| {
            Error::UnexpectedBehavior("SFTP handle length exceeds protocol limit".to_owned())
        })?;
        let overhead = WRITE_OVERHEAD_LENGTH
            .checked_add(handle_len)
            .ok_or_else(|| {
                Error::UnexpectedBehavior(
                    "SFTP write packet overhead exceeds protocol limit".to_owned(),
                )
            })?;
        let packet_payload = self.negotiated.max_packet_len.saturating_sub(overhead);
        let advertised = self
            .negotiated
            .limits
            .and_then(|limits| limits.write_len)
            .unwrap_or(u64::from(packet_payload));
        let effective = advertised
            .min(u64::from(packet_payload))
            .min(u64::from(u32::MAX));

        if effective == 0 {
            return Err(Error::UnexpectedBehavior(
                "effective SFTP write payload length is zero".to_owned(),
            ));
        }

        Ok(effective as usize)
    }

    /// Streams `reader` to this remote file with up to `max_inflight` concurrent
    /// SFTP `WRITE` requests in flight. Each request carries up to the negotiated
    /// `write_len` (or the per-handle packet ceiling when no limit is advertised).
    ///
    /// This hides the per-request RTT by driving the reader and dispatching
    /// WRITEs in lockstep, mirroring how OpenSSH's `sftp` client behaves (~64
    /// outstanding requests by default).
    ///
    /// On success returns the number of bytes streamed and advances the file
    /// position. Reading from `reader` and dispatching writes are interleaved,
    /// so memory usage is bounded by `max_inflight * chunk_size`.
    pub async fn write_all_pipelined<R>(
        &mut self,
        reader: &mut R,
        max_inflight: usize,
    ) -> SftpResult<u64>
    where
        R: AsyncRead + Unpin,
    {
        if max_inflight == 0 {
            return Err(Error::UnexpectedBehavior(
                "max_inflight must be at least 1".to_owned(),
            ));
        }

        let chunk_size = self.effective_write_len()?;

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

                let session = Arc::clone(&self.session);
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
    /// file size is used to avoid speculative reads beyond EOF, short reads
    /// before it are retried for the missing range, and an empty reply before
    /// it is an error; if the size is unavailable, the transfer stops on EOF
    /// or the first short read.
    ///
    /// Returns the number of bytes streamed and advances the file position.
    pub async fn read_to_writer_pipelined<W>(
        &mut self,
        writer: &mut W,
        max_inflight: usize,
    ) -> SftpResult<u64>
    where
        W: AsyncWrite + Unpin,
    {
        if max_inflight == 0 {
            return Err(Error::UnexpectedBehavior(
                "max_inflight must be at least 1".to_owned(),
            ));
        }

        let chunk_size = self.effective_read_len()?;
        let file_end = self
            .session
            .fstat(self.handle.as_str())
            .await
            .ok()
            .and_then(|attrs| attrs.attrs.size)
            .filter(|&size| size >= self.pos);

        let mut total: u64 = 0;
        let mut next_offset = self.pos;
        let mut next_to_write = self.pos;
        let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut in_flight = FuturesUnordered::new();
        let mut eof = false;
        let read_request = |session: Arc<RawSftpSession>, handle: String, off: u64, len: u32| async move {
            match session.read(handle, off, len).await {
                Ok(data) => SftpResult::Ok((off, len, Some(data.data))),
                Err(Error::Status(s)) if s.status_code == StatusCode::Eof => {
                    SftpResult::Ok((off, len, None))
                }
                Err(e) => Err(e),
            }
        };

        loop {
            while !eof
                && in_flight.len() + pending.len() < max_inflight
                && file_end.is_none_or(|end| next_offset < end)
            {
                let session = Arc::clone(&self.session);
                let handle = self.handle.clone();
                let off = next_offset;
                let len = file_end.map_or(chunk_size as u64, |end| {
                    (end - next_offset).min(chunk_size as u64)
                }) as u32;

                in_flight.push(read_request(session, handle, off, len));

                next_offset += u64::from(len);
            }

            match in_flight.next().await {
                Some(Ok((off, len, Some(data)))) => {
                    if data.is_empty() {
                        if file_end.is_some_and(|end| off < end) {
                            return Err(Error::UnexpectedBehavior(format!(
                                "unexpected empty read before file size at offset {off}"
                            )));
                        }
                        eof = true;
                    } else {
                        if data.len() > len as usize {
                            return Err(Error::UnexpectedBehavior(format!(
                                "read returned more data than requested at offset {off}: requested {len} bytes, received {} bytes",
                                data.len()
                            )));
                        }

                        if let Some(end) = file_end {
                            let got_end = off.saturating_add(data.len() as u64);
                            if got_end > end {
                                return Err(Error::UnexpectedBehavior(format!(
                                    "read returned data past known EOF at offset {off}: requested {len} bytes, received {} bytes",
                                    data.len()
                                )));
                            }
                            if data.len() < len as usize && got_end < end {
                                let remaining = u64::from(len) - data.len() as u64;
                                let retry_len = remaining.min(u64::from(u32::MAX)) as u32;
                                let session = Arc::clone(&self.session);
                                let handle = self.handle.clone();
                                in_flight.push(read_request(session, handle, got_end, retry_len));
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

    /// Ask the server to flush this file to stable storage with
    /// `fsync@openssh.com`. A no-op when the server does not offer it.
    pub async fn sync_all(&self) -> SftpResult<()> {
        if !self.negotiated.fsync {
            return Ok(());
        }
        self.session.fsync(self.handle.as_str()).await.map(|_| ())
    }

    /// Close the handle and wait for the server to confirm it.
    pub async fn close(mut self) -> SftpResult<()> {
        self.closed = true;
        self.session.close(self.handle.as_str()).await.map(|_| ())
    }
}

impl Drop for RemoteFile {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Release the server-side handle even when a transfer failed midway.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let session = Arc::clone(&self.session);
            let handle = std::mem::take(&mut self.handle);
            runtime.spawn(async move {
                let _ = session.close(handle).await;
            });
        }
    }
}
