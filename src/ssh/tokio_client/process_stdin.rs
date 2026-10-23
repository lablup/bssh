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

//! Cancel-safe process stdin for SSH protocol forwarding.

use std::io;

use tokio::io::AsyncRead;

pub(crate) type ProcessStdin = Box<dyn AsyncRead + Send + Unpin>;

/// Open process stdin without leaving an uncancellable blocking read behind.
///
/// Tokio's standard-input adapter uses its blocking thread pool. Dropping a
/// pending read does not stop that thread, so runtime shutdown can deadlock
/// when a protocol peer intentionally keeps the pipe open after the SSH
/// channel closes (for example, OpenSSH `scp -3`).
pub(crate) fn open() -> io::Result<ProcessStdin> {
    imp::open()
}

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::sys::stat::{SFlag, fstat};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, ReadBuf};

    use super::ProcessStdin;

    pub(super) fn open() -> io::Result<ProcessStdin> {
        let stdin = std::io::stdin();
        let fd = nix::unistd::dup(stdin.as_fd()).map_err(io::Error::from)?;
        from_owned_fd(fd)
    }

    fn from_owned_fd(fd: OwnedFd) -> io::Result<ProcessStdin> {
        let mode = fstat(fd.as_fd()).map_err(io::Error::from)?.st_mode;

        match pollable_stream_kind(mode) {
            Some(StreamKind::Pipe) => {
                // Register before mutating the shared file-description flags.
                // If registration fails, process stdin remains untouched.
                // SAFETY: fd is an OwnedFd moved into the AsyncFd, so the
                // descriptor stays open and unchanged until it is dropped.
                let fd = unsafe { AsyncFd::register(fd) }?;
                let restore_flags = set_pipe_nonblocking(fd.get_ref().as_fd())?;
                return Ok(Box::new(AsyncStreamInput {
                    fd,
                    kind: StreamKind::Pipe,
                    restore_flags,
                }));
            }
            Some(StreamKind::Socket) => {
                // SAFETY: as above, the OwnedFd is owned by the AsyncFd.
                let fd = unsafe { AsyncFd::register(fd) }?;
                return Ok(Box::new(AsyncStreamInput {
                    fd,
                    kind: StreamKind::Socket,
                    restore_flags: None,
                }));
            }
            None => {}
        }

        // Regular files do not wait indefinitely for new input, so Tokio's
        // file adapter is safe here. It also covers non-pollable devices.
        Ok(Box::new(tokio::fs::File::from_std(File::from(fd))))
    }

    #[derive(Clone, Copy)]
    enum StreamKind {
        Pipe,
        Socket,
    }

    fn pollable_stream_kind(mode: nix::sys::stat::mode_t) -> Option<StreamKind> {
        // File types are masked enum values, not independent flags. In
        // particular S_IFREG and S_IFSOCK share bits, so `intersects` would
        // misclassify regular redirected input as a socket on Linux.
        let file_type = SFlag::from_bits_truncate(mode) & SFlag::S_IFMT;
        if file_type == SFlag::S_IFIFO {
            Some(StreamKind::Pipe)
        } else if file_type == SFlag::S_IFSOCK {
            Some(StreamKind::Socket)
        } else {
            None
        }
    }

    fn set_pipe_nonblocking(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<Option<OFlag>> {
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
        let flags = OFlag::from_bits_truncate(flags);
        if flags & OFlag::O_ACCMODE != OFlag::O_RDONLY {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stdin FIFO must be opened read-only for cancel-safe forwarding",
            ));
        }
        if flags.contains(OFlag::O_NONBLOCK) {
            return Ok(None);
        }
        fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(io::Error::from)?;
        Ok(Some(flags))
    }

    struct AsyncStreamInput {
        fd: AsyncFd<OwnedFd>,
        kind: StreamKind,
        /// Status flags to restore when this reader added O_NONBLOCK to a
        /// read-only pipe. `dup` shares file status flags with process stdin.
        restore_flags: Option<OFlag>,
    }

    impl Drop for AsyncStreamInput {
        fn drop(&mut self) {
            if let Some(flags) = self.restore_flags {
                let _ = fcntl(self.fd.get_ref().as_fd(), FcntlArg::F_SETFL(flags));
            }
        }
    }

    impl AsyncRead for AsyncStreamInput {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = match self.fd.poll_read_ready(cx) {
                    Poll::Ready(Ok(guard)) => guard,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                };
                let unfilled = buf.initialize_unfilled();
                let result = unsafe {
                    // SAFETY: AsyncStreamInput owns this open descriptor and
                    // ReadBuf exposes a valid writable slice. Pipes are set
                    // nonblocking. Sockets use the per-call MSG_DONTWAIT flag
                    // because scp -3 connects stdin and stdout to the same
                    // socket and changing O_NONBLOCK would affect writes.
                    match self.kind {
                        StreamKind::Pipe => nix::libc::read(
                            self.fd.get_ref().as_raw_fd(),
                            unfilled.as_mut_ptr().cast(),
                            unfilled.len(),
                        ),
                        StreamKind::Socket => nix::libc::recv(
                            self.fd.get_ref().as_raw_fd(),
                            unfilled.as_mut_ptr().cast(),
                            unfilled.len(),
                            nix::libc::MSG_DONTWAIT,
                        ),
                    }
                };
                if result >= 0 {
                    // Retain readiness and keep draining until a nonblocking
                    // operation reports EAGAIN. Clearing after an arbitrary
                    // bounded read can lose an edge while buffered data
                    // remains, stalling protocol input indefinitely.
                    guard.retain_ready();
                    buf.advance(result as usize);
                    return Poll::Ready(Ok(()));
                }

                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    guard.retain_ready();
                    continue;
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(error));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs::OpenOptions;
        use std::io::{ErrorKind, Seek, SeekFrom, Write};
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;
        use socket2::SockRef;
        use tokio::io::AsyncReadExt;

        use super::{from_owned_fd, pollable_stream_kind};

        #[tokio::test]
        async fn pending_pipe_read_is_cancel_safe() {
            let (reader, writer) = nix::unistd::pipe().expect("create pipe");
            let flags_observer = nix::unistd::dup(reader.as_fd()).expect("duplicate pipe reader");
            let mut input = from_owned_fd(reader).expect("wrap pipe reader");
            let active_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read active pipe flags");
            assert!(active_flags.contains(OFlag::O_NONBLOCK));
            let read = tokio::spawn(async move {
                let mut byte = [0_u8; 1];
                input.read(&mut byte).await
            });

            tokio::task::yield_now().await;
            read.abort();
            let error = tokio::time::timeout(Duration::from_secs(1), read)
                .await
                .expect("cancelled read must not block runtime shutdown")
                .expect_err("aborted read unexpectedly completed");
            assert!(error.is_cancelled());
            let restored_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read restored pipe flags");
            assert!(!restored_flags.contains(OFlag::O_NONBLOCK));
            drop(writer);
        }

        #[tokio::test]
        async fn read_write_fifo_is_rejected_without_changing_shared_flags() {
            let directory = tempfile::tempdir().expect("create temporary directory");
            let path = directory.path().join("stdin.fifo");
            mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("create fifo");
            let fifo = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .expect("open fifo read-write");
            let flags_observer = nix::unistd::dup(fifo.as_fd()).expect("duplicate fifo");
            let original_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read original fifo flags");

            let error = from_owned_fd(fifo.into())
                .err()
                .expect("read-write fifo must fail closed");
            assert_eq!(error.kind(), ErrorKind::Unsupported);
            assert!(error.to_string().contains("opened read-only"));
            let final_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read final fifo flags");
            assert_eq!(final_flags, original_flags);
        }

        #[tokio::test]
        async fn consumed_readiness_does_not_block_the_runtime() {
            let (reader, writer) = nix::unistd::pipe().expect("create pipe");
            let mut input = from_owned_fd(reader).expect("wrap pipe reader");
            nix::unistd::write(&writer, &[7]).expect("seed pipe");

            let mut byte = [0_u8; 1];
            input.read_exact(&mut byte).await.expect("read seeded byte");
            assert_eq!(byte, [7]);

            let pending =
                tokio::time::timeout(Duration::from_millis(50), input.read_exact(&mut byte)).await;
            assert!(
                pending.is_err(),
                "a consumed readiness event must not trigger another blocking read"
            );

            drop(writer);
            assert_eq!(input.read(&mut byte).await.expect("read pipe EOF"), 0);
        }

        #[tokio::test]
        async fn regular_file_uses_file_input_and_remains_readable() {
            assert!(pollable_stream_kind(nix::libc::S_IFREG).is_none());

            let mut file = tempfile::tempfile().expect("create temporary input");
            file.write_all(b"redirected input")
                .expect("write temporary input");
            file.seek(SeekFrom::Start(0)).expect("rewind input");
            let mut input = from_owned_fd(file.into()).expect("wrap regular input");
            let mut contents = Vec::new();
            input
                .read_to_end(&mut contents)
                .await
                .expect("read regular input");
            assert_eq!(contents, b"redirected input");
        }

        #[tokio::test]
        async fn buffered_socket_is_drained_past_one_chunk_and_remains_cancel_safe() {
            const CHUNK_SIZE: usize = 32 * 1024;
            let payload = vec![0x5a; CHUNK_SIZE * 3];
            let (reader, mut writer) = UnixStream::pair().expect("create socket pair");
            SockRef::from(&reader)
                .set_recv_buffer_size(payload.len() * 2)
                .expect("enlarge receive buffer");
            SockRef::from(&writer)
                .set_send_buffer_size(payload.len() * 2)
                .expect("enlarge send buffer");
            writer
                .set_write_timeout(Some(Duration::from_secs(1)))
                .expect("bound socket prebuffer write");
            writer.write_all(&payload).expect("prebuffer socket input");

            let flags_observer = nix::unistd::dup(reader.as_fd()).expect("duplicate socket reader");
            let original_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read original socket flags");
            let mut input = from_owned_fd(reader.into()).expect("wrap socket reader");
            let active_flags = fcntl(flags_observer.as_fd(), FcntlArg::F_GETFL)
                .map(OFlag::from_bits_truncate)
                .expect("read active socket flags");
            assert_eq!(active_flags, original_flags);
            let mut received = Vec::with_capacity(payload.len());
            let mut chunk = [0_u8; CHUNK_SIZE];
            while received.len() < payload.len() {
                let count = tokio::time::timeout(Duration::from_secs(1), input.read(&mut chunk))
                    .await
                    .expect("buffered input must not lose its readiness edge")
                    .expect("read buffered socket input");
                assert_ne!(count, 0, "writer remains open until the test completes");
                received.extend_from_slice(&chunk[..count]);
            }
            assert_eq!(received, payload);

            let pending =
                tokio::time::timeout(Duration::from_millis(50), input.read(&mut chunk)).await;
            assert!(
                pending.is_err(),
                "an open writer without data must leave a cancel-safe pending read"
            );
            drop(writer);
            assert_eq!(input.read(&mut chunk).await.expect("read socket EOF"), 0);
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;

    use super::ProcessStdin;

    pub(super) fn open() -> io::Result<ProcessStdin> {
        Ok(Box::new(tokio::io::stdin()))
    }
}
