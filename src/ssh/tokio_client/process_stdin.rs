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

        if is_pipe_or_socket(mode) {
            return Ok(Box::new(AsyncPipeInput {
                fd: AsyncFd::new(fd)?,
            }));
        }

        // Regular files do not wait indefinitely for new input, so Tokio's
        // file adapter is safe here. It also covers non-pollable devices.
        Ok(Box::new(tokio::fs::File::from_std(File::from(fd))))
    }

    fn is_pipe_or_socket(mode: nix::sys::stat::mode_t) -> bool {
        // File types are masked enum values, not independent flags. In
        // particular S_IFREG and S_IFSOCK share bits, so `intersects` would
        // misclassify regular redirected input as a socket on Linux.
        let file_type = SFlag::from_bits_truncate(mode) & SFlag::S_IFMT;
        file_type == SFlag::S_IFIFO || file_type == SFlag::S_IFSOCK
    }

    struct AsyncPipeInput {
        fd: AsyncFd<OwnedFd>,
    }

    impl AsyncRead for AsyncPipeInput {
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
                    // SAFETY: AsyncPipeInput owns this open descriptor, and
                    // ReadBuf exposes a valid writable slice for this call.
                    // This is the process's sole reader and readiness has
                    // already been observed, so the read cannot block. We
                    // deliberately preserve the descriptor's status flags:
                    // scp -3 connects stdin and stdout to the same socket,
                    // and O_NONBLOCK would otherwise affect protocol writes.
                    nix::libc::read(
                        self.fd.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if result >= 0 {
                    // The descriptor intentionally remains in blocking mode
                    // so a shared stdin/stdout socket keeps blocking writes.
                    // Consume Tokio's cached readiness now; otherwise the
                    // next poll would issue another blocking read before the
                    // SSH transport gets a chance to flush this input.
                    guard.clear_ready();
                    buf.advance(result as usize);
                    return Poll::Ready(Ok(()));
                }

                let error = io::Error::last_os_error();
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
        use std::io::{Seek, SeekFrom, Write};
        use std::time::Duration;

        use tokio::io::AsyncReadExt;

        use super::{from_owned_fd, is_pipe_or_socket};

        #[tokio::test]
        async fn pending_pipe_read_is_cancel_safe() {
            let (reader, writer) = nix::unistd::pipe().expect("create pipe");
            let mut input = from_owned_fd(reader).expect("wrap pipe reader");
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
            drop(writer);
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
            assert!(!is_pipe_or_socket(nix::libc::S_IFREG));

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
