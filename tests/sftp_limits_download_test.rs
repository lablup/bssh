use std::collections::HashMap;
use std::path::PathBuf;

use bssh::server::sftp::{SftpError, SftpHandler};
use bssh::shared::auth_types::UserInfo;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, OpenFlags, Packet, Status, StatusCode, Version,
};
use tokio::io::AsyncWriteExt;

const BSSH_MAX_READ_LEN: u64 = 261_120;
const BSSH_MAX_HANDLES: u64 = 1_000;
const MAX_INFLIGHT: usize = 64;

async fn sftp_session_with_handler<H>(handler: H) -> SftpSession
where
    H: russh_sftp::server::Handler + Send + 'static,
{
    let (client, server) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run(server, handler).await;
    SftpSession::new(client)
        .await
        .expect("SFTP session should initialize")
}

async fn raw_session_with_handler<H>(handler: H) -> RawSftpSession
where
    H: russh_sftp::server::Handler + Send + 'static,
{
    let (client, server) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run(server, handler).await;
    RawSftpSession::new(client)
}

fn bssh_handler(root: PathBuf) -> SftpHandler {
    SftpHandler::new(UserInfo::new("testuser"), None, root)
}

fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((i.wrapping_mul(31) ^ (i >> 7)) & 0xff) as u8)
        .collect()
}

async fn upload_payload(sftp: &SftpSession, path: &str, payload: &[u8]) {
    let mut remote = sftp
        .open_with_flags(
            path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
        )
        .await
        .expect("remote file should open for upload");
    let (mut reader, mut writer) = tokio::io::duplex(64 * 1024);
    let payload_for_writer = payload.to_vec();
    let writer_task = tokio::spawn(async move {
        writer
            .write_all(&payload_for_writer)
            .await
            .expect("payload should feed upload reader");
        writer
            .shutdown()
            .await
            .expect("payload reader should close");
    });

    let written = remote
        .write_all_pipelined(&mut reader, MAX_INFLIGHT)
        .await
        .expect("pipelined upload should complete");
    writer_task
        .await
        .expect("payload writer task should finish");
    assert_eq!(written as usize, payload.len());
    remote
        .close()
        .await
        .expect("remote upload handle should close");
}

async fn download_payload(sftp: &SftpSession, path: &str) -> Vec<u8> {
    let mut remote = sftp
        .open(path)
        .await
        .expect("remote file should open for download");
    let mut downloaded = Vec::new();
    let read = remote
        .read_to_writer_pipelined(&mut downloaded, MAX_INFLIGHT)
        .await
        .expect("pipelined download should complete");
    assert_eq!(read as usize, downloaded.len());
    remote
        .close()
        .await
        .expect("remote download handle should close");
    downloaded
}

#[tokio::test]
async fn bssh_server_advertises_limits_extension() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let raw = raw_session_with_handler(bssh_handler(dir.path().to_path_buf())).await;

    let version = raw.init().await.expect("init should return version");
    assert_eq!(
        version
            .extensions
            .get(russh_sftp::extensions::LIMITS)
            .map(String::as_str),
        Some("1")
    );

    let limits = raw.limits().await.expect("limits extension should reply");
    assert_eq!(
        limits.max_packet_len,
        u64::from(russh_sftp::server::Config::default().max_client_packet_len)
    );
    assert_eq!(limits.max_read_len, BSSH_MAX_READ_LEN);
    assert_eq!(limits.max_write_len, BSSH_MAX_READ_LEN);
    assert_eq!(limits.max_open_handles, BSSH_MAX_HANDLES);

    match raw
        .extended("unsupported@example.com", Vec::new())
        .await
        .expect("unsupported extension should receive a status reply")
    {
        Packet::Status(status) => assert_eq!(status.status_code, StatusCode::OpUnsupported),
        other => panic!("expected unsupported extension status, got {other:?}"),
    }

    raw.close_session()
        .expect("raw SFTP session should shut down cleanly");
}

#[tokio::test]
async fn bssh_to_bssh_pipelined_round_trip_above_read_cap() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let sftp = sftp_session_with_handler(bssh_handler(dir.path().to_path_buf())).await;

    for (name, size) in [("payload-300k.bin", 300_000), ("payload-2m.bin", 2_100_123)] {
        let expected = payload(size);
        upload_payload(&sftp, name, &expected).await;
        let downloaded = download_payload(&sftp, name).await;
        assert_eq!(
            downloaded, expected,
            "downloaded payload must match for {name}"
        );
    }

    sftp.close()
        .await
        .expect("high-level SFTP session should shut down cleanly");
}

struct ShortReadHandler {
    data: Vec<u8>,
    max_chunk: usize,
}

impl ShortReadHandler {
    fn new(data: Vec<u8>, max_chunk: usize) -> Self {
        Self { data, max_chunk }
    }
}

impl russh_sftp::server::Handler for ShortReadHandler {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::not_supported()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        _filename: String,
        _pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        Ok(Handle {
            id,
            handle: "short".to_owned(),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let len = self.data.len() as u64;
        if handle != "short" {
            return Err(SftpError::invalid_handle());
        }
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(len),
                ..FileAttributes::default()
            },
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        if handle != "short" {
            Err(SftpError::invalid_handle())
        } else if offset >= self.data.len() as u64 {
            Err(SftpError::eof())
        } else {
            let start = offset as usize;
            let requested_end = start.saturating_add(len as usize).min(self.data.len());
            let short_end = start
                .saturating_add(self.max_chunk)
                .min(requested_end)
                .min(self.data.len());
            Ok(Data {
                id,
                data: self.data[start..short_end].to_vec(),
            })
        }
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: "en-US".to_owned(),
        })
    }
}

#[tokio::test]
async fn read_to_writer_retries_short_reads_before_known_eof() {
    let expected = payload(300_000);
    let sftp = sftp_session_with_handler(ShortReadHandler::new(expected.clone(), 57_000)).await;
    let mut remote = sftp
        .open("ignored.bin")
        .await
        .expect("short-read file should open");
    let mut downloaded = Vec::new();

    let read = remote
        .read_to_writer_pipelined(&mut downloaded, 4)
        .await
        .expect("short reads before EOF should be retried");

    assert_eq!(read as usize, expected.len());
    assert_eq!(downloaded, expected);
    remote
        .close()
        .await
        .expect("short-read handle should close");
    sftp.close()
        .await
        .expect("short-read session should shut down cleanly");
}
