use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bssh::server::sftp::{SftpError, SftpHandler};
use bssh::shared::auth_types::UserInfo;
use russh_sftp::client::{Config as ClientConfig, RawSftpSession, SftpSession};
use russh_sftp::extensions::{self, LimitsExtension};
use russh_sftp::protocol::{
    Attrs, Data, ExtendedReply, FileAttributes, Handle, OpenFlags, Packet, Status, StatusCode,
    Version,
};
use tokio::io::AsyncWriteExt;

const BSSH_MAX_READ_LEN: u64 = 261_120;
const BSSH_MAX_HANDLES: u64 = 1_000;
const MAX_INFLIGHT: usize = 64;
const READ_OVERHEAD_LEN: u32 = 9;
const WRITE_OVERHEAD_LEN: u32 = 21;
const SMALL_CLIENT_PACKET_LEN: u32 = 1_024;

async fn sftp_session_with_handler<H>(handler: H) -> SftpSession
where
    H: russh_sftp::server::Handler + Send + 'static,
{
    sftp_session_with_handler_and_configs(
        handler,
        ClientConfig::default(),
        russh_sftp::server::Config::default(),
    )
    .await
}

async fn sftp_session_with_handler_and_config<H>(handler: H, cfg: ClientConfig) -> SftpSession
where
    H: russh_sftp::server::Handler + Send + 'static,
{
    sftp_session_with_handler_and_configs(handler, cfg, russh_sftp::server::Config::default()).await
}

async fn sftp_session_with_handler_and_configs<H>(
    handler: H,
    cfg: ClientConfig,
    server_cfg: russh_sftp::server::Config,
) -> SftpSession
where
    H: russh_sftp::server::Handler + Send + 'static,
{
    let (client, server) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run_with_config(server, handler, server_cfg).await;
    SftpSession::new_with_config(client, cfg)
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

#[derive(Clone, Default)]
struct ObservedChunks {
    reads: Arc<Mutex<Vec<u32>>>,
    writes: Arc<Mutex<Vec<usize>>>,
}

struct HugeAdvertisedLimitsHandler {
    data: Vec<u8>,
    observed: ObservedChunks,
}

impl HugeAdvertisedLimitsHandler {
    fn new(data: Vec<u8>, observed: ObservedChunks) -> Self {
        Self { data, observed }
    }
}

impl russh_sftp::server::Handler for HugeAdvertisedLimitsHandler {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError::not_supported()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut version = Version::new();
        version
            .extensions
            .insert(extensions::LIMITS.to_owned(), "1".to_owned());
        Ok(version)
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        _data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        if request != extensions::LIMITS {
            return Err(SftpError::not_supported());
        }

        let data = russh_sftp::ser::to_bytes(&LimitsExtension {
            max_packet_len: u64::MAX,
            max_read_len: u64::MAX,
            max_write_len: u64::MAX,
            max_open_handles: u64::MAX,
        })
        .map(|bytes| bytes.to_vec())
        .map_err(|err| SftpError::failure(err.to_string()))?;

        Ok(Packet::ExtendedReply(ExtendedReply { id, data }))
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
            handle: "huge".to_owned(),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        if handle != "huge" {
            return Err(SftpError::invalid_handle());
        }

        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(self.data.len() as u64),
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
        if handle != "huge" {
            return Err(SftpError::invalid_handle());
        }
        self.observed
            .reads
            .lock()
            .expect("reads mutex poisoned")
            .push(len);
        if offset >= self.data.len() as u64 {
            return Err(SftpError::eof());
        }

        let start = offset as usize;
        let end = start.saturating_add(len as usize).min(self.data.len());
        Ok(Data {
            id,
            data: self.data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        _offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if handle != "huge" {
            return Err(SftpError::invalid_handle());
        }
        self.observed
            .writes
            .lock()
            .expect("writes mutex poisoned")
            .push(data.len());
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: String::new(),
            language_tag: "en-US".to_owned(),
        })
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

#[tokio::test]
async fn client_clamps_advertised_read_limit_to_packet_payload() {
    let observed = ObservedChunks::default();
    let expected = payload((SMALL_CLIENT_PACKET_LEN as usize * 3) + 17);
    let sftp = sftp_session_with_handler_and_config(
        HugeAdvertisedLimitsHandler::new(expected.clone(), observed.clone()),
        ClientConfig {
            max_packet_len: SMALL_CLIENT_PACKET_LEN,
            ..ClientConfig::default()
        },
    )
    .await;

    let mut remote = sftp
        .open("ignored.bin")
        .await
        .expect("read-limit file should open");
    let mut downloaded = Vec::new();
    remote
        .read_to_writer_pipelined(&mut downloaded, 3)
        .await
        .expect("oversized advertised read limit should be clamped");

    let expected_max = SMALL_CLIENT_PACKET_LEN - READ_OVERHEAD_LEN;
    let read_lengths = observed.reads.lock().expect("reads mutex poisoned").clone();
    assert!(
        !read_lengths.is_empty(),
        "handler should observe at least one read"
    );
    assert_eq!(read_lengths[0], expected_max);
    assert!(
        read_lengths.iter().all(|&len| len <= expected_max),
        "read requests exceeded packet payload ceiling: {read_lengths:?}"
    );
    assert_eq!(downloaded, expected);
}

#[tokio::test]
async fn client_clamps_advertised_write_limit_to_packet_payload() {
    let observed = ObservedChunks::default();
    let data = payload((SMALL_CLIENT_PACKET_LEN as usize * 3) + 29);
    let sftp = sftp_session_with_handler_and_configs(
        HugeAdvertisedLimitsHandler::new(Vec::new(), observed.clone()),
        ClientConfig {
            max_packet_len: SMALL_CLIENT_PACKET_LEN,
            ..ClientConfig::default()
        },
        russh_sftp::server::Config {
            max_write_coalesce_len: 0,
            ..russh_sftp::server::Config::default()
        },
    )
    .await;

    let mut remote = sftp
        .create("ignored.bin")
        .await
        .expect("write-limit file should open");
    let (mut reader, mut writer) = tokio::io::duplex(2 * SMALL_CLIENT_PACKET_LEN as usize);
    let payload_for_writer = data.clone();
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
        .write_all_pipelined(&mut reader, 3)
        .await
        .expect("oversized advertised write limit should be clamped");
    writer_task
        .await
        .expect("payload writer task should finish");

    let expected_max = SMALL_CLIENT_PACKET_LEN - (WRITE_OVERHEAD_LEN + 4);
    let write_lengths = observed
        .writes
        .lock()
        .expect("writes mutex poisoned")
        .clone();
    assert_eq!(written as usize, data.len());
    assert!(
        !write_lengths.is_empty(),
        "handler should observe at least one write"
    );
    assert_eq!(write_lengths[0], expected_max as usize);
    assert!(
        write_lengths
            .iter()
            .all(|&len| len <= expected_max as usize),
        "write requests exceeded packet payload ceiling: {write_lengths:?}"
    );
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

struct EmptyDataBeforeEofHandler {
    data: Vec<u8>,
}

impl russh_sftp::server::Handler for EmptyDataBeforeEofHandler {
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
            handle: "empty".to_owned(),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        if handle != "empty" {
            return Err(SftpError::invalid_handle());
        }
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(self.data.len() as u64),
                ..FileAttributes::default()
            },
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        _len: u32,
    ) -> Result<Data, Self::Error> {
        if handle != "empty" {
            return Err(SftpError::invalid_handle());
        }
        if offset == 0 {
            return Ok(Data {
                id,
                data: Vec::new(),
            });
        }
        Err(SftpError::eof())
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
async fn read_to_writer_rejects_empty_data_before_known_eof() {
    let expected = payload(1024);
    let sftp = sftp_session_with_handler(EmptyDataBeforeEofHandler { data: expected }).await;
    let mut remote = sftp
        .open("ignored.bin")
        .await
        .expect("empty-read file should open");
    let mut downloaded = Vec::new();

    let err = remote
        .read_to_writer_pipelined(&mut downloaded, 4)
        .await
        .expect_err("empty DATA before known EOF must not truncate successfully");

    assert!(
        err.to_string()
            .contains("unexpected empty read before file size"),
        "unexpected error: {err}"
    );
    assert!(downloaded.is_empty());
    remote
        .close()
        .await
        .expect("empty-read handle should close");
    sftp.close()
        .await
        .expect("empty-read session should shut down cleanly");
}
