//! `SftpClient::upload_from` must keep the durability step bssh's uploads have
//! always had: `fsync@openssh.com` after the last WRITE and before CLOSE when
//! the server offers it, and no fsync request when it does not.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bssh::server::sftp_loop;
use bssh::ssh::tokio_client::sftp_client::SftpClient;
use russh_sftp::protocol::{Handle, OpenFlags, Packet, Status, StatusCode, Version};

#[derive(Clone)]
struct RecordingHandler {
    offer_fsync: bool,
    ops: Arc<Mutex<Vec<String>>>,
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: "en-US".to_owned(),
    }
}

impl russh_sftp::server::Handler for RecordingHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut version = Version::new();
        if self.offer_fsync {
            version
                .extensions
                .insert("fsync@openssh.com".to_owned(), "1".to_owned());
        }
        Ok(version)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _pflags: OpenFlags,
        _attrs: russh_sftp::protocol::FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.ops.lock().unwrap().push("open".to_owned());
        Ok(Handle {
            id,
            handle: filename,
        })
    }

    async fn write(
        &mut self,
        id: u32,
        _handle: String,
        _offset: u64,
        _data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.ops.lock().unwrap().push("write".to_owned());
        Ok(ok(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        _data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        self.ops.lock().unwrap().push(request);
        Ok(Packet::Status(ok(id)))
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        self.ops.lock().unwrap().push("close".to_owned());
        Ok(ok(id))
    }
}

async fn upload_ops(offer_fsync: bool) -> Vec<String> {
    let ops = Arc::new(Mutex::new(Vec::new()));
    let handler = RecordingHandler {
        offer_fsync,
        ops: Arc::clone(&ops),
    };
    let (client, server) = tokio::io::duplex(1 << 20);
    sftp_loop::run(server, handler).await;
    let sftp = SftpClient::new(client).await.expect("session should start");

    let payload = vec![7u8; 300_000];
    let written = sftp
        .upload_from(
            &mut payload.as_slice(),
            "file.bin",
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            8,
        )
        .await
        .expect("upload should succeed");
    assert_eq!(written as usize, payload.len());

    sftp.close().await.expect("session should close");
    let ops = ops.lock().unwrap().clone();
    assert_eq!(ops.first().map(String::as_str), Some("open"));
    assert!(ops.iter().any(|op| op == "write"));
    ops
}

#[tokio::test]
async fn upload_fsyncs_before_close_when_offered() {
    let ops = upload_ops(true).await;
    let tail = &ops[ops.len() - 2..];
    assert_eq!(tail, ["fsync@openssh.com", "close"], "ops: {ops:?}");
}

#[tokio::test]
async fn upload_skips_fsync_when_not_offered() {
    let ops = upload_ops(false).await;
    assert!(
        !ops.iter().any(|op| op == "fsync@openssh.com"),
        "ops: {ops:?}"
    );
    assert_eq!(ops.last().map(String::as_str), Some("close"));
}
