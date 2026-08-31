// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::forwarding::ForwardingDirective;
use crate::ssh::SessionPolicy;
use crate::ssh::tokio_client::AddressFamily;

use super::ControlCommand;

/// Version of bssh's length-prefixed JSON multiplexing protocol.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
/// Largest accepted serialized control message.
pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
/// Largest binary chunk carried in one data message.
pub const MAX_CONTROL_DATA_BYTES: usize = 64 * 1024;
const MAX_CONTROL_ENVIRONMENT_ENTRIES: usize = 4_096;

/// One framed message on a bssh control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ControlMessage {
    Request(ControlRequest),
    Response(ControlResponse),
    Data(ControlData),
}

impl ControlMessage {
    fn validate(&self) -> Result<(), ControlProtocolError> {
        match self {
            Self::Request(request) => request.validate(),
            Self::Response(_) => Ok(()),
            Self::Data(data) => data.validate(),
        }
    }
}

/// Correlated client-to-master request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    pub request_id: u64,
    pub operation: ControlOperation,
}

impl ControlRequest {
    /// Validate semantic limits that cannot be expressed by the JSON frame
    /// length alone.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        match &self.operation {
            ControlOperation::Hello { version } if *version != CONTROL_PROTOCOL_VERSION => {
                Err(ControlProtocolError::UnsupportedVersion {
                    received: *version,
                    supported: CONTROL_PROTOCOL_VERSION,
                })
            }
            ControlOperation::Hello { .. } => Ok(()),
            ControlOperation::OpenSession(session) => session.validate(),
            ControlOperation::Command {
                command, forwards, ..
            } => match command {
                ControlCommand::Forward | ControlCommand::Cancel if forwards.is_empty() => {
                    Err(ControlProtocolError::MissingForwarding(*command))
                }
                ControlCommand::Check | ControlCommand::Exit | ControlCommand::Stop
                    if !forwards.is_empty() =>
                {
                    Err(ControlProtocolError::UnexpectedForwarding(*command))
                }
                _ => Ok(()),
            },
        }
    }
}

/// Request operation understood by a bssh control master.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ControlOperation {
    Hello {
        version: u32,
    },
    OpenSession(SessionOpenRequest),
    Command {
        command: ControlCommand,
        /// Raw directives in original CLI/config order.
        forwards: Vec<ForwardingDirective>,
        /// Address family used when the master parses raw forwarding specs.
        address_family: AddressFamily,
    },
}

/// Session policy transferred to the authenticated control master.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOpenRequest {
    pub policy: SessionPolicy,
    /// Client-side terminal name used when `policy.request_pty` is true.
    pub terminal: Option<String>,
}

impl SessionOpenRequest {
    /// Build a wire request. `LocalCommand` must execute in the invoking client
    /// process, never in the long-lived master.
    pub fn new(
        policy: SessionPolicy,
        terminal: Option<String>,
    ) -> Result<Self, ControlProtocolError> {
        let request = Self { policy, terminal };
        request.validate()?;
        Ok(request)
    }

    /// Enforce limits before sending or accepting a session request.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.policy.local_command.is_some() {
            return Err(ControlProtocolError::LocalCommandNotAllowed);
        }
        if self.policy.environment.len() > MAX_CONTROL_ENVIRONMENT_ENTRIES {
            return Err(ControlProtocolError::TooManyEnvironmentEntries {
                count: self.policy.environment.len(),
                maximum: MAX_CONTROL_ENVIRONMENT_ENTRIES,
            });
        }
        Ok(())
    }
}

/// Correlated master-to-client response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResponse {
    pub request_id: u64,
    pub kind: ControlResponseKind,
}

/// Result variants needed by #286's session and five control commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ControlResponseKind {
    Ok,
    Alive { pid: u32 },
    SessionOpened { session_id: u64 },
    ExitStatus { session_id: u64, status: u32 },
    Error { code: String, message: String },
}

/// Byte stream represented by a data message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ControlDataStream {
    Stdin,
    Stdout,
    Stderr,
}

/// Ordered session data or EOF indication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlData {
    pub session_id: u64,
    pub stream: ControlDataStream,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub eof: bool,
}

impl ControlData {
    /// Validate the per-message binary payload limit.
    pub fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.payload.len() > MAX_CONTROL_DATA_BYTES {
            return Err(ControlProtocolError::DataTooLarge {
                length: self.payload.len(),
                maximum: MAX_CONTROL_DATA_BYTES,
            });
        }
        Ok(())
    }
}

/// Serialize and write one bounded big-endian-length-prefixed JSON message.
pub async fn write_control_message<W>(
    writer: &mut W,
    message: &ControlMessage,
) -> Result<(), ControlProtocolError>
where
    W: AsyncWrite + Unpin,
{
    message.validate()?;
    let encoded = serde_json::to_vec(message)?;
    if encoded.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlProtocolError::FrameTooLarge {
            length: encoded.len(),
            maximum: MAX_CONTROL_FRAME_BYTES,
        });
    }
    let length = u32::try_from(encoded.len()).map_err(|_| ControlProtocolError::FrameTooLarge {
        length: encoded.len(),
        maximum: MAX_CONTROL_FRAME_BYTES,
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

/// Read, decode, and validate one bounded big-endian-length-prefixed JSON
/// message without allocating an attacker-declared oversized frame.
pub async fn read_control_message<R>(reader: &mut R) -> Result<ControlMessage, ControlProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(ControlProtocolError::EmptyFrame);
    }
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlProtocolError::FrameTooLarge {
            length,
            maximum: MAX_CONTROL_FRAME_BYTES,
        });
    }

    let mut encoded = vec![0u8; length];
    reader.read_exact(&mut encoded).await?;
    let message = serde_json::from_slice::<ControlMessage>(&encoded)?;
    message.validate()?;
    Ok(message)
}

/// Framing, serialization, version, or semantic-limit failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ControlProtocolError {
    #[error("control socket I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("control message JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control protocol frame must not be empty")]
    EmptyFrame,
    #[error("control protocol frame is {length} bytes, exceeding the {maximum}-byte limit")]
    FrameTooLarge { length: usize, maximum: usize },
    #[error("control data chunk is {length} bytes, exceeding the {maximum}-byte limit")]
    DataTooLarge { length: usize, maximum: usize },
    #[error("control protocol version {received} is unsupported; this build supports {supported}")]
    UnsupportedVersion { received: u32, supported: u32 },
    #[error(
        "LocalCommand must execute in the invoking process and cannot be sent to a control master"
    )]
    LocalCommandNotAllowed,
    #[error("session request contains {count} environment entries; maximum is {maximum}")]
    TooManyEnvironmentEntries { count: usize, maximum: usize },
    #[error("control command '{0}' requires at least one forwarding directive")]
    MissingForwarding(ControlCommand),
    #[error("control command '{0}' does not accept forwarding directives")]
    UnexpectedForwarding(ControlCommand),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::SessionRequest;

    fn session_policy() -> SessionPolicy {
        SessionPolicy {
            environment: vec![("LANG".into(), "C.UTF-8".into())],
            local_command: None,
            request_pty: false,
            stdin_null: false,
            request: SessionRequest::Exec("printf test".into()),
        }
    }

    #[tokio::test]
    async fn request_round_trip_preserves_session_policy() {
        let request = ControlMessage::Request(ControlRequest {
            request_id: 7,
            operation: ControlOperation::OpenSession(
                SessionOpenRequest::new(session_policy(), Some("xterm-256color".into()))
                    .expect("wire-safe session"),
            ),
        });
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let write = write_control_message(&mut client, &request);
        let read = read_control_message(&mut server);
        let (written, decoded) = tokio::join!(write, read);
        written.expect("write succeeds");
        assert_eq!(decoded.expect("read succeeds"), request);
    }

    #[tokio::test]
    async fn data_round_trip_is_binary_safe() {
        let message = ControlMessage::Data(ControlData {
            session_id: 9,
            stream: ControlDataStream::Stdout,
            sequence: 3,
            payload: vec![0, 255, b'\n', 0],
            eof: true,
        });
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let write = write_control_message(&mut client, &message);
        let read = read_control_message(&mut server);
        let (written, decoded) = tokio::join!(write, read);
        written.expect("write succeeds");
        assert_eq!(decoded.expect("read succeeds"), message);
    }

    #[tokio::test]
    async fn oversized_declared_frame_is_rejected_before_payload_read() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client
            .write_all(&((MAX_CONTROL_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .expect("header write");
        let error = read_control_message(&mut server)
            .await
            .expect_err("oversized frame");
        assert!(matches!(error, ControlProtocolError::FrameTooLarge { .. }));
    }

    #[tokio::test]
    async fn oversized_data_is_rejected_before_serialization() {
        let message = ControlMessage::Data(ControlData {
            session_id: 1,
            stream: ControlDataStream::Stdin,
            sequence: 0,
            payload: vec![0; MAX_CONTROL_DATA_BYTES + 1],
            eof: false,
        });
        let mut sink = tokio::io::sink();
        let error = write_control_message(&mut sink, &message)
            .await
            .expect_err("oversized data");
        assert!(matches!(error, ControlProtocolError::DataTooLarge { .. }));
    }

    #[test]
    fn local_command_cannot_cross_the_master_boundary() {
        let mut policy = session_policy();
        policy.local_command = Some("touch /tmp/client-only".into());
        assert!(matches!(
            SessionOpenRequest::new(policy, None),
            Err(ControlProtocolError::LocalCommandNotAllowed)
        ));
    }

    #[test]
    fn command_forwarding_shape_is_validated() {
        let missing = ControlRequest {
            request_id: 1,
            operation: ControlOperation::Command {
                command: ControlCommand::Forward,
                forwards: Vec::new(),
                address_family: AddressFamily::Any,
            },
        };
        assert!(matches!(
            missing.validate(),
            Err(ControlProtocolError::MissingForwarding(
                ControlCommand::Forward
            ))
        ));

        let unexpected = ControlRequest {
            request_id: 2,
            operation: ControlOperation::Command {
                command: ControlCommand::Check,
                forwards: vec![ForwardingDirective::Dynamic("1080".into())],
                address_family: AddressFamily::Any,
            },
        };
        assert!(matches!(
            unexpected.validate(),
            Err(ControlProtocolError::UnexpectedForwarding(
                ControlCommand::Check
            ))
        ));
    }
}
