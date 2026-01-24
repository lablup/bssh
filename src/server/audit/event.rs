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

//! Audit event types for logging security and operational events.
//!
//! This module defines the core audit event types used throughout the SSH server
//! to track authentication, file operations, and other security-relevant activities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Audit event for logging security and operational events.
///
/// Each audit event represents a single discrete action or occurrence
/// that should be tracked for compliance, security monitoring, or debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: String,

    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,

    /// Type of event
    pub event_type: EventType,

    /// Session ID associated with this event
    pub session_id: String,

    /// Username associated with this event
    pub user: String,

    /// Client IP address (if available)
    pub client_ip: Option<IpAddr>,

    /// File path for file operations
    pub path: Option<PathBuf>,

    /// Destination path for rename/copy operations
    pub dest_path: Option<PathBuf>,

    /// Number of bytes transferred
    pub bytes: Option<u64>,

    /// Result of the operation
    pub result: EventResult,

    /// Additional details about the event
    pub details: Option<String>,

    /// Protocol used (ssh, sftp, scp)
    pub protocol: Option<String>,
}

/// Type of audit event.
///
/// This enum categorizes different types of security and operational events
/// that can occur in the SSH server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Authentication events
    /// Successful authentication
    AuthSuccess,
    /// Failed authentication attempt
    AuthFailure,
    /// Authentication rate limited
    AuthRateLimited,

    // Session events
    /// Session started
    SessionStart,
    /// Session ended
    SessionEnd,

    // Command execution
    /// Command executed
    CommandExecuted,
    /// Command blocked by policy
    CommandBlocked,

    // File operations
    /// File opened for reading
    FileOpenRead,
    /// File opened for writing
    FileOpenWrite,
    /// File read operation
    FileRead,
    /// File write operation
    FileWrite,
    /// File closed
    FileClose,
    /// File uploaded
    FileUploaded,
    /// File downloaded
    FileDownloaded,
    /// File deleted
    FileDeleted,
    /// File renamed
    FileRenamed,

    // Directory operations
    /// Directory created
    DirectoryCreated,
    /// Directory deleted
    DirectoryDeleted,
    /// Directory listed
    DirectoryListed,

    // Filter events
    /// Transfer denied by filter
    TransferDenied,
    /// Transfer allowed
    TransferAllowed,

    // Security events
    /// IP address blocked
    IpBlocked,
    /// IP address unblocked
    IpUnblocked,
    /// Suspicious activity detected
    SuspiciousActivity,
}

/// Result of an audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventResult {
    /// Operation succeeded
    Success,
    /// Operation failed
    Failure,
    /// Operation denied by policy
    Denied,
    /// Operation resulted in error
    Error,
}

impl AuditEvent {
    /// Create a new audit event with the minimum required fields.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Type of event
    /// * `user` - Username associated with the event
    /// * `session_id` - Session ID
    ///
    /// # Example
    ///
    /// ```
    /// use bssh::server::audit::event::{AuditEvent, EventType};
    ///
    /// let event = AuditEvent::new(
    ///     EventType::AuthSuccess,
    ///     "alice".to_string(),
    ///     "session-123".to_string(),
    /// );
    /// ```
    pub fn new(event_type: EventType, user: String, session_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            session_id,
            user,
            client_ip: None,
            path: None,
            dest_path: None,
            bytes: None,
            result: EventResult::Success,
            details: None,
            protocol: None,
        }
    }

    /// Set the client IP address.
    pub fn with_client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Set the file path.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the destination path (for rename/copy operations).
    pub fn with_dest_path(mut self, dest_path: PathBuf) -> Self {
        self.dest_path = Some(dest_path);
        self
    }

    /// Set the number of bytes transferred.
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Set the operation result.
    pub fn with_result(mut self, result: EventResult) -> Self {
        self.result = result;
        self
    }

    /// Set additional details.
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Set the protocol.
    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = Some(protocol.to_string());
        self
    }
}

impl Default for AuditEvent {
    fn default() -> Self {
        Self::new(EventType::CommandExecuted, String::new(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "alice".to_string(),
            "session-123".to_string(),
        );

        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert_eq!(event.user, "alice");
        assert_eq!(event.session_id, "session-123");
        assert_eq!(event.result, EventResult::Success);
        assert!(event.client_ip.is_none());
        assert!(event.path.is_none());
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_audit_event_builder() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let event = AuditEvent::new(
            EventType::FileUploaded,
            "bob".to_string(),
            "session-456".to_string(),
        )
        .with_client_ip(ip)
        .with_path(PathBuf::from("/home/bob/file.txt"))
        .with_bytes(1024)
        .with_result(EventResult::Success)
        .with_protocol("sftp")
        .with_details("Upload completed".to_string());

        assert_eq!(event.client_ip, Some(ip));
        assert_eq!(event.path, Some(PathBuf::from("/home/bob/file.txt")));
        assert_eq!(event.bytes, Some(1024));
        assert_eq!(event.result, EventResult::Success);
        assert_eq!(event.protocol, Some("sftp".to_string()));
        assert_eq!(event.details, Some("Upload completed".to_string()));
    }

    #[test]
    fn test_event_type_serialization() {
        let event_type = EventType::AuthSuccess;
        let serialized = serde_json::to_string(&event_type).unwrap();
        assert_eq!(serialized, r#""auth_success""#);

        let deserialized: EventType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, EventType::AuthSuccess);
    }

    #[test]
    fn test_event_result_serialization() {
        let result = EventResult::Denied;
        let serialized = serde_json::to_string(&result).unwrap();
        assert_eq!(serialized, r#""denied""#);

        let deserialized: EventResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, EventResult::Denied);
    }

    #[test]
    fn test_full_event_serialization() {
        let event = AuditEvent::new(
            EventType::SessionStart,
            "charlie".to_string(),
            "session-789".to_string(),
        )
        .with_client_ip("10.0.0.1".parse().unwrap())
        .with_protocol("ssh");

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.user, event.user);
        assert_eq!(deserialized.session_id, event.session_id);
        assert_eq!(deserialized.client_ip, event.client_ip);
        assert_eq!(deserialized.protocol, event.protocol);
    }

    #[test]
    fn test_default_event() {
        let event = AuditEvent::default();
        assert_eq!(event.event_type, EventType::CommandExecuted);
        assert_eq!(event.result, EventResult::Success);
        assert!(event.user.is_empty());
        assert!(event.session_id.is_empty());
    }

    #[test]
    fn test_event_with_dest_path() {
        let event = AuditEvent::new(
            EventType::FileRenamed,
            "dave".to_string(),
            "session-101".to_string(),
        )
        .with_path(PathBuf::from("/home/dave/old.txt"))
        .with_dest_path(PathBuf::from("/home/dave/new.txt"));

        assert_eq!(event.path, Some(PathBuf::from("/home/dave/old.txt")));
        assert_eq!(event.dest_path, Some(PathBuf::from("/home/dave/new.txt")));
    }
}
