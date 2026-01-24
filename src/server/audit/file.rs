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

//! File-based audit exporter implementation.
//!
//! This module provides a file-based audit exporter that writes audit events
//! in JSON Lines format. It supports log rotation and optional gzip compression.

use super::event::AuditEvent;
use super::exporter::AuditExporter;
use anyhow::Result;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;

/// Configuration for file rotation.
#[derive(Debug, Clone)]
pub struct RotateConfig {
    /// Maximum file size in bytes before rotation
    pub max_size: u64,
    /// Maximum number of backup files to keep
    pub max_backups: usize,
    /// Compress rotated files with gzip
    pub compress: bool,
}

impl Default for RotateConfig {
    fn default() -> Self {
        Self {
            max_size: 100 * 1024 * 1024, // 100 MB
            max_backups: 5,
            compress: true,
        }
    }
}

impl RotateConfig {
    /// Create a new rotation configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum file size before rotation.
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size;
        self
    }

    /// Set the maximum number of backup files to keep.
    pub fn with_max_backups(mut self, max_backups: usize) -> Self {
        self.max_backups = max_backups;
        self
    }

    /// Enable or disable gzip compression for rotated files.
    pub fn with_compress(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }
}

/// File-based audit exporter that writes events in JSON Lines format.
///
/// Each event is written as a single JSON object on its own line, making it
/// easy to parse and process with standard tools.
///
/// # Features
///
/// - Append mode to preserve existing data
/// - Optional log rotation based on file size
/// - Optional gzip compression for rotated files
/// - Thread-safe using async Mutex
/// - Async I/O using tokio
///
/// # Example
///
/// ```no_run
/// use bssh::server::audit::file::{FileExporter, RotateConfig};
/// use std::path::Path;
///
/// # async fn example() -> anyhow::Result<()> {
/// let exporter = FileExporter::new(Path::new("/var/log/audit.log"))?;
///
/// // With rotation
/// let rotate_config = RotateConfig::new()
///     .with_max_size(50 * 1024 * 1024)
///     .with_max_backups(10)
///     .with_compress(true);
///
/// let exporter = FileExporter::new(Path::new("/var/log/audit.log"))?
///     .with_rotation(rotate_config);
/// # Ok(())
/// # }
/// ```
pub struct FileExporter {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    rotate_config: Option<RotateConfig>,
}

impl FileExporter {
    /// Create a new file exporter.
    ///
    /// The file is opened in append mode and created if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the audit log file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or created.
    pub fn new(path: &Path) -> Result<Self> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            writer: Mutex::new(BufWriter::new(File::from_std(file))),
            rotate_config: None,
        })
    }

    /// Enable log rotation with the given configuration.
    pub fn with_rotation(mut self, config: RotateConfig) -> Self {
        self.rotate_config = Some(config);
        self
    }

    /// Check if the file should be rotated and perform rotation if needed.
    async fn check_rotation(&self) -> Result<()> {
        if let Some(ref config) = self.rotate_config {
            // Flush to ensure accurate size check
            {
                let mut writer = self.writer.lock().await;
                writer.flush().await?;
            }

            let metadata = tokio::fs::metadata(&self.path).await?;
            if metadata.len() >= config.max_size {
                self.rotate(config).await?;
            }
        }
        Ok(())
    }

    /// Rotate the log file.
    ///
    /// This method:
    /// 1. Flushes and closes the current writer
    /// 2. Shifts existing backup files (file.log.N -> file.log.N+1)
    /// 3. Renames current file to file.log.1
    /// 4. Optionally compresses the renamed file
    /// 5. Deletes the oldest backup if exceeding max_backups
    /// 6. Reopens the file for writing
    async fn rotate(&self, config: &RotateConfig) -> Result<()> {
        // Flush and close current writer
        {
            let mut writer = self.writer.lock().await;
            writer.flush().await?;
        }

        // Rotate existing backup files: file.log.N -> file.log.N+1
        for i in (1..config.max_backups).rev() {
            let old_path = if config.compress {
                format!("{}.{}.gz", self.path.display(), i)
            } else {
                format!("{}.{}", self.path.display(), i)
            };

            let new_path = if config.compress {
                format!("{}.{}.gz", self.path.display(), i + 1)
            } else {
                format!("{}.{}", self.path.display(), i + 1)
            };

            if tokio::fs::metadata(&old_path).await.is_ok() {
                tokio::fs::rename(&old_path, &new_path).await?;
            }
        }

        // Move current file to .1
        let backup_path = format!("{}.1", self.path.display());
        tokio::fs::rename(&self.path, &backup_path).await?;

        // Compress if configured
        if config.compress {
            self.compress_file(&backup_path).await?;
        }

        // Delete oldest backup if it exceeds max_backups
        let oldest = if config.compress {
            format!("{}.{}.gz", self.path.display(), config.max_backups + 1)
        } else {
            format!("{}.{}", self.path.display(), config.max_backups + 1)
        };
        let _ = tokio::fs::remove_file(&oldest).await;

        // Reopen file for writing
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;

        let mut writer = self.writer.lock().await;
        *writer = BufWriter::new(file);

        Ok(())
    }

    /// Compress a file using gzip and delete the original.
    async fn compress_file(&self, path: &str) -> Result<()> {
        use async_compression::tokio::write::GzipEncoder;

        let input = tokio::fs::read(path).await?;
        let compressed_path = format!("{}.gz", path);

        let file = tokio::fs::File::create(&compressed_path).await?;
        let mut encoder = GzipEncoder::new(file);
        encoder.write_all(&input).await?;
        encoder.shutdown().await?;

        tokio::fs::remove_file(path).await?;
        Ok(())
    }
}

#[async_trait]
impl AuditExporter for FileExporter {
    async fn export(&self, event: AuditEvent) -> Result<()> {
        self.check_rotation().await?;

        let json = serde_json::to_string(&event)?;

        let mut writer = self.writer.lock().await;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        Ok(())
    }

    async fn export_batch(&self, events: &[AuditEvent]) -> Result<()> {
        self.check_rotation().await?;

        let mut writer = self.writer.lock().await;

        for event in events {
            let json = serde_json::to_string(event)?;
            writer.write_all(json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.flush().await?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::audit::event::{EventResult, EventType};
    use std::net::IpAddr;
    use tempfile::TempDir;

    async fn create_test_exporter() -> (FileExporter, TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let exporter = FileExporter::new(&log_path).unwrap();
        (exporter, temp_dir, log_path)
    }

    #[tokio::test]
    async fn test_file_exporter_creation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let result = FileExporter::new(&log_path);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_exporter_write_event() {
        let (exporter, _temp_dir, log_path) = create_test_exporter().await;

        let event = AuditEvent::new(
            EventType::AuthSuccess,
            "test_user".to_string(),
            "session-123".to_string(),
        );

        let result = exporter.export(event).await;
        assert!(result.is_ok());

        exporter.flush().await.unwrap();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(content.contains("test_user"));
        assert!(content.contains("session-123"));
        assert!(content.contains("auth_success"));
    }

    #[tokio::test]
    async fn test_file_exporter_json_lines_format() {
        let (exporter, _temp_dir, log_path) = create_test_exporter().await;

        let event1 = AuditEvent::new(
            EventType::FileUploaded,
            "alice".to_string(),
            "sess-001".to_string(),
        )
        .with_bytes(1024);

        let event2 = AuditEvent::new(
            EventType::AuthFailure,
            "bob".to_string(),
            "sess-002".to_string(),
        )
        .with_result(EventResult::Failure);

        exporter.export(event1).await.unwrap();
        exporter.export(event2).await.unwrap();
        exporter.flush().await.unwrap();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON
        let json1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let json2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(json1["user"], "alice");
        assert_eq!(json2["user"], "bob");
    }

    #[tokio::test]
    async fn test_file_exporter_batch() {
        let (exporter, _temp_dir, log_path) = create_test_exporter().await;

        let events = vec![
            AuditEvent::new(
                EventType::SessionStart,
                "user1".to_string(),
                "session-1".to_string(),
            ),
            AuditEvent::new(
                EventType::SessionEnd,
                "user2".to_string(),
                "session-2".to_string(),
            ),
        ];

        exporter.export_batch(&events).await.unwrap();
        exporter.flush().await.unwrap();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn test_file_exporter_append_mode() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        {
            let exporter = FileExporter::new(&log_path).unwrap();
            let event = AuditEvent::new(
                EventType::FileUploaded,
                "user1".to_string(),
                "session-1".to_string(),
            );
            exporter.export(event).await.unwrap();
            exporter.flush().await.unwrap();
        }

        {
            let exporter = FileExporter::new(&log_path).unwrap();
            let event = AuditEvent::new(
                EventType::FileDownloaded,
                "user2".to_string(),
                "session-2".to_string(),
            );
            exporter.export(event).await.unwrap();
            exporter.flush().await.unwrap();
        }

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn test_file_exporter_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        let rotate_config = RotateConfig::new()
            .with_max_size(100) // Small size to trigger rotation
            .with_max_backups(3)
            .with_compress(false);

        let exporter = FileExporter::new(&log_path)
            .unwrap()
            .with_rotation(rotate_config);

        // Write enough events to trigger rotation
        for i in 0..10 {
            let event = AuditEvent::new(
                EventType::FileUploaded,
                format!("user{}", i),
                format!("session-{}", i),
            )
            .with_client_ip("192.168.1.100".parse::<IpAddr>().unwrap())
            .with_bytes(1024);

            exporter.export(event).await.unwrap();
        }

        exporter.flush().await.unwrap();

        // Check that rotation happened
        let backup_path = format!("{}.1", log_path.display());
        assert!(tokio::fs::metadata(&backup_path).await.is_ok());
    }

    #[tokio::test]
    async fn test_file_exporter_rotation_with_compression() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        let rotate_config = RotateConfig::new()
            .with_max_size(100)
            .with_max_backups(3)
            .with_compress(true);

        let exporter = FileExporter::new(&log_path)
            .unwrap()
            .with_rotation(rotate_config);

        // Write enough events to trigger rotation
        for i in 0..10 {
            let event = AuditEvent::new(
                EventType::FileUploaded,
                format!("user{}", i),
                format!("session-{}", i),
            )
            .with_bytes(1024);

            exporter.export(event).await.unwrap();
        }

        exporter.flush().await.unwrap();

        // Check that compressed backup exists
        let backup_path = format!("{}.1.gz", log_path.display());
        assert!(tokio::fs::metadata(&backup_path).await.is_ok());
    }

    #[tokio::test]
    async fn test_file_exporter_max_backups() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");

        let rotate_config = RotateConfig::new()
            .with_max_size(50)
            .with_max_backups(2)
            .with_compress(false);

        let exporter = FileExporter::new(&log_path)
            .unwrap()
            .with_rotation(rotate_config);

        // Write enough to trigger multiple rotations
        for i in 0..30 {
            let event = AuditEvent::new(
                EventType::FileUploaded,
                format!("user{}", i),
                format!("session-{}", i),
            )
            .with_bytes(1024);

            exporter.export(event).await.unwrap();
        }

        exporter.flush().await.unwrap();

        // Should have backups .1 and .2 only
        let backup1 = format!("{}.1", log_path.display());
        let backup2 = format!("{}.2", log_path.display());
        let backup3 = format!("{}.3", log_path.display());

        assert!(tokio::fs::metadata(&backup1).await.is_ok());
        assert!(tokio::fs::metadata(&backup2).await.is_ok());
        assert!(tokio::fs::metadata(&backup3).await.is_err());
    }

    #[tokio::test]
    async fn test_rotate_config_builder() {
        let config = RotateConfig::new()
            .with_max_size(50 * 1024 * 1024)
            .with_max_backups(10)
            .with_compress(true);

        assert_eq!(config.max_size, 50 * 1024 * 1024);
        assert_eq!(config.max_backups, 10);
        assert!(config.compress);
    }

    #[tokio::test]
    async fn test_file_exporter_creates_parent_dir() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("subdir").join("audit.log");

        let result = FileExporter::new(&log_path);
        assert!(result.is_ok());
        assert!(log_path.parent().unwrap().exists());
    }
}
