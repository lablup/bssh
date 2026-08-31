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

//! Routing for bssh-owned diagnostics.
//!
//! This deliberately does not replace file descriptor 2. Remote command
//! stderr is written through `executor::output_sync` and must remain visible
//! to the caller even when `ssh -E` compatibility logging is enabled.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;

static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
static QUIET_WARNINGS: AtomicBool = AtomicBool::new(false);

/// Select whether non-error diagnostics should be suppressed.
///
/// Errors continue to use [`write_line`] and are always emitted. This switch
/// is intentionally process-wide because the CLI initializes it once before
/// any configuration warnings are produced.
pub fn set_quiet_warnings(quiet: bool) {
    QUIET_WARNINGS.store(quiet, Ordering::Relaxed);
}

/// Open `path` as the destination for subsequent bssh diagnostics.
///
/// OpenSSH's `-E` option appends to an existing file. Opening is completed
/// before tracing or application initialization so failures are reported on
/// stderr and terminate the process instead of silently falling back.
pub fn set_log_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);

    let file = options
        .open(path)
        .with_context(|| format!("Cannot open log file {}", path.display()))?;

    let mut destination = LOG_FILE
        .lock()
        .map_err(|_| anyhow::anyhow!("diagnostic log lock is poisoned"))?;
    *destination = Some(file);
    Ok(())
}

/// Return whether diagnostics currently target an explicitly selected file.
pub fn has_log_file() -> bool {
    LOG_FILE
        .lock()
        .map(|destination| destination.is_some())
        .unwrap_or(false)
}

fn write(bytes: &[u8]) -> io::Result<()> {
    let mut destination = LOG_FILE
        .lock()
        .map_err(|_| io::Error::other("diagnostic log lock is poisoned"))?;
    if let Some(file) = destination.as_mut() {
        file.write_all(bytes)?;
        file.flush()
    } else {
        let mut stderr = io::stderr().lock();
        stderr.write_all(bytes)?;
        stderr.flush()
    }
}

/// Write one human-facing diagnostic line to the configured destination.
pub fn write_line(arguments: fmt::Arguments<'_>) {
    let mut line = String::new();
    if fmt::write(&mut line, arguments).is_ok() {
        line.push('\n');
        let _ = write(line.as_bytes());
    }
}

/// Write one warning unless OpenSSH-compatible quiet mode is active.
pub fn write_warning_line(arguments: fmt::Arguments<'_>) {
    if !QUIET_WARNINGS.load(Ordering::Relaxed) {
        write_line(arguments);
    }
}

/// A tracing writer that emits each formatted event as one diagnostic write.
#[derive(Debug, Default)]
pub struct DiagnosticWriter {
    buffer: Vec<u8>,
}

impl Write for DiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let result = write(&self.buffer);
        if result.is_ok() {
            self.buffer.clear();
        }
        result
    }
}

impl Drop for DiagnosticWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Factory used by `tracing_subscriber` for diagnostic events.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiagnosticMakeWriter;

impl<'a> MakeWriter<'a> for DiagnosticMakeWriter {
    type Writer = DiagnosticWriter;

    fn make_writer(&'a self) -> Self::Writer {
        DiagnosticWriter::default()
    }
}

#[macro_export]
macro_rules! diagnosticln {
    ($($argument:tt)*) => {
        $crate::utils::diagnostics::write_line(format_args!($($argument)*))
    };
}

#[macro_export]
macro_rules! warningln {
    ($($argument:tt)*) => {
        $crate::utils::diagnostics::write_warning_line(format_args!($($argument)*))
    };
}
