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

//! Output mode configuration for multi-node command execution.
//!
//! This module defines how command output should be displayed or saved:
//! - Normal: Traditional batch mode (show all output after completion)
//! - Stream: Real-time streaming with [node] prefixes
//! - File: Save per-node output to separate files

use std::path::PathBuf;

/// Output mode for command execution
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Normal batch mode - show output after all nodes complete
    ///
    /// This is the default behavior, compatible with existing functionality.
    /// All output is collected and displayed together after execution completes.
    #[default]
    Normal,

    /// Stream mode - real-time output with [node] prefixes
    ///
    /// Each line of output is prefixed with [hostname] and displayed
    /// in real-time as it arrives. This allows monitoring long-running
    /// commands across multiple nodes.
    /// The bool indicates whether to disable the prefix (no_prefix option).
    Stream { no_prefix: bool },

    /// File mode - save per-node output to separate files
    ///
    /// Each node's output is saved to a separate file in the specified
    /// directory. Files are named with hostname and timestamp.
    /// The bool indicates whether to disable the prefix in status messages.
    File { path: PathBuf, no_prefix: bool },

    /// TUI mode - interactive terminal UI with multiple view modes
    ///
    /// Provides an interactive ratatui-based terminal UI for real-time
    /// monitoring of multiple nodes. Supports summary, detail, split, and
    /// diff view modes with keyboard navigation.
    Tui,
}

impl OutputMode {
    /// Create output mode from CLI arguments
    ///
    /// Priority:
    /// 1. --output-dir (File mode)
    /// 2. --stream (Stream mode)
    /// 3. Auto-detect TUI if TTY and no explicit mode
    /// 4. Default (Normal mode)
    pub fn from_args(stream: bool, output_dir: Option<PathBuf>) -> Self {
        Self::from_args_with_no_prefix(stream, output_dir, false)
    }

    /// Create output mode from CLI arguments with no_prefix option
    ///
    /// Priority:
    /// 1. --output-dir (File mode)
    /// 2. --stream (Stream mode)
    /// 3. Auto-detect TUI if TTY and no explicit mode
    /// 4. Default (Normal mode)
    pub fn from_args_with_no_prefix(
        stream: bool,
        output_dir: Option<PathBuf>,
        no_prefix: bool,
    ) -> Self {
        if let Some(dir) = output_dir {
            OutputMode::File {
                path: dir,
                no_prefix,
            }
        } else if stream {
            OutputMode::Stream { no_prefix }
        } else if is_tty() {
            // Auto-enable TUI mode for interactive terminals
            OutputMode::Tui
        } else {
            OutputMode::Normal
        }
    }

    /// Create output mode with explicit TUI disable option
    ///
    /// Used when --no-tui or similar flags are present
    pub fn from_args_explicit(stream: bool, output_dir: Option<PathBuf>, enable_tui: bool) -> Self {
        Self::from_args_explicit_with_no_prefix(stream, output_dir, enable_tui, false)
    }

    /// Create output mode with explicit TUI disable option and no_prefix
    ///
    /// Used when --no-tui or similar flags are present
    pub fn from_args_explicit_with_no_prefix(
        stream: bool,
        output_dir: Option<PathBuf>,
        enable_tui: bool,
        no_prefix: bool,
    ) -> Self {
        if let Some(dir) = output_dir {
            OutputMode::File {
                path: dir,
                no_prefix,
            }
        } else if stream {
            OutputMode::Stream { no_prefix }
        } else if enable_tui && is_tty() {
            OutputMode::Tui
        } else {
            OutputMode::Normal
        }
    }

    /// Check if this is normal mode
    pub fn is_normal(&self) -> bool {
        matches!(self, OutputMode::Normal)
    }

    /// Check if this is stream mode
    pub fn is_stream(&self) -> bool {
        matches!(self, OutputMode::Stream { .. })
    }

    /// Check if this is file mode
    pub fn is_file(&self) -> bool {
        matches!(self, OutputMode::File { .. })
    }

    /// Check if this is TUI mode
    pub fn is_tui(&self) -> bool {
        matches!(self, OutputMode::Tui)
    }

    /// Get output directory if in file mode
    pub fn output_dir(&self) -> Option<&PathBuf> {
        match self {
            OutputMode::File { path, .. } => Some(path),
            _ => None,
        }
    }

    /// Check if prefix is disabled for this output mode
    pub fn is_no_prefix(&self) -> bool {
        match self {
            OutputMode::Stream { no_prefix } => *no_prefix,
            OutputMode::File { no_prefix, .. } => *no_prefix,
            _ => false,
        }
    }
}

/// Check if stdout is a TTY
///
/// This is used to automatically disable fancy output modes when
/// output is being piped or redirected, or when running in CI environments.
pub fn is_tty() -> bool {
    use std::io::IsTerminal;

    // Check if stdout is a terminal
    let is_terminal = std::io::stdout().is_terminal();

    // Check if we're in CI environment
    let is_ci = std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
        || std::env::var("TRAVIS").is_ok();

    is_terminal && !is_ci
}

/// Check if colors should be enabled
///
/// Colors are enabled when:
/// - Output is a TTY
/// - NO_COLOR environment variable is not set
/// - TERM is not "dumb"
pub fn should_use_colors() -> bool {
    if !is_tty() {
        return false;
    }

    // Check NO_COLOR convention
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check TERM
    if let Ok(term) = std::env::var("TERM") {
        if term == "dumb" {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_mode_from_args() {
        // Default is Normal
        let mode = OutputMode::from_args(false, None);
        assert!(mode.is_normal());

        // Stream mode
        let mode = OutputMode::from_args(true, None);
        assert!(mode.is_stream());

        // File mode takes precedence
        let dir = PathBuf::from("/tmp/output");
        let mode = OutputMode::from_args(true, Some(dir.clone()));
        assert!(mode.is_file());
        assert_eq!(mode.output_dir(), Some(&dir));
    }

    #[test]
    fn test_output_mode_checks() {
        let normal = OutputMode::Normal;
        assert!(normal.is_normal());
        assert!(!normal.is_stream());
        assert!(!normal.is_file());

        let stream = OutputMode::Stream { no_prefix: false };
        assert!(!stream.is_normal());
        assert!(stream.is_stream());
        assert!(!stream.is_file());

        let file = OutputMode::File {
            path: PathBuf::from("/tmp"),
            no_prefix: false,
        };
        assert!(!file.is_normal());
        assert!(!file.is_stream());
        assert!(file.is_file());
    }

    #[test]
    fn test_default_output_mode() {
        let mode = OutputMode::default();
        assert!(mode.is_normal());
    }

    #[test]
    fn test_no_prefix_option() {
        // Stream mode with no_prefix
        let mode = OutputMode::from_args_with_no_prefix(true, None, true);
        assert!(mode.is_stream());
        assert!(mode.is_no_prefix());

        // Stream mode without no_prefix
        let mode = OutputMode::from_args_with_no_prefix(true, None, false);
        assert!(mode.is_stream());
        assert!(!mode.is_no_prefix());

        // File mode with no_prefix
        let dir = PathBuf::from("/tmp/output");
        let mode = OutputMode::from_args_with_no_prefix(false, Some(dir.clone()), true);
        assert!(mode.is_file());
        assert!(mode.is_no_prefix());
        assert_eq!(mode.output_dir(), Some(&dir));

        // Normal mode (no_prefix doesn't apply)
        let mode = OutputMode::Normal;
        assert!(!mode.is_no_prefix());
    }
}
