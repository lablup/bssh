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

//! Local escape sequence handling (OpenSSH-style).
//!
//! Handles sequences like `~.` for disconnect without sending to remote.
//! This matches OpenSSH's behavior for local command sequences.
//!
//! # Supported Escape Sequences
//! - `~.` - Terminate connection (must follow newline)
//!
//! # State Machine
//! The detector uses a state machine to track position in the escape sequence:
//! 1. After newline, wait for `~`
//! 2. After `~`, check for `.`
//! 3. On any other character, reset to waiting for newline

use smallvec::SmallVec;

/// Action to take after processing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAction {
    /// Disconnect the session
    Disconnect,
    /// Pass data through to remote (optionally filtered).
    /// Reserved for future escape sequences like `~?` (help) or `~~` (send literal tilde).
    #[allow(dead_code)]
    Passthrough(SmallVec<[u8; 64]>),
}

/// State machine for detecting `~.` after newline.
///
/// # Example
/// ```ignore
/// // Example is for documentation only - module is internal
/// let mut detector = LocalEscapeDetector::new();
///
/// // Normal input passes through
/// assert_eq!(detector.process(b"hello"), None);
///
/// // Newline followed by ~. triggers disconnect
/// assert_eq!(
///     detector.process(b"\n~."),
///     Some(LocalAction::Disconnect)
/// );
/// ```
pub struct LocalEscapeDetector {
    after_newline: bool,
    saw_tilde: bool,
}

impl LocalEscapeDetector {
    /// Create a new escape detector.
    ///
    /// Starts in the "after newline" state to allow `~.` at the
    /// beginning of a session.
    pub fn new() -> Self {
        Self {
            after_newline: true, // Start as if after newline
            saw_tilde: false,
        }
    }

    /// Process input and check for local escape sequences.
    ///
    /// Returns `None` if data should pass through unchanged, or
    /// `Some(LocalAction)` if a local escape was detected.
    ///
    /// # Arguments
    /// * `data` - Raw input bytes to process
    ///
    /// # Returns
    /// - `None` - Data should be sent to remote as-is
    /// - `Some(LocalAction::Disconnect)` - User requested disconnect
    /// - `Some(LocalAction::Passthrough(filtered))` - Send filtered data
    ///
    /// # Example
    /// ```ignore
    /// // Example is for documentation only - module is internal
    /// match detector.process(b"\n~.") {
    ///     Some(LocalAction::Disconnect) => {
    ///         // Close the connection
    ///     }
    ///     Some(LocalAction::Passthrough(data)) => {
    ///         // Send filtered data to remote
    ///     }
    ///     None => {
    ///         // Send data to remote unchanged
    ///     }
    /// }
    /// ```
    pub fn process(&mut self, data: &[u8]) -> Option<LocalAction> {
        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    self.after_newline = true;
                    self.saw_tilde = false;
                }
                b'~' if self.after_newline => {
                    self.saw_tilde = true;
                    self.after_newline = false;
                }
                b'.' if self.saw_tilde => {
                    // Disconnect sequence detected
                    return Some(LocalAction::Disconnect);
                }
                _ => {
                    self.after_newline = false;
                    self.saw_tilde = false;
                }
            }
        }
        None // Pass through
    }

    /// Reset the detector state.
    ///
    /// Useful when starting a new session or after handling an escape.
    /// Currently unused but kept for API completeness and testing.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.after_newline = true;
        self.saw_tilde = false;
    }
}

impl Default for LocalEscapeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_input_passes_through() {
        let mut detector = LocalEscapeDetector::new();
        assert_eq!(detector.process(b"hello world"), None);
        assert_eq!(detector.process(b"test\n"), None);
    }

    #[test]
    fn test_disconnect_after_newline() {
        let mut detector = LocalEscapeDetector::new();
        detector.process(b"hello\n");
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_disconnect_at_start() {
        let mut detector = LocalEscapeDetector::new();
        // Starts in "after newline" state
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_tilde_without_dot() {
        let mut detector = LocalEscapeDetector::new();
        detector.process(b"\n");
        assert_eq!(detector.process(b"~x"), None);
        // State should reset after non-dot character
    }

    #[test]
    fn test_dot_without_tilde() {
        let mut detector = LocalEscapeDetector::new();
        detector.process(b"\n");
        assert_eq!(detector.process(b"."), None);
    }

    #[test]
    fn test_tilde_not_after_newline() {
        let mut detector = LocalEscapeDetector::new();
        assert_eq!(detector.process(b"x~."), None);
    }

    #[test]
    fn test_carriage_return_enables_escape() {
        let mut detector = LocalEscapeDetector::new();
        detector.process(b"hello\r");
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_reset() {
        let mut detector = LocalEscapeDetector::new();
        detector.process(b"x");
        detector.reset();
        // After reset, should be in "after newline" state
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_default() {
        let _detector = LocalEscapeDetector::default();
    }

    #[test]
    fn test_multiple_sequences() {
        let mut detector = LocalEscapeDetector::new();

        // First sequence
        detector.process(b"hello\n");
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));

        // Reset for next sequence
        detector.reset();
        detector.process(b"world\r");
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_partial_sequence_in_chunks() {
        let mut detector = LocalEscapeDetector::new();

        // Process in separate chunks
        assert_eq!(detector.process(b"\n"), None);
        assert_eq!(detector.process(b"~"), None);
        assert_eq!(detector.process(b"."), Some(LocalAction::Disconnect));
    }
}
