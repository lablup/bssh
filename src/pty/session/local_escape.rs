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

    #[test]
    fn test_data_ending_with_tilde() {
        let mut detector = LocalEscapeDetector::new();

        // Data ends with tilde after newline - state should persist
        assert_eq!(detector.process(b"\n~"), None);
        // Subsequent dot should trigger disconnect
        assert_eq!(detector.process(b"."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_data_ending_with_newline() {
        let mut detector = LocalEscapeDetector::new();

        // Data ends with newline - ready for escape
        assert_eq!(detector.process(b"hello\n"), None);
        // Subsequent ~. should trigger disconnect
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_consecutive_newlines() {
        let mut detector = LocalEscapeDetector::new();

        // Multiple consecutive newlines
        assert_eq!(detector.process(b"\n\n\n"), None);
        // Still in after_newline state
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_mixed_cr_and_lf() {
        let mut detector = LocalEscapeDetector::new();

        // CRLF sequence
        assert_eq!(detector.process(b"\r\n"), None);
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_lfcr_sequence() {
        let mut detector = LocalEscapeDetector::new();

        // LFCR (unusual but possible)
        assert_eq!(detector.process(b"\n\r"), None);
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_large_buffer_with_escape() {
        let mut detector = LocalEscapeDetector::new();

        // Large buffer with escape sequence in the middle
        let mut data = vec![b'x'; 1000];
        data.push(b'\n');
        data.push(b'~');
        data.push(b'.');
        data.extend_from_slice(&[b'y'; 500]);

        // Should detect disconnect at ~.
        assert_eq!(detector.process(&data), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_tilde_after_text() {
        let mut detector = LocalEscapeDetector::new();

        // Tilde in the middle of text (not after newline)
        assert_eq!(detector.process(b"hello~.world"), None);
    }

    #[test]
    fn test_multiple_tildes() {
        let mut detector = LocalEscapeDetector::new();

        // Multiple tildes after newline
        assert_eq!(detector.process(b"\n~~."), None);
        // Second tilde resets the state
    }

    #[test]
    fn test_tilde_then_newline() {
        let mut detector = LocalEscapeDetector::new();

        // Tilde then newline resets
        assert_eq!(detector.process(b"\n~\n"), None);
        // Should be in after_newline state again
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_empty_input() {
        let mut detector = LocalEscapeDetector::new();

        // Empty input should not change state
        assert_eq!(detector.process(b""), None);
        // Still in initial after_newline state
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_escape_in_binary_data() {
        let mut detector = LocalEscapeDetector::new();

        // Binary data with escape sequence
        let data = [0x00, 0xFF, b'\n', b'~', b'.', 0x7F];
        assert_eq!(detector.process(&data), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_only_newline_then_only_tilde() {
        let mut detector = LocalEscapeDetector::new();

        // Single byte inputs
        assert_eq!(detector.process(b"\n"), None);
        assert_eq!(detector.process(b"~"), None);
        // State: saw_tilde = true, after_newline = false
        assert_eq!(detector.process(b"."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_state_after_non_dot() {
        let mut detector = LocalEscapeDetector::new();

        // After ~x, state should reset
        assert_eq!(detector.process(b"\n~x"), None);
        // Need another newline before ~.
        assert_eq!(detector.process(b"~."), None);
        // Now with newline
        assert_eq!(detector.process(b"\n~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_rapid_escape_attempts() {
        let mut detector = LocalEscapeDetector::new();

        // Rapid repeated attempts
        assert_eq!(
            detector.process(b"\n~x\n~y\n~z\n~."),
            Some(LocalAction::Disconnect)
        );
    }

    #[test]
    fn test_unicode_does_not_interfere() {
        let mut detector = LocalEscapeDetector::new();

        // UTF-8 encoded characters should not interfere
        assert_eq!(detector.process("한글\n".as_bytes()), None);
        assert_eq!(detector.process(b"~."), Some(LocalAction::Disconnect));
    }

    #[test]
    fn test_local_action_eq() {
        // Test LocalAction equality
        assert_eq!(LocalAction::Disconnect, LocalAction::Disconnect);
    }

    #[test]
    fn test_local_action_debug() {
        // Test LocalAction debug implementation
        let action = LocalAction::Disconnect;
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("Disconnect"));
    }

    #[test]
    fn test_local_action_clone() {
        // Test LocalAction clone
        let action = LocalAction::Disconnect;
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }
}
