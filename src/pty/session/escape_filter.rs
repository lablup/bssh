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

//! Terminal escape sequence filter for PTY sessions.
//!
//! This module filters out terminal escape sequence responses that should not
//! be displayed on screen. When applications like Neovim query terminal
//! capabilities, the responses can sometimes appear as raw text if not
//! properly handled.
//!
//! ## Filtered Sequences
//!
//! The filter handles the following types of terminal responses:
//!
//! - **XTGETTCAP responses** (`\x1bP+r...`): Terminal capability query responses
//! - **DA1/DA2/DA3 responses** (`\x1b[?...c`): Device Attributes responses
//! - **OSC responses** (`\x1b]...`): Operating System Command responses
//! - **DCS responses** (`\x1bP...`): Device Control String responses
//!
//! ## Design Philosophy
//!
//! The filter uses a conservative approach:
//! - Only filters known terminal response sequences
//! - Preserves all other output including valid escape sequences for colors, etc.
//! - Uses a state machine to track incomplete sequences across buffer boundaries

use std::time::{Duration, Instant};

/// Maximum size for CSI sequences before forcing buffer flush.
/// Standard CSI sequences are typically under 32 bytes (e.g., "\x1b[38;2;255;255;255m" is 22 bytes).
/// Using 256 bytes provides generous headroom while preventing DoS through malformed input.
const MAX_CSI_SEQUENCE_SIZE: usize = 256;

/// Maximum size for pending buffer before overflow protection triggers.
const MAX_PENDING_SIZE: usize = 4096;

/// Maximum time to wait for incomplete escape sequences before flushing.
/// Terminal responses typically arrive within milliseconds, so 500ms is generous.
const SEQUENCE_TIMEOUT: Duration = Duration::from_millis(500);

/// Filter for terminal escape sequence responses.
///
/// This filter removes terminal query responses that applications send back
/// to the terminal but should not be visible to the user.
#[derive(Debug)]
pub struct EscapeSequenceFilter {
    /// Buffer for incomplete escape sequences spanning multiple data chunks
    pending_buffer: Vec<u8>,
    /// Current filter state
    state: FilterState,
    /// Timestamp when the current pending sequence started
    sequence_start: Option<Instant>,
}

/// State machine for tracking escape sequence parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterState {
    /// Normal text processing
    Normal,
    /// Saw ESC (0x1b), waiting for next character
    Escape,
    /// In CSI sequence (ESC [)
    Csi,
    /// In CSI with question mark (ESC [ ?)
    CsiQuestion,
    /// In DCS sequence (ESC P) - not yet determined if it's a response
    Dcs,
    /// In DCS with + (ESC P +)
    DcsPlus,
    /// In XTGETTCAP response (ESC P + r) - should be filtered
    Xtgettcap,
    /// In DCS $ sequence (ESC P $) - DECRQSS response, should be filtered
    DcsDecrqss,
    /// In DCS passthrough (non-response DCS sequence) - should pass through
    DcsPassthrough,
    /// In OSC sequence (ESC ])
    Osc,
    /// In ST (String Terminator) - saw ESC, waiting for backslash
    St,
}

impl Default for EscapeSequenceFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeSequenceFilter {
    /// Create a new escape sequence filter.
    pub fn new() -> Self {
        Self {
            pending_buffer: Vec::with_capacity(64),
            state: FilterState::Normal,
            sequence_start: None,
        }
    }

    /// Reset to normal state and clear timing.
    #[inline]
    fn reset_to_normal(&mut self) {
        self.pending_buffer.clear();
        self.state = FilterState::Normal;
        self.sequence_start = None;
    }

    /// Filter terminal data, removing terminal query responses.
    ///
    /// Returns the filtered data that should be displayed.
    pub fn filter(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());

        // Check for timed-out incomplete sequences at the start of each filter call
        if self.state != FilterState::Normal {
            if let Some(start) = self.sequence_start {
                if start.elapsed() > SEQUENCE_TIMEOUT {
                    tracing::trace!(
                        "Flushing timed-out escape sequence ({:?}): {:?}",
                        start.elapsed(),
                        String::from_utf8_lossy(&self.pending_buffer)
                    );
                    output.extend_from_slice(&self.pending_buffer);
                    self.pending_buffer.clear();
                    self.state = FilterState::Normal;
                    self.sequence_start = None;
                }
            }
        }

        let mut i = 0;

        while i < data.len() {
            let byte = data[i];

            match self.state {
                FilterState::Normal => {
                    if byte == 0x1b {
                        // Start of escape sequence
                        self.state = FilterState::Escape;
                        self.pending_buffer.clear();
                        self.pending_buffer.push(byte);
                        self.sequence_start = Some(Instant::now());
                    } else {
                        output.push(byte);
                    }
                }

                FilterState::Escape => {
                    self.pending_buffer.push(byte);
                    match byte {
                        b'[' => {
                            // CSI sequence
                            self.state = FilterState::Csi;
                        }
                        b'P' => {
                            // DCS sequence
                            self.state = FilterState::Dcs;
                        }
                        b']' => {
                            // OSC sequence
                            self.state = FilterState::Osc;
                        }
                        _ => {
                            // Other escape sequence - pass through
                            output.extend_from_slice(&self.pending_buffer);
                            self.reset_to_normal();
                        }
                    }
                }

                FilterState::Csi => {
                    self.pending_buffer.push(byte);
                    if byte == b'?' {
                        self.state = FilterState::CsiQuestion;
                    } else if byte.is_ascii_alphabetic() || byte == b'~' {
                        // End of CSI sequence - pass through (colors, cursor, etc.)
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    } else if self.pending_buffer.len() > MAX_CSI_SEQUENCE_SIZE {
                        // Malformed CSI sequence - too long without terminator
                        // Flush buffer to prevent memory issues and output delay
                        tracing::trace!(
                            "Flushing malformed CSI sequence (size {})",
                            self.pending_buffer.len()
                        );
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    }
                    // Continue collecting CSI sequence parameters
                }

                FilterState::CsiQuestion => {
                    self.pending_buffer.push(byte);
                    if byte == b'c' {
                        // This is a DA (Device Attributes) response: ESC [ ? ... c
                        // Filter it out - don't add to output
                        tracing::trace!(
                            "Filtered DA response: {:?}",
                            String::from_utf8_lossy(&self.pending_buffer)
                        );
                        self.reset_to_normal();
                    } else if byte.is_ascii_alphabetic() || byte == b'~' {
                        // End of CSI ? sequence - pass through (DEC private modes)
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    } else if self.pending_buffer.len() > MAX_CSI_SEQUENCE_SIZE {
                        // Malformed CSI ? sequence - too long without terminator
                        // Flush buffer to prevent memory issues and output delay
                        tracing::trace!(
                            "Flushing malformed CSI? sequence (size {})",
                            self.pending_buffer.len()
                        );
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    }
                    // Continue collecting CSI ? sequence parameters
                }

                FilterState::Dcs => {
                    self.pending_buffer.push(byte);
                    if byte == b'+' {
                        self.state = FilterState::DcsPlus;
                    } else if byte == b'$' {
                        // DECRQSS response (ESC P $ ...)
                        self.state = FilterState::DcsDecrqss;
                    } else if byte == 0x1b {
                        // Start of string terminator - treat as passthrough
                        // since we didn't identify it as a known response
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of DCS
                        // Unknown DCS type - pass through to preserve functionality
                        // (e.g., sixel graphics, DECUDK, application-specific sequences)
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    } else {
                        // Other DCS content - transition to passthrough mode
                        self.state = FilterState::DcsPassthrough;
                    }
                }

                FilterState::DcsPlus => {
                    self.pending_buffer.push(byte);
                    if byte == b'r' {
                        // XTGETTCAP response: ESC P + r ...
                        self.state = FilterState::Xtgettcap;
                    } else if byte == 0x1b {
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator
                        tracing::trace!(
                            "Filtered DCS+ sequence: {:?}",
                            String::from_utf8_lossy(&self.pending_buffer)
                        );
                        self.reset_to_normal();
                    }
                }

                FilterState::Xtgettcap => {
                    self.pending_buffer.push(byte);
                    if byte == 0x1b {
                        // Start of string terminator
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of XTGETTCAP response
                        tracing::trace!(
                            "Filtered XTGETTCAP response: {:?}",
                            String::from_utf8_lossy(&self.pending_buffer)
                        );
                        self.reset_to_normal();
                    }
                    // Continue collecting XTGETTCAP content
                }

                FilterState::DcsDecrqss => {
                    self.pending_buffer.push(byte);
                    if byte == 0x1b {
                        // Start of string terminator
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of DECRQSS response
                        tracing::trace!(
                            "Filtered DECRQSS response: {:?}",
                            String::from_utf8_lossy(&self.pending_buffer)
                        );
                        self.reset_to_normal();
                    }
                    // Continue collecting DECRQSS content
                }

                FilterState::DcsPassthrough => {
                    self.pending_buffer.push(byte);
                    if byte == 0x1b {
                        // Start of string terminator
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of DCS passthrough
                        // Pass through non-response DCS sequences
                        output.extend_from_slice(&self.pending_buffer);
                        self.reset_to_normal();
                    }
                    // Continue collecting DCS passthrough content
                }

                FilterState::Osc => {
                    self.pending_buffer.push(byte);
                    if byte == 0x1b {
                        // Start of string terminator (ESC \)
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of OSC
                        // Some OSC sequences should be passed through (like title setting)
                        // But OSC responses (like OSC 52 clipboard responses) should be filtered
                        if self.is_osc_response() {
                            tracing::trace!(
                                "Filtered OSC response: {:?}",
                                String::from_utf8_lossy(&self.pending_buffer)
                            );
                        } else {
                            output.extend_from_slice(&self.pending_buffer);
                        }
                        self.reset_to_normal();
                    }
                    // Continue collecting OSC content
                }

                FilterState::St => {
                    self.pending_buffer.push(byte);
                    if byte == b'\\' {
                        // String terminator complete (ESC \)
                        // Check what type of sequence we were in
                        match self.pending_buffer.get(1) {
                            Some(b'P') => {
                                // DCS sequence complete - check if it's a response
                                if self.is_dcs_response() {
                                    tracing::trace!(
                                        "Filtered DCS response with ST: {:?}",
                                        String::from_utf8_lossy(&self.pending_buffer)
                                    );
                                } else {
                                    // Non-response DCS - pass through
                                    output.extend_from_slice(&self.pending_buffer);
                                }
                            }
                            Some(b']') => {
                                // OSC sequence complete
                                if self.is_osc_response() {
                                    tracing::trace!(
                                        "Filtered OSC response with ST: {:?}",
                                        String::from_utf8_lossy(&self.pending_buffer)
                                    );
                                } else {
                                    output.extend_from_slice(&self.pending_buffer);
                                }
                            }
                            _ => {
                                // Unknown - pass through to be safe
                                output.extend_from_slice(&self.pending_buffer);
                            }
                        }
                        self.reset_to_normal();
                    } else {
                        // False ST start - return to appropriate state
                        // This handles cases where ESC appears in the middle of a sequence
                        match self.pending_buffer.get(1) {
                            Some(b'P') => {
                                // Return to appropriate DCS state based on content
                                if self.is_dcs_response() {
                                    // Stay in a response state (Xtgettcap or DcsDecrqss)
                                    if self.pending_buffer.len() > 3 && self.pending_buffer[2] == b'+' {
                                        self.state = FilterState::Xtgettcap;
                                    } else if self.pending_buffer.len() > 2 && self.pending_buffer[2] == b'$' {
                                        self.state = FilterState::DcsDecrqss;
                                    } else {
                                        self.state = FilterState::DcsPassthrough;
                                    }
                                } else {
                                    self.state = FilterState::DcsPassthrough;
                                }
                            }
                            Some(b']') => self.state = FilterState::Osc,
                            _ => {
                                // Malformed - pass through
                                output.extend_from_slice(&self.pending_buffer);
                                self.reset_to_normal();
                            }
                        }
                    }
                }
            }

            i += 1;
        }

        // Handle buffer timeout for incomplete sequences
        // If pending buffer gets too large, it's likely garbage - flush it
        if self.pending_buffer.len() > MAX_PENDING_SIZE {
            tracing::warn!(
                "Escape sequence buffer overflow, flushing {} bytes",
                self.pending_buffer.len()
            );
            output.extend_from_slice(&self.pending_buffer);
            self.reset_to_normal();
        }

        output
    }

    /// Check if the current DCS sequence is a response that should be filtered.
    fn is_dcs_response(&self) -> bool {
        // DCS sequences that are responses (not commands):
        // - ESC P + r ... (XTGETTCAP response)
        // - ESC P $ ... (DECRQSS response)
        if self.pending_buffer.len() < 3 {
            return false;
        }

        // Check the third byte to determine DCS type
        match self.pending_buffer.get(2) {
            Some(b'+') => true, // XTGETTCAP response
            Some(b'$') => true, // DECRQSS response
            _ => false,         // Other DCS sequences (sixel, DECUDK, etc.) - pass through
        }
    }

    /// Check if the current OSC sequence is a response that should be filtered.
    fn is_osc_response(&self) -> bool {
        // OSC sequences that are responses (not commands):
        // - OSC 52 ; ... (clipboard response)
        // - OSC 10-19 (color query responses)
        // - OSC 4 ; ... (color palette response)
        if self.pending_buffer.len() < 4 {
            return false;
        }

        // Parse OSC parameter number directly from bytes to avoid String allocation
        // Format: ESC ] NUMBER ; ...
        if let Some(param) = self.parse_osc_param() {
            // Filter known response types
            matches!(param, 4 | 10..=19 | 52)
        } else {
            false
        }
    }

    /// Parse OSC parameter number directly from bytes without allocation.
    /// Returns None if parsing fails.
    fn parse_osc_param(&self) -> Option<u32> {
        let start = 2; // Skip ESC ]
        let mut idx = start;
        let mut value: u32 = 0;

        // Limit to 10 digits to prevent overflow (max u32 is 10 digits)
        while idx < self.pending_buffer.len() && idx - start < 10 {
            let byte = self.pending_buffer[idx];
            if byte.is_ascii_digit() {
                // Safe: checked_mul and checked_add prevent overflow
                value = value.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
                idx += 1;
            } else {
                break;
            }
        }

        // Return Some only if we parsed at least one digit
        if idx > start {
            Some(value)
        } else {
            None
        }
    }

    /// Reset the filter state.
    ///
    /// Call this when starting a new session or after an error.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.reset_to_normal();
    }

    /// Check if there's a pending incomplete sequence that might need flushing.
    /// Returns true if there's an incomplete sequence that has timed out.
    #[allow(dead_code)]
    pub fn has_timed_out_sequence(&self) -> bool {
        if self.state != FilterState::Normal {
            if let Some(start) = self.sequence_start {
                return start.elapsed() > SEQUENCE_TIMEOUT;
            }
        }
        false
    }

    /// Flush any pending incomplete sequence regardless of state.
    /// Returns the pending data if any.
    #[allow(dead_code)]
    pub fn flush_pending(&mut self) -> Vec<u8> {
        let data = std::mem::take(&mut self.pending_buffer);
        self.reset_to_normal();
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_text_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        let input = b"Hello, World!";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_normal_escape_sequences_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // Color escape sequence: ESC [ 31 m (red foreground)
        let input = b"\x1b[31mRed Text\x1b[0m";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_da_response_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // DA1 response: ESC [ ? 6 4 ; 4 c
        let input = b"\x1b[?64;4c";
        let output = filter.filter(input);
        assert!(output.is_empty(), "DA response should be filtered");
    }

    #[test]
    fn test_xtgettcap_response_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // XTGETTCAP response: ESC P + r ... ST
        let input = b"\x1bP+r736574726762\x1b\\";
        let output = filter.filter(input);
        assert!(output.is_empty(), "XTGETTCAP response should be filtered");
    }

    #[test]
    fn test_xtgettcap_with_bel_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // XTGETTCAP response with BEL terminator
        let input = b"\x1bP+r736574726762\x07";
        let output = filter.filter(input);
        assert!(
            output.is_empty(),
            "XTGETTCAP response with BEL should be filtered"
        );
    }

    #[test]
    fn test_mixed_content() {
        let mut filter = EscapeSequenceFilter::new();
        // Mix of normal text, color codes, and filtered responses
        let input = b"Hello\x1b[31m\x1b[?64;4cWorld\x1b[0m";
        let output = filter.filter(input);
        // Should keep: Hello, color start, World, color reset
        // Should filter: DA response
        assert_eq!(output, b"Hello\x1b[31mWorld\x1b[0m");
    }

    #[test]
    fn test_osc_title_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // OSC 0 ; title BEL (set window title)
        let input = b"\x1b]0;My Title\x07";
        let output = filter.filter(input);
        // Title setting should pass through (not a response)
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_osc_color_response_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // OSC 10 ; ... BEL (foreground color query response)
        let input = b"\x1b]10;rgb:ffff/ffff/ffff\x07";
        let output = filter.filter(input);
        assert!(output.is_empty(), "OSC color response should be filtered");
    }

    #[test]
    fn test_partial_sequence_buffering() {
        let mut filter = EscapeSequenceFilter::new();

        // Send escape sequence in parts
        let part1 = b"\x1b[?64";
        let part2 = b";4c";

        let output1 = filter.filter(part1);
        assert!(output1.is_empty(), "Partial sequence should be buffered");

        let output2 = filter.filter(part2);
        assert!(
            output2.is_empty(),
            "Complete DA response should be filtered"
        );
    }

    #[test]
    fn test_cursor_movement_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // Cursor movement: ESC [ H (home), ESC [ 10 ; 20 H (move to 10,20)
        let input = b"\x1b[H\x1b[10;20H";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_dec_private_mode_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // Enable alternate screen: ESC [ ? 1049 h
        let input = b"\x1b[?1049h";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_malformed_csi_sequence_flushed() {
        let mut filter = EscapeSequenceFilter::new();
        // Create a malformed CSI sequence that exceeds MAX_CSI_SEQUENCE_SIZE (256 bytes)
        // without a proper terminator (no alphabetic character or ~)
        let mut malformed = vec![0x1b, b'[']; // ESC [
        // Add enough non-terminating bytes to exceed the limit
        for _ in 0..300 {
            malformed.push(b';'); // Keep adding parameter separators
        }
        malformed.push(b'X'); // Finally add a terminator

        let output = filter.filter(&malformed);

        // The malformed sequence should be flushed (not filtered)
        // because it exceeded the size limit before getting a terminator
        assert!(!output.is_empty(), "Malformed CSI sequence should be flushed to output");
    }

    #[test]
    fn test_buffer_overflow_protection() {
        let mut filter = EscapeSequenceFilter::new();
        // Create a DCS sequence that exceeds MAX_PENDING_SIZE (4096 bytes)
        // DCS sequences don't have the early termination, only the global limit applies
        let mut large_dcs = vec![0x1b, b'P']; // ESC P (DCS start)
        // Add enough bytes to exceed the 4096 byte limit
        for i in 0..5000 {
            large_dcs.push(b'A' + (i % 26) as u8);
        }

        let output = filter.filter(&large_dcs);

        // The buffer should be flushed when it exceeds MAX_PENDING_SIZE
        assert!(!output.is_empty(), "Buffer overflow should flush content to output");
        // State should be reset to Normal
        assert_eq!(filter.state, FilterState::Normal);
        assert!(filter.pending_buffer.is_empty(), "Pending buffer should be cleared");
    }

    #[test]
    fn test_malformed_csi_question_sequence_flushed() {
        let mut filter = EscapeSequenceFilter::new();
        // Create a malformed CSI ? sequence that exceeds MAX_CSI_SEQUENCE_SIZE
        let mut malformed = vec![0x1b, b'[', b'?']; // ESC [ ?
        // Add enough non-terminating bytes
        for _ in 0..300 {
            malformed.push(b'0'); // Keep adding digits
        }
        malformed.push(b'h'); // Finally add a terminator

        let output = filter.filter(&malformed);

        // The malformed sequence should be flushed (not filtered)
        assert!(!output.is_empty(), "Malformed CSI? sequence should be flushed to output");
    }

    #[test]
    fn test_dcs_sixel_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // Sixel graphics DCS sequence: ESC P q ... ST
        // This should pass through, not be filtered
        let input = b"\x1bPq#0;2;0;0;0#1;2;100;100;100\x1b\\";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec(), "Sixel DCS should pass through");
    }

    #[test]
    fn test_dcs_xtgettcap_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // XTGETTCAP response: ESC P + r ... ST (should be filtered)
        let input = b"\x1bP+r736574726762\x1b\\";
        let output = filter.filter(input);
        assert!(output.is_empty(), "XTGETTCAP response should be filtered");
    }

    #[test]
    fn test_dcs_decrqss_filtered() {
        let mut filter = EscapeSequenceFilter::new();
        // DECRQSS response: ESC P $ r ... ST (should be filtered)
        let input = b"\x1bP$r0m\x1b\\";
        let output = filter.filter(input);
        assert!(output.is_empty(), "DECRQSS response should be filtered");
    }

    #[test]
    fn test_dcs_generic_passthrough() {
        let mut filter = EscapeSequenceFilter::new();
        // Generic DCS sequence (not + or $): ESC P 1 2 3 ST
        // This should pass through
        let input = b"\x1bP123\x1b\\";
        let output = filter.filter(input);
        assert_eq!(output, input.to_vec(), "Generic DCS should pass through");
    }

    #[test]
    fn test_sequence_start_timestamp_set() {
        let mut filter = EscapeSequenceFilter::new();
        // Initially no timestamp
        assert!(filter.sequence_start.is_none());

        // Start an incomplete sequence
        let _ = filter.filter(b"\x1b[?64");

        // Timestamp should be set
        assert!(filter.sequence_start.is_some());
        assert_eq!(filter.state, FilterState::CsiQuestion);
    }

    #[test]
    fn test_sequence_timestamp_cleared_on_completion() {
        let mut filter = EscapeSequenceFilter::new();

        // Complete a sequence
        let _ = filter.filter(b"\x1b[31m");

        // Timestamp should be cleared
        assert!(filter.sequence_start.is_none());
        assert_eq!(filter.state, FilterState::Normal);
    }

    #[test]
    fn test_has_timed_out_sequence() {
        let mut filter = EscapeSequenceFilter::new();

        // No pending sequence - should not be timed out
        assert!(!filter.has_timed_out_sequence());

        // Start an incomplete sequence
        let _ = filter.filter(b"\x1b[?64");

        // Should not be timed out immediately
        assert!(!filter.has_timed_out_sequence());

        // State should be CsiQuestion
        assert_eq!(filter.state, FilterState::CsiQuestion);
    }

    #[test]
    fn test_flush_pending() {
        let mut filter = EscapeSequenceFilter::new();

        // Start an incomplete sequence
        let _ = filter.filter(b"\x1b[?64");

        // Flush should return the pending data
        let flushed = filter.flush_pending();
        assert_eq!(flushed, b"\x1b[?64");

        // State should be reset
        assert_eq!(filter.state, FilterState::Normal);
        assert!(filter.sequence_start.is_none());
        assert!(filter.pending_buffer.is_empty());
    }

    #[test]
    fn test_parse_osc_param_valid() {
        let mut filter = EscapeSequenceFilter::new();

        // OSC 10 - should parse to 10
        filter.pending_buffer = b"\x1b]10;test\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), Some(10));

        // OSC 52 - should parse to 52
        filter.pending_buffer = b"\x1b]52;data\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), Some(52));

        // OSC 0 - should parse to 0
        filter.pending_buffer = b"\x1b]0;title\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), Some(0));

        // OSC 4 - should parse to 4
        filter.pending_buffer = b"\x1b]4;color\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), Some(4));
    }

    #[test]
    fn test_parse_osc_param_invalid() {
        let mut filter = EscapeSequenceFilter::new();

        // No digits after ESC ]
        filter.pending_buffer = b"\x1b];text\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), None);

        // Buffer too short
        filter.pending_buffer = b"\x1b]".to_vec();
        assert_eq!(filter.parse_osc_param(), None);
    }

    #[test]
    fn test_parse_osc_param_overflow_protection() {
        let mut filter = EscapeSequenceFilter::new();

        // Very large number that would overflow u32 - should return None
        filter.pending_buffer = b"\x1b]99999999999;test\x07".to_vec();
        assert_eq!(filter.parse_osc_param(), None);
    }
}
