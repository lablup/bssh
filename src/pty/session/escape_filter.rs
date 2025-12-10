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
    /// In DCS sequence (ESC P)
    Dcs,
    /// In DCS with + (ESC P +)
    DcsPlus,
    /// In XTGETTCAP response (ESC P + r)
    Xtgettcap,
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
        }
    }

    /// Filter terminal data, removing terminal query responses.
    ///
    /// Returns the filtered data that should be displayed.
    pub fn filter(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
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
                            self.pending_buffer.clear();
                            self.state = FilterState::Normal;
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
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
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
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
                    } else if byte.is_ascii_alphabetic() || byte == b'~' {
                        // End of CSI ? sequence - pass through (DEC private modes)
                        output.extend_from_slice(&self.pending_buffer);
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
                    }
                    // Continue collecting CSI ? sequence parameters
                }

                FilterState::Dcs => {
                    self.pending_buffer.push(byte);
                    if byte == b'+' {
                        self.state = FilterState::DcsPlus;
                    } else if byte == 0x1b {
                        // Start of string terminator
                        self.state = FilterState::St;
                    } else if byte == 0x07 {
                        // BEL as string terminator - end of DCS
                        // Filter out DCS sequences (most are responses)
                        tracing::trace!(
                            "Filtered DCS sequence: {:?}",
                            String::from_utf8_lossy(&self.pending_buffer)
                        );
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
                    }
                    // Continue collecting DCS content
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
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
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
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
                    }
                    // Continue collecting XTGETTCAP content
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
                            self.pending_buffer.clear();
                        } else {
                            output.extend_from_slice(&self.pending_buffer);
                            self.pending_buffer.clear();
                        }
                        self.state = FilterState::Normal;
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
                                // DCS sequence complete - filter it
                                tracing::trace!(
                                    "Filtered DCS sequence with ST: {:?}",
                                    String::from_utf8_lossy(&self.pending_buffer)
                                );
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
                        self.pending_buffer.clear();
                        self.state = FilterState::Normal;
                    } else {
                        // False ST start - return to appropriate state
                        // This handles cases where ESC appears in the middle of a sequence
                        match self.pending_buffer.get(1) {
                            Some(b'P') => self.state = FilterState::Dcs,
                            Some(b']') => self.state = FilterState::Osc,
                            _ => {
                                // Malformed - pass through
                                output.extend_from_slice(&self.pending_buffer);
                                self.pending_buffer.clear();
                                self.state = FilterState::Normal;
                            }
                        }
                    }
                }
            }

            i += 1;
        }

        // Handle buffer timeout for incomplete sequences
        // If pending buffer gets too large, it's likely garbage - flush it
        const MAX_PENDING_SIZE: usize = 4096;
        if self.pending_buffer.len() > MAX_PENDING_SIZE {
            tracing::warn!(
                "Escape sequence buffer overflow, flushing {} bytes",
                self.pending_buffer.len()
            );
            output.extend_from_slice(&self.pending_buffer);
            self.pending_buffer.clear();
            self.state = FilterState::Normal;
        }

        output
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

        // Check for OSC parameter number
        // Format: ESC ] NUMBER ; ...
        let start = 2; // Skip ESC ]
        let mut end = start;
        while end < self.pending_buffer.len() && self.pending_buffer[end].is_ascii_digit() {
            end += 1;
        }

        if end == start {
            return false;
        }

        let param_str = String::from_utf8_lossy(&self.pending_buffer[start..end]);
        if let Ok(param) = param_str.parse::<u32>() {
            // Filter known response types
            matches!(param, 4 | 10..=19 | 52)
        } else {
            false
        }
    }

    /// Reset the filter state.
    ///
    /// Call this when starting a new session or after an error.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.pending_buffer.clear();
        self.state = FilterState::Normal;
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
}
