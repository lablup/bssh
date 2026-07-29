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

//! Tracks delivered DECSET/DECRST 1049 transitions across fragmented output.

const MAX_CSI_SEQUENCE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    Ground,
    Escape,
    Csi,
    String,
    StringEscape,
}

#[derive(Debug)]
pub(crate) struct ScreenModeTracker {
    state: ParserState,
    csi: Vec<u8>,
}

impl ScreenModeTracker {
    pub(crate) fn new() -> Self {
        Self {
            state: ParserState::Ground,
            csi: Vec::with_capacity(16),
        }
    }

    /// Return the last DEC 1049 state explicitly selected by delivered output.
    ///
    /// OSC, DCS, APC, PM, and SOS payloads are skipped until BEL or ST so an
    /// escape-looking payload cannot be mistaken for an executed CSI command.
    pub(crate) fn observe(&mut self, input: &[u8]) -> Option<bool> {
        let mut current = None;

        for &byte in input {
            match self.state {
                ParserState::Ground => self.consume_ground(byte),
                ParserState::Escape => self.consume_escape(byte),
                ParserState::Csi => {
                    if let Some(is_set) = self.consume_csi(byte) {
                        current = Some(is_set);
                    }
                }
                ParserState::String => self.consume_string(byte),
                ParserState::StringEscape => self.consume_string_escape(byte),
            }
        }

        current
    }

    fn consume_ground(&mut self, byte: u8) {
        match byte {
            b'\x1b' => self.state = ParserState::Escape,
            0x9b => self.start_csi(),
            0x90 | 0x98 | 0x9d | 0x9e | 0x9f => self.state = ParserState::String,
            _ => {}
        }
    }

    fn consume_escape(&mut self, byte: u8) {
        match byte {
            b'[' => self.start_csi(),
            // DCS, SOS, OSC, PM, and APC.
            b'P' | b'X' | b']' | b'^' | b'_' => self.state = ParserState::String,
            b'\x1b' => {}
            _ => self.state = ParserState::Ground,
        }
    }

    fn start_csi(&mut self) {
        self.csi.clear();
        self.state = ParserState::Csi;
    }

    fn consume_csi(&mut self, byte: u8) -> Option<bool> {
        match byte {
            // CAN and SUB cancel a control sequence.
            0x18 | 0x1a | 0x9c => {
                self.csi.clear();
                self.state = ParserState::Ground;
                return None;
            }
            b'\x1b' => {
                self.csi.clear();
                self.state = ParserState::Escape;
                return None;
            }
            _ => self.csi.push(byte),
        }

        if self.csi.len() > MAX_CSI_SEQUENCE {
            self.csi.clear();
            self.state = ParserState::Ground;
            return None;
        }
        if !(0x40..=0x7e).contains(&byte) {
            return None;
        }

        let selection = parse_1049_selection(&self.csi);
        self.csi.clear();
        self.state = ParserState::Ground;
        selection
    }

    fn consume_string(&mut self, byte: u8) {
        match byte {
            b'\x07' | 0x9c => self.state = ParserState::Ground,
            b'\x1b' => self.state = ParserState::StringEscape,
            _ => {}
        }
    }

    fn consume_string_escape(&mut self, byte: u8) {
        match byte {
            b'\\' | b'\x07' | 0x9c => self.state = ParserState::Ground,
            b'\x1b' => {}
            _ => self.state = ParserState::String,
        }
    }
}

fn parse_1049_selection(sequence: &[u8]) -> Option<bool> {
    let (&final_byte, body) = sequence.split_last()?;
    let is_set = match final_byte {
        b'h' => true,
        b'l' => false,
        _ => return None,
    };
    let parameters = body.strip_prefix(b"?")?;
    if parameters.is_empty()
        || !parameters
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';')
    {
        return None;
    }

    parameters
        .split(|byte| *byte == b';')
        .any(|mode| mode == b"1049")
        .then_some(is_set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_fragmented_1049_transitions_and_last_value() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"text\x1b[?10"), None);
        assert_eq!(tracker.observe(b"49h\x1b[?25;1049l"), Some(false));
        assert_eq!(tracker.observe(b"\x1b[?47h"), None);
    }

    #[test]
    fn skips_osc_dcs_and_tmux_payload_false_positives() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"\x1b]0;title\x1b[?1049h\x07"), None);
        assert_eq!(tracker.observe(b"\x1bPpayload\x1b[?1049l\x1b\\"), None);
        assert_eq!(tracker.observe(b"\x1bPtmux;\x1b\x1b[?1049h\x1b\\"), None);
        assert_eq!(tracker.observe(b"\x1b[?1049h"), Some(true));
    }

    #[test]
    fn skips_apc_pm_and_sos_until_fragmented_st() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"\x1b_payload\x1b[?1049h\x1b"), None);
        assert_eq!(tracker.observe(b"\\"), None);
        assert_eq!(tracker.observe(b"\x1b^payload\x1b[?1049l\x1b\\"), None);
        assert_eq!(tracker.observe(b"\x1bXpayload\x1b[?1049h\x07"), None);
        assert_eq!(tracker.observe(b"\x1b[?1049l"), Some(false));
    }

    #[test]
    fn rejects_invalid_csi_parameters() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"\x1b[?1049:1h"), None);
        assert_eq!(tracker.observe(b"\x1b[?1049$h"), None);
        assert_eq!(tracker.observe(b"\x1b[?x;1049h"), None);
        assert_eq!(tracker.observe(b"\x1b[?25;1049h"), Some(true));
    }

    #[test]
    fn supports_eight_bit_csi_strings_and_st() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"\x9dtitle\x9b?1049h\x9c"), None);
        assert_eq!(tracker.observe(b"\x90payload\x9b?1049l\x9c"), None);
        assert_eq!(tracker.observe(b"\x9b?1049h"), Some(true));
    }
}
