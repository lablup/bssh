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

//! Bounded capture and restoration of local enhanced-keyboard terminal modes.

use std::io::Write;
use std::time::{Duration, Instant};

use super::session::raw_input::RawInputReader;

const QUERY_SEQUENCE: &[u8] = b"\x1b[?u\x1b[?4m\x1b[?1049$p\x1b[c";
const QUERY_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_QUERY_INPUT: usize = 4096;
const MAX_CSI_SEQUENCE: usize = 64;

const COMMON_RESET_PREFIX: &[u8] =
    b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l";
const LEAVE_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049l";
const ENTER_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";
const KEYBOARD_RESET: &[u8] = b"\x1b[<999u\x1b[=0u\x1b[>4;0m";
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProtocolState {
    /// Raw Kitty progressive-enhancement flags, including flags unknown to crossterm.
    kitty_flags: Option<u32>,
    /// xterm's `modifyOtherKeys` resource value.
    modify_other_keys: Option<ModifyOtherKeys>,
    /// Whether DEC private mode 1049 was set before bssh took control.
    alternate_screen: Option<bool>,
    /// Last screen selection observed in remote output.
    current_alternate_screen: Option<bool>,
    /// Whether remote output switched away from the initial screen at any point.
    screen_changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModifyOtherKeys {
    Value(u32),
    Disabled,
}

impl ProtocolState {
    pub(crate) fn set_screen_observation(
        &mut self,
        is_alternate: Option<bool>,
        screen_changed: bool,
    ) {
        self.current_alternate_screen = is_alternate;
        self.screen_changed = screen_changed;
    }

    pub(crate) fn current_alternate_screen(&self) -> Option<bool> {
        self.current_alternate_screen
    }

    pub(crate) fn initial_alternate_screen(&self) -> Option<bool> {
        self.alternate_screen
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProtocolCapture {
    pub(crate) state: ProtocolState,
    pub(crate) pending_input: Vec<u8>,
}

trait QueryInput {
    fn poll(&self, timeout: Duration) -> std::io::Result<bool>;
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize>;
}

impl QueryInput for RawInputReader {
    fn poll(&self, timeout: Duration) -> std::io::Result<bool> {
        RawInputReader::poll(self, timeout)
    }

    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        RawInputReader::read(self, buffer)
    }
}

/// Capture terminal protocol state before the PTY input task starts.
///
/// The primary-device-attributes request is a sentinel: terminals answer it even
/// when they do not implement the preceding optional queries. Bytes that are not
/// strict matches for one of our replies are returned for normal PTY forwarding.
pub(crate) fn capture_protocol_state(writer: &mut impl Write) -> ProtocolCapture {
    let mut reader = RawInputReader::new();
    capture_with_io(writer, &mut reader, QUERY_TIMEOUT)
}

fn capture_with_io(
    writer: &mut impl Write,
    reader: &mut impl QueryInput,
    timeout: Duration,
) -> ProtocolCapture {
    if writer
        .write_all(QUERY_SEQUENCE)
        .and_then(|()| writer.flush())
        .is_err()
    {
        return ProtocolCapture::default();
    }

    let deadline = Instant::now() + timeout;
    let mut input = Vec::new();
    let mut buffer = [0_u8; 256];

    while input.len() < MAX_QUERY_INPUT {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match reader.poll(remaining) {
            Ok(true) => {}
            Ok(false) | Err(_) => break,
        }

        let read_limit = buffer.len().min(MAX_QUERY_INPUT - input.len());
        match reader.read(&mut buffer[..read_limit]) {
            Ok(0) | Err(_) => break,
            Ok(read) => input.extend_from_slice(&buffer[..read]),
        }

        if contains_primary_device_attributes(&input) {
            break;
        }
    }

    parse_query_input(&input)
}

fn contains_primary_device_attributes(input: &[u8]) -> bool {
    csi_sequences(input).any(is_primary_device_attributes)
}

fn parse_query_input(input: &[u8]) -> ProtocolCapture {
    let mut capture = ProtocolCapture::default();
    let mut cursor = 0;

    for (start, end) in csi_ranges(input) {
        capture
            .pending_input
            .extend_from_slice(&input[cursor..start]);
        let sequence = &input[start..end];

        if let Some(flags) = parse_decimal_reply(sequence, b"\x1b[?", b"u") {
            capture.state.kitty_flags = Some(flags);
        } else if let Some(value) = parse_decimal_reply(sequence, b"\x1b[>4;", b"m") {
            capture.state.modify_other_keys = Some(ModifyOtherKeys::Value(value));
        } else if sequence == b"\x1b[>4n" {
            capture.state.modify_other_keys = Some(ModifyOtherKeys::Disabled);
        } else if let Some(mode) = parse_decimal_reply(sequence, b"\x1b[?1049;", b"$y") {
            capture.state.alternate_screen = match mode {
                1 | 3 => Some(true),
                2 | 4 => Some(false),
                _ => None,
            };
            capture.state.current_alternate_screen = capture.state.alternate_screen;
        } else if !is_primary_device_attributes(sequence) {
            capture.pending_input.extend_from_slice(sequence);
        }

        cursor = end;
    }
    capture.pending_input.extend_from_slice(&input[cursor..]);
    capture
}

fn parse_decimal_reply(sequence: &[u8], prefix: &[u8], suffix: &[u8]) -> Option<u32> {
    let digits = sequence.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

fn is_primary_device_attributes(sequence: &[u8]) -> bool {
    let Some(parameters) = sequence
        .strip_prefix(b"\x1b[?")
        .and_then(|value| value.strip_suffix(b"c"))
    else {
        return false;
    };
    !parameters.is_empty()
        && parameters
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b';')
}

fn csi_sequences(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    csi_ranges(input).map(|(start, end)| &input[start..end])
}

fn csi_ranges(input: &[u8]) -> impl Iterator<Item = (usize, usize)> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        while offset + 1 < input.len() {
            if input[offset] != b'\x1b' || input[offset + 1] != b'[' {
                offset += 1;
                continue;
            }

            let start = offset;
            let limit = input.len().min(start + MAX_CSI_SEQUENCE);
            offset += 2;
            while offset < limit {
                if (0x40..=0x7e).contains(&input[offset]) {
                    offset += 1;
                    return Some((start, offset));
                }
                offset += 1;
            }
        }
        None
    })
}

/// Reset remote-owned modes, then restore the captured local keyboard state.
pub(crate) fn write_terminal_cleanup(writer: &mut impl Write, state: &ProtocolState) {
    let _ = (|| -> std::io::Result<()> {
        writer.write_all(COMMON_RESET_PREFIX)?;

        match (
            state.alternate_screen,
            state.current_alternate_screen,
            state.screen_changed,
        ) {
            (Some(true), Some(true), false) | (Some(false), Some(false), false) => {
                write_keyboard_restore(writer, state)?;
            }
            (Some(true), Some(false), _) => {
                writer.write_all(ENTER_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                write_keyboard_restore(writer, state)?;
            }
            (Some(false), Some(true), _) => {
                writer.write_all(LEAVE_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                write_keyboard_restore(writer, state)?;
            }
            (Some(true), Some(true), true) => {
                writer.write_all(LEAVE_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                writer.write_all(ENTER_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                write_keyboard_restore(writer, state)?;
            }
            (Some(false), Some(false), true) => {
                writer.write_all(ENTER_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                writer.write_all(LEAVE_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
                write_keyboard_restore(writer, state)?;
            }
            _ => {
                writer.write_all(LEAVE_ALTERNATE_SCREEN)?;
                writer.write_all(KEYBOARD_RESET)?;
            }
        }

        writer.write_all(SHOW_CURSOR)?;
        writer.flush()
    })();
}

fn write_keyboard_restore(writer: &mut impl Write, state: &ProtocolState) -> std::io::Result<()> {
    if let Some(flags) = state.kitty_flags {
        write!(writer, "\x1b[={flags}u")?;
    }
    if let Some(value) = state.modify_other_keys {
        match value {
            ModifyOtherKeys::Value(value) => write!(writer, "\x1b[>4;{value}m")?,
            ModifyOtherKeys::Disabled => writer.write_all(b"\x1b[>4n")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Default)]
    struct FakeInput {
        chunks: VecDeque<Vec<u8>>,
    }

    impl FakeInput {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
            }
        }
    }

    impl QueryInput for FakeInput {
        fn poll(&self, _timeout: Duration) -> std::io::Result<bool> {
            Ok(!self.chunks.is_empty())
        }

        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(0);
            };
            let read = chunk.len().min(buffer.len());
            buffer[..read].copy_from_slice(&chunk[..read]);
            Ok(read)
        }
    }

    #[test]
    fn captures_fragmented_replies_and_preserves_user_input() {
        let mut output = Vec::new();
        let mut input = FakeInput::new(&[
            b"typed",
            b"\x1b[?3",
            b"1u\x1b[>4;2m\x1b[?1049;1$y\x1b[?1;2c",
        ]);

        let capture = capture_with_io(&mut output, &mut input, Duration::from_secs(1));

        assert_eq!(output, QUERY_SEQUENCE);
        assert_eq!(
            capture.state,
            ProtocolState {
                kitty_flags: Some(31),
                modify_other_keys: Some(ModifyOtherKeys::Value(2)),
                alternate_screen: Some(true),
                current_alternate_screen: Some(true),
                screen_changed: false,
            }
        );
        assert_eq!(capture.pending_input, b"typed");
    }

    #[test]
    fn timeout_and_unsupported_terminal_fall_back_without_losing_input() {
        let mut output = Vec::new();
        let mut input = FakeInput::new(&[b"abc\x1b[?1;2c"]);

        let capture = capture_with_io(&mut output, &mut input, Duration::from_secs(1));

        assert_eq!(capture.state, ProtocolState::default());
        assert_eq!(capture.pending_input, b"abc");
    }

    #[test]
    fn malformed_and_unrelated_sequences_are_preserved() {
        let input = b"\x1b[?99999999999u\x1b[?x u\x1b[Aplain";

        let capture = parse_query_input(input);

        assert_eq!(capture.state, ProtocolState::default());
        assert_eq!(capture.pending_input, input);
    }

    #[test]
    fn restores_main_screen_flags_exactly() {
        let mut output = Vec::new();
        let state = ProtocolState {
            kitty_flags: Some(31),
            modify_other_keys: Some(ModifyOtherKeys::Value(2)),
            alternate_screen: Some(false),
            current_alternate_screen: Some(false),
            screen_changed: false,
        };

        write_terminal_cleanup(&mut output, &state);

        assert_eq!(
            output,
            b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\
              \x1b[=31u\x1b[>4;2m\x1b[?25h"
        );
    }

    #[test]
    fn preserves_outer_alternate_screen_without_switching_buffers() {
        let mut output = Vec::new();
        let state = ProtocolState {
            kitty_flags: Some(7),
            modify_other_keys: Some(ModifyOtherKeys::Value(1)),
            alternate_screen: Some(true),
            current_alternate_screen: Some(true),
            screen_changed: false,
        };

        write_terminal_cleanup(&mut output, &state);

        assert_eq!(
            output,
            b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\
              \x1b[=7u\x1b[>4;1m\x1b[?25h"
        );
    }

    #[test]
    fn returns_to_outer_alternate_screen_when_remote_left_it() {
        let mut output = Vec::new();
        let state = ProtocolState {
            kitty_flags: Some(7),
            modify_other_keys: Some(ModifyOtherKeys::Value(1)),
            alternate_screen: Some(true),
            current_alternate_screen: Some(false),
            screen_changed: true,
        };

        write_terminal_cleanup(&mut output, &state);

        assert!(output.windows(8).any(|window| window == b"\x1b[?1049h"));
        assert!(output.ends_with(b"\x1b[=7u\x1b[>4;1m\x1b[?25h"));
    }

    #[test]
    fn cleans_both_screens_after_remote_round_trip() {
        let mut output = Vec::new();
        let state = ProtocolState {
            kitty_flags: Some(7),
            modify_other_keys: None,
            alternate_screen: Some(true),
            current_alternate_screen: Some(true),
            screen_changed: true,
        };

        write_terminal_cleanup(&mut output, &state);

        assert!(output.windows(8).any(|window| window == b"\x1b[?1049l"));
        assert!(output.windows(8).any(|window| window == b"\x1b[?1049h"));
        assert!(output.ends_with(b"\x1b[=7u\x1b[?25h"));
    }

    #[test]
    fn unknown_screen_state_uses_legacy_baseline() {
        let mut output = Vec::new();

        write_terminal_cleanup(&mut output, &ProtocolState::default());

        assert_eq!(
            output,
            b"\x1b[?2004l\x1b[<999u\x1b[=0u\x1b[>4;0m\
              \x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\
              \x1b[?1049l\x1b[<999u\x1b[=0u\x1b[>4;0m\x1b[?25h"
        );
    }

    #[test]
    fn repeated_cleanup_keeps_restoring_the_captured_state() {
        let state = ProtocolState {
            kitty_flags: Some(31),
            modify_other_keys: Some(ModifyOtherKeys::Value(2)),
            alternate_screen: Some(false),
            current_alternate_screen: Some(false),
            screen_changed: false,
        };
        let mut output = Vec::new();

        for _ in 0..3 {
            write_terminal_cleanup(&mut output, &state);
        }

        assert_eq!(
            output
                .windows(b"\x1b[=31u".len())
                .filter(|window| *window == b"\x1b[=31u")
                .count(),
            3
        );
        assert_eq!(
            output
                .windows(b"\x1b[>4;2m".len())
                .filter(|window| *window == b"\x1b[>4;2m")
                .count(),
            3
        );
    }
}
