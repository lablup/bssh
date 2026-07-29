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
pub(crate) use super::terminal_protocol_restore::write_terminal_cleanup;

const INITIAL_QUERY: &[u8] = b"\x1b[?u\x1b[?4m\x1b[?1049$p\x1b[c";
const HIDDEN_SCREEN_QUERY: &[u8] = b"\x1b[?u\x1b[c";
const QUERY_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_QUERY_INPUT: usize = 4096;
const MAX_CSI_SEQUENCE: usize = 64;

const SELECT_MAIN_SCREEN: &[u8] = b"\x1b[?47l";
const SELECT_ALTERNATE_SCREEN: &[u8] = b"\x1b[?47h";
const ENTRY_KEYBOARD_BASELINE: &[u8] = b"\x1b[=0u\x1b[>4;0m";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProtocolState {
    /// Raw Kitty flags for the main screen, including flags unknown to crossterm.
    pub(crate) main_kitty_flags: Option<u32>,
    /// Raw Kitty flags for the alternate screen.
    pub(crate) alternate_kitty_flags: Option<u32>,
    /// xterm's `modifyOtherKeys` resource value.
    pub(crate) modify_other_keys: Option<ModifyOtherKeys>,
    /// Whether DEC private mode 1049 was set before bssh took control.
    pub(crate) alternate_screen: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModifyOtherKeys {
    Value(u32),
    Disabled,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProtocolCapture {
    pub(crate) state: ProtocolState,
    pub(crate) pending_input: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct QueryReplies {
    kitty_flags: Option<u32>,
    modify_other_keys: Option<ModifyOtherKeys>,
    pub(crate) alternate_screen: Option<bool>,
    pub(crate) pending_input: Vec<u8>,
    pub(crate) completed: bool,
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
    capture_all_screens(writer, &mut reader, QUERY_TIMEOUT)
}

fn capture_all_screens(
    writer: &mut impl Write,
    reader: &mut impl QueryInput,
    timeout: Duration,
) -> ProtocolCapture {
    let first = capture_transaction(writer, reader, timeout, INITIAL_QUERY);
    let mut pending_input = first.pending_input;
    let Some(initial_alternate) = first.alternate_screen else {
        let _ = writer.write_all(ENTRY_KEYBOARD_BASELINE);
        let _ = writer.flush();
        return ProtocolCapture {
            state: ProtocolState::default(),
            pending_input,
        };
    };
    if !first.completed {
        let _ = writer.write_all(ENTRY_KEYBOARD_BASELINE);
        let _ = writer.flush();
        return ProtocolCapture {
            state: ProtocolState::default(),
            pending_input,
        };
    }

    let _ = writer.write_all(ENTRY_KEYBOARD_BASELINE);
    let hidden_switch = if initial_alternate {
        SELECT_MAIN_SCREEN
    } else {
        SELECT_ALTERNATE_SCREEN
    };
    let return_switch = if initial_alternate {
        SELECT_ALTERNATE_SCREEN
    } else {
        SELECT_MAIN_SCREEN
    };
    if writer
        .write_all(hidden_switch)
        .and_then(|()| writer.flush())
        .is_err()
    {
        return ProtocolCapture {
            state: ProtocolState::default(),
            pending_input,
        };
    }

    let hidden = capture_transaction(writer, reader, timeout, HIDDEN_SCREEN_QUERY);
    pending_input.extend_from_slice(&hidden.pending_input);
    let _ = writer.write_all(ENTRY_KEYBOARD_BASELINE);
    let _ = writer.write_all(return_switch);
    let _ = writer.write_all(ENTRY_KEYBOARD_BASELINE);
    let _ = writer.flush();

    if !hidden.completed {
        return ProtocolCapture {
            state: ProtocolState::default(),
            pending_input,
        };
    }

    let (main_kitty_flags, alternate_kitty_flags) = if initial_alternate {
        (hidden.kitty_flags, first.kitty_flags)
    } else {
        (first.kitty_flags, hidden.kitty_flags)
    };
    ProtocolCapture {
        state: ProtocolState {
            main_kitty_flags,
            alternate_kitty_flags,
            modify_other_keys: first.modify_other_keys,
            alternate_screen: Some(initial_alternate),
        },
        pending_input,
    }
}

fn capture_transaction(
    writer: &mut impl Write,
    reader: &mut impl QueryInput,
    timeout: Duration,
    query: &[u8],
) -> QueryReplies {
    if writer
        .write_all(query)
        .and_then(|()| writer.flush())
        .is_err()
    {
        return QueryReplies::default();
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

pub(crate) fn parse_query_input(input: &[u8]) -> QueryReplies {
    let Some(sentinel_end) = csi_ranges(input)
        .find_map(|(start, end)| is_primary_device_attributes(&input[start..end]).then_some(end))
    else {
        return QueryReplies {
            pending_input: input.to_vec(),
            ..QueryReplies::default()
        };
    };

    let mut capture = QueryReplies::default();
    let mut cursor = 0;

    for (start, end) in csi_ranges(&input[..sentinel_end]) {
        capture
            .pending_input
            .extend_from_slice(&input[cursor..start]);
        let sequence = &input[start..end];

        if let Some(flags) = parse_decimal_reply(sequence, b"\x1b[?", b"u") {
            capture.kitty_flags = Some(flags);
        } else if let Some(value) = parse_decimal_reply(sequence, b"\x1b[>4;", b"m") {
            capture.modify_other_keys = Some(ModifyOtherKeys::Value(value));
        } else if sequence == b"\x1b[>4n" {
            capture.modify_other_keys = Some(ModifyOtherKeys::Disabled);
        } else if let Some(mode) = parse_decimal_reply(sequence, b"\x1b[?1049;", b"$y") {
            match mode {
                1 | 3 => capture.alternate_screen = Some(true),
                2 | 4 => capture.alternate_screen = Some(false),
                _ => capture.pending_input.extend_from_slice(sequence),
            }
        } else if is_primary_device_attributes(sequence) {
            capture.completed = true;
        } else {
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
            b"\x1b[?5u\x1b[?1;2c",
        ]);

        let capture = capture_all_screens(&mut output, &mut input, Duration::from_secs(1));

        assert_eq!(
            output,
            b"\x1b[?u\x1b[?4m\x1b[?1049$p\x1b[c\
              \x1b[=0u\x1b[>4;0m\x1b[?47l\
              \x1b[?u\x1b[c\
              \x1b[=0u\x1b[>4;0m\x1b[?47h\
              \x1b[=0u\x1b[>4;0m"
        );
        assert_eq!(
            capture.state,
            ProtocolState {
                main_kitty_flags: Some(5),
                alternate_kitty_flags: Some(31),
                modify_other_keys: Some(ModifyOtherKeys::Value(2)),
                alternate_screen: Some(true),
            }
        );
        assert_eq!(capture.pending_input, b"typed");
    }

    #[test]
    fn timeout_and_unsupported_terminal_fall_back_without_losing_input() {
        let mut output = Vec::new();
        let mut input = FakeInput::new(&[b"abc\x1b[?1;2c"]);

        let capture = capture_all_screens(&mut output, &mut input, Duration::from_secs(1));

        assert_eq!(capture.state, ProtocolState::default());
        assert_eq!(capture.pending_input, b"abc");
    }

    #[test]
    fn malformed_and_unrelated_sequences_are_preserved() {
        let input = b"\x1b[?99999999999u\x1b[?x u\x1b[Aplain";

        let capture = parse_query_input(input);

        assert!(!capture.completed);
        assert_eq!(capture.pending_input, input);
    }
}
