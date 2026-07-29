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

use std::{collections::VecDeque, io::Write};

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

struct FailOnceWriter {
    output: Vec<u8>,
    writes: usize,
    fail_at: usize,
}

impl Write for FailOnceWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self.writes == self.fail_at {
            return Err(std::io::Error::other("injected write failure"));
        }
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FailOnceFlushWriter {
    output: Vec<u8>,
    flushes: usize,
    fail_at: usize,
}

impl Write for FailOnceFlushWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        if self.flushes == self.fail_at {
            return Err(std::io::Error::other("injected flush failure"));
        }
        Ok(())
    }
}

struct NoReplyInput;

impl QueryInput for NoReplyInput {
    fn poll(&self, timeout: Duration) -> std::io::Result<bool> {
        std::thread::sleep(timeout);
        Ok(false)
    }

    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        unreachable!("poll never reports readable input")
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
            initial_screen_alternate: Some(true),
            current_1049: Some(true),
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

#[test]
fn hidden_switch_write_failure_best_effort_returns_to_initial_screen() {
    let mut output = FailOnceWriter {
        output: Vec::new(),
        writes: 0,
        fail_at: 3,
    };
    let mut input = FakeInput::new(&[b"\x1b[?7u\x1b[?1049;2$y\x1b[?1;2c"]);

    let capture = capture_all_screens(&mut output, &mut input, Duration::from_secs(1));

    assert_eq!(capture.state, ProtocolState::default());
    assert!(output.output.ends_with(b"\x1b[?47l\x1b[=0u\x1b[>4;0m"));
}

#[test]
fn hidden_switch_flush_failure_best_effort_returns_to_initial_screen() {
    let mut output = FailOnceFlushWriter {
        output: Vec::new(),
        flushes: 0,
        fail_at: 3,
    };
    let mut input = FakeInput::new(&[b"\x1b[?7u\x1b[?1049;2$y\x1b[?1;2c"]);

    let capture = capture_all_screens(&mut output, &mut input, Duration::from_secs(1));

    assert_eq!(capture.state, ProtocolState::default());
    assert!(output.output.ends_with(b"\x1b[?47l\x1b[=0u\x1b[>4;0m"));
}

#[test]
fn no_da_reply_waits_for_the_bounded_timeout() {
    let timeout = Duration::from_millis(15);
    let started = Instant::now();
    let mut output = Vec::new();
    let mut input = NoReplyInput;

    let capture = capture_all_screens(&mut output, &mut input, timeout);

    assert!(started.elapsed() >= Duration::from_millis(10));
    assert_eq!(capture.state, ProtocolState::default());
    assert!(capture.pending_input.is_empty());
}

#[test]
fn captures_xtqmodkeys_disabled_reply() {
    let capture = parse_query_input(b"\x1b[>4n\x1b[?1;2c");

    assert!(capture.completed);
    assert_eq!(capture.modify_other_keys, Some(ModifyOtherKeys::Disabled));
    assert!(capture.pending_input.is_empty());
}

#[test]
fn accepts_permanently_set_and_reset_decrqm_statuses() {
    let set = parse_query_input(b"\x1b[?1049;3$y\x1b[?1;2c");
    let reset = parse_query_input(b"\x1b[?1049;4$y\x1b[?1;2c");

    assert_eq!(set.alternate_screen, Some(true));
    assert_eq!(reset.alternate_screen, Some(false));
    assert!(set.pending_input.is_empty());
    assert!(reset.pending_input.is_empty());
}
