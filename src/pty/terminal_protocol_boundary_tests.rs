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

use super::terminal_protocol::parse_query_input;

#[test]
fn preserves_reply_shaped_and_user_bytes_after_da_sentinel() {
    let input = b"\x1b[?7u\x1b[?1049;2$y\x1b[?1;2c\x1b[?31uuser";

    let capture = parse_query_input(input);

    assert!(capture.completed);
    assert_eq!(capture.pending_input, b"\x1b[?31uuser");
}

#[test]
fn missing_da_discards_state_and_preserves_every_captured_byte() {
    let input = b"typed\x1b[?31u\x1b[>4;2m\x1b[?1049;1$y";

    let capture = parse_query_input(input);

    assert!(!capture.completed);
    assert_eq!(capture.pending_input, input);
}

#[test]
fn invalid_decrqm_mode_is_preserved_as_malformed_input() {
    let input = b"\x1b[?1049;9$y\x1b[?1;2c";

    let capture = parse_query_input(input);

    assert!(capture.completed);
    assert!(capture.alternate_screen.is_none());
    assert_eq!(capture.pending_input, b"\x1b[?1049;9$y");
}
