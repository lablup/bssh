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

//! Ordered filtering, terminal delivery, and observation of remote output.

use std::io::{self, Write};

use super::escape_filter::EscapeSequenceFilter;

/// Deliver remote bytes for either a PTY terminal or a no-PTY transparent
/// stream. Transparent delivery does not inspect or mutate escape/binary bytes.
pub(super) fn deliver_session_output(
    transparent: bool,
    filter: &mut EscapeSequenceFilter,
    writer: &mut impl Write,
    input: &[u8],
    commit: impl FnOnce(&[u8]),
) -> io::Result<()> {
    if transparent {
        writer.write_all(input)?;
        let _ = writer.flush();
        return Ok(());
    }
    deliver_filtered_output(filter, writer, input, commit)
}

/// Filter remote bytes, write the surviving bytes, then commit only bytes the
/// terminal actually accepted to the protocol observer.
pub(super) fn deliver_filtered_output(
    filter: &mut EscapeSequenceFilter,
    writer: &mut impl Write,
    input: &[u8],
    commit: impl FnOnce(&[u8]),
) -> io::Result<()> {
    let output = filter.filter(input);
    if output.is_empty() {
        return Ok(());
    }

    writer.write_all(&output)?;
    commit(&output);
    let _ = writer.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::terminal_screen::ScreenModeTracker;

    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected delivery failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn transparent_delivery_preserves_escape_nul_and_binary_bytes() {
        let mut filter = EscapeSequenceFilter::new();
        let input = b"\0\xff\x1b]10;payload\x07\x80";
        let mut output = Vec::new();
        let mut committed = false;

        deliver_session_output(true, &mut filter, &mut output, input, |_| {
            committed = true;
        })
        .unwrap();

        assert_eq!(output, input);
        assert!(!committed);
    }

    #[test]
    fn failed_delivery_does_not_commit_screen_transition() {
        let mut filter = EscapeSequenceFilter::new();
        let mut tracker = ScreenModeTracker::new();
        let mut committed = false;

        let result =
            deliver_filtered_output(&mut filter, &mut FailedWriter, b"\x1b[?1049h", |output| {
                committed = true;
                tracker.observe(output);
            });

        assert!(result.is_err());
        assert!(!committed);
    }

    #[test]
    fn filtered_payload_does_not_commit_screen_transition() {
        let mut filter = EscapeSequenceFilter::new();
        let mut tracker = ScreenModeTracker::new();
        let mut output = Vec::new();
        let mut committed = false;

        deliver_filtered_output(
            &mut filter,
            &mut output,
            b"\x1b]10;payload\x1b[?1049h\x07",
            |delivered| {
                committed = true;
                tracker.observe(delivered);
            },
        )
        .unwrap();

        assert!(output.is_empty());
        assert!(!committed);
    }

    #[test]
    fn successful_delivery_commits_screen_transition() {
        let mut filter = EscapeSequenceFilter::new();
        let mut tracker = ScreenModeTracker::new();
        let mut output = Vec::new();
        let mut observed = None;

        deliver_filtered_output(&mut filter, &mut output, b"\x1b[?1049h", |delivered| {
            observed = tracker.observe(delivered);
        })
        .unwrap();

        assert_eq!(output, b"\x1b[?1049h");
        assert_eq!(observed, Some(true));
    }
}
