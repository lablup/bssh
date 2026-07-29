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

//! Tracks remote DECSET/DECRST 1049 transitions across fragmented PTY output.

const MAX_CSI_SEQUENCE: usize = 64;

#[derive(Debug)]
pub(crate) struct ScreenModeTracker {
    pending: Vec<u8>,
}

impl ScreenModeTracker {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Return the last DEC 1049 state explicitly selected by this output.
    pub(crate) fn observe(&mut self, input: &[u8]) -> Option<bool> {
        self.pending.extend_from_slice(input);
        let mut current = None;
        let mut consumed = 0;

        for (start, end) in csi_ranges(&self.pending) {
            if let Some(is_set) = parse_1049_selection(&self.pending[start..end]) {
                current = Some(is_set);
            }
            consumed = end;
        }

        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        if self.pending.len() > MAX_CSI_SEQUENCE {
            let keep_from = self.pending.len() - MAX_CSI_SEQUENCE;
            self.pending.drain(..keep_from);
        }

        current
    }
}

fn parse_1049_selection(sequence: &[u8]) -> Option<bool> {
    let (parameters, is_set) = if let Some(value) = sequence
        .strip_prefix(b"\x1b[?")
        .and_then(|value| value.strip_suffix(b"h"))
    {
        (value, true)
    } else {
        (sequence.strip_prefix(b"\x1b[?")?.strip_suffix(b"l")?, false)
    };

    parameters
        .split(|byte| *byte == b';')
        .any(|mode| mode == b"1049")
        .then_some(is_set)
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
    use super::*;

    #[test]
    fn tracks_fragmented_1049_transitions_and_last_value() {
        let mut tracker = ScreenModeTracker::new();

        assert_eq!(tracker.observe(b"text\x1b[?10"), None);
        assert_eq!(tracker.observe(b"49h\x1b[?25;1049l"), Some(false));
        assert_eq!(tracker.observe(b"\x1b[?47h"), None);
    }
}
