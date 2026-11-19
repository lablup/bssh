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

//! Serde helper for audit event timestamps.
//!
//! Audit timestamps are serialized as RFC 3339 UTC strings with a `Z` suffix
//! and 0, 3, 6, or 9 fractional-second digits: the shortest of those widths
//! that represents the instant exactly. This is the format bssh has always
//! written, so downstream log consumers see no change. Deserialization accepts
//! any RFC 3339 timestamp with up to 9 fractional digits and any offset.

use jiff::Timestamp;
use jiff::fmt::temporal::DateTimePrinter;
use serde::{Deserialize, Deserializer, Serializer};

/// Format a timestamp as RFC 3339 UTC with 0, 3, 6, or 9 fractional digits.
pub(crate) fn format(timestamp: &Timestamp) -> String {
    let nanos = timestamp.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    DateTimePrinter::new()
        .precision(Some(precision))
        .timestamp_to_string(timestamp)
}

pub(crate) fn serialize<S: Serializer>(
    timestamp: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format(timestamp))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Timestamp, D::Error> {
    Timestamp::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(nanos: i32) -> Timestamp {
        // 2026-11-20T01:02:03Z
        Timestamp::new(1_795_136_523, nanos).unwrap()
    }

    #[test]
    fn test_format_uses_shortest_si_precision() {
        assert_eq!(format(&ts(0)), "2026-11-20T01:02:03Z");
        assert_eq!(format(&ts(100_000_000)), "2026-11-20T01:02:03.100Z");
        assert_eq!(format(&ts(123_000_000)), "2026-11-20T01:02:03.123Z");
        assert_eq!(format(&ts(123_400_000)), "2026-11-20T01:02:03.123400Z");
        assert_eq!(format(&ts(123_456_000)), "2026-11-20T01:02:03.123456Z");
        assert_eq!(format(&ts(123_456_700)), "2026-11-20T01:02:03.123456700Z");
        assert_eq!(format(&ts(1)), "2026-11-20T01:02:03.000000001Z");
    }

    #[test]
    fn test_parse_round_trips_every_precision() {
        for nanos in [0, 100_000_000, 123_456_000, 123_456_789, 1] {
            let original = ts(nanos);
            let parsed: Timestamp = format(&original).parse().unwrap();
            assert_eq!(parsed, original);
        }
    }
}
