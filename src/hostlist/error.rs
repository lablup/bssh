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

//! Error types for hostlist parsing and expansion

use thiserror::Error;

/// Errors that can occur during hostlist parsing and expansion
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostlistError {
    /// Empty bracket expression (e.g., `node[]`)
    #[error("empty bracket expression in '{expression}'")]
    EmptyBracket { expression: String },

    /// Unclosed bracket (e.g., `node[1-5`)
    #[error("unclosed bracket in '{expression}'")]
    UnclosedBracket { expression: String },

    /// Unmatched closing bracket (e.g., `node]1-5[`)
    #[error("unmatched closing bracket in '{expression}'")]
    UnmatchedBracket { expression: String },

    /// Invalid range syntax (e.g., `node[a-z]`)
    #[error("invalid range syntax '{range}' in '{expression}': {reason}")]
    InvalidRange {
        expression: String,
        range: String,
        reason: String,
    },

    /// Reversed range (e.g., `node[5-1]`)
    #[error("reversed range '{start}-{end}' in '{expression}' (start must be <= end)")]
    ReversedRange {
        expression: String,
        start: i64,
        end: i64,
    },

    /// Range produces too many hosts
    #[error(
        "range expansion would produce {count} hosts, exceeding limit of {limit} in '{expression}'"
    )]
    RangeTooLarge {
        expression: String,
        count: usize,
        limit: usize,
    },

    /// Invalid number in range
    #[error("invalid number '{value}' in range expression '{expression}'")]
    InvalidNumber { expression: String, value: String },

    /// File not found for ^ prefix
    #[error("hostfile not found: {path}")]
    FileNotFound { path: String },

    /// Error reading hostfile
    #[error("failed to read hostfile '{path}': {reason}")]
    FileReadError { path: String, reason: String },

    /// Nested brackets (e.g., `node[[1-2]]`)
    #[error("nested brackets are not supported in '{expression}'")]
    NestedBrackets { expression: String },

    /// IPv6 address disambiguation failure
    #[error("cannot distinguish IPv6 literal from range expression in '{expression}'")]
    Ipv6Ambiguity { expression: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HostlistError::EmptyBracket {
            expression: "node[]".to_string(),
        };
        assert_eq!(err.to_string(), "empty bracket expression in 'node[]'");

        let err = HostlistError::UnclosedBracket {
            expression: "node[1-5".to_string(),
        };
        assert_eq!(err.to_string(), "unclosed bracket in 'node[1-5'");

        let err = HostlistError::ReversedRange {
            expression: "node[5-1]".to_string(),
            start: 5,
            end: 1,
        };
        assert_eq!(
            err.to_string(),
            "reversed range '5-1' in 'node[5-1]' (start must be <= end)"
        );
    }
}
