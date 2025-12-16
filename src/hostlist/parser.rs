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

//! Parser for hostlist expressions
//!
//! This module parses hostlist expressions into structured representations
//! that can be expanded into lists of hostnames.

use super::error::HostlistError;
use std::path::Path;

/// Represents a parsed range item (single value or range)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeItem {
    /// A single numeric value
    Single(i64),
    /// A range from start to end (inclusive)
    Range { start: i64, end: i64 },
}

/// Represents a parsed range expression with padding information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeExpression {
    /// The range items (values and ranges)
    pub items: Vec<RangeItem>,
    /// The minimum padding width (determined from zero-padded numbers)
    pub padding: usize,
}

/// Represents a segment of a host pattern (literal text or range expression)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternSegment {
    /// Literal text (e.g., "node", ".example.com")
    Literal(String),
    /// Range expression (e.g., [1-5], [01-05])
    Range(RangeExpression),
}

/// Represents a complete host pattern
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// The segments making up this pattern
    pub segments: Vec<PatternSegment>,
}

impl HostPattern {
    /// Check if this pattern contains any range expressions
    pub fn has_ranges(&self) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s, PatternSegment::Range(_)))
    }

    /// Get the expected expansion count (product of all range sizes)
    pub fn expansion_count(&self) -> usize {
        let mut count = 1usize;
        for segment in &self.segments {
            if let PatternSegment::Range(range) = segment {
                count = count.saturating_mul(range.item_count());
            }
        }
        count
    }
}

impl RangeExpression {
    /// Count the total number of values this range expression represents
    pub fn item_count(&self) -> usize {
        self.items.iter().map(|item| item.count()).sum()
    }

    /// Generate all values from this range expression
    pub fn values(&self) -> Vec<i64> {
        let mut result = Vec::new();
        for item in &self.items {
            match item {
                RangeItem::Single(v) => result.push(*v),
                RangeItem::Range { start, end } => {
                    for v in *start..=*end {
                        result.push(v);
                    }
                }
            }
        }
        result
    }

    /// Format a value with the appropriate padding
    pub fn format_value(&self, value: i64) -> String {
        if self.padding > 0 {
            format!("{:0>width$}", value, width = self.padding)
        } else {
            value.to_string()
        }
    }
}

impl RangeItem {
    /// Count the number of values this item represents
    pub fn count(&self) -> usize {
        match self {
            RangeItem::Single(_) => 1,
            RangeItem::Range { start, end } => {
                if end >= start {
                    (end - start + 1) as usize
                } else {
                    0
                }
            }
        }
    }
}

/// Parse a host pattern string into a HostPattern structure
///
/// # Arguments
///
/// * `pattern` - The host pattern string to parse
///
/// # Returns
///
/// A parsed HostPattern structure or an error.
///
/// # Examples
///
/// ```rust
/// use bssh::hostlist::parse_host_pattern;
///
/// let pattern = parse_host_pattern("node[1-3]").unwrap();
/// assert!(pattern.has_ranges());
/// assert_eq!(pattern.expansion_count(), 3);
/// ```
pub fn parse_host_pattern(pattern: &str) -> Result<HostPattern, HostlistError> {
    if pattern.is_empty() {
        return Ok(HostPattern {
            segments: Vec::new(),
        });
    }

    let mut segments = Vec::new();
    let mut current_literal = String::new();
    let mut chars = pattern.chars().peekable();
    let mut bracket_depth = 0;

    while let Some(ch) = chars.next() {
        match ch {
            '[' => {
                if bracket_depth > 0 {
                    return Err(HostlistError::NestedBrackets {
                        expression: pattern.to_string(),
                    });
                }

                // Check for IPv6 literal (starts with digit or colon after [)
                if let Some(&next_ch) = chars.peek() {
                    if is_ipv6_start(next_ch, &chars) {
                        // This might be an IPv6 literal, collect until matching ]
                        current_literal.push(ch);
                        continue;
                    }
                }

                // Save any accumulated literal
                if !current_literal.is_empty() {
                    segments.push(PatternSegment::Literal(current_literal.clone()));
                    current_literal.clear();
                }

                // Parse range expression
                bracket_depth = 1;
                let mut range_content = String::new();

                for inner_ch in chars.by_ref() {
                    match inner_ch {
                        '[' => {
                            return Err(HostlistError::NestedBrackets {
                                expression: pattern.to_string(),
                            });
                        }
                        ']' => {
                            bracket_depth = 0;
                            break;
                        }
                        _ => range_content.push(inner_ch),
                    }
                }

                if bracket_depth != 0 {
                    return Err(HostlistError::UnclosedBracket {
                        expression: pattern.to_string(),
                    });
                }

                if range_content.is_empty() {
                    return Err(HostlistError::EmptyBracket {
                        expression: pattern.to_string(),
                    });
                }

                let range_expr = parse_range_expression(&range_content, pattern)?;
                segments.push(PatternSegment::Range(range_expr));
            }
            ']' => {
                if bracket_depth == 0 {
                    return Err(HostlistError::UnmatchedBracket {
                        expression: pattern.to_string(),
                    });
                }
                bracket_depth -= 1;
            }
            _ => {
                current_literal.push(ch);
            }
        }
    }

    // Save any remaining literal
    if !current_literal.is_empty() {
        segments.push(PatternSegment::Literal(current_literal));
    }

    Ok(HostPattern { segments })
}

/// Check if a character sequence might be the start of an IPv6 literal
fn is_ipv6_start(next_ch: char, _chars: &std::iter::Peekable<std::str::Chars>) -> bool {
    // IPv6 literals start with a colon (e.g., [::1] or [2001:db8::1])
    // We use a conservative heuristic: only treat as IPv6 if we see a colon
    // This means hex digits like 'a' will be treated as potential hostlist content
    // and will fail with InvalidNumber if they're not valid numeric ranges
    next_ch == ':'
}

/// Parse a range expression (content between brackets)
fn parse_range_expression(content: &str, pattern: &str) -> Result<RangeExpression, HostlistError> {
    let mut items = Vec::new();
    let mut max_padding = 0;

    // Split by comma to get individual range items
    for item_str in content.split(',') {
        let item_str = item_str.trim();
        if item_str.is_empty() {
            continue;
        }

        // Check if this is a range (contains -)
        if let Some(dash_pos) = item_str.find('-') {
            // Could be a negative number or a range
            // If dash is at position 0, it's a negative number start
            if dash_pos == 0 {
                // Starts with -, could be negative number or negative range start
                let rest = &item_str[1..];
                if let Some(second_dash) = rest.find('-') {
                    // Negative start to something: -5-10 means -5 to 10
                    let start_str = &item_str[..=second_dash];
                    let end_str = &rest[second_dash + 1..];
                    let (start, start_padding) = parse_number(start_str, pattern)?;
                    let (end, end_padding) = parse_number(end_str, pattern)?;

                    if start > end {
                        return Err(HostlistError::ReversedRange {
                            expression: pattern.to_string(),
                            start,
                            end,
                        });
                    }

                    max_padding = max_padding.max(start_padding).max(end_padding);
                    items.push(RangeItem::Range { start, end });
                } else {
                    // Just a negative number
                    let (value, padding) = parse_number(item_str, pattern)?;
                    max_padding = max_padding.max(padding);
                    items.push(RangeItem::Single(value));
                }
            } else {
                // Normal range: start-end
                let start_str = &item_str[..dash_pos];
                let end_str = &item_str[dash_pos + 1..];

                // Check for negative end (e.g., 5--3 is invalid, but handle gracefully)
                if end_str.starts_with('-') && !end_str[1..].starts_with('-') {
                    // Negative end value
                    let (start, start_padding) = parse_number(start_str, pattern)?;
                    let (end, end_padding) = parse_number(end_str, pattern)?;

                    if start > end {
                        return Err(HostlistError::ReversedRange {
                            expression: pattern.to_string(),
                            start,
                            end,
                        });
                    }

                    max_padding = max_padding.max(start_padding).max(end_padding);
                    items.push(RangeItem::Range { start, end });
                } else {
                    let (start, start_padding) = parse_number(start_str, pattern)?;
                    let (end, end_padding) = parse_number(end_str, pattern)?;

                    if start > end {
                        return Err(HostlistError::ReversedRange {
                            expression: pattern.to_string(),
                            start,
                            end,
                        });
                    }

                    max_padding = max_padding.max(start_padding).max(end_padding);
                    items.push(RangeItem::Range { start, end });
                }
            }
        } else {
            // Single value
            let (value, padding) = parse_number(item_str, pattern)?;
            max_padding = max_padding.max(padding);
            items.push(RangeItem::Single(value));
        }
    }

    if items.is_empty() {
        return Err(HostlistError::EmptyBracket {
            expression: pattern.to_string(),
        });
    }

    Ok(RangeExpression {
        items,
        padding: max_padding,
    })
}

/// Parse a number string, returning the value and padding width
fn parse_number(s: &str, pattern: &str) -> Result<(i64, usize), HostlistError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(HostlistError::InvalidNumber {
            expression: pattern.to_string(),
            value: s.to_string(),
        });
    }

    // Determine padding from leading zeros
    let digits = if let Some(rest) = s.strip_prefix('-') {
        rest
    } else {
        s
    };

    // Count padding (leading zeros)
    let padding = if digits.len() > 1 && digits.starts_with('0') {
        digits.len()
    } else {
        0
    };

    // Parse the number (includes sign if present)
    let value: i64 = s.parse().map_err(|_| HostlistError::InvalidNumber {
        expression: pattern.to_string(),
        value: s.to_string(),
    })?;

    Ok((value, padding))
}

/// Maximum file size for hostfile (1 MB)
const MAX_HOSTFILE_SIZE: u64 = 1024 * 1024;

/// Maximum number of lines in a hostfile
const MAX_HOSTFILE_LINES: usize = 100_000;

/// Parse hosts from a file (one per line)
///
/// # Arguments
///
/// * `path` - Path to the hostfile
///
/// # Returns
///
/// A vector of hostnames read from the file.
///
/// # Security
///
/// This function implements resource limits to prevent DoS attacks:
/// - Maximum file size: 1 MB
/// - Maximum number of lines: 100,000
pub fn parse_hostfile(path: &Path) -> Result<Vec<String>, HostlistError> {
    // Check file size before reading to prevent resource exhaustion
    let metadata = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            HostlistError::FileNotFound {
                path: path.display().to_string(),
            }
        } else {
            HostlistError::FileReadError {
                path: path.display().to_string(),
                reason: e.to_string(),
            }
        }
    })?;

    let file_size = metadata.len();
    if file_size > MAX_HOSTFILE_SIZE {
        return Err(HostlistError::FileReadError {
            path: path.display().to_string(),
            reason: format!(
                "file size {} bytes exceeds maximum allowed size of {} bytes",
                file_size, MAX_HOSTFILE_SIZE
            ),
        });
    }

    let content = std::fs::read_to_string(path).map_err(|e| HostlistError::FileReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;

    let hosts: Vec<String> = content
        .lines()
        .take(MAX_HOSTFILE_LINES)
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    // Check if we hit the line limit
    if content.lines().count() > MAX_HOSTFILE_LINES {
        return Err(HostlistError::FileReadError {
            path: path.display().to_string(),
            reason: format!(
                "file contains more than {} lines (limit exceeded)",
                MAX_HOSTFILE_LINES
            ),
        });
    }

    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_range() {
        let pattern = parse_host_pattern("node[1-3]").unwrap();
        assert_eq!(pattern.segments.len(), 2);

        match &pattern.segments[0] {
            PatternSegment::Literal(s) => assert_eq!(s, "node"),
            _ => panic!("Expected literal"),
        }

        match &pattern.segments[1] {
            PatternSegment::Range(r) => {
                assert_eq!(r.items.len(), 1);
                assert_eq!(r.padding, 0);
                match &r.items[0] {
                    RangeItem::Range { start, end } => {
                        assert_eq!(*start, 1);
                        assert_eq!(*end, 3);
                    }
                    _ => panic!("Expected range"),
                }
            }
            _ => panic!("Expected range"),
        }
    }

    #[test]
    fn test_parse_zero_padded_range() {
        let pattern = parse_host_pattern("node[01-05]").unwrap();

        match &pattern.segments[1] {
            PatternSegment::Range(r) => {
                assert_eq!(r.padding, 2);
                assert_eq!(r.values(), vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("Expected range"),
        }
    }

    #[test]
    fn test_parse_comma_separated_values() {
        let pattern = parse_host_pattern("node[1,3,5]").unwrap();

        match &pattern.segments[1] {
            PatternSegment::Range(r) => {
                assert_eq!(r.items.len(), 3);
                assert_eq!(r.values(), vec![1, 3, 5]);
            }
            _ => panic!("Expected range"),
        }
    }

    #[test]
    fn test_parse_mixed_range() {
        let pattern = parse_host_pattern("node[1-3,7,9-10]").unwrap();

        match &pattern.segments[1] {
            PatternSegment::Range(r) => {
                assert_eq!(r.values(), vec![1, 2, 3, 7, 9, 10]);
            }
            _ => panic!("Expected range"),
        }
    }

    #[test]
    fn test_parse_multiple_ranges() {
        let pattern = parse_host_pattern("rack[1-2]-node[1-3]").unwrap();
        assert_eq!(pattern.segments.len(), 4);
        assert!(pattern.has_ranges());
        assert_eq!(pattern.expansion_count(), 6);
    }

    #[test]
    fn test_parse_with_domain() {
        let pattern = parse_host_pattern("web[1-3].example.com").unwrap();
        assert_eq!(pattern.segments.len(), 3);

        match &pattern.segments[2] {
            PatternSegment::Literal(s) => assert_eq!(s, ".example.com"),
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_parse_no_range() {
        let pattern = parse_host_pattern("simple.host.com").unwrap();
        assert_eq!(pattern.segments.len(), 1);
        assert!(!pattern.has_ranges());
        assert_eq!(pattern.expansion_count(), 1);
    }

    #[test]
    fn test_parse_empty_bracket_error() {
        let result = parse_host_pattern("node[]");
        assert!(matches!(result, Err(HostlistError::EmptyBracket { .. })));
    }

    #[test]
    fn test_parse_unclosed_bracket_error() {
        let result = parse_host_pattern("node[1-5");
        assert!(matches!(result, Err(HostlistError::UnclosedBracket { .. })));
    }

    #[test]
    fn test_parse_unmatched_bracket_error() {
        let result = parse_host_pattern("node]1-5[");
        assert!(matches!(
            result,
            Err(HostlistError::UnmatchedBracket { .. })
        ));
    }

    #[test]
    fn test_parse_reversed_range_error() {
        let result = parse_host_pattern("node[5-1]");
        assert!(matches!(result, Err(HostlistError::ReversedRange { .. })));
    }

    #[test]
    fn test_parse_invalid_number_error() {
        let result = parse_host_pattern("node[a-z]");
        assert!(matches!(result, Err(HostlistError::InvalidNumber { .. })));
    }

    #[test]
    fn test_parse_nested_brackets_error() {
        let result = parse_host_pattern("node[[1-2]]");
        assert!(matches!(result, Err(HostlistError::NestedBrackets { .. })));
    }

    #[test]
    fn test_range_expression_format_value() {
        let expr = RangeExpression {
            items: vec![RangeItem::Range { start: 1, end: 5 }],
            padding: 3,
        };
        assert_eq!(expr.format_value(1), "001");
        assert_eq!(expr.format_value(12), "012");
        assert_eq!(expr.format_value(123), "123");
    }

    #[test]
    fn test_range_item_count() {
        assert_eq!(RangeItem::Single(5).count(), 1);
        assert_eq!(RangeItem::Range { start: 1, end: 5 }.count(), 5);
        assert_eq!(RangeItem::Range { start: 0, end: 0 }.count(), 1);
    }
}
