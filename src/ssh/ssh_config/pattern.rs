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

//! Pattern matching utilities for SSH configuration
//!
//! This module provides wildcard pattern matching functionality for SSH host patterns,
//! supporting '*', '?', and negation patterns with '!'.

/// Check if a hostname matches any of the host patterns
pub(super) fn matches_host_pattern(hostname: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if matches_pattern(hostname, pattern) {
            return true;
        }
    }
    false
}

/// Check if a hostname matches a single pattern (supports wildcards)
pub(super) fn matches_pattern(hostname: &str, pattern: &str) -> bool {
    // Handle negation (!)
    if let Some(neg_pattern) = pattern.strip_prefix('!') {
        return !matches_pattern(hostname, neg_pattern);
    }

    // Simple wildcard matching
    if pattern.contains('*') || pattern.contains('?') {
        wildcard_match(hostname, pattern)
    } else {
        // Exact match (case insensitive)
        hostname.eq_ignore_ascii_case(pattern)
    }
}

/// Simple wildcard matching for patterns
pub(super) fn wildcard_match(text: &str, pattern: &str) -> bool {
    wildcard_match_impl(text, pattern)
}

/// Internal recursive implementation for wildcard matching
fn wildcard_match_impl(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();

    match_recursive(&text_chars, &pattern_chars, 0, 0)
}

/// Recursive helper for wildcard matching
pub(super) fn match_recursive(
    text_chars: &[char],
    pattern_chars: &[char],
    text_idx: usize,
    pattern_idx: usize,
) -> bool {
    // Base cases
    if pattern_idx >= pattern_chars.len() {
        return text_idx >= text_chars.len();
    }

    if text_idx >= text_chars.len() {
        // Check if remaining pattern is all '*'
        return pattern_chars[pattern_idx..].iter().all(|&c| c == '*');
    }

    let pattern_char = pattern_chars[pattern_idx];
    let text_char = text_chars[text_idx];

    match pattern_char {
        '*' => {
            // Try matching zero characters (skip the *)
            if match_recursive(text_chars, pattern_chars, text_idx, pattern_idx + 1) {
                return true;
            }

            // Try matching one or more characters
            if match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx) {
                return true;
            }

            false
        }
        '?' => {
            // Match any single character
            match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx + 1)
        }
        _ => {
            // Exact character match (case insensitive)
            if text_char.eq_ignore_ascii_case(&pattern_char) {
                match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx + 1)
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(wildcard_match("web1.example.com", "web*.example.com"));
        assert!(wildcard_match("web123.example.com", "web*.example.com"));
        assert!(!wildcard_match("db1.example.com", "web*.example.com"));
        assert!(wildcard_match("test", "?est"));
        assert!(!wildcard_match("testing", "?est"));
        assert!(wildcard_match("anything", "*"));
    }

    #[test]
    fn test_pattern_matching_with_negation() {
        assert!(matches_pattern("web1.example.com", "web*.example.com"));
        assert!(!matches_pattern("web1.example.com", "!web*.example.com"));
        assert!(matches_pattern("db1.example.com", "!web*.example.com"));
    }

    #[test]
    fn test_host_pattern_matching() {
        let patterns = vec!["web*.example.com".to_string(), "*.test.com".to_string()];
        assert!(matches_host_pattern("web1.example.com", &patterns));
        assert!(matches_host_pattern("api.test.com", &patterns));
        assert!(!matches_host_pattern("db1.example.com", &patterns));
    }
}
