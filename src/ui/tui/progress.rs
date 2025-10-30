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

//! Progress parsing utilities for detecting progress indicators in command output.
//!
//! This module provides heuristics to parse progress information from command output,
//! detecting patterns like "78%", "23/100", or common progress bar formats.

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Matches percentage patterns like "78%", "100.0%"
    static ref PERCENT_PATTERN: Regex = Regex::new(r"(\d+(?:\.\d+)?)\s*%").unwrap();

    /// Matches fraction patterns like "23/100", "45/50"
    static ref FRACTION_PATTERN: Regex = Regex::new(r"(\d+)\s*/\s*(\d+)").unwrap();

    /// Matches apt/dpkg progress patterns like "Reading package lists... 78%"
    static ref APT_PROGRESS: Regex = Regex::new(r"(?:Reading|Building|Preparing|Unpacking|Setting up|Processing).*?(\d+)%").unwrap();
}

/// Parse progress from a text string
///
/// Returns progress as a percentage (0.0 to 100.0) or None if no progress detected.
///
/// # Examples
///
/// ```
/// use bssh::ui::tui::progress::parse_progress;
///
/// assert_eq!(parse_progress("Downloading: 78%"), Some(78.0));
/// assert_eq!(parse_progress("Progress: 45/100"), Some(45.0));
/// assert_eq!(parse_progress("No progress here"), None);
/// ```
pub fn parse_progress(text: &str) -> Option<f32> {
    // Try apt-specific pattern first (more specific)
    if let Some(cap) = APT_PROGRESS.captures(text) {
        if let Ok(percent) = cap[1].parse::<f32>() {
            return Some(percent.min(100.0));
        }
    }

    // Try general percent pattern: "78%"
    if let Some(cap) = PERCENT_PATTERN.captures(text) {
        if let Ok(percent) = cap[1].parse::<f32>() {
            return Some(percent.min(100.0));
        }
    }

    // Try fraction pattern: "23/100"
    if let Some(cap) = FRACTION_PATTERN.captures(text) {
        if let (Ok(current), Ok(total)) = (cap[1].parse::<f32>(), cap[2].parse::<f32>()) {
            if total > 0.0 {
                return Some((current / total * 100.0).min(100.0));
            }
        }
    }

    None
}

/// Parse progress from command output buffer
///
/// Looks for progress in the last few lines of output (most recent progress is usually
/// at the end). Returns the highest progress value found, or None if no progress detected.
///
/// # Examples
///
/// ```
/// use bssh::ui::tui::progress::parse_progress_from_output;
///
/// let output = b"Starting...\nDownloading: 50%\nDownloading: 75%\nDone";
/// assert_eq!(parse_progress_from_output(output), Some(75.0));
/// ```
pub fn parse_progress_from_output(output: &[u8]) -> Option<f32> {
    let text = String::from_utf8_lossy(output);

    // Look for progress in last 20 lines (performance optimization)
    // Take the maximum progress value found
    text.lines()
        .rev()
        .take(20)
        .filter_map(parse_progress)
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
}

/// Extract a human-readable status message from the last few lines of output
///
/// This tries to find meaningful status text near progress indicators,
/// like "Unpacking packages..." or "Configuring postgresql..."
pub fn extract_status_message(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);

    // Look for the last non-empty line that contains useful info
    text.lines()
        .rev()
        .take(10)
        .find(|line| {
            let line = line.trim();
            !line.is_empty() && line.len() < 100 // Reasonable length for status
        })
        .map(|line| {
            // Trim and clean up the line
            let line = line.trim();

            // If line is too long, truncate with ellipsis
            if line.len() > 80 {
                format!("{}...", &line[..77])
            } else {
                line.to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_percent() {
        assert_eq!(parse_progress("Progress: 78%"), Some(78.0));
        assert_eq!(parse_progress("100%"), Some(100.0));
        assert_eq!(parse_progress("50.5%"), Some(50.5));
        assert_eq!(parse_progress("  25 %  "), Some(25.0));
    }

    #[test]
    fn test_parse_fraction() {
        assert_eq!(parse_progress("23/100"), Some(23.0));
        assert_eq!(parse_progress("45 / 50"), Some(90.0));
        assert_eq!(parse_progress("1/2"), Some(50.0));
    }

    #[test]
    fn test_parse_apt_progress() {
        assert_eq!(parse_progress("Reading package lists... 78%"), Some(78.0));
        assert_eq!(
            parse_progress("Building dependency tree... 50%"),
            Some(50.0)
        );
        assert_eq!(parse_progress("Unpacking postgresql... 95%"), Some(95.0));
    }

    #[test]
    fn test_parse_no_progress() {
        assert_eq!(parse_progress("No progress here"), None);
        assert_eq!(parse_progress("Starting..."), None);
        assert_eq!(parse_progress(""), None);
    }

    #[test]
    fn test_parse_progress_from_output() {
        let output = b"Starting...\nDownloading: 50%\nDownloading: 75%\nDone";
        assert_eq!(parse_progress_from_output(output), Some(75.0));

        let no_progress = b"Just some text\nNo progress here";
        assert_eq!(parse_progress_from_output(no_progress), None);
    }

    #[test]
    fn test_parse_multiple_progress() {
        // Should return the highest value
        let output = b"Step 1: 25%\nStep 2: 50%\nStep 3: 75%\nStep 4: 60%";
        assert_eq!(parse_progress_from_output(output), Some(75.0));
    }

    #[test]
    fn test_extract_status_message() {
        let output = b"Downloading packages...\nUnpacking postgresql-14...";
        assert_eq!(
            extract_status_message(output),
            Some("Unpacking postgresql-14...".to_string())
        );

        let empty = b"";
        assert_eq!(extract_status_message(empty), None);
    }
}
