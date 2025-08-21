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

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Helper function to resolve glob patterns (mimics the main.rs implementation)
fn resolve_source_files(source: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(pattern_str) = source.to_str() {
        if pattern_str.contains('*') || pattern_str.contains('?') || pattern_str.contains('[') {
            // It's a glob pattern
            let matches: Vec<PathBuf> = glob::glob(pattern_str)?.filter_map(Result::ok).collect();

            if matches.is_empty() {
                anyhow::bail!("No files matched the pattern: {}", pattern_str);
            }

            return Ok(matches);
        }
    }

    // Not a glob pattern, return as-is
    Ok(vec![source.to_path_buf()])
}

#[test]
fn test_glob_pattern_matching_txt_files() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    fs::write(temp_dir.path().join("test1.txt"), "content1").unwrap();
    fs::write(temp_dir.path().join("test2.txt"), "content2").unwrap();
    fs::write(temp_dir.path().join("readme.md"), "readme").unwrap();
    fs::write(temp_dir.path().join("config.conf"), "config").unwrap();

    // Test *.txt pattern
    let pattern = temp_dir.path().join("*.txt");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 2);

    let filenames: Vec<String> = matches
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(filenames.contains(&"test1.txt".to_string()));
    assert!(filenames.contains(&"test2.txt".to_string()));
}

#[test]
fn test_glob_pattern_matching_all_files() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    fs::write(temp_dir.path().join("file1.txt"), "content1").unwrap();
    fs::write(temp_dir.path().join("file2.log"), "content2").unwrap();
    fs::write(temp_dir.path().join("file3.conf"), "content3").unwrap();

    // Test * pattern (all files)
    let pattern = temp_dir.path().join("*");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 3);
}

#[test]
fn test_glob_pattern_with_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let sub_dir = temp_dir.path().join("logs");
    fs::create_dir(&sub_dir).unwrap();

    // Create test files in subdirectory
    fs::write(sub_dir.join("app1.log"), "log1").unwrap();
    fs::write(sub_dir.join("app2.log"), "log2").unwrap();
    fs::write(sub_dir.join("error.txt"), "error").unwrap();

    // Test logs/*.log pattern
    let pattern = temp_dir.path().join("logs").join("*.log");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 2);

    let filenames: Vec<String> = matches
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(filenames.contains(&"app1.log".to_string()));
    assert!(filenames.contains(&"app2.log".to_string()));
}

#[test]
fn test_glob_pattern_no_matches() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    fs::write(temp_dir.path().join("test.txt"), "content").unwrap();

    // Test pattern with no matches
    let pattern = temp_dir.path().join("*.pdf");
    let result = resolve_source_files(&pattern);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No files matched"));
}

#[test]
fn test_non_glob_pattern() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("single_file.txt");
    fs::write(&test_file, "content").unwrap();

    // Test non-glob pattern (single file)
    let matches = resolve_source_files(&test_file).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], test_file);
}

#[test]
fn test_glob_pattern_with_question_mark() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    fs::write(temp_dir.path().join("test1.txt"), "content1").unwrap();
    fs::write(temp_dir.path().join("test2.txt"), "content2").unwrap();
    fs::write(temp_dir.path().join("test10.txt"), "content10").unwrap();

    // Test test?.txt pattern (matches single character)
    let pattern = temp_dir.path().join("test?.txt");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 2); // Should match test1.txt and test2.txt, not test10.txt
}

#[test]
fn test_glob_pattern_with_brackets() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    fs::write(temp_dir.path().join("file1.txt"), "content1").unwrap();
    fs::write(temp_dir.path().join("file2.txt"), "content2").unwrap();
    fs::write(temp_dir.path().join("file3.txt"), "content3").unwrap();
    fs::write(temp_dir.path().join("file4.txt"), "content4").unwrap();

    // Test file[1-2].txt pattern
    let pattern = temp_dir.path().join("file[1-2].txt");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 2);

    let filenames: Vec<String> = matches
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert!(filenames.contains(&"file1.txt".to_string()));
    assert!(filenames.contains(&"file2.txt".to_string()));
}

#[test]
fn test_complex_glob_pattern() {
    let temp_dir = TempDir::new().unwrap();

    // Create a complex directory structure
    let logs_dir = temp_dir.path().join("logs");
    fs::create_dir(&logs_dir).unwrap();

    fs::write(logs_dir.join("app.2024-01-01.log"), "log1").unwrap();
    fs::write(logs_dir.join("app.2024-01-02.log"), "log2").unwrap();
    fs::write(logs_dir.join("error.2024-01-01.log"), "error1").unwrap();
    fs::write(logs_dir.join("debug.txt"), "debug").unwrap();

    // Test app.*.log pattern
    let pattern = temp_dir.path().join("logs").join("app.*.log");
    let matches = resolve_source_files(&pattern).unwrap();

    assert_eq!(matches.len(), 2);

    for path in &matches {
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("app."));
        assert!(filename.ends_with(".log"));
    }
}
