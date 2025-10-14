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

use anyhow::{Context, Result};
use glob::glob;
use std::path::{Path, PathBuf};

pub fn resolve_source_files(source: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let source_str = source.to_string_lossy();

    // Check if it's a glob pattern (contains *, ?, [, ])
    if source_str.contains('*') || source_str.contains('?') || source_str.contains('[') {
        // Use glob to find matching files
        let mut files = Vec::new();
        for entry in
            glob(&source_str).with_context(|| format!("Invalid glob pattern: {source_str}"))?
        {
            match entry {
                Ok(path) if path.is_file() => files.push(path),
                Ok(path) if path.is_dir() && recursive => {
                    // Recursively add files from directories when using glob with --recursive
                    files.extend(walk_directory(&path)?);
                }
                Ok(_) => {} // Skip directories if not recursive
                Err(e) => tracing::warn!("Failed to read glob entry: {}", e),
            }
        }
        Ok(files)
    } else if source.is_file() {
        // Single file
        Ok(vec![source.to_path_buf()])
    } else if source.exists() && source.is_dir() {
        if recursive {
            // Recursively walk the directory
            walk_directory(source)
        } else {
            anyhow::bail!(
                "Source is a directory. Use --recursive flag or a glob pattern like '{source_str}/*' to upload files"
            );
        }
    } else {
        // Try as glob pattern even without special characters (might be escaped)
        let mut files = Vec::new();
        for path in glob(&source_str)
            .unwrap_or_else(|_| glob::glob("").unwrap())
            .flatten()
        {
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() && recursive {
                files.extend(walk_directory(&path)?);
            }
        }

        if files.is_empty() {
            anyhow::bail!("Source file does not exist: {source:?}");
        }
        Ok(files)
    }
}

// Helper function to recursively walk a directory and collect all files
pub fn walk_directory(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;

        if metadata.is_file() {
            files.push(path);
        } else if metadata.is_dir() {
            // Recursively walk subdirectories
            files.extend(walk_directory(&path)?);
        }
        // Skip symlinks and other special files
    }

    Ok(files)
}

// Helper function to format bytes in human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}
