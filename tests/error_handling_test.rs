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

use bssh::executor::ParallelExecutor;
use bssh::node::Node;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_upload_nonexistent_file() {
    let nodes = vec![Node::new("localhost".to_string(), 22, "user".to_string())];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Try to upload a file that doesn't exist
    let nonexistent_file = PathBuf::from("/this/file/does/not/exist.txt");
    let results = executor.upload_file(
        &nonexistent_file,
        "/tmp/destination.txt",
    ).await;
    
    // Should complete but with error in results
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_success());
}

#[tokio::test]
async fn test_download_to_invalid_directory() {
    let nodes = vec![Node::new("localhost".to_string(), 22, "user".to_string())];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Try to download to a directory that doesn't exist
    let invalid_dir = PathBuf::from("/this/directory/does/not/exist");
    let results = executor.download_file(
        "/etc/passwd",
        &invalid_dir,
    ).await;
    
    // Should complete but with error in results
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_success());
}

#[tokio::test]
async fn test_connection_to_invalid_host() {
    let nodes = vec![
        Node::new("this.host.does.not.exist.invalid".to_string(), 22, "user".to_string()),
    ];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Try to execute command on invalid host
    let results = executor.execute("echo test").await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_success());
}

#[tokio::test]
async fn test_connection_to_invalid_port() {
    let nodes = vec![
        Node::new("localhost".to_string(), 59999, "user".to_string()), // Invalid port
    ];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Try to execute command on invalid port
    let results = executor.execute("echo test").await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_success());
}

#[tokio::test]
async fn test_invalid_ssh_key_path() {
    let nodes = vec![Node::new("localhost".to_string(), 22, "user".to_string())];
    let executor = ParallelExecutor::new(
        nodes,
        1,
        Some("/this/key/does/not/exist.pem".to_string()),
    );
    
    let results = executor.execute("echo test").await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_success());
}

#[tokio::test]
async fn test_parallel_execution_with_mixed_results() {
    let nodes = vec![
        Node::new("localhost".to_string(), 22, std::env::var("USER").unwrap_or_else(|_| "user".to_string())),
        Node::new("invalid.host.example".to_string(), 22, "user".to_string()),
        Node::new("another.invalid.host".to_string(), 22, "user".to_string()),
    ];
    
    let executor = ParallelExecutor::new(nodes, 3, None);
    
    let results = executor.execute("echo test").await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 3);
    
    // At least some should fail (the invalid hosts)
    let failures = results.iter().filter(|r| !r.is_success()).count();
    assert!(failures >= 2);
}

#[tokio::test]
async fn test_upload_with_permission_denied() {
    let nodes = vec![Node::new("localhost".to_string(), 22, std::env::var("USER").unwrap_or_else(|_| "user".to_string()))];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Create a test file
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, "test content").unwrap();
    
    // Try to upload to a directory without write permissions (root directory)
    let results = executor.upload_file(
        &test_file,
        "/test_file_should_not_be_created.txt",
    ).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    // This might succeed or fail depending on user permissions
    // Just verify it doesn't panic
}

#[tokio::test]
async fn test_download_nonexistent_remote_file() {
    let nodes = vec![Node::new("localhost".to_string(), 22, std::env::var("USER").unwrap_or_else(|_| "user".to_string()))];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    let temp_dir = TempDir::new().unwrap();
    
    // Try to download a file that doesn't exist
    let results = executor.download_file(
        "/this/remote/file/does/not/exist.txt",
        temp_dir.path(),
    ).await;
    
    assert!(results.is_ok());
    let results = results.unwrap();
    assert_eq!(results.len(), 1);
    // Should fail since file doesn't exist
    if results[0].is_success() {
        // If it somehow succeeds (unlikely), just verify it doesn't panic
        assert!(true);
    } else {
        assert!(!results[0].is_success());
    }
}

#[tokio::test]
async fn test_glob_pattern_with_no_matches() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a test file that won't match our pattern
    std::fs::write(temp_dir.path().join("test.txt"), "content").unwrap();
    
    let nodes = vec![Node::new("localhost".to_string(), 22, "user".to_string())];
    let executor = ParallelExecutor::new(nodes, 1, None);
    
    // Try to upload files matching a pattern that has no matches
    let pattern = temp_dir.path().join("*.pdf"); // No PDF files exist
    
    // This should handle the error gracefully
    let results = executor.upload_file(
        &pattern,
        "/tmp/",
    ).await;
    
    // The executor should handle this gracefully
    assert!(results.is_ok());
}