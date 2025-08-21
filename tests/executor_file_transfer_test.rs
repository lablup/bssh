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

use bssh::executor::{DownloadResult, ParallelExecutor, UploadResult};
use bssh::node::Node;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_upload_result_is_success() {
    let node = Node::new("localhost".to_string(), 22, "test".to_string());
    
    let success_result = UploadResult {
        node: node.clone(),
        result: Ok(()),
    };
    assert!(success_result.is_success());
    
    let failure_result = UploadResult {
        node: node.clone(),
        result: Err(anyhow::anyhow!("Upload failed")),
    };
    assert!(!failure_result.is_success());
}

#[tokio::test]
async fn test_download_result_is_success() {
    let node = Node::new("localhost".to_string(), 22, "test".to_string());
    
    let success_result = DownloadResult {
        node: node.clone(),
        result: Ok(PathBuf::from("/tmp/downloaded_file")),
    };
    assert!(success_result.is_success());
    
    let failure_result = DownloadResult {
        node: node.clone(),
        result: Err(anyhow::anyhow!("Download failed")),
    };
    assert!(!failure_result.is_success());
}

#[tokio::test]
async fn test_parallel_executor_creation() {
    let nodes = vec![
        Node::new("host1".to_string(), 22, "user1".to_string()),
        Node::new("host2".to_string(), 2222, "user2".to_string()),
    ];
    
    let _executor = ParallelExecutor::new(
        nodes.clone(),
        10,
        Some("/path/to/key".to_string()),
    );
    
    // The executor should be created successfully
    // We can't test actual SSH operations without a mock SSH server
    assert!(true);
}

#[tokio::test]
async fn test_upload_result_print_summary() {
    let node = Node::new("test-host".to_string(), 22, "user".to_string());
    
    let success_result = UploadResult {
        node: node.clone(),
        result: Ok(()),
    };
    
    // This should not panic
    success_result.print_summary();
    
    let failure_result = UploadResult {
        node: node.clone(),
        result: Err(anyhow::anyhow!("Connection refused")),
    };
    
    // This should not panic either
    failure_result.print_summary();
}

#[tokio::test]
async fn test_download_result_print_summary() {
    let node = Node::new("test-host".to_string(), 22, "user".to_string());
    let temp_dir = TempDir::new().unwrap();
    let download_path = temp_dir.path().join("downloaded_file.txt");
    
    let success_result = DownloadResult {
        node: node.clone(),
        result: Ok(download_path.clone()),
    };
    
    // This should not panic
    success_result.print_summary();
    
    let failure_result = DownloadResult {
        node: node.clone(),
        result: Err(anyhow::anyhow!("File not found")),
    };
    
    // This should not panic either
    failure_result.print_summary();
}

#[cfg(test)]
mod mock_tests {
    use super::*;
    
    // These tests would require a mock SSH server to properly test
    // For now, we're testing the structure and error handling
    
    #[tokio::test]
    async fn test_executor_with_invalid_host() {
        let nodes = vec![
            Node::new("nonexistent.invalid.host".to_string(), 22, "user".to_string()),
        ];
        
        let executor = ParallelExecutor::new(
            nodes,
            1,
            None,
        );
        
        // Try to upload to an invalid host
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();
        
        let results = executor.upload_file(
            &test_file,
            "/tmp/remote_test.txt",
        ).await;
        
        // The operation should complete but with errors
        assert!(results.is_ok());
        let results = results.unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_success());
    }
    
    #[tokio::test]
    async fn test_executor_with_invalid_download() {
        let nodes = vec![
            Node::new("nonexistent.invalid.host".to_string(), 22, "user".to_string()),
        ];
        
        let executor = ParallelExecutor::new(
            nodes,
            1,
            None,
        );
        
        let temp_dir = TempDir::new().unwrap();
        
        let results = executor.download_file(
            "/nonexistent/file.txt",
            temp_dir.path(),
        ).await;
        
        // The operation should complete but with errors
        assert!(results.is_ok());
        let results = results.unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_success());
    }
}