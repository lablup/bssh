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
use bssh::ssh::client::ConnectionConfig;
use bssh::ssh::known_hosts::StrictHostKeyChecking;
use bssh::ssh::tokio_client::client::CommandOutput;
use bssh::ssh::SshClient;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

/// Check if SSH is available and can connect to localhost
fn can_ssh_to_localhost() -> bool {
    // Check if SSH server is running and we can connect to localhost
    let output = Command::new("ssh")
        .args([
            "-o",
            "ConnectTimeout=2",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "BatchMode=yes",
            "localhost",
            "echo",
            "test",
        ])
        .output();

    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

fn build_test_output_buffer() -> (Sender<CommandOutput>, JoinHandle<(Vec<u8>, Vec<u8>)>) {
    let (sender, mut output_receiver) = tokio::sync::mpsc::channel(10);

    let receiver_task = tokio::task::spawn(async move {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(output) = output_receiver.recv().await {
            match output {
                CommandOutput::StdOut(buffer) => stdout.extend_from_slice(&buffer),
                CommandOutput::StdErr(buffer) => stderr.extend_from_slice(&buffer),
            }
        }

        (stdout, stderr)
    });

    (sender, receiver_task)
}

fn get_localhost_test_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

#[tokio::test]
async fn test_localhost_execute_streaming_output() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping integration test: Cannot SSH to localhost");
        return;
    }

    let mut client = SshClient::new("localhost".into(), 22, get_localhost_test_user());

    let config = ConnectionConfig {
        key_path: None,
        strict_mode: Some(StrictHostKeyChecking::No),
        use_agent: false,
        use_password: false,
        timeout_seconds: None,
        jump_hosts_spec: None,
    };

    const COMMAND: &str = "bash -c 'echo a message && echo an error >&2 && exit 123'";

    let (sender, receiver_task) = build_test_output_buffer();

    let exit_code = client
        .connect_and_execute_with_output_streaming(COMMAND, &config, sender)
        .await
        .expect("executed command");

    assert_eq!(exit_code, 123);

    let (stdout, stderr) = receiver_task.await.expect("joined output task");

    let stdout = String::from_utf8_lossy(&stdout).to_string();
    let stderr = String::from_utf8_lossy(&stderr).to_string();

    assert_eq!(stdout, "a message\n");
    assert_eq!(stderr, "an error\n");
}

#[tokio::test]
async fn test_localhost_upload_download_roundtrip() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping integration test: Cannot SSH to localhost");
        return;
    }

    // Create temporary directories for testing
    let local_temp = TempDir::new().unwrap();
    let remote_temp = TempDir::new().unwrap();

    // Create a test file
    let test_content = "Integration test content for bssh SFTP";
    let local_file = local_temp.path().join("test_file.txt");
    fs::write(&local_file, test_content).unwrap();

    // Create executor with localhost node
    let nodes = vec![Node::new(
        "localhost".to_string(),
        22,
        get_localhost_test_user(),
    )];
    // Try to find an SSH key - use None if not found (will try SSH agent)
    let ssh_key = dirs::home_dir().and_then(|h| {
        let key_path = h.join(".ssh/id_rsa");
        if key_path.exists() {
            Some(key_path.to_string_lossy().to_string())
        } else {
            None
        }
    });
    let executor = ParallelExecutor::new(nodes, 1, ssh_key);

    // Test upload
    let remote_path = format!("{}/uploaded_file.txt", remote_temp.path().display());
    let upload_results = executor
        .upload_file(&local_file, &remote_path)
        .await
        .unwrap();

    assert_eq!(upload_results.len(), 1);
    if !upload_results[0].is_success() {
        eprintln!("Upload failed: {:?}", upload_results[0].result);
        return;
    }

    // Verify file was uploaded
    assert!(PathBuf::from(&remote_path).exists());
    let uploaded_content = fs::read_to_string(&remote_path).unwrap();
    assert_eq!(uploaded_content, test_content);

    // Test download
    let download_temp = TempDir::new().unwrap();
    let download_results = executor
        .download_file(&remote_path, download_temp.path())
        .await
        .unwrap();

    assert_eq!(download_results.len(), 1);
    assert!(download_results[0].is_success());

    // Verify downloaded file
    if let Ok(downloaded_path) = &download_results[0].result {
        assert!(downloaded_path.exists());
        let downloaded_content = fs::read_to_string(downloaded_path).unwrap();
        assert_eq!(downloaded_content, test_content);
    }
}

#[tokio::test]
async fn test_localhost_multiple_file_upload() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping integration test: Cannot SSH to localhost");
        return;
    }

    // Create temporary directories
    let local_temp = TempDir::new().unwrap();
    let remote_temp = TempDir::new().unwrap();

    // Create multiple test files
    let files = vec![
        ("file1.txt", "Content of file 1"),
        ("file2.txt", "Content of file 2"),
        ("file3.log", "Log content"),
    ];

    for (name, content) in &files {
        fs::write(local_temp.path().join(name), content).unwrap();
    }

    // Create executor
    let nodes = vec![Node::new(
        "localhost".to_string(),
        22,
        get_localhost_test_user(),
    )];
    // Try to find an SSH key - use None if not found (will try SSH agent)
    let ssh_key = dirs::home_dir().and_then(|h| {
        let key_path = h.join(".ssh/id_rsa");
        if key_path.exists() {
            Some(key_path.to_string_lossy().to_string())
        } else {
            None
        }
    });
    let executor = ParallelExecutor::new(nodes, 1, ssh_key);

    // Upload each file
    for (name, content) in &files {
        let local_file = local_temp.path().join(name);
        let remote_path = format!("{}/{}", remote_temp.path().display(), name);

        let results = executor
            .upload_file(&local_file, &remote_path)
            .await
            .unwrap();
        assert!(results[0].is_success());

        // Verify upload
        let uploaded_content = fs::read_to_string(&remote_path).unwrap();
        assert_eq!(&uploaded_content, content);
    }
}

#[tokio::test]
async fn test_parallel_execution_with_multiple_nodes() {
    // This test simulates multiple nodes by using the same localhost multiple times
    // In a real scenario, these would be different hosts

    if !can_ssh_to_localhost() {
        eprintln!("Skipping integration test: Cannot SSH to localhost");
        return;
    }

    let user = get_localhost_test_user();
    let nodes = vec![
        Node::new("localhost".to_string(), 22, user.clone()),
        Node::new("127.0.0.1".to_string(), 22, user.clone()),
    ];

    // Try to find an SSH key - use None if not found (will try SSH agent)
    let ssh_key = dirs::home_dir().and_then(|h| {
        let key_path = h.join(".ssh/id_rsa");
        if key_path.exists() {
            Some(key_path.to_string_lossy().to_string())
        } else {
            None
        }
    });
    let executor = ParallelExecutor::new(nodes, 2, ssh_key);

    // Execute a simple command
    let results = executor.execute("echo 'test'").await.unwrap();

    assert_eq!(results.len(), 2);
    for result in &results {
        assert!(result.is_success());
        if let Ok(cmd_result) = &result.result {
            assert!(cmd_result.stdout_string().contains("test"));
        }
    }
}

#[tokio::test]
async fn test_download_with_unique_filenames() {
    if !can_ssh_to_localhost() {
        eprintln!("Skipping integration test: Cannot SSH to localhost");
        return;
    }

    // Create a file to download
    let source_temp = TempDir::new().unwrap();
    let source_file = source_temp.path().join("shared_file.txt");
    fs::write(&source_file, "Shared content").unwrap();

    // Create executor with two "different" nodes (both localhost)
    let user = get_localhost_test_user();
    let nodes = vec![
        Node::new("localhost".to_string(), 22, user.clone()),
        Node::new("127.0.0.1".to_string(), 22, user),
    ];

    // Try to find an SSH key - use None if not found (will try SSH agent)
    let ssh_key = dirs::home_dir().and_then(|h| {
        let key_path = h.join(".ssh/id_rsa");
        if key_path.exists() {
            Some(key_path.to_string_lossy().to_string())
        } else {
            None
        }
    });
    let executor = ParallelExecutor::new(nodes, 2, ssh_key);

    // Download from both nodes
    let download_temp = TempDir::new().unwrap();
    let results = executor
        .download_file(source_file.to_str().unwrap(), download_temp.path())
        .await
        .unwrap();

    assert_eq!(results.len(), 2);

    // Check that files have unique names
    let mut downloaded_files = Vec::new();
    for result in &results {
        if let Ok(path) = &result.result {
            downloaded_files.push(path.clone());
            assert!(path.exists());
        }
    }

    // Ensure filenames are unique
    assert_eq!(downloaded_files.len(), 2);
    assert_ne!(downloaded_files[0], downloaded_files[1]);

    // Both should contain the same content
    for path in &downloaded_files {
        let content = fs::read_to_string(path).unwrap();
        assert_eq!(content, "Shared content");
    }
}
