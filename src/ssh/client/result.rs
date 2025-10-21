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

/// Result of a remote command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub host: String,
    pub output: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: u32,
}

impl CommandResult {
    /// Convert stdout to a UTF-8 string
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }

    /// Convert stderr to a UTF-8 string
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    /// Check if the command execution was successful (exit status 0)
    pub fn is_success(&self) -> bool {
        self.exit_status == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_result_success() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: b"Hello World\n".to_vec(),
            stderr: Vec::new(),
            exit_status: 0,
        };

        assert!(result.is_success());
        assert_eq!(result.stdout_string(), "Hello World\n");
        assert_eq!(result.stderr_string(), "");
    }

    #[test]
    fn test_command_result_failure() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: Vec::new(),
            stderr: b"Command not found\n".to_vec(),
            exit_status: 127,
        };

        assert!(!result.is_success());
        assert_eq!(result.stdout_string(), "");
        assert_eq!(result.stderr_string(), "Command not found\n");
    }

    #[test]
    fn test_command_result_with_utf8() {
        let result = CommandResult {
            host: "test.com".to_string(),
            output: "한글 테스트\n".as_bytes().to_vec(),
            stderr: "エラー\n".as_bytes().to_vec(),
            exit_status: 1,
        };

        assert!(!result.is_success());
        assert_eq!(result.stdout_string(), "한글 테스트\n");
        assert_eq!(result.stderr_string(), "エラー\n");
    }
}
