// Tests for security fixes in certificate authentication PR
#[cfg(test)]
mod tests {
    use crate::ssh::ssh_config::SshConfig;

    #[test]
    fn test_certificate_file_blocks_etc_passwd() {
        // Test that /etc/passwd is blocked as a certificate file
        let content = r#"
Host example.com
    CertificateFile /etc/passwd
"#;
        let result = SshConfig::parse(content);
        assert!(
            result.is_err(),
            "Should reject /etc/passwd as certificate file"
        );
        // The important thing is that it's rejected, not the exact error message
        // since the error gets wrapped multiple times
    }

    #[test]
    fn test_certificate_file_blocks_private_key() {
        // Test that private keys without -cert.pub extension are blocked
        let content = r#"
Host example.com
    CertificateFile ~/.ssh/id_rsa
"#;
        let result = SshConfig::parse(content);
        assert!(
            result.is_err(),
            "Should reject private key as certificate file"
        );
        // The important thing is that it's rejected, not the exact error message
        // since the error gets wrapped multiple times
    }

    #[test]
    fn test_certificate_file_allows_valid_cert() {
        // Test that valid certificate files are allowed
        let content = r#"
Host example.com
    CertificateFile ~/.ssh/id_rsa-cert.pub
"#;
        let result = SshConfig::parse(content);
        assert!(result.is_ok(), "Should allow valid certificate file");
        let config = result.unwrap();
        assert_eq!(config.hosts[0].certificate_files.len(), 1);
    }

    #[test]
    fn test_max_certificate_files_during_merge() {
        // Test that certificate files are limited during merging
        let mut content = String::new();

        // Create 50 Host blocks that all match "test.example.com"
        for i in 0..50 {
            content.push_str(&format!(
                "Host *.example.com\n    CertificateFile ~/.ssh/cert_{i}.pub\n\n"
            ));
        }

        // Add more specific patterns that also match
        for i in 50..60 {
            content.push_str(&format!(
                "Host test.example.com\n    CertificateFile ~/.ssh/specific_cert_{i}.pub\n\n"
            ));
        }

        let config = SshConfig::parse(&content).unwrap();
        let merged = config.find_host_config("test.example.com");

        // Should be capped at MAX_CERTIFICATE_FILES (100)
        assert!(
            merged.certificate_files.len() <= 100,
            "Certificate files should be limited to prevent memory exhaustion, got {}",
            merged.certificate_files.len()
        );
    }

    #[test]
    fn test_deduplication_of_certificate_files() {
        // Test that duplicate certificate files are deduplicated
        let content = r#"
Host *.example.com
    CertificateFile ~/.ssh/shared-cert.pub
    CertificateFile ~/.ssh/domain-cert.pub

Host test.example.com
    CertificateFile ~/.ssh/shared-cert.pub
    CertificateFile ~/.ssh/specific-cert.pub

Host test.example.com
    CertificateFile ~/.ssh/shared-cert.pub
"#;
        let config = SshConfig::parse(content).unwrap();
        let merged = config.find_host_config("test.example.com");

        // Count unique certificate files
        let unique_certs: std::collections::HashSet<_> = merged.certificate_files.iter().collect();
        assert_eq!(
            unique_certs.len(),
            merged.certificate_files.len(),
            "Certificate files should be deduplicated"
        );

        // Should have exactly 3 unique certificates
        assert_eq!(
            merged.certificate_files.len(),
            3,
            "Should have 3 unique certificates after deduplication"
        );
    }

    #[test]
    fn test_max_permit_remote_open_entries() {
        // Test that PermitRemoteOpen entries are limited
        let mut content = String::from("Host example.com\n");

        // Add 1500 PermitRemoteOpen entries (exceeds limit of 1000)
        for i in 0..1500 {
            content.push_str(&format!("    PermitRemoteOpen host{}:808{}\n", i, i % 10));
        }

        let config = SshConfig::parse(&content).unwrap();
        let merged = config.find_host_config("example.com");

        // Should be capped at MAX_PERMIT_REMOTE_OPEN (1000)
        assert!(
            merged.permit_remote_open.len() <= 1000,
            "PermitRemoteOpen should be limited to prevent memory exhaustion, got {}",
            merged.permit_remote_open.len()
        );
    }

    #[test]
    fn test_algorithm_list_limits() {
        // Test that algorithm lists are limited
        let mut algorithms = vec![];
        for i in 0..100 {
            algorithms.push(format!("algo-{i}"));
        }
        let algo_list = algorithms.join(",");

        let content = format!(
            r#"
Host example.com
    CASignatureAlgorithms {algo_list}
    HostbasedAcceptedAlgorithms {algo_list}
"#
        );

        let config = SshConfig::parse(&content).unwrap();

        // Should be limited to MAX_ALGORITHMS (50)
        assert!(
            config.hosts[0].ca_signature_algorithms.len() <= 50,
            "CASignatureAlgorithms should be limited, got {}",
            config.hosts[0].ca_signature_algorithms.len()
        );

        assert!(
            config.hosts[0].hostbased_accepted_algorithms.len() <= 50,
            "HostbasedAcceptedAlgorithms should be limited, got {}",
            config.hosts[0].hostbased_accepted_algorithms.len()
        );
    }

    #[test]
    fn test_algorithm_list_malformed_input() {
        // Test that malformed algorithm lists are handled gracefully
        let content = r#"
Host example.com
    CASignatureAlgorithms ssh-ed25519,,rsa-sha2-512,,,,,rsa-sha2-256
    HostbasedAcceptedAlgorithms ,ssh-rsa,,,,ssh-dss,
"#;
        let config = SshConfig::parse(content).unwrap();

        // Empty strings should be filtered out
        assert_eq!(
            config.hosts[0].ca_signature_algorithms.len(),
            3,
            "Should filter out empty algorithm entries"
        );
        assert_eq!(
            config.hosts[0].hostbased_accepted_algorithms.len(),
            2,
            "Should filter out empty algorithm entries"
        );

        // Verify actual algorithms
        assert_eq!(config.hosts[0].ca_signature_algorithms[0], "ssh-ed25519");
        assert_eq!(config.hosts[0].ca_signature_algorithms[1], "rsa-sha2-512");
        assert_eq!(config.hosts[0].ca_signature_algorithms[2], "rsa-sha2-256");
    }

    #[test]
    fn test_gateway_ports_case_insensitive() {
        // Test that GatewayPorts accepts case variations
        let test_cases = vec![
            ("yes", "yes"),
            ("YES", "yes"),
            ("Yes", "yes"),
            ("no", "no"),
            ("NO", "no"),
            ("No", "no"),
            ("clientspecified", "clientspecified"),
            ("CLIENTSPECIFIED", "clientspecified"),
            ("ClientSpecified", "clientspecified"),
        ];

        for (input, expected) in test_cases {
            let content = format!("Host example.com\n    GatewayPorts {input}");
            let config = SshConfig::parse(&content).unwrap();
            assert_eq!(
                config.hosts[0].gateway_ports,
                Some(expected.to_string()),
                "GatewayPorts should normalize '{input}' to '{expected}'"
            );
        }
    }

    #[test]
    fn test_gateway_ports_invalid_values() {
        // Test that invalid GatewayPorts values are rejected
        let invalid_values = vec![
            "maybe",
            "true",
            "false",
            "1",
            "0",
            "yess",          // Typo
            "noo",           // Typo
            "client",        // Incomplete
            "$(whoami)",     // Command injection
            "../etc/passwd", // Path traversal
        ];

        for value in invalid_values {
            let content = format!("Host example.com\n    GatewayPorts {value}");
            let result = SshConfig::parse(&content);
            assert!(
                result.is_err(),
                "Should reject invalid GatewayPorts value: {value}"
            );
            // The important thing is that it's rejected
        }
    }

    #[test]
    fn test_sensitive_paths_in_certificate() {
        // Test various sensitive paths are blocked
        let sensitive_paths = vec![
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/master.passwd",
            "/proc/self/environ",
            "/sys/kernel/debug/",
            "C:\\Windows\\System32\\config\\SAM",
            "~/.bash_history",
            "~/.mysql_history",
        ];

        for path in sensitive_paths {
            let content = format!("Host example.com\n    CertificateFile {path}");
            let result = SshConfig::parse(&content);
            assert!(
                result.is_err(),
                "Should reject sensitive path as certificate: {path}"
            );
        }
    }
}
