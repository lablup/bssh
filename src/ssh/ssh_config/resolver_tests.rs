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

//! Tests for resolver functionality with certificate and forwarding options

#[cfg(test)]
mod tests {
    use crate::ssh::ssh_config::parser::parse;
    use crate::ssh::ssh_config::resolver::find_host_config;

    #[test]
    fn test_certificate_file_merging_across_host_blocks() {
        let content = r#"
Host *
    CertificateFile ~/.ssh/global-cert.pub

Host example.com
    CertificateFile ~/.ssh/example-cert.pub
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should have both certificate files (appending behavior)
        assert_eq!(config.certificate_files.len(), 2);
        assert!(config.certificate_files[0]
            .to_string_lossy()
            .contains("global-cert.pub"));
        assert!(config.certificate_files[1]
            .to_string_lossy()
            .contains("example-cert.pub"));
    }

    #[test]
    fn test_certificate_file_deduplication() {
        let content = r#"
Host *
    CertificateFile ~/.ssh/shared-cert.pub

Host example.com
    CertificateFile ~/.ssh/shared-cert.pub
    CertificateFile ~/.ssh/example-cert.pub
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should deduplicate the shared cert
        assert_eq!(config.certificate_files.len(), 2);
        // First should be the shared cert (from first Host *)
        assert!(config.certificate_files[0]
            .to_string_lossy()
            .contains("shared-cert.pub"));
        // Second should be the example-specific cert
        assert!(config.certificate_files[1]
            .to_string_lossy()
            .contains("example-cert.pub"));
    }

    #[test]
    fn test_certificate_file_limit_during_merge() {
        // Create a config with more than 100 certificate files
        let mut config_lines = vec!["Host example.com".to_string()];
        for i in 0..110 {
            config_lines.push(format!("    CertificateFile ~/.ssh/cert-{}.pub", i));
        }
        let content = config_lines.join("\n");

        let hosts = parse(&content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should be limited to 100 entries
        assert_eq!(config.certificate_files.len(), 100);
    }

    #[test]
    fn test_permit_remote_open_merging_across_host_blocks() {
        let content = r#"
Host *
    PermitRemoteOpen localhost:8080

Host example.com
    PermitRemoteOpen db.internal:5432
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should have both entries (appending behavior)
        assert_eq!(config.permit_remote_open.len(), 2);
        assert_eq!(config.permit_remote_open[0], "localhost:8080");
        assert_eq!(config.permit_remote_open[1], "db.internal:5432");
    }

    #[test]
    fn test_permit_remote_open_deduplication() {
        let content = r#"
Host *
    PermitRemoteOpen localhost:8080

Host example.com
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should deduplicate localhost:8080
        assert_eq!(config.permit_remote_open.len(), 2);
        assert_eq!(config.permit_remote_open[0], "localhost:8080");
        assert_eq!(config.permit_remote_open[1], "db.internal:5432");
    }

    #[test]
    fn test_ca_signature_algorithms_override() {
        let content = r#"
Host *
    CASignatureAlgorithms ssh-rsa,ssh-dss

Host example.com
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should override (not append) - only the latter values
        assert_eq!(config.ca_signature_algorithms.len(), 2);
        assert_eq!(config.ca_signature_algorithms[0], "ssh-ed25519");
        assert_eq!(config.ca_signature_algorithms[1], "rsa-sha2-512");
    }

    #[test]
    fn test_hostbased_accepted_algorithms_override() {
        let content = r#"
Host *
    HostbasedAcceptedAlgorithms ssh-rsa,ssh-dss

Host example.com
    HostbasedAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should override (not append)
        assert_eq!(config.hostbased_accepted_algorithms.len(), 2);
        assert_eq!(config.hostbased_accepted_algorithms[0], "ssh-ed25519");
        assert_eq!(
            config.hostbased_accepted_algorithms[1],
            "ecdsa-sha2-nistp256"
        );
    }

    #[test]
    fn test_gateway_ports_override() {
        let content = r#"
Host *
    GatewayPorts no

Host example.com
    GatewayPorts yes
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should override to "yes"
        assert_eq!(config.gateway_ports, Some("yes".to_string()));
    }

    #[test]
    fn test_exit_on_forward_failure_override() {
        let content = r#"
Host *
    ExitOnForwardFailure no

Host example.com
    ExitOnForwardFailure yes
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should override to true
        assert_eq!(config.exit_on_forward_failure, Some(true));
    }

    #[test]
    fn test_hostbased_authentication_override() {
        let content = r#"
Host *
    HostbasedAuthentication no

Host example.com
    HostbasedAuthentication yes
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Should override to true
        assert_eq!(config.hostbased_authentication, Some(true));
    }

    #[test]
    fn test_multiple_host_blocks_with_priority() {
        // SSH config: later matches override earlier matches for scalar values
        // Lists accumulate across all matches
        let content = r#"
Host example.com
    GatewayPorts yes
    CertificateFile ~/.ssh/first-cert.pub

Host *.com
    GatewayPorts no
    CertificateFile ~/.ssh/second-cert.pub

Host *
    ExitOnForwardFailure yes
    CertificateFile ~/.ssh/third-cert.pub
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // GatewayPorts: Later matches override (*.com overrides example.com)
        // So the final value should be "no" from *.com
        assert_eq!(config.gateway_ports, Some("no".to_string()));

        // ExitOnForwardFailure: Only set in * block, so it's yes
        assert_eq!(config.exit_on_forward_failure, Some(true));

        // CertificateFile: all three accumulate
        assert_eq!(config.certificate_files.len(), 3);
        assert!(config.certificate_files[0]
            .to_string_lossy()
            .contains("first-cert.pub"));
        assert!(config.certificate_files[1]
            .to_string_lossy()
            .contains("second-cert.pub"));
        assert!(config.certificate_files[2]
            .to_string_lossy()
            .contains("third-cert.pub"));
    }

    #[test]
    fn test_all_new_options_together() {
        let content = r#"
Host secure.example.com
    CertificateFile ~/.ssh/user-cert.pub
    CertificateFile ~/.ssh/host-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "secure.example.com");

        // Verify all fields
        assert_eq!(config.certificate_files.len(), 2);
        assert_eq!(config.ca_signature_algorithms.len(), 3);
        assert_eq!(config.gateway_ports, Some("clientspecified".to_string()));
        assert_eq!(config.exit_on_forward_failure, Some(true));
        assert_eq!(config.permit_remote_open.len(), 2);
        assert_eq!(config.permit_remote_open[0], "localhost:8080");
        assert_eq!(config.permit_remote_open[1], "db.internal:5432");
        assert_eq!(config.hostbased_authentication, Some(true));
        assert_eq!(config.hostbased_accepted_algorithms.len(), 2);
    }

    #[test]
    fn test_empty_vs_unset_options() {
        let content = r#"
Host example.com
    User testuser
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Options not set should remain empty/None
        assert_eq!(config.certificate_files.len(), 0);
        assert_eq!(config.ca_signature_algorithms.len(), 0);
        assert_eq!(config.gateway_ports, None);
        assert_eq!(config.exit_on_forward_failure, None);
        assert_eq!(config.permit_remote_open.len(), 0);
        assert_eq!(config.hostbased_authentication, None);
        assert_eq!(config.hostbased_accepted_algorithms.len(), 0);
    }

    #[test]
    fn test_partial_option_set() {
        let content = r#"
Host example.com
    CertificateFile ~/.ssh/cert.pub
    GatewayPorts yes
"#;
        let hosts = parse(content).unwrap();
        let config = find_host_config(&hosts, "example.com");

        // Only set options should have values
        assert_eq!(config.certificate_files.len(), 1);
        assert_eq!(config.gateway_ports, Some("yes".to_string()));

        // Others should be empty/None
        assert_eq!(config.ca_signature_algorithms.len(), 0);
        assert_eq!(config.exit_on_forward_failure, None);
        assert_eq!(config.permit_remote_open.len(), 0);
        assert_eq!(config.hostbased_authentication, None);
        assert_eq!(config.hostbased_accepted_algorithms.len(), 0);
    }
}
