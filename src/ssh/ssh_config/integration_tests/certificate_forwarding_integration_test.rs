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

//! Integration tests for certificate authentication and advanced port forwarding options
//!
//! Tests the interaction of Include, Match, and Host directives with:
//! - Certificate-based authentication (CertificateFile, CASignatureAlgorithms)
//! - Host-based authentication (HostbasedAuthentication, HostbasedAcceptedAlgorithms)
//! - Advanced port forwarding (GatewayPorts, ExitOnForwardFailure, PermitRemoteOpen)

#[cfg(test)]
pub(crate) mod tests {
    use crate::ssh::ssh_config::SshConfig;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_include_with_certificate_options() {
        let temp_dir = TempDir::new().unwrap();

        // Create an included file with certificate options
        let include_file = temp_dir.path().join("certs.conf");
        let include_content = r#"
Host *.prod.example.com
    CertificateFile ~/.ssh/prod-user-cert.pub
    CertificateFile ~/.ssh/prod-host-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
"#;
        fs::write(&include_file, include_content).unwrap();

        // Create main config that includes the certificate config
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            r#"
Include {}

Host web.prod.example.com
    User webuser
    Port 22
"#,
            include_file.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Parse the configuration
        let config = SshConfig::load_from_file(&main_config).await.unwrap();

        // Should have 2 blocks: Include inserts *.prod.example.com, then web.prod.example.com
        assert_eq!(config.hosts.len(), 2);

        // First block should have certificate options
        assert_eq!(config.hosts[0].certificate_files.len(), 2);
        assert_eq!(config.hosts[0].ca_signature_algorithms.len(), 2);
        assert_eq!(config.hosts[0].hostbased_authentication, Some(true));
        assert_eq!(config.hosts[0].hostbased_accepted_algorithms.len(), 2);

        // Test resolution for web.prod.example.com (should get certs from included file)
        let resolved = config.find_host_config("web.prod.example.com");
        assert_eq!(resolved.certificate_files.len(), 2);
        assert!(resolved.certificate_files[0]
            .to_string_lossy()
            .contains("prod-user-cert.pub"));
        assert!(resolved.certificate_files[1]
            .to_string_lossy()
            .contains("prod-host-cert.pub"));
        assert_eq!(resolved.ca_signature_algorithms.len(), 2);
        assert_eq!(resolved.user, Some("webuser".to_string()));
        assert_eq!(resolved.port, Some(22));
    }

    #[tokio::test]
    async fn test_include_with_forwarding_options() {
        let temp_dir = TempDir::new().unwrap();

        // Create an included file with forwarding options
        let include_file = temp_dir.path().join("forwarding.conf");
        let include_content = r#"
Host *.secure.example.com
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432
"#;
        fs::write(&include_file, include_content).unwrap();

        // Create main config
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            r#"
Include {}

Host app.secure.example.com
    User appuser
"#,
            include_file.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Parse the configuration
        let config = SshConfig::load_from_file(&main_config).await.unwrap();

        // Test resolution for app.secure.example.com
        let resolved = config.find_host_config("app.secure.example.com");
        assert_eq!(resolved.gateway_ports, Some("clientspecified".to_string()));
        assert_eq!(resolved.exit_on_forward_failure, Some(true));
        assert_eq!(resolved.permit_remote_open.len(), 2);
        assert_eq!(resolved.permit_remote_open[0], "localhost:8080");
        assert_eq!(resolved.permit_remote_open[1], "db.internal:5432");
        assert_eq!(resolved.user, Some("appuser".to_string()));
    }

    #[tokio::test]
    async fn test_match_with_certificate_options() {
        use crate::ssh::ssh_config::match_directive::MatchCondition;
        use crate::ssh::ssh_config::types::ConfigBlock;

        let content = r#"
Match host *.prod.example.com user admin
    CertificateFile ~/.ssh/admin-cert.pub
    CASignatureAlgorithms ssh-ed25519
    HostbasedAuthentication yes

Host web.prod.example.com
    User admin
    Port 443
"#;
        let config = SshConfig::parse(content).unwrap();

        // Should have 2 blocks
        assert_eq!(config.hosts.len(), 2);

        // First should be the Match block
        match &config.hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 2);
                // Verify it's a Match for host and user
                assert!(matches!(conditions[0], MatchCondition::Host(_)));
                assert!(matches!(conditions[1], MatchCondition::User(_)));
            }
            _ => panic!("Expected Match block"),
        }

        // Match block should have certificate options
        assert_eq!(config.hosts[0].certificate_files.len(), 1);
        assert!(config.hosts[0].certificate_files[0]
            .to_string_lossy()
            .contains("admin-cert.pub"));
        assert_eq!(config.hosts[0].ca_signature_algorithms.len(), 1);
        assert_eq!(config.hosts[0].hostbased_authentication, Some(true));
    }

    #[tokio::test]
    async fn test_match_with_forwarding_options() {
        use crate::ssh::ssh_config::match_directive::MatchCondition;
        use crate::ssh::ssh_config::types::ConfigBlock;

        let content = r#"
Match host *.secure.example.com
    GatewayPorts yes
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:*

Host app.secure.example.com
    User appuser
"#;
        let config = SshConfig::parse(content).unwrap();

        // Should have 2 blocks
        assert_eq!(config.hosts.len(), 2);

        // First should be Match block with forwarding options
        match &config.hosts[0].block_type {
            Some(ConfigBlock::Match(conditions)) => {
                assert_eq!(conditions.len(), 1);
                assert!(matches!(conditions[0], MatchCondition::Host(_)));
            }
            _ => panic!("Expected Match block"),
        }

        assert_eq!(config.hosts[0].gateway_ports, Some("yes".to_string()));
        assert_eq!(config.hosts[0].exit_on_forward_failure, Some(true));
        assert_eq!(config.hosts[0].permit_remote_open.len(), 1);
        assert_eq!(config.hosts[0].permit_remote_open[0], "localhost:*");
    }

    #[tokio::test]
    async fn test_complex_include_match_host_combination() {
        let temp_dir = TempDir::new().unwrap();

        // Create a base config with Match
        let base_file = temp_dir.path().join("base.conf");
        let base_content = r#"
Match host *.corp.example.com
    CertificateFile ~/.ssh/corp-cert.pub
    HostbasedAuthentication yes
"#;
        fs::write(&base_file, base_content).unwrap();

        // Create forwarding config
        let forward_file = temp_dir.path().join("forward.conf");
        let forward_content = r#"
Host *.prod.corp.example.com
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
"#;
        fs::write(&forward_file, forward_content).unwrap();

        // Main config includes both
        let main_config = temp_dir.path().join("config");
        let main_content = format!(
            r#"
Include {}
Include {}

Host web.prod.corp.example.com
    User webuser
    Port 443
    CertificateFile ~/.ssh/web-cert.pub
"#,
            base_file.display(),
            forward_file.display()
        );
        fs::write(&main_config, &main_content).unwrap();

        // Parse
        let config = SshConfig::load_from_file(&main_config).await.unwrap();

        // Resolve for web.prod.corp.example.com
        let resolved = config.find_host_config("web.prod.corp.example.com");

        // Should have:
        // - Certificate files from Match block AND Host block (2 total)
        // - Forwarding options from *.prod.corp.example.com
        // - User and port from specific Host block
        assert_eq!(resolved.certificate_files.len(), 2); // corp-cert + web-cert
        assert_eq!(resolved.hostbased_authentication, Some(true));
        assert_eq!(resolved.gateway_ports, Some("clientspecified".to_string()));
        assert_eq!(resolved.exit_on_forward_failure, Some(true));
        assert_eq!(resolved.permit_remote_open.len(), 1);
        assert_eq!(resolved.user, Some("webuser".to_string()));
        assert_eq!(resolved.port, Some(443));
    }

    #[tokio::test]
    async fn test_nested_includes_with_all_new_options() {
        let temp_dir = TempDir::new().unwrap();

        // Deep include: base authentication
        let deep_file = temp_dir.path().join("deep.conf");
        fs::write(
            &deep_file,
            r#"
Host *
    HostbasedAuthentication no
    CertificateFile ~/.ssh/default-cert.pub
"#,
        )
        .unwrap();

        // Middle include: prod-specific
        let middle_file = temp_dir.path().join("middle.conf");
        fs::write(
            &middle_file,
            format!(
                r#"
Include {}

Host *.prod.example.com
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512
    HostbasedAuthentication yes
    GatewayPorts clientspecified
"#,
                deep_file.display()
            ),
        )
        .unwrap();

        // Main config
        let main_config = temp_dir.path().join("config");
        fs::write(
            &main_config,
            format!(
                r#"
Include {}

Match host web*.prod.example.com
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen db.internal:5432

Host web1.prod.example.com
    User webuser
"#,
                middle_file.display()
            ),
        )
        .unwrap();

        // Parse
        let config = SshConfig::load_from_file(&main_config).await.unwrap();

        // Resolve for web1.prod.example.com
        let resolved = config.find_host_config("web1.prod.example.com");

        // Should combine all layers:
        // - Default cert from deep.conf
        // - CA algorithms from middle.conf
        // - Hostbased auth overridden to yes in middle.conf
        // - Gateway ports from middle.conf
        // - Exit on forward failure from Match block
        // - Permit remote open from Match block
        // - User from specific Host block
        assert_eq!(resolved.certificate_files.len(), 1);
        assert!(resolved.certificate_files[0]
            .to_string_lossy()
            .contains("default-cert.pub"));
        assert_eq!(resolved.ca_signature_algorithms.len(), 2);
        assert_eq!(resolved.hostbased_authentication, Some(true)); // Overridden
        assert_eq!(resolved.gateway_ports, Some("clientspecified".to_string()));
        assert_eq!(resolved.exit_on_forward_failure, Some(true));
        assert_eq!(resolved.permit_remote_open.len(), 2);
        assert_eq!(resolved.user, Some("webuser".to_string()));
    }

    #[tokio::test]
    async fn test_all_new_options_in_real_scenario() {
        let temp_dir = TempDir::new().unwrap();

        // Create a comprehensive config file
        let config_file = temp_dir.path().join("config");
        let config_content = r#"
# Global defaults
Host *
    HostbasedAuthentication no
    ExitOnForwardFailure no

# Production servers with certificates
Host *.prod.example.com
    CertificateFile ~/.ssh/prod-user-cert.pub
    CertificateFile ~/.ssh/prod-host-cert.pub
    CASignatureAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
    HostbasedAuthentication yes
    HostbasedAcceptedAlgorithms ssh-ed25519,rsa-sha2-512

# Secure hosts with strict forwarding
Match host *.secure.prod.example.com
    GatewayPorts clientspecified
    ExitOnForwardFailure yes
    PermitRemoteOpen localhost:8080
    PermitRemoteOpen localhost:5432
    PermitRemoteOpen db.internal:5432

# Specific web server
Host web.secure.prod.example.com
    User webadmin
    Port 443
    CertificateFile ~/.ssh/web-specific-cert.pub
    PermitRemoteOpen cache.internal:6379
"#;
        fs::write(&config_file, config_content).unwrap();

        // Parse
        let config = SshConfig::load_from_file(&config_file).await.unwrap();

        // Resolve for web.secure.prod.example.com
        let resolved = config.find_host_config("web.secure.prod.example.com");

        // Verify complete configuration:
        // CertificateFile: default + prod (2) + web-specific (1) = 3 total
        assert_eq!(resolved.certificate_files.len(), 3);

        // CASignatureAlgorithms: from *.prod.example.com
        assert_eq!(resolved.ca_signature_algorithms.len(), 3);
        assert_eq!(resolved.ca_signature_algorithms[0], "ssh-ed25519");

        // HostbasedAuthentication: yes from *.prod.example.com
        assert_eq!(resolved.hostbased_authentication, Some(true));

        // HostbasedAcceptedAlgorithms: from *.prod.example.com
        assert_eq!(resolved.hostbased_accepted_algorithms.len(), 2);

        // GatewayPorts: from Match block
        assert_eq!(resolved.gateway_ports, Some("clientspecified".to_string()));

        // ExitOnForwardFailure: yes from Match block (overrides global no)
        assert_eq!(resolved.exit_on_forward_failure, Some(true));

        // PermitRemoteOpen: from Match (3) + specific Host (1) = 4 total
        assert_eq!(resolved.permit_remote_open.len(), 4);
        assert_eq!(resolved.permit_remote_open[0], "localhost:8080");
        assert_eq!(resolved.permit_remote_open[1], "localhost:5432");
        assert_eq!(resolved.permit_remote_open[2], "db.internal:5432");
        assert_eq!(resolved.permit_remote_open[3], "cache.internal:6379");

        // Basic options
        assert_eq!(resolved.user, Some("webadmin".to_string()));
        assert_eq!(resolved.port, Some(443));
    }
}
