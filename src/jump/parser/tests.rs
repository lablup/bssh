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
    use super::super::host_parser::parse_single_jump_host;
    use super::super::*;

    #[test]
    fn test_parse_single_jump_host_hostname_only() {
        let result = parse_single_jump_host("example.com").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_with_user() {
        let result = parse_single_jump_host("admin@example.com").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_with_port() {
        let result = parse_single_jump_host("example.com:2222").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, None);
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_with_user_and_port() {
        let result = parse_single_jump_host("admin@example.com:2222").unwrap();
        assert_eq!(result.host, "example.com");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_brackets() {
        let result = parse_single_jump_host("[::1]").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, None);
        assert_eq!(result.port, None);
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_with_port() {
        let result = parse_single_jump_host("[::1]:2222").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, None);
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_single_jump_host_ipv6_with_user_and_port() {
        let result = parse_single_jump_host("admin@[::1]:2222").unwrap();
        assert_eq!(result.host, "::1");
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.port, Some(2222));
    }

    #[test]
    fn test_parse_jump_hosts_multiple() {
        let result = parse_jump_hosts("jump1@host1,user@host2:2222,host3").unwrap();
        assert_eq!(result.len(), 3);

        assert_eq!(result[0].host, "host1");
        assert_eq!(result[0].user, Some("jump1".to_string()));
        assert_eq!(result[0].port, None);

        assert_eq!(result[1].host, "host2");
        assert_eq!(result[1].user, Some("user".to_string()));
        assert_eq!(result[1].port, Some(2222));

        assert_eq!(result[2].host, "host3");
        assert_eq!(result[2].user, None);
        assert_eq!(result[2].port, None);
    }

    #[test]
    fn test_parse_jump_hosts_whitespace_handling() {
        let result = parse_jump_hosts(" host1 , user@host2:2222 , host3 ").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].host, "host1");
        assert_eq!(result[1].host, "host2");
        assert_eq!(result[2].host, "host3");
    }

    #[test]
    fn test_parse_jump_hosts_empty_string() {
        let result = parse_jump_hosts("").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_jump_hosts_only_commas() {
        let result = parse_jump_hosts(",,");
        assert!(result.is_err()); // Should error since no valid jump hosts found
    }

    #[test]
    fn test_parse_single_jump_host_errors() {
        // Empty specification
        assert!(parse_single_jump_host("").is_err());

        // Empty username
        assert!(parse_single_jump_host("@host").is_err());

        // Empty hostname
        assert!(parse_single_jump_host("user@").is_err());

        // Empty port
        assert!(parse_single_jump_host("host:").is_err());

        // Zero port
        assert!(parse_single_jump_host("host:0").is_err());

        // Invalid port (too large)
        assert!(parse_single_jump_host("host:99999").is_err());

        // Unclosed IPv6 bracket
        assert!(parse_single_jump_host("[::1").is_err());

        // Empty IPv6 address
        assert!(parse_single_jump_host("[]").is_err());
    }

    #[test]
    fn test_jump_host_display() {
        let host = JumpHost::new("example.com".to_string(), None, None);
        assert_eq!(format!("{host}"), "example.com");

        let host = JumpHost::new("example.com".to_string(), Some("user".to_string()), None);
        assert_eq!(format!("{host}"), "user@example.com");

        let host = JumpHost::new("example.com".to_string(), None, Some(2222));
        assert_eq!(format!("{host}"), "example.com:2222");

        let host = JumpHost::new(
            "example.com".to_string(),
            Some("user".to_string()),
            Some(2222),
        );
        assert_eq!(format!("{host}"), "user@example.com:2222");
    }

    #[test]
    fn test_jump_host_effective_values() {
        let host = JumpHost::new("example.com".to_string(), None, None);
        assert_eq!(host.effective_port(), 22);
        assert!(!host.effective_user().is_empty()); // Should return current user

        let host = JumpHost::new(
            "example.com".to_string(),
            Some("testuser".to_string()),
            Some(2222),
        );
        assert_eq!(host.effective_port(), 2222);
        assert_eq!(host.effective_user(), "testuser");
    }

    #[test]
    #[serial_test::serial]
    fn test_max_jump_hosts_limit_exactly_10() {
        // Clear any environment variable first
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");

        // Exactly 10 jump hosts should be allowed
        let spec = (0..10)
            .map(|i| format!("host{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_jump_hosts(&spec);
        assert!(result.is_ok(), "Should accept exactly 10 jump hosts");
        assert_eq!(result.unwrap().len(), 10);
    }

    #[test]
    #[serial_test::serial]
    fn test_max_jump_hosts_limit_11_rejected() {
        // Clear any environment variable first
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");

        // 11 jump hosts should be rejected
        let spec = (0..11)
            .map(|i| format!("host{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_jump_hosts(&spec);
        assert!(result.is_err(), "Should reject 11 jump hosts");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Too many jump hosts"),
            "Error should mention 'Too many jump hosts', got: {err_msg}"
        );
        assert!(
            err_msg.contains("11"),
            "Error should mention the actual count (11), got: {err_msg}"
        );
        assert!(
            err_msg.contains("10"),
            "Error should mention the maximum (10), got: {err_msg}"
        );
    }

    #[test]
    fn test_max_jump_hosts_limit_excessive() {
        // Test with way more than the limit to ensure proper handling
        let spec = (0..100)
            .map(|i| format!("host{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_jump_hosts(&spec);
        assert!(
            result.is_err(),
            "Should reject excessive number of jump hosts"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Too many jump hosts"),
            "Error should be about too many hosts, got: {err_msg}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_get_max_jump_hosts_default() {
        // Without environment variable, should return default (10)
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
        let max = get_max_jump_hosts();
        assert_eq!(max, 10, "Default should be 10");
    }

    #[test]
    #[serial_test::serial]
    fn test_get_max_jump_hosts_custom_value() {
        // Set environment variable to custom value
        unsafe {
            std::env::set_var("BSSH_MAX_JUMP_HOSTS", "15");
        }
        let max = get_max_jump_hosts();
        assert_eq!(max, 15, "Should use custom value from environment");

        // Cleanup
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
    }

    #[test]
    #[serial_test::serial]
    fn test_get_max_jump_hosts_capped_at_absolute_max() {
        // Set environment variable beyond absolute maximum (30)
        unsafe {
            std::env::set_var("BSSH_MAX_JUMP_HOSTS", "50");
        }
        let max = get_max_jump_hosts();
        assert_eq!(
            max, 30,
            "Should be capped at absolute maximum of 30 for security"
        );

        // Cleanup
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
    }

    #[test]
    #[serial_test::serial]
    fn test_get_max_jump_hosts_zero_falls_back() {
        // Zero is invalid, should fall back to default
        unsafe {
            std::env::set_var("BSSH_MAX_JUMP_HOSTS", "0");
        }
        let max = get_max_jump_hosts();
        assert_eq!(max, 10, "Zero should fall back to default (10)");

        // Cleanup
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
    }

    #[test]
    #[serial_test::serial]
    fn test_get_max_jump_hosts_invalid_value() {
        // Invalid value should fall back to default
        unsafe {
            std::env::set_var("BSSH_MAX_JUMP_HOSTS", "invalid");
        }
        let max = get_max_jump_hosts();
        assert_eq!(max, 10, "Invalid value should fall back to default (10)");

        // Cleanup
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
    }

    #[test]
    #[serial_test::serial]
    fn test_max_jump_hosts_respects_environment() {
        // Set custom limit via environment variable
        unsafe {
            std::env::set_var("BSSH_MAX_JUMP_HOSTS", "15");
        }

        // Create spec with 15 hosts (should succeed)
        let spec_15 = (0..15)
            .map(|i| format!("host{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_jump_hosts(&spec_15);
        assert!(
            result.is_ok(),
            "Should accept 15 hosts when BSSH_MAX_JUMP_HOSTS=15"
        );
        assert_eq!(result.unwrap().len(), 15);

        // Create spec with 16 hosts (should fail)
        let spec_16 = (0..16)
            .map(|i| format!("host{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = parse_jump_hosts(&spec_16);
        assert!(
            result.is_err(),
            "Should reject 16 hosts when BSSH_MAX_JUMP_HOSTS=15"
        );

        // Cleanup
        std::env::remove_var("BSSH_MAX_JUMP_HOSTS");
    }
}
