// Additional security test cases for Option=Value syntax
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_multiple_equals_signs() {
        // Test: Multiple equals signs should only split on first
        let content = r#"
Host example.com
    User=test=user=name
    HostName=server=name.com
"#;
        let hosts = parse(content).unwrap();
        // The value should be everything after the first equals
        assert_eq!(hosts[0].user, Some("test=user=name".to_string()));
        assert_eq!(hosts[0].hostname, Some("server=name.com".to_string()));
    }

    #[test]
    fn test_empty_value_after_equals() {
        // Test: Empty value after equals should result in None
        let content = r#"
Host example.com
    User=
    Port=
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, None);
        assert_eq!(hosts[0].port, None);
    }

    #[test]
    fn test_only_equals_no_key() {
        // Test: Line with only equals and no key should be ignored
        let content = r#"
Host example.com
    =value
    User=test
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("test".to_string()));
    }

    #[test]
    fn test_leading_whitespace_before_equals() {
        // Test: Whitespace handling around equals
        let content = r#"
Host example.com
    User   =   testuser
    Port   =   2222
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
    }

    #[test]
    fn test_tabs_around_equals() {
        // Test: Tab characters around equals
        let content = "Host example.com\n\tUser\t=\ttestuser\n\tPort\t=\t2222";
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[0].port, Some(2222));
    }

    #[test]
    fn test_equals_in_host_line() {
        // Test: Equals in Host line should not trigger equals parsing
        let content = r#"
Host example=test.com
    User testuser
"#;
        let hosts = parse(content).unwrap();
        // Host patterns should handle equals as part of the pattern
        assert_eq!(hosts[0].host_patterns, vec!["example=test.com"]);
    }

    #[test]
    fn test_command_injection_in_equals_value() {
        // Test: Command injection patterns should be caught by security validation
        let content = r#"
Host example.com
    ProxyCommand=nc $(whoami) 22
"#;
        let result = parse(content);
        // Should fail due to command injection detection
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("command substitution") || err.contains("dangerous"));
    }

    #[test]
    fn test_very_long_key_before_equals() {
        // Test: Extremely long key (potential DoS)
        let long_key = "A".repeat(10000);
        let content = format!("Host example.com\n    {}=value", long_key);
        let result = parse(&content);
        // Should handle gracefully - unknown option warning
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_value_after_equals() {
        // Test: Extremely long value (potential DoS)
        let long_value = "a".repeat(1_000_000);
        let content = format!("Host example.com\n    User={}", long_value);
        let hosts = parse(&content).unwrap();
        assert_eq!(hosts[0].user, Some(long_value.clone()));
    }

    #[test]
    fn test_equals_with_special_chars() {
        // Test: Special characters in values with equals syntax
        let content = r#"
Host example.com
    User=test@user
    HostName=server.example.com:8080
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("test@user".to_string()));
        assert_eq!(hosts[0].hostname, Some("server.example.com:8080".to_string()));
    }

    #[test]
    fn test_unicode_in_equals_syntax() {
        // Test: Unicode characters should be handled correctly
        let content = r#"
Host example.com
    User=用户名
    HostName=服务器.com
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("用户名".to_string()));
        assert_eq!(hosts[0].hostname, Some("服务器.com".to_string()));
    }

    #[test]
    fn test_setenv_with_nested_equals() {
        // Test: SetEnv which legitimately has equals in its value format
        let content = r#"
Host example.com
    SetEnv NAME=VALUE OTHER=THING
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].set_env.get("NAME"), Some(&"VALUE".to_string()));
        assert_eq!(hosts[0].set_env.get("OTHER"), Some(&"THING".to_string()));
    }

    #[test]
    fn test_quoted_values_with_equals() {
        // Test: Quoted values containing equals
        let content = r#"
Host example.com
    User="test=user"
    HostName='server=name.com'
"#;
        let hosts = parse(content).unwrap();
        // Quotes should be preserved in the value
        assert_eq!(hosts[0].user, Some("\"test=user\"".to_string()));
        assert_eq!(hosts[0].hostname, Some("'server=name.com'".to_string()));
    }

    #[test]
    fn test_malformed_port_with_equals() {
        // Test: Invalid port value with equals syntax
        let content = r#"
Host example.com
    Port=not_a_number
"#;
        let result = parse(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid port"));
    }

    #[test]
    fn test_comma_separated_with_spaces_equals() {
        // Test: Comma-separated values with spaces in equals syntax
        let content = r#"
Host example.com
    Ciphers = aes128-ctr, aes192-ctr, aes256-ctr
    PreferredAuthentications=publickey, password, keyboard-interactive
"#;
        let hosts = parse(content).unwrap();
        // Space after comma should be handled
        assert_eq!(hosts[0].ciphers, vec!["aes128-ctr,", "aes192-ctr,", "aes256-ctr"]);
        assert_eq!(hosts[0].preferred_authentications, vec!["publickey", "password", "keyboard-interactive"]);
    }

    #[test]
    fn test_control_path_with_equals() {
        // Test: ControlPath with SSH tokens and equals
        let content = r#"
Host example.com
    ControlPath=/tmp/ssh-%r@%h:%p.sock
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].control_path, Some("/tmp/ssh-%r@%h:%p.sock".to_string()));
    }

    #[test]
    fn test_proxy_command_none_with_equals() {
        // Test: Special value "none" with equals syntax
        let content = r#"
Host example.com
    ProxyCommand=none
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].proxy_command, Some("none".to_string()));
    }

    #[test]
    fn test_mixing_space_and_equals_same_option() {
        // Test: Same option with different syntaxes in different hosts
        let content = r#"
Host host1
    User testuser
Host host2
    User=testuser2
"#;
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].user, Some("testuser".to_string()));
        assert_eq!(hosts[1].user, Some("testuser2".to_string()));
    }

    #[test]
    fn test_global_option_with_equals() {
        // Test: Global option (outside Host block) with equals syntax
        let content = r#"
User=globaluser
Host example.com
    Port=2222
"#;
        // Global options are currently ignored (as per existing implementation)
        let hosts = parse(content).unwrap();
        assert_eq!(hosts[0].port, Some(2222));
        assert_eq!(hosts[0].user, None); // Global user not applied
    }
}