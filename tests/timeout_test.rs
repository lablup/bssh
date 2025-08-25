use bssh::config::Config;

#[tokio::test]
async fn test_config_timeout_parsing() {
    let yaml = r#"
defaults:
  timeout: 120

clusters:
  production:
    nodes:
      - host1.example.com
    timeout: 60
  
  staging:
    nodes:
      - host2.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Test default timeout
    assert_eq!(config.defaults.timeout, Some(120));

    // Test cluster-specific timeout
    assert_eq!(config.get_timeout(Some("production")), Some(60));

    // Test cluster without timeout (falls back to default)
    assert_eq!(config.get_timeout(Some("staging")), Some(120));

    // Test unknown cluster (falls back to default)
    assert_eq!(config.get_timeout(Some("unknown")), Some(120));

    // Test no cluster specified (uses default)
    assert_eq!(config.get_timeout(None), Some(120));
}

#[tokio::test]
async fn test_config_no_timeout() {
    let yaml = r#"
clusters:
  production:
    nodes:
      - host1.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Test no timeout configured anywhere
    assert_eq!(config.defaults.timeout, None);
    assert_eq!(config.get_timeout(Some("production")), None);
}

#[tokio::test]
async fn test_config_zero_timeout() {
    let yaml = r#"
defaults:
  timeout: 0

clusters:
  production:
    nodes:
      - host1.example.com
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    // Test timeout 0 (unlimited)
    assert_eq!(config.defaults.timeout, Some(0));
    assert_eq!(config.get_timeout(Some("production")), Some(0));
}
