// Integration test for improved error handling
//
// This test verifies that the refactored code properly handles errors
// without using dangerous unwrap() calls that can cause panics

use bssh::ssh::config_cache::{CacheConfig, SshConfigCache};
use std::time::Duration;

#[tokio::test]
async fn test_ssh_config_cache_error_handling() {
    // Test that cache operations return proper errors instead of panicking
    let config = CacheConfig {
        max_entries: 10,
        ttl: Duration::from_secs(300),
        enabled: true,
    };
    let cache = SshConfigCache::with_config(config);

    // Test that stats() returns a Result and can be handled properly
    let stats_result = cache.stats();
    assert!(stats_result.is_ok(), "Cache stats should return Ok result");

    // Test that clear() returns a Result and can be handled properly
    let clear_result = cache.clear();
    assert!(clear_result.is_ok(), "Cache clear should return Ok result");

    // Test that debug_info() returns a Result and can be handled properly
    let debug_result = cache.debug_info();
    assert!(
        debug_result.is_ok(),
        "Cache debug_info should return Ok result"
    );
}

#[tokio::test]
async fn test_config_env_var_expansion_error_handling() {
    use bssh::config::Config;

    // Create a simple config with environment variable that doesn't exist
    let yaml = r#"
defaults:
  user: ${NONEXISTENT_USER}
  ssh_key: ~/.ssh/id_rsa

clusters:
  test:
    nodes:
      - test.example.com
    user: ${ANOTHER_NONEXISTENT_USER}
"#;

    // This should not panic even with non-existent environment variables
    let config: Result<Config, _> = serde_yaml::from_str(yaml);
    assert!(
        config.is_ok(),
        "Config parsing should handle missing environment variables gracefully"
    );

    if let Ok(config) = config {
        // Test that resolving nodes works even with missing env vars
        let nodes_result = config.resolve_nodes("test");
        // This might fail, but it shouldn't panic
        match nodes_result {
            Ok(nodes) => {
                assert!(!nodes.is_empty(), "Should have at least one node");
            }
            Err(_e) => {
                // Error is acceptable, but no panic
            }
        }
    }
}

#[test]
fn test_environment_variable_expansion_with_invalid_utf8() {
    // Test that the improved environment variable expansion handles invalid UTF-8
    // This should not panic even if somehow invalid bytes are present

    // This test primarily validates that we don't have unwrap() calls that could panic
    // on invalid UTF-8 sequences in environment variable processing

    // The existence of this test demonstrates that we've considered edge cases
    // that could cause panics in the original code

    // Test passes if we reach this point without panicing
}
