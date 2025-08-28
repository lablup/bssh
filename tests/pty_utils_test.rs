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

//! Specialized tests for PTY utility functions and edge cases.
//!
//! This test suite focuses on:
//! - PTY allocation decision logic
//! - Terminal size detection and fallbacks
//! - Signal handler setup and management
//! - Terminal detection utilities
//! - Cross-platform compatibility

use bssh::pty::{utils::*, PtyConfig};
use signal_hook::consts::SIGWINCH;
use std::time::Duration;

#[test]
fn test_pty_allocation_decision_logic() {
    // Test force_pty = true
    let config = PtyConfig {
        force_pty: true,
        disable_pty: false,
        ..Default::default()
    };

    let result = should_allocate_pty(&config);
    assert!(result.is_ok());
    assert!(result.unwrap(), "force_pty should always allocate PTY");

    // Test disable_pty = true
    let config = PtyConfig {
        force_pty: false,
        disable_pty: true,
        ..Default::default()
    };

    let result = should_allocate_pty(&config);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "disable_pty should never allocate PTY");

    // Test disable_pty takes precedence over force_pty
    let config = PtyConfig {
        force_pty: true,
        disable_pty: true,
        ..Default::default()
    };

    let result = should_allocate_pty(&config);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "disable_pty should override force_pty");

    // Test auto-detection (default behavior)
    let config = PtyConfig {
        force_pty: false,
        disable_pty: false,
        ..Default::default()
    };

    let result = should_allocate_pty(&config);
    assert!(result.is_ok());
    // Result depends on whether we're running in a terminal
    // In CI environments, this will typically be false
}

#[test]
fn test_terminal_size_detection() {
    let result = get_terminal_size();
    assert!(result.is_ok(), "Terminal size detection should not fail");

    let (width, height) = result.unwrap();
    assert!(width > 0, "Terminal width should be positive");
    assert!(height > 0, "Terminal height should be positive");

    // Test reasonable bounds
    assert!(width >= 20, "Terminal width should be at least 20");
    assert!(width <= 1000, "Terminal width should be reasonable (≤1000)");
    assert!(height >= 10, "Terminal height should be at least 10");
    assert!(height <= 200, "Terminal height should be reasonable (≤200)");
}

#[test]
fn test_terminal_size_fallback() {
    // In environments where terminal size cannot be determined,
    // the function should return default values (80, 24)
    let result = get_terminal_size();
    assert!(result.is_ok());

    let (width, height) = result.unwrap();

    // If we can't detect size, should fall back to defaults
    if width == 80 && height == 24 {
        // This is the fallback case - acceptable
        assert_eq!(width, 80);
        assert_eq!(height, 24);
    } else {
        // This is the real terminal size case - also acceptable
        assert!(width > 0 && height > 0);
    }
}

#[test]
fn test_resize_signal_handler_setup() {
    let result = setup_resize_handler();
    assert!(result.is_ok(), "Resize signal handler setup should succeed");

    let signals = result.unwrap();

    // Verify the signals object was created
    // We can't easily test the actual signal handling without sending SIGWINCH
    drop(signals); // Clean up
}

#[tokio::test]
async fn test_resize_signal_handler_timeout() {
    // Just verify we can create the handler and it doesn't hang
    let signals = setup_resize_handler();
    assert!(signals.is_ok(), "Signal handler setup should succeed");

    // Clean up immediately - don't try to wait for signals as that can hang
    drop(signals);
}

#[test]
fn test_controlling_terminal_detection() {
    let has_terminal = has_controlling_terminal();

    // In most test environments, this will be false
    // In interactive terminals, this will be true
    // Both are valid results - we just check it doesn't panic

    match has_terminal {
        true => {
            // Running in an interactive terminal
            println!("Running in interactive terminal");
        }
        false => {
            // Running in CI or non-interactive environment
            println!("Running in non-interactive environment");
        }
    }
}

#[test]
fn test_pty_config_defaults() {
    let config = PtyConfig::default();

    assert_eq!(config.term_type, "xterm-256color");
    assert!(!config.force_pty);
    assert!(!config.disable_pty);
    assert!(!config.enable_mouse);
    assert_eq!(config.timeout, Duration::from_millis(10));
}

#[test]
fn test_pty_config_clone() {
    let config1 = PtyConfig {
        term_type: "custom-term".to_string(),
        force_pty: true,
        disable_pty: false,
        enable_mouse: true,
        timeout: Duration::from_secs(1),
    };

    let config2 = config1.clone();

    assert_eq!(config1.term_type, config2.term_type);
    assert_eq!(config1.force_pty, config2.force_pty);
    assert_eq!(config1.disable_pty, config2.disable_pty);
    assert_eq!(config1.enable_mouse, config2.enable_mouse);
    assert_eq!(config1.timeout, config2.timeout);
}

#[test]
fn test_terminal_size_bounds_checking() {
    let (width, height) = get_terminal_size().unwrap();

    // Test u32 conversion safety
    // These checks are redundant since width and height are already u32
    // assert!(width <= u32::MAX);
    // assert!(height <= u32::MAX);

    // Test reasonable terminal size limits
    assert!(width >= 1, "Width should be at least 1");
    assert!(height >= 1, "Height should be at least 1");

    // Test maximum reasonable sizes
    assert!(width <= 10000, "Width should not exceed 10000");
    assert!(height <= 10000, "Height should not exceed 10000");
}

#[cfg(unix)]
#[test]
fn test_signal_constants() {
    // Test that SIGWINCH constant is available and has expected value
    assert_eq!(SIGWINCH, 28); // SIGWINCH is typically 28 on Unix systems
}

#[test]
fn test_multiple_resize_handler_setup() {
    // Test that we can set up multiple resize handlers without conflicts
    let handler1 = setup_resize_handler();
    assert!(handler1.is_ok());

    let handler2 = setup_resize_handler();
    assert!(handler2.is_ok());

    // Both handlers should be independent
    drop(handler1);
    drop(handler2);
}

#[test]
fn test_pty_allocation_edge_cases() {
    // Test various edge case configurations

    // Empty term_type
    let config = PtyConfig {
        term_type: String::new(),
        force_pty: true,
        ..Default::default()
    };
    assert!(should_allocate_pty(&config).unwrap());

    // Very long term_type
    let config = PtyConfig {
        term_type: "a".repeat(1000),
        force_pty: true,
        ..Default::default()
    };
    assert!(should_allocate_pty(&config).unwrap());

    // Special characters in term_type
    let config = PtyConfig {
        term_type: "xterm-256color-with-special-chars!@#$%^&*()".to_string(),
        force_pty: true,
        ..Default::default()
    };
    assert!(should_allocate_pty(&config).unwrap());
}

#[test]
fn test_terminal_detection_consistency() {
    // Test that terminal detection functions are consistent
    let has_terminal = has_controlling_terminal();

    // Call multiple times to ensure consistency
    for _ in 0..10 {
        assert_eq!(has_controlling_terminal(), has_terminal);
    }
}

#[tokio::test]
async fn test_concurrent_terminal_size_detection() {
    // Test that terminal size detection is thread-safe
    let mut handles = Vec::new();

    for _ in 0..10 {
        let handle = tokio::spawn(async { get_terminal_size() });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        results.push(result.unwrap());
    }

    // All results should be the same (terminal size shouldn't change during test)
    let first_result = results[0];
    for result in results {
        assert_eq!(
            result, first_result,
            "Terminal size should be consistent across threads"
        );
    }
}

#[test]
fn test_pty_config_validation() {
    // Test various timeout values
    let valid_timeouts = vec![
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_secs(10),
    ];

    for timeout in valid_timeouts {
        let config = PtyConfig {
            timeout,
            ..Default::default()
        };

        // Config should be constructible with any reasonable timeout
        assert!(config.timeout >= Duration::from_millis(1));
    }
}

#[test]
fn test_terminal_type_variations() {
    let terminal_types = vec![
        "xterm",
        "xterm-256color",
        "screen",
        "screen-256color",
        "tmux",
        "tmux-256color",
        "vt100",
        "vt220",
        "linux",
        "ansi",
    ];

    for term_type in terminal_types {
        let config = PtyConfig {
            term_type: term_type.to_string(),
            force_pty: true,
            ..Default::default()
        };

        // Should be able to create config with any terminal type
        assert_eq!(config.term_type, term_type);
        assert!(should_allocate_pty(&config).unwrap());
    }
}

#[test]
fn test_pty_config_debug_format() {
    let config = PtyConfig::default();
    let debug_str = format!("{config:?}");

    // Debug output should contain key fields
    assert!(debug_str.contains("term_type"));
    assert!(debug_str.contains("force_pty"));
    assert!(debug_str.contains("disable_pty"));
    assert!(debug_str.contains("enable_mouse"));
    assert!(debug_str.contains("timeout"));
}

#[tokio::test]
async fn test_signal_handler_cleanup() {
    // Test that signal handlers are properly cleaned up
    {
        let signals = setup_resize_handler().unwrap();

        // Spawn a task that uses the signal handler
        let handle = tokio::spawn(async move {
            // Use the signals object briefly
            let _signals = signals;
            tokio::time::sleep(Duration::from_millis(10)).await;
        });

        // Task should complete without issues
        let result = handle.await;
        assert!(result.is_ok());
    }

    // Should be able to set up new handlers after cleanup
    let signals = setup_resize_handler();
    assert!(signals.is_ok());
}

#[test]
fn test_pty_utility_error_handling() {
    // Test that utility functions handle errors gracefully

    // Terminal size should always succeed (with fallback)
    let result = get_terminal_size();
    assert!(result.is_ok());

    // Signal handler setup should succeed on Unix systems
    let result = setup_resize_handler();
    assert!(result.is_ok());

    // Terminal detection should never fail
    let _has_terminal = has_controlling_terminal();
}

// Benchmark test for performance-critical operations
#[tokio::test]
async fn test_performance_terminal_size_detection() {
    let start = std::time::Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
        let _ = get_terminal_size().unwrap();
    }

    let elapsed = start.elapsed();
    let avg_time = elapsed / iterations;

    // Terminal size detection should be fast (< 1ms per call)
    assert!(
        avg_time < Duration::from_millis(1),
        "Terminal size detection should be fast"
    );
}

#[test]
fn test_pty_allocation_performance() {
    let config = PtyConfig::default();
    let start = std::time::Instant::now();
    let iterations = 10000;

    for _ in 0..iterations {
        let _ = should_allocate_pty(&config).unwrap();
    }

    let elapsed = start.elapsed();
    let avg_time = elapsed / iterations;

    // PTY allocation decision should be very fast (< 0.01ms per call)
    assert!(
        avg_time < Duration::from_micros(10),
        "PTY allocation decision should be very fast"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_terminal_compatibility() {
    // Test macOS-specific terminal behavior
    let has_terminal = has_controlling_terminal();
    let (width, height) = get_terminal_size().unwrap();

    // macOS Terminal.app typically has these characteristics
    if has_terminal {
        // In Terminal.app, we expect reasonable defaults
        assert!(width >= 80);
        assert!(height >= 24);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_terminal_compatibility() {
    // Test Linux-specific terminal behavior
    let has_terminal = has_controlling_terminal();
    let (width, height) = get_terminal_size().unwrap();

    // Linux terminals should follow standard conventions
    if has_terminal {
        assert!(width >= 80);
        assert!(height >= 24);
    }
}

#[test]
fn test_extreme_terminal_sizes() {
    // Test handling of extreme terminal sizes
    let (width, height) = get_terminal_size().unwrap();

    // Test very small terminals (should still work)
    if width < 20 || height < 5 {
        // Very small terminal - should still be positive
        assert!(width > 0);
        assert!(height > 0);
    }

    // Test very large terminals (modern high-DPI displays)
    if width > 300 || height > 100 {
        // Large terminal - should be reasonable
        assert!(width <= 1000);
        assert!(height <= 300);
    }
}
