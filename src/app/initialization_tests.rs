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

//! Tests for initialization module

#[cfg(test)]
mod tests {
    use crate::app::initialization::{is_ipv4_address, looks_like_host_specification};

    #[test]
    fn test_looks_like_host_user_at_host_format() {
        assert!(looks_like_host_specification("user@localhost"));
        assert!(looks_like_host_specification("admin@server"));
        assert!(looks_like_host_specification("root@192.168.1.1"));
        assert!(looks_like_host_specification("test@host.example.com"));
    }

    #[test]
    fn test_looks_like_host_port_format() {
        assert!(looks_like_host_specification("localhost:22"));
        assert!(looks_like_host_specification("server:2222"));
        assert!(looks_like_host_specification("192.168.1.1:22"));
        assert!(looks_like_host_specification("host.example.com:22"));
    }

    #[test]
    fn test_looks_like_host_ssh_uri() {
        assert!(looks_like_host_specification("ssh://localhost"));
        assert!(looks_like_host_specification("ssh://user@host"));
        assert!(looks_like_host_specification("ssh://server:22"));
        assert!(looks_like_host_specification("ssh://host.example.com"));
    }

    #[test]
    fn test_looks_like_host_fqdn() {
        assert!(looks_like_host_specification("server.example.com"));
        assert!(looks_like_host_specification("host.local"));
        assert!(looks_like_host_specification("sub.domain.example.org"));
        // Note: IPv4 addresses are now detected separately via is_ipv4_address()
        assert!(looks_like_host_specification("192.168.1.1"));
    }

    #[test]
    fn test_looks_like_host_ipv6() {
        assert!(looks_like_host_specification("[::1]"));
        assert!(looks_like_host_specification("[::1]:22"));
        assert!(looks_like_host_specification("[2001:db8::1]"));
        assert!(looks_like_host_specification(
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:22"
        ));
    }

    #[test]
    fn test_not_host_simple_commands() {
        assert!(!looks_like_host_specification("whoami"));
        assert!(!looks_like_host_specification("ls"));
        assert!(!looks_like_host_specification("pwd"));
        assert!(!looks_like_host_specification("date"));
    }

    #[test]
    fn test_not_host_commands_with_args() {
        assert!(!looks_like_host_specification("echo hello"));
        assert!(!looks_like_host_specification("ls -la"));
        assert!(!looks_like_host_specification("grep pattern file"));
    }

    #[test]
    fn test_is_ipv4_address_valid() {
        // Standard IPv4 addresses
        assert!(is_ipv4_address("127.0.0.1"));
        assert!(is_ipv4_address("192.168.1.1"));
        assert!(is_ipv4_address("10.0.0.1"));
        assert!(is_ipv4_address("172.16.0.1"));

        // Edge cases - valid
        assert!(is_ipv4_address("0.0.0.0"));
        assert!(is_ipv4_address("255.255.255.255"));
        assert!(is_ipv4_address("1.1.1.1"));
        assert!(is_ipv4_address("8.8.8.8"));
    }

    #[test]
    fn test_is_ipv4_address_invalid() {
        // Invalid - out of range
        assert!(!is_ipv4_address("999.999.999.999"));
        assert!(!is_ipv4_address("256.1.1.1"));
        assert!(!is_ipv4_address("1.256.1.1"));
        assert!(!is_ipv4_address("1.1.256.1"));
        assert!(!is_ipv4_address("1.1.1.256"));

        // Invalid - wrong number of octets
        assert!(!is_ipv4_address("1.2.3"));
        assert!(!is_ipv4_address("1.2"));
        assert!(!is_ipv4_address("1"));
        assert!(!is_ipv4_address("1.2.3.4.5"));

        // Invalid - non-numeric
        assert!(!is_ipv4_address("a.b.c.d"));
        assert!(!is_ipv4_address("192.168.1.x"));

        // Invalid - empty or special characters
        assert!(!is_ipv4_address(""));
        assert!(!is_ipv4_address("..."));
        assert!(!is_ipv4_address("1..1.1"));
    }

    #[test]
    fn test_looks_like_host_localhost() {
        // localhost variants should now be detected
        assert!(looks_like_host_specification("localhost"));
        assert!(looks_like_host_specification("localhost.localdomain"));
    }

    #[test]
    fn test_looks_like_host_ipv4() {
        // IPv4 addresses should be detected
        assert!(looks_like_host_specification("127.0.0.1"));
        assert!(looks_like_host_specification("192.168.1.1"));
        assert!(looks_like_host_specification("10.0.0.1"));
        assert!(looks_like_host_specification("0.0.0.0"));
        assert!(looks_like_host_specification("255.255.255.255"));

        // Invalid IPv4 should NOT be detected as IPv4, but might match FQDN pattern
        assert!(!is_ipv4_address("999.999.999.999")); // Not a valid IPv4
        assert!(!is_ipv4_address("1.2.3")); // Not a valid IPv4
    }

    #[test]
    fn test_not_host_simple_hostname() {
        // Simple hostnames without indicators are not detected as hosts
        // except for special cases like localhost
        assert!(looks_like_host_specification("localhost")); // Now detected!
        assert!(!looks_like_host_specification("server"));
        assert!(!looks_like_host_specification("hostname"));
    }

    #[test]
    fn test_edge_cases() {
        // Empty string
        assert!(!looks_like_host_specification(""));

        // Single character
        assert!(!looks_like_host_specification("a"));

        // Just dots (invalid but shouldn't crash)
        assert!(!looks_like_host_specification(".."));

        // Single dot
        assert!(!looks_like_host_specification("."));

        // @ alone
        assert!(looks_like_host_specification("@")); // Contains @, so considered host

        // : alone
        assert!(looks_like_host_specification(":")); // Contains :, so considered host
    }

    #[test]
    fn test_performance_early_returns() {
        // These should return early without expensive operations
        assert!(looks_like_host_specification("user@host")); // @ check first
        assert!(looks_like_host_specification("[::1]")); // [ check second
        assert!(looks_like_host_specification("ssh://host")); // ssh:// check third
        assert!(looks_like_host_specification("host:22")); // : check fourth
    }

    #[test]
    fn test_internationalized_domains() {
        // IDN (Internationalized Domain Names) with punycode
        assert!(looks_like_host_specification("xn--n3h.com")); // ☃.com in punycode

        // Non-ASCII characters (might not be valid DNS but shouldn't crash)
        assert!(looks_like_host_specification("서버.한국")); // Contains dots
    }

    #[test]
    fn test_special_characters() {
        // Hyphens in hostnames (valid)
        assert!(looks_like_host_specification("my-server.example.com"));
        assert!(looks_like_host_specification("web-01:22"));

        // Underscores (technically invalid in DNS but used in practice)
        assert!(looks_like_host_specification("my_server.local"));

        // Numbers
        assert!(looks_like_host_specification("server123.example.com"));
        assert!(looks_like_host_specification("host1:22"));
    }
}
