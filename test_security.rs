// Security test cases for SSH config parser Option=Value syntax

use bssh::ssh::ssh_config::parser::parse;

#[test]
fn test_malicious_equals_injection_1() {
    // Test: Multiple equals signs - could lead to unexpected parsing
    let content = r#"
Host example.com
    User=test=malicious=value
    Port==2222
    HostName===server.com
"#;
    let result = parse(content);
    // Check how this is parsed - could lead to security issues
    if let Ok(hosts) = result {
        println!("User: {:?}", hosts[0].user);
        println!("Port: {:?}", hosts[0].port);
        println!("HostName: {:?}", hosts[0].hostname);
    }
}

#[test]
fn test_malicious_equals_injection_2() {
    // Test: Equals with command injection attempts
    let content = r#"
Host example.com
    User=$(whoami)
    ProxyCommand=nc=;rm -rf /
    HostName=`cat /etc/passwd`
"#;
    let result = parse(content);
    // This should be caught by security validation
    println!("Result: {:?}", result);
}

#[test]
fn test_empty_key_equals() {
    // Test: Empty key before equals
    let content = r#"
Host example.com
    =value
    User=test
"#;
    let result = parse(content);
    println!("Result: {:?}", result);
}

#[test]
fn test_whitespace_injection() {
    // Test: Various whitespace patterns that might break parsing
    let content = r#"
Host example.com
    User	=	test
    Port =		2222
    HostName= 	server.com
"#;
    let result = parse(content);
    if let Ok(hosts) = result {
        println!("User: {:?}", hosts[0].user);
        println!("Port: {:?}", hosts[0].port);
        println!("HostName: {:?}", hosts[0].hostname);
    }
}

#[test]
fn test_very_long_value() {
    // Test: Extremely long value that could cause memory issues
    let long_value = "a".repeat(1_000_000);
    let content = format!(r#"
Host example.com
    User={}
"#, long_value);
    let result = parse(&content);
    println!("Result for 1MB value: {:?}", result.is_ok());
}

#[test]
fn test_special_chars_in_equals_value() {
    // Test: Special characters that might break parsing
    let content = r#"
Host example.com
    User=test\n\r\0
    HostName=server;ls
    Port=22$(echo 23)
"#;
    let result = parse(content);
    println!("Result: {:?}", result);
}

#[test]
fn test_nested_equals_patterns() {
    // Test: Complex nested patterns
    let content = r#"
Host example.com
    User=test=user=name
    ProxyCommand=ssh -o Option=Value proxy
    SetEnv NAME=VALUE=SOMETHING
"#;
    let result = parse(content);
    if let Ok(hosts) = result {
        println!("User: {:?}", hosts[0].user);
        println!("ProxyCommand: {:?}", hosts[0].proxy_command);
        println!("SetEnv: {:?}", hosts[0].set_env);
    }
}

#[test]
fn test_equals_in_host_pattern() {
    // Test: Equals in Host pattern itself
    let content = r#"
Host example=test.com
    User=testuser
"#;
    let result = parse(content);
    if let Ok(hosts) = result {
        println!("Host patterns: {:?}", hosts[0].host_patterns);
    }
}

#[test]
fn test_leading_equals() {
    // Test: Leading equals sign
    let content = r#"
Host example.com
    =User=testuser
    = Port=2222
"#;
    let result = parse(content);
    println!("Result: {:?}", result);
}

#[test]
fn test_unicode_in_equals() {
    // Test: Unicode characters that might cause issues
    let content = r#"
Host example.com
    User=测试用户
    HostName=服务器.com
    ProxyCommand=ssh 用户@主机
"#;
    let result = parse(content);
    if let Ok(hosts) = result {
        println!("User: {:?}", hosts[0].user);
        println!("HostName: {:?}", hosts[0].hostname);
        println!("ProxyCommand: {:?}", hosts[0].proxy_command);
    }
}

#[test]
fn test_equals_with_quotes() {
    // Test: Quotes around equals values
    let content = r#"
Host example.com
    User="test=user"
    HostName='server=name.com'
    Port="2222"
"#;
    let result = parse(content);
    if let Ok(hosts) = result {
        println!("User: {:?}", hosts[0].user);
        println!("HostName: {:?}", hosts[0].hostname);
        println!("Port: {:?}", hosts[0].port);
    }
}

#[test]
fn test_option_value_spaces_only() {
    // Test: Option with spaces but no value after equals
    let content = r#"
Host example.com
    User=
    Port=
    HostName=
"#;
    let result = parse(content);
    println!("Result: {:?}", result);
}

fn main() {
    println!("Running security tests...");
    test_malicious_equals_injection_1();
    test_malicious_equals_injection_2();
    test_empty_key_equals();
    test_whitespace_injection();
    test_very_long_value();
    test_special_chars_in_equals_value();
    test_nested_equals_patterns();
    test_equals_in_host_pattern();
    test_leading_equals();
    test_unicode_in_equals();
    test_equals_with_quotes();
    test_option_value_spaces_only();
}