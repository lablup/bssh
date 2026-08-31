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

//! Runtime application of ssh_config channel and command policy.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::process::ExitStatus;

use anyhow::{Context, Result};
use glob::Pattern;
use sha1::{Digest, Sha1};
use tokio::process::Command;

use crate::node::Node;

use super::ssh_config::SshHostConfig;

pub const MAX_ENVIRONMENT_NAME_BYTES: usize = 256;
pub const MAX_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1024;
pub const MAX_ENVIRONMENT_REQUESTS: usize = 1024;
const MAX_EXPANDED_COMMAND_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CliTtyMode {
    #[default]
    Default,
    Force,
    Disable,
}

/// Traffic profile used by transport options such as `IPQoS`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionPurpose {
    Interactive,
    #[default]
    Bulk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRequest {
    Exec(String),
    Shell,
    Subsystem(String),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub environment: Vec<(String, String)>,
    pub local_command: Option<String>,
    pub request_pty: bool,
    pub stdin_null: bool,
    pub request: SessionRequest,
}

#[derive(Debug, Clone)]
struct TokenContext {
    effective_host: String,
    original_host: String,
    host_key_alias: String,
    port: String,
    remote_user: String,
    local_user: String,
    local_home: String,
    local_host: String,
    local_host_short: String,
    local_uid: String,
    jump_host: String,
    connection_hash: String,
}

impl SessionPolicy {
    #[must_use]
    pub fn purpose(&self) -> SessionPurpose {
        if self.request_pty {
            SessionPurpose::Interactive
        } else {
            SessionPurpose::Bulk
        }
    }

    pub fn resolve(
        config: &SshHostConfig,
        node: &Node,
        explicit_command: Option<&str>,
        cli_tty: CliTtyMode,
        stdin_is_terminal: bool,
    ) -> Result<Self> {
        Self::resolve_with_jump_spec(
            config,
            node,
            explicit_command,
            cli_tty,
            stdin_is_terminal,
            None,
        )
    }

    pub fn resolve_with_jump_spec(
        config: &SshHostConfig,
        node: &Node,
        explicit_command: Option<&str>,
        cli_tty: CliTtyMode,
        stdin_is_terminal: bool,
        jump_spec: Option<&str>,
    ) -> Result<Self> {
        Self::resolve_with_environment_and_jump_spec(
            config,
            node,
            explicit_command,
            cli_tty,
            stdin_is_terminal,
            jump_spec,
            std::env::vars_os(),
        )
    }

    #[cfg(test)]
    fn resolve_with_environment<I>(
        config: &SshHostConfig,
        node: &Node,
        explicit_command: Option<&str>,
        cli_tty: CliTtyMode,
        stdin_is_terminal: bool,
        local_environment: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        Self::resolve_with_environment_and_jump_spec(
            config,
            node,
            explicit_command,
            cli_tty,
            stdin_is_terminal,
            None,
            local_environment,
        )
    }

    fn resolve_with_environment_and_jump_spec<I>(
        config: &SshHostConfig,
        node: &Node,
        explicit_command: Option<&str>,
        cli_tty: CliTtyMode,
        stdin_is_terminal: bool,
        jump_spec: Option<&str>,
        local_environment: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let tokens = TokenContext::for_node(config, node, jump_spec)?;
        let local_environment = local_environment
            .into_iter()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect::<BTreeMap<_, _>>();
        let environment = resolve_environment(config, &local_environment, &tokens)?;
        let local_command = if config.permit_local_command.unwrap_or(false) {
            config
                .local_command
                .as_deref()
                .map(|command| {
                    expand_tokens(
                        command,
                        &tokens,
                        TokenSet::LocalCommand,
                        true,
                        None,
                        MAX_EXPANDED_COMMAND_BYTES,
                    )
                })
                .transpose()?
                .map(|command| validate_local_shell_command(&command).map(|()| command))
                .transpose()?
        } else {
            None
        };

        let configured_command = config
            .remote_command
            .as_deref()
            .map(|command| {
                expand_tokens(
                    command,
                    &tokens,
                    TokenSet::Default,
                    true,
                    None,
                    MAX_EXPANDED_COMMAND_BYTES,
                )
            })
            .transpose()?
            .map(|command| crate::utils::sanitize_command(&command))
            .transpose()?;
        if configured_command.is_some() && explicit_command.is_some_and(|value| !value.is_empty()) {
            anyhow::bail!("RemoteCommand cannot be used together with an explicit command");
        }
        let command = configured_command.or_else(|| {
            explicit_command
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        });

        let request =
            match config.session_type.as_deref().unwrap_or("default") {
                "default" => command.map_or(SessionRequest::Shell, SessionRequest::Exec),
                "subsystem" => SessionRequest::Subsystem(command.context(
                    "SessionType subsystem requires RemoteCommand to name the subsystem",
                )?),
                "none" if command.is_some() => {
                    anyhow::bail!("SessionType none cannot be used with a command")
                }
                "none" => SessionRequest::None,
                value => anyhow::bail!("Unsupported SessionType value: {value}"),
            };
        let interactive = matches!(request, SessionRequest::Shell);
        let stdin_null = config.stdin_null.unwrap_or(false);
        let request_pty = resolve_request_pty(
            cli_tty,
            config.request_tty.as_deref(),
            stdin_is_terminal && !stdin_null,
            interactive,
        )?;

        Ok(Self {
            environment,
            local_command,
            request_pty,
            stdin_null,
            request,
        })
    }

    /// Run the configured local command once after authentication.
    pub async fn run_local_command(&self) -> Result<()> {
        let Some(command) = self.local_command.as_deref() else {
            return Ok(());
        };
        let status = local_shell(command)
            .status()
            .await
            .with_context(|| "Failed to execute LocalCommand")?;
        ensure_local_command_success(status)
    }
}

impl TokenContext {
    fn for_node(config: &SshHostConfig, node: &Node, jump_spec: Option<&str>) -> Result<Self> {
        let local_user = whoami::username().unwrap_or_else(|_| "user".to_string());
        let local_home = dirs::home_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let local_host = whoami::hostname().unwrap_or_else(|_| "localhost".to_string());
        let local_host_short = local_host
            .split('.')
            .next()
            .unwrap_or(&local_host)
            .to_string();
        let local_uid = local_uid();
        let host_key_alias = config
            .host_key_alias
            .clone()
            .unwrap_or_else(|| node.original_host.clone());
        let jump_host = jump_spec
            .or(config.proxy_jump.as_deref())
            .filter(|value| !value.eq_ignore_ascii_case("none"))
            .unwrap_or("")
            .to_string();
        let mut digest = Sha1::new();
        digest.update(local_host.as_bytes());
        digest.update(node.host.as_bytes());
        digest.update(node.port.to_string().as_bytes());
        digest.update(node.username.as_bytes());
        digest.update(jump_host.as_bytes());
        let digest = digest.finalize();
        let mut connection_hash = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(connection_hash, "{byte:02x}").expect("writing to a String cannot fail");
        }

        Ok(Self {
            effective_host: node.host.clone(),
            original_host: node.original_host.clone(),
            host_key_alias,
            port: node.port.to_string(),
            remote_user: node.username.clone(),
            local_user,
            local_home,
            local_host,
            local_host_short,
            local_uid,
            jump_host,
            connection_hash,
        })
    }
}

fn resolve_environment(
    config: &SshHostConfig,
    local_environment: &BTreeMap<String, String>,
    tokens: &TokenContext,
) -> Result<Vec<(String, String)>> {
    if config.send_env.len() > MAX_ENVIRONMENT_REQUESTS {
        anyhow::bail!("Too many SendEnv patterns (max {MAX_ENVIRONMENT_REQUESTS})");
    }
    let send_env_patterns = resolve_send_env_patterns(&config.send_env)?;
    let mut environment = BTreeMap::new();
    for (name, value) in local_environment {
        if send_env_selected(name, &send_env_patterns) {
            validate_environment(name, value)?;
            environment.insert(name.clone(), value.clone());
            validate_environment_count(environment.len())?;
        }
    }
    for (name, value) in &config.set_env {
        let value = expand_tokens(
            value,
            tokens,
            TokenSet::Default,
            false,
            Some(local_environment),
            MAX_ENVIRONMENT_VALUE_BYTES,
        )?;
        validate_environment(name, &value)?;
        environment.insert(name.clone(), value);
        validate_environment_count(environment.len())?;
    }
    Ok(environment.into_iter().collect())
}

fn resolve_send_env_patterns(patterns: &[String]) -> Result<Vec<(String, Pattern)>> {
    let mut active = Vec::new();
    for raw in patterns {
        if raw.len() > MAX_ENVIRONMENT_NAME_BYTES + usize::from(raw.starts_with('-'))
            || raw.contains('=')
            || raw.contains('\0')
        {
            anyhow::bail!("Invalid or oversized SendEnv pattern: {raw}");
        }
        if let Some(removal) = raw.strip_prefix('-') {
            if removal.is_empty() {
                anyhow::bail!("SendEnv removal pattern cannot be empty");
            }
            let removal = Pattern::new(removal)
                .with_context(|| format!("Invalid SendEnv removal pattern: {raw}"))?;
            active.retain(|(source, _): &(String, Pattern)| !removal.matches(source));
        } else {
            let pattern =
                Pattern::new(raw).with_context(|| format!("Invalid SendEnv pattern: {raw}"))?;
            active.push((raw.clone(), pattern));
        }
    }
    Ok(active)
}

fn send_env_selected(name: &str, patterns: &[(String, Pattern)]) -> bool {
    patterns.iter().any(|(_, pattern)| pattern.matches(name))
}

fn validate_environment_count(count: usize) -> Result<()> {
    if count > MAX_ENVIRONMENT_REQUESTS {
        anyhow::bail!(
            "Too many SSH environment requests: {count} (max {MAX_ENVIRONMENT_REQUESTS})"
        );
    }
    Ok(())
}

pub(crate) fn validate_environment(name: &str, value: &str) -> Result<()> {
    if name.is_empty() || name.contains('=') || name.contains('\0') {
        anyhow::bail!("SSH environment name is empty or contains '=' or NUL");
    }
    if name.len() > MAX_ENVIRONMENT_NAME_BYTES {
        anyhow::bail!("SSH environment name is too long (max {MAX_ENVIRONMENT_NAME_BYTES} bytes)");
    }
    if value.contains('\0') || value.len() > MAX_ENVIRONMENT_VALUE_BYTES {
        anyhow::bail!(
            "SSH environment value is invalid or too long (max {MAX_ENVIRONMENT_VALUE_BYTES} bytes)"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSet {
    Default,
    LocalCommand,
}

fn expand_tokens(
    value: &str,
    tokens: &TokenContext,
    token_set: TokenSet,
    shell_safe: bool,
    local_environment: Option<&BTreeMap<String, String>>,
    max_bytes: usize,
) -> Result<String> {
    if value.len() > max_bytes {
        anyhow::bail!("SSH value is too long before token expansion (max {max_bytes} bytes)");
    }
    let mut expanded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') && local_environment.is_some() {
            chars.next();
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => name.push(ch),
                    None => {
                        anyhow::bail!("Environment variable expansion is missing closing '}}'")
                    }
                }
            }
            if name.is_empty() {
                anyhow::bail!("Environment variable expansion has an empty name");
            }
            let replacement = local_environment
                .and_then(|environment| environment.get(&name))
                .with_context(|| format!("Environment variable ${{{name}}} is not set"))?;
            expanded.push_str(replacement);
            if expanded.len() > max_bytes {
                anyhow::bail!("Expanded SSH value is too long (max {max_bytes} bytes)");
            }
            continue;
        }
        if ch != '%' {
            expanded.push(ch);
            continue;
        }
        let token = chars
            .next()
            .context("Incomplete '%' token in SSH command")?;
        let (name, replacement) = match token {
            '%' => ("literal percent", "%"),
            'C' => ("connection hash", tokens.connection_hash.as_str()),
            'd' => ("local home", tokens.local_home.as_str()),
            'h' => ("effective host", tokens.effective_host.as_str()),
            'i' => ("local uid", tokens.local_uid.as_str()),
            'j' => ("proxy jump", tokens.jump_host.as_str()),
            'k' => ("host key alias", tokens.host_key_alias.as_str()),
            'L' => ("short local host", tokens.local_host_short.as_str()),
            'l' => ("local host", tokens.local_host.as_str()),
            'n' => ("original host", tokens.original_host.as_str()),
            'p' => ("port", tokens.port.as_str()),
            'r' => ("remote user", tokens.remote_user.as_str()),
            'T' if token_set == TokenSet::LocalCommand => ("tun/tap device", "NONE"),
            'u' => ("local user", tokens.local_user.as_str()),
            _ => anyhow::bail!("Unsupported SSH percent token: %{token}"),
        };
        if shell_safe {
            validate_shell_token_value(name, replacement)?;
        }
        expanded.push_str(replacement);
        if expanded.len() > max_bytes {
            anyhow::bail!("Expanded SSH value is too long (max {max_bytes} bytes)");
        }
    }
    Ok(expanded)
}

fn resolve_request_pty(
    cli: CliTtyMode,
    configured: Option<&str>,
    stdin_is_terminal: bool,
    interactive: bool,
) -> Result<bool> {
    match cli {
        CliTtyMode::Force => return Ok(true),
        CliTtyMode::Disable => return Ok(false),
        CliTtyMode::Default => {}
    }
    match configured.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "force" => Ok(true),
        "yes" => Ok(stdin_is_terminal),
        "auto" => Ok(interactive && stdin_is_terminal),
        "no" => Ok(false),
        value => anyhow::bail!("Unsupported RequestTTY value: {value}"),
    }
}

fn validate_local_shell_command(command: &str) -> Result<()> {
    if command.trim().is_empty() {
        anyhow::bail!("LocalCommand cannot be empty");
    }
    if let Some(value) = command
        .chars()
        .find(|value| matches!(value, '\0' | '\n' | '\r'))
    {
        anyhow::bail!("LocalCommand contains invalid control character {value:?}");
    }
    Ok(())
}

fn validate_shell_token_value(name: &str, value: &str) -> Result<()> {
    if value.len() > 1024
        || value.chars().any(|ch| {
            ch.is_control()
                || matches!(
                    ch,
                    '\'' | '"' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '\\'
                )
        })
    {
        anyhow::bail!("Unsafe {name} value for SSH command token expansion");
    }
    Ok(())
}

fn ensure_local_command_success(status: ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("LocalCommand exited with status {status}")
    }
}

#[cfg(unix)]
fn local_uid() -> String {
    // SAFETY: getuid has no arguments, dereferences no pointers, and cannot fail.
    unsafe { libc::getuid() }.to_string()
}

#[cfg(not(unix))]
fn local_uid() -> String {
    "0".to_string()
}

#[cfg(unix)]
fn local_shell(command: &str) -> Command {
    let mut child = Command::new(std::env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into()));
    child.arg("-c").arg(command);
    child
}

#[cfg(windows)]
fn local_shell(command: &str) -> Command {
    let mut child = Command::new("cmd.exe");
    child.arg("/C").arg(command);
    child
}

#[cfg(test)]
#[path = "session_policy_tests.rs"]
mod tests;
