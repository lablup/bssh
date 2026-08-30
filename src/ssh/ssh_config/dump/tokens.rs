use std::fmt::Write as _;

use anyhow::{Context, Result};
use sha1::{Digest, Sha1};

use super::super::SshHostConfig;

pub(super) struct TokenContext {
    pub(super) effective_host: String,
    original_host: String,
    pub(super) remote_user: String,
    local_user: String,
    local_home: String,
    local_host: String,
    local_host_short: String,
    local_uid: String,
    pub(super) port: String,
    host_key_alias: String,
    connection_hash: String,
}

impl TokenContext {
    pub(super) fn new(original_host: &str, config: &SshHostConfig) -> Self {
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
        Self {
            effective_host: config
                .hostname
                .clone()
                .unwrap_or_else(|| original_host.to_string()),
            original_host: original_host.to_string(),
            remote_user: config.user.clone().unwrap_or_else(|| local_user.clone()),
            local_user,
            local_home,
            local_host,
            local_host_short,
            local_uid: local_uid(),
            port: config.port.unwrap_or(22).to_string(),
            host_key_alias: config
                .host_key_alias
                .clone()
                .unwrap_or_else(|| original_host.to_string()),
            connection_hash: String::new(),
        }
    }

    pub(super) fn refresh_hash(&mut self, jump: &str) {
        let mut digest = Sha1::new();
        digest.update(self.local_host.as_bytes());
        digest.update(self.effective_host.as_bytes());
        digest.update(self.port.as_bytes());
        digest.update(self.remote_user.as_bytes());
        digest.update(jump.as_bytes());
        self.connection_hash.clear();
        for byte in digest.finalize() {
            let _ = write!(self.connection_hash, "{byte:02x}");
        }
    }

    pub(super) fn expand(&self, value: &str) -> Result<String> {
        let mut output = String::with_capacity(value.len());
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '$' && chars.peek() == Some(&'$') {
                chars.next();
                output.push('$');
                continue;
            }
            if ch == '$' && chars.peek() == Some(&'{') {
                chars.next();
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => name.push(ch),
                        None => anyhow::bail!("Environment expansion is missing closing '}}'"),
                    }
                }
                let value = std::env::var(&name)
                    .with_context(|| format!("Environment variable ${{{name}}} is not set"))?;
                output.push_str(&value);
                continue;
            }
            if ch != '%' {
                output.push(ch);
                continue;
            }
            let token = chars
                .next()
                .context("Incomplete '%' token in SSH configuration")?;
            let replacement = match token {
                '%' => "%",
                'C' => &self.connection_hash,
                'd' => &self.local_home,
                'h' => &self.effective_host,
                'i' => &self.local_uid,
                'k' => &self.host_key_alias,
                'L' => &self.local_host_short,
                'l' => &self.local_host,
                'n' => &self.original_host,
                'p' => &self.port,
                'r' => &self.remote_user,
                'u' => &self.local_user,
                _ => anyhow::bail!("Unsupported SSH percent token: %{token}"),
            };
            output.push_str(replacement);
        }
        Ok(output)
    }

    pub(super) fn expand_path(&self, value: &str) -> Result<String> {
        let value = if value == "~" {
            format!("{}/", self.local_home)
        } else if let Some(suffix) = value.strip_prefix("~/") {
            format!("{}/{suffix}", self.local_home)
        } else {
            value.to_string()
        };
        self.expand(&value)
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
