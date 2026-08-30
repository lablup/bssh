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

//! Bounded, shell-free `KnownHostsCommand` execution.

use std::{fmt::Write as _, io, process::Stdio, time::Duration};

use sha1::Digest as _;
use tokio::{io::AsyncReadExt, process::Command};

use super::Error;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STDOUT: usize = 256 * 1024;
const MAX_STDERR: usize = 64 * 1024;
const MAX_EXPANDED_COMMAND: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct KnownHostsCommandContext<'a> {
    pub lookup_host: &'a str,
    pub target_host: &'a str,
    pub original_host: &'a str,
    pub host_key_alias: Option<&'a str>,
    pub connection_port: u16,
    pub remote_user: &'a str,
    pub local_user: &'a str,
    pub local_user_id: &'a str,
    pub local_hostname: &'a str,
    pub local_hostname_fqdn: &'a str,
    pub home_dir: &'a str,
    pub proxy_jump: &'a str,
    pub invocation: &'a str,
    pub fingerprint: &'a str,
    pub key_base64: &'a str,
    pub key_type: &'a str,
}

fn expand_arguments(
    mut argv: Vec<String>,
    context: &KnownHostsCommandContext<'_>,
) -> Result<Vec<String>, Error> {
    let Some((_program, arguments)) = argv.split_first_mut() else {
        return Err(command_error("empty command"));
    };

    let connection_hash = connection_hash(context);
    let port = context.connection_port.to_string();
    for argument in arguments {
        let mut expanded = String::with_capacity(argument.len());
        let mut chars = argument.chars();
        while let Some(ch) = chars.next() {
            if ch == '$' && chars.as_str().starts_with('{') {
                chars.next();
                let mut variable = String::new();
                let mut closed = false;
                for character in chars.by_ref() {
                    if character == '}' {
                        closed = true;
                        break;
                    }
                    variable.push(character);
                }
                if !closed {
                    return Err(command_error("environment variable is missing closing '}'"));
                }
                if !valid_environment_name(&variable) {
                    return Err(command_error(format!(
                        "invalid environment variable name '{variable}'"
                    )));
                }
                let value = std::env::var(&variable).map_err(|_| {
                    command_error(format!(
                        "environment variable '{variable}' is not set or is not UTF-8"
                    ))
                })?;
                expanded.push_str(&value);
            } else if ch != '%' {
                expanded.push(ch);
            } else {
                let Some(token) = chars.next() else {
                    return Err(command_error("incomplete '%' token"));
                };
                match token {
                    '%' => expanded.push('%'),
                    'C' => expanded.push_str(&connection_hash),
                    'd' => expanded.push_str(context.home_dir),
                    'f' => expanded.push_str(context.fingerprint),
                    'H' => expanded.push_str(context.lookup_host),
                    'h' => expanded.push_str(context.target_host),
                    'I' => expanded.push_str(context.invocation),
                    'i' => expanded.push_str(context.local_user_id),
                    'j' => expanded.push_str(context.proxy_jump),
                    'K' => expanded.push_str(context.key_base64),
                    'k' => {
                        expanded.push_str(context.host_key_alias.unwrap_or(context.original_host))
                    }
                    'L' => expanded.push_str(context.local_hostname),
                    'l' => expanded.push_str(context.local_hostname_fqdn),
                    'n' => expanded.push_str(context.original_host),
                    'p' => expanded.push_str(&port),
                    'r' => expanded.push_str(context.remote_user),
                    't' => expanded.push_str(context.key_type),
                    'u' => expanded.push_str(context.local_user),
                    other => return Err(command_error(format!("unsupported token '%{other}'"))),
                }
            }
            if expanded.len() > MAX_EXPANDED_COMMAND {
                return Err(command_error("expanded command exceeds 8 KiB"));
            }
        }
        *argument = expanded;
    }

    let total = argv
        .iter()
        .try_fold(0_usize, |total, argument| {
            total
                .checked_add(argument.len() + 1)
                .filter(|length| *length <= MAX_EXPANDED_COMMAND)
        })
        .ok_or_else(|| command_error("expanded command exceeds 8 KiB"))?;
    debug_assert!(total <= MAX_EXPANDED_COMMAND);
    Ok(argv)
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn connection_hash(context: &KnownHostsCommandContext<'_>) -> String {
    let port = context.connection_port.to_string();
    let mut hasher = sha1::Sha1::new();
    for value in [
        context.local_hostname_fqdn,
        context.target_host,
        &port,
        context.remote_user,
        context.proxy_jump,
    ] {
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

pub(crate) async fn run_known_hosts_command(
    template: &str,
    context: &KnownHostsCommandContext<'_>,
) -> Result<String, Error> {
    // Split the operator-authored template before expanding untrusted tokens.
    // This mirrors OpenSSH and prevents a hostname containing whitespace from
    // injecting additional argv entries.
    let argv = shell_words::split(template)
        .map_err(|error| command_error(format!("invalid argument quoting: {error}")))?;
    let argv = expand_arguments(argv, context)?;
    let Some(program) = argv.first() else {
        return Err(command_error("empty command"));
    };

    let mut child = Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| command_error(format!("could not start '{program}': {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| command_error("stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| command_error("stderr pipe was unavailable"))?;

    let reads = async {
        tokio::try_join!(
            read_bounded(stdout, MAX_STDOUT, "stdout"),
            read_bounded(stderr, MAX_STDERR, "stderr")
        )
    };
    tokio::pin!(reads);
    let wait = child.wait();
    tokio::pin!(wait);

    let completed = tokio::time::timeout(COMMAND_TIMEOUT, async {
        tokio::select! {
            captured = &mut reads => {
                let captured = captured?;
                let status = wait.await?;
                Ok::<_, CaptureError>((status, captured))
            }
            status = &mut wait => {
                let status = status?;
                let captured = reads.await?;
                Ok((status, captured))
            }
        }
    })
    .await;

    let (status, (stdout, stderr)) = match completed {
        Err(_) => return Err(command_error("timed out after 5 seconds")),
        Ok(Err(error)) => return Err(command_error(error.to_string())),
        Ok(Ok(output)) => output,
    };

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let detail = stderr.trim();
        let reason = if detail.is_empty() {
            format!("exited with {status}")
        } else {
            format!("exited with {status}: {detail}")
        };
        return Err(command_error(reason));
    }

    String::from_utf8(stdout).map_err(|_| command_error("stdout was not valid UTF-8"))
}

#[derive(Debug)]
enum CaptureError {
    Io(io::Error),
    TooLarge { stream: &'static str, limit: usize },
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::TooLarge { stream, limit } => {
                write!(formatter, "{stream} exceeds the {limit}-byte limit")
            }
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

async fn read_bounded(
    reader: impl tokio::io::AsyncRead + Unpin,
    limit: usize,
    stream: &'static str,
) -> Result<Vec<u8>, CaptureError> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(CaptureError::TooLarge { stream, limit });
    }
    Ok(bytes)
}

fn command_error(reason: impl Into<String>) -> Error {
    Error::KnownHostsCommandFailed {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>() -> KnownHostsCommandContext<'a> {
        KnownHostsCommandContext {
            lookup_host: "alias.example",
            target_host: "node.example",
            original_host: "cluster-node",
            host_key_alias: Some("alias.example"),
            connection_port: 2222,
            remote_user: "remote",
            local_user: "local",
            local_user_id: "1000",
            local_hostname: "workstation",
            local_hostname_fqdn: "workstation.example",
            home_dir: "/home/local",
            proxy_jump: "jump.example",
            invocation: "HOSTNAME",
            fingerprint: "SHA256:abc",
            key_base64: "AAAAkey",
            key_type: "ssh-ed25519",
        }
    }

    #[test]
    fn expands_all_supported_tokens_without_a_shell() {
        let argv = expand_arguments(
            shell_words::split("helper %% %C %d %f %H %h %I %i %j %K %k %L %l %n %p %r %t %u")
                .unwrap(),
            &context(),
        )
        .unwrap();
        assert_eq!(argv[0], "helper");
        assert_eq!(argv[1], "%");
        assert_eq!(argv[2].len(), 40);
        assert!(
            argv[2]
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_eq!(
            &argv[3..],
            &[
                "/home/local",
                "SHA256:abc",
                "alias.example",
                "node.example",
                "HOSTNAME",
                "1000",
                "jump.example",
                "AAAAkey",
                "alias.example",
                "workstation",
                "workstation.example",
                "cluster-node",
                "2222",
                "remote",
                "ssh-ed25519",
                "local",
            ]
        );
    }

    #[test]
    fn token_values_cannot_inject_new_arguments() {
        let mut context = context();
        context.target_host = "node.example extra-argument";
        let argv =
            expand_arguments(shell_words::split("helper '%h' fixed").unwrap(), &context).unwrap();
        assert_eq!(argv, ["helper", "node.example extra-argument", "fixed"]);
    }

    #[test]
    fn order_uses_none_key_tokens_and_bounded_environment_expansion() {
        let mut context = context();
        context.invocation = "ORDER";
        context.fingerprint = "NONE";
        context.key_base64 = "NONE";
        context.key_type = "NONE";
        let path = std::env::var("PATH").expect("test process should define PATH");
        let argv = expand_arguments(
            shell_words::split("helper %I %f %K %t '${PATH}'").unwrap(),
            &context,
        )
        .unwrap();
        assert_eq!(argv, ["helper", "ORDER", "NONE", "NONE", "NONE", &path]);

        let program =
            expand_arguments(shell_words::split("'${PATH}' %I").unwrap(), &context).unwrap();
        assert_eq!(program, ["${PATH}", "ORDER"]);
        assert!(
            expand_arguments(
                shell_words::split("helper '${BSSH_TEST_DEFINITELY_MISSING_ENV}'").unwrap(),
                &context,
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn success_empty_nonzero_and_output_bounds_are_enforced() {
        let success = run_known_hosts_command("/usr/bin/printf 'key-line\\n'", &context())
            .await
            .unwrap();
        assert_eq!(success, "key-line\n");
        assert_eq!(
            run_known_hosts_command("/usr/bin/true", &context())
                .await
                .unwrap(),
            ""
        );
        assert!(matches!(
            run_known_hosts_command("/usr/bin/false", &context()).await,
            Err(Error::KnownHostsCommandFailed { .. })
        ));
        assert!(
            run_known_hosts_command("/usr/bin/yes", &context())
                .await
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn timeout_is_fail_closed() {
        let error = run_known_hosts_command("/usr/bin/sleep 10", &context())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }
}
