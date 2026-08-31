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

//! Ordered application of resolved session policy to live SSH channels.

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc::Sender;

use crate::ssh::{SessionPolicy, SessionRequest};

use super::channel_manager::{CommandExecutedResult, CommandOutput, CommandOutputBuffer};
use super::connection::Client;

impl Client {
    pub async fn execute_session_streaming(
        &self,
        policy: &SessionPolicy,
        sender: Sender<CommandOutput>,
    ) -> Result<u32, super::Error> {
        self.execute_session_streaming_with_input(policy, sender, tokio::io::empty())
            .await
    }

    /// Execute a resolved session while forwarding piped process input.
    pub async fn execute_session_streaming_with_stdin(
        &self,
        policy: &SessionPolicy,
        sender: Sender<CommandOutput>,
    ) -> Result<u32, super::Error> {
        self.execute_session_streaming_with_input(policy, sender, tokio::io::stdin())
            .await
    }

    pub(crate) async fn execute_session_streaming_with_input<R>(
        &self,
        policy: &SessionPolicy,
        sender: Sender<CommandOutput>,
        input: R,
    ) -> Result<u32, super::Error>
    where
        R: AsyncRead + Unpin,
    {
        self.execute_session_streaming_with_input_and_terminal(policy, None, sender, input)
            .await
    }

    pub(crate) async fn execute_session_streaming_with_input_and_terminal<R>(
        &self,
        policy: &SessionPolicy,
        terminal: Option<&str>,
        sender: Sender<CommandOutput>,
        input: R,
    ) -> Result<u32, super::Error>
    where
        R: AsyncRead + Unpin,
    {
        if matches!(policy.request, SessionRequest::None) {
            return Ok(0);
        }
        let channel = self.open_policy_channel(policy, terminal).await?;
        self.drain_policy_channel_with_input(channel, sender, input)
            .await
    }

    pub async fn execute_session(
        &self,
        policy: &SessionPolicy,
    ) -> Result<CommandExecutedResult, super::Error> {
        let output_buffer = CommandOutputBuffer::new();
        let sender = output_buffer.sender.clone();
        let exit_status = self.execute_session_streaming(policy, sender).await?;
        drop(output_buffer.sender);
        let (stdout, stderr) = output_buffer
            .receiver_task
            .await
            .map_err(super::Error::JoinError)?;
        Ok(CommandExecutedResult {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_status,
        })
    }

    async fn open_policy_channel(
        &self,
        policy: &SessionPolicy,
        terminal: Option<&str>,
    ) -> Result<Channel<Msg>, super::Error> {
        let channel = self
            .connection_handle
            .channel_open_session()
            .await
            .map_err(|source| self.session_error_or(super::Error::ChannelOpen { source }))?;

        if policy.request_pty {
            let inherited_terminal;
            let terminal = match terminal {
                Some(terminal) => terminal,
                None => {
                    inherited_terminal =
                        std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
                    &inherited_terminal
                }
            };
            channel
                .request_pty(true, terminal, 80, 24, 0, 0, &[])
                .await
                .map_err(|source| {
                    self.session_error_or(super::Error::CommandExecution {
                        action: "PTY request",
                        source,
                    })
                })?;
        }
        for (name, value) in &policy.environment {
            channel
                .set_env(false, name, value)
                .await
                .map_err(|source| {
                    self.session_error_or(super::Error::CommandExecution {
                        action: "environment request",
                        source,
                    })
                })?;
        }

        match &policy.request {
            SessionRequest::Exec(command) => {
                let command = crate::utils::sanitize_command(command)
                    .map_err(|error| super::Error::CommandValidationFailed(error.to_string()))?;
                channel.exec(true, command.as_bytes()).await
            }
            SessionRequest::Shell => channel.request_shell(true).await,
            SessionRequest::Subsystem(name) => channel.request_subsystem(true, name).await,
            SessionRequest::None => {
                return Err(super::Error::CommandValidationFailed(
                    "SessionType none does not create a command channel".to_string(),
                ));
            }
        }
        .map_err(|source| {
            self.session_error_or(super::Error::CommandExecution {
                action: "session request",
                source,
            })
        })?;
        Ok(channel)
    }

    async fn drain_policy_channel_with_input<R>(
        &self,
        mut channel: Channel<Msg>,
        sender: Sender<CommandOutput>,
        mut input: R,
    ) -> Result<u32, super::Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut exit_status = None;
        let mut receiver_open = true;
        let mut input_open = true;
        let mut input_buffer = [0_u8; 32 * 1024];
        loop {
            let message = if input_open {
                tokio::select! {
                    read = input.read(&mut input_buffer) => {
                        match read.map_err(super::Error::IoError)? {
                            0 => {
                                channel.eof().await?;
                                input_open = false;
                            }
                            count => channel.data(&input_buffer[..count]).await?,
                        }
                        continue;
                    }
                    message = channel.wait() => message,
                }
            } else {
                channel.wait().await
            };

            let Some(message) = message else {
                break;
            };
            let output = match message {
                ChannelMsg::Data { data } => Some(CommandOutput::StdOut(data)),
                ChannelMsg::ExtendedData { data, ext: 1 } => Some(CommandOutput::StdErr(data)),
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => {
                    exit_status = Some(status);
                    None
                }
                _ => None,
            };
            if receiver_open
                && let Some(output) = output
                && sender.send(output).await.is_err()
            {
                receiver_open = false;
            }
        }
        drop(sender);
        exit_status.ok_or_else(|| self.session_error_or(super::Error::CommandDidntExit))
    }
}
