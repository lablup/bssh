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

#![cfg(unix)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use bssh::ssh::tokio_client::{AuthMethod, Client, ServerCheckMethod, SshConnectionConfig};
use bssh::ssh::{SessionPolicy, SessionRequest};
use common::EnvGuard;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Msg, Server, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use serial_test::serial;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const AGENT_REQUEST: &[u8] = b"agent-request";
const AGENT_RESPONSE: &[u8] = b"agent-response";

#[derive(Default)]
struct ServerState {
    agent_requests: AtomicUsize,
    handle: Mutex<Option<server::Handle>>,
    held_session_started: Notify,
    release_held_session: Notify,
}

impl ServerState {
    fn handle(&self) -> server::Handle {
        self.handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("session handle must be captured before opening an agent channel")
    }
}

#[derive(Clone)]
struct AgentForwardingServer {
    state: Arc<ServerState>,
}

impl Server for AgentForwardingServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl server::Handler for AgentForwardingServer {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        if password == "test" {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        *self
            .state
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session.handle());
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.state.agent_requests.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel)?;
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if data == b"hold" {
            let state = Arc::clone(&self.state);
            let handle = session.handle();
            state.held_session_started.notify_one();
            tokio::spawn(async move {
                state.release_held_session.notified().await;
                let _ = handle.exit_status_request(channel, 0).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
        } else {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

struct RunningSshServer {
    address: SocketAddr,
    state: Arc<ServerState>,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningSshServer {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind SSH test server");
        let address = listener.local_addr().expect("SSH server address");
        let state = Arc::new(ServerState::default());
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("generate SSH test host key");
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let mut server = AgentForwardingServer {
            state: Arc::clone(&state),
        };
        let task = tokio::spawn(async move { server.run_on_socket(config, &listener).await });
        Self {
            address,
            state,
            task,
        }
    }

    async fn connect(&self, config: &SshConnectionConfig) -> Client {
        Client::connect_with_ssh_config(
            self.address,
            "test",
            AuthMethod::with_password("test"),
            ServerCheckMethod::NoCheck,
            config,
        )
        .await
        .expect("connect to SSH test server")
    }

    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn policy(forward_agent: bool) -> SessionPolicy {
    SessionPolicy {
        environment: Vec::new(),
        local_command: None,
        forward_agent,
        request_pty: false,
        stdin_null: true,
        request: SessionRequest::Exec(if forward_agent { "hold" } else { "true" }.to_string()),
    }
}

#[tokio::test]
#[serial]
async fn agent_channel_bridges_only_after_forwarding_is_requested() {
    let directory = TempDir::new().expect("agent socket tempdir");

    let enabled_socket = directory.path().join("enabled-agent.sock");
    let enabled_listener = UnixListener::bind(&enabled_socket).expect("bind fake SSH agent");
    let enabled_agent = tokio::spawn(async move {
        let (mut stream, _) = timeout(TEST_TIMEOUT, enabled_listener.accept())
            .await
            .expect("client did not connect to fake SSH agent")
            .expect("accept fake SSH agent connection");
        let mut request = vec![0; AGENT_REQUEST.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut request))
            .await
            .expect("agent request timed out")
            .expect("read forwarded agent request");
        assert_eq!(request, AGENT_REQUEST);
        stream
            .write_all(AGENT_RESPONSE)
            .await
            .expect("write fake agent response");
    });

    {
        let _socket = EnvGuard::remove("SSH_AUTH_SOCK");
        let ssh = RunningSshServer::start().await;
        let config = SshConnectionConfig::default()
            .with_forward_agent_socket_path(Some(enabled_socket.to_string_lossy().into_owned()));
        let client = ssh.connect(&config).await;
        let session_client = client.clone();
        let session_task =
            tokio::spawn(async move { session_client.execute_session(&policy(true)).await });
        timeout(TEST_TIMEOUT, ssh.state.held_session_started.notified())
            .await
            .expect("forwarded session did not start");
        assert_eq!(ssh.state.agent_requests.load(Ordering::SeqCst), 1);

        let channel = timeout(TEST_TIMEOUT, ssh.state.handle().channel_open_agent())
            .await
            .expect("opening forwarded agent channel timed out")
            .expect("client rejected enabled agent channel");
        let mut stream = channel.into_stream();
        stream
            .write_all(AGENT_REQUEST)
            .await
            .expect("write request through agent channel");
        let mut response = vec![0; AGENT_RESPONSE.len()];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut response))
            .await
            .expect("forwarded agent response timed out")
            .expect("read response through agent channel");
        assert_eq!(response, AGENT_RESPONSE);

        enabled_agent.await.expect("fake SSH agent task failed");
        ssh.state.release_held_session.notify_one();
        timeout(TEST_TIMEOUT, session_task)
            .await
            .expect("forwarded session did not finish")
            .expect("forwarded session task failed")
            .expect("execute session with agent forwarding");

        let error = timeout(TEST_TIMEOUT, ssh.state.handle().channel_open_agent())
            .await
            .expect("post-session agent channel rejection timed out")
            .expect_err("client retained agent permission after the forwarded session ended");
        assert!(matches!(
            error,
            russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)
        ));

        client.disconnect().await.expect("disconnect SSH client");
        ssh.shutdown().await;
    }

    let disabled_socket = directory.path().join("disabled-agent.sock");
    let disabled_listener = UnixListener::bind(&disabled_socket).expect("bind unused SSH agent");
    {
        let _socket = EnvGuard::set("SSH_AUTH_SOCK", &disabled_socket);
        let ssh = RunningSshServer::start().await;
        let client = ssh.connect(&SshConnectionConfig::default()).await;
        client
            .execute_session(&policy(false))
            .await
            .expect("execute session without agent forwarding");
        assert_eq!(ssh.state.agent_requests.load(Ordering::SeqCst), 0);

        let error = timeout(TEST_TIMEOUT, ssh.state.handle().channel_open_agent())
            .await
            .expect("agent channel rejection timed out")
            .expect_err("client accepted agent channel without ForwardAgent opt-in");
        assert!(matches!(
            error,
            russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited)
        ));
        assert!(
            timeout(Duration::from_millis(100), disabled_listener.accept())
                .await
                .is_err(),
            "disabled forwarding must not connect to SSH_AUTH_SOCK"
        );

        client.disconnect().await.expect("disconnect SSH client");
        ssh.shutdown().await;
    }
}
