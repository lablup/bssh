use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use bssh::forwarding::{ForwardingDirective, ForwardingPlan};
use bssh::security::{Password, SudoPassword};
use bssh::ssh::SshConfig;
use bssh::ssh::client::{ConnectionConfig, SshClient};
use bssh::ssh::known_hosts::StrictHostKeyChecking;
use bssh::ssh::tokio_client::{
    AddressFamily, AuthMethod, Client, ServerCheckMethod, SshConnectionConfig,
    SshConnectionConfigResolver,
};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Msg, Server, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ServerState {
    authentications: AtomicUsize,
    allocated_port: AtomicU16,
    reject_remote: AtomicBool,
    events: Mutex<Vec<String>>,
    remote_listeners: AsyncMutex<HashMap<(String, u32), CancellationToken>>,
}

impl ServerState {
    fn record(&self, event: impl Into<String>) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.into());
    }

    fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Clone)]
struct ForwardingServer {
    state: Arc<ServerState>,
}

impl server::Server for ForwardingServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl server::Handler for ForwardingServer {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.state.authentications.fetch_add(1, Ordering::SeqCst);
        self.state.record("auth");
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.record("session");
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.record("exec");
        session.channel_success(channel)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.record("pty");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.record("shell");
        session.channel_success(channel)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(tcp) = TcpStream::connect((host_to_connect, port_to_connect as u16)).await else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut tcp = tcp;
            let mut ssh = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut ssh).await;
        });
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.state.reject_remote.load(Ordering::Acquire) {
            self.state.record("remote-failed");
            return Ok(false);
        }
        let listener = match TcpListener::bind((address, *port as u16)).await {
            Ok(listener) => listener,
            Err(_) => {
                self.state.record("remote-failed");
                return Ok(false);
            }
        };
        let allocated = u32::from(listener.local_addr()?.port());
        *port = allocated;
        self.state
            .allocated_port
            .store(allocated as u16, Ordering::Release);
        self.state.record(format!("remote:{allocated}"));

        let cancel = CancellationToken::new();
        self.state
            .remote_listeners
            .lock()
            .await
            .insert((address.to_string(), allocated), cancel.clone());
        let handle = session.handle();
        let address = address.to_string();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = cancel.cancelled() => break,
                };
                let Ok((tcp, peer)) = accepted else {
                    break;
                };
                let handle = handle.clone();
                let connected_address = address.clone();
                tokio::spawn(async move {
                    let Ok(channel) = handle
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            allocated,
                            peer.ip().to_string(),
                            u32::from(peer.port()),
                        )
                        .await
                    else {
                        return;
                    };
                    let mut tcp = tcp;
                    let mut ssh = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut ssh).await;
                });
            }
        });
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let token = self
            .state
            .remote_listeners
            .lock()
            .await
            .remove(&(address.to_string(), port));
        if let Some(token) = token {
            token.cancel();
            self.state.record(format!("cancel:{port}"));
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct TestSshServer {
    address: SocketAddr,
    state: Arc<ServerState>,
    task: JoinHandle<std::io::Result<()>>,
}

impl TestSshServer {
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
        let mut server = ForwardingServer {
            state: Arc::clone(&state),
        };
        let task = tokio::spawn(async move { server.run_on_socket(config, &listener).await });
        Self {
            address,
            state,
            task,
        }
    }

    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

struct EchoServer {
    address: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl EchoServer {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo server");
        let address = listener.local_addr().expect("echo server address");
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = task_cancel.cancelled() => break,
                };
                let Ok((mut stream, _)) = accepted else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    while let Ok(size) = stream.read(&mut buffer).await {
                        if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            address,
            cancel,
            task,
        }
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

async fn unused_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("reserve test port")
        .local_addr()
        .expect("reserved port")
        .port()
}

async fn echo_round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream
        .write_all(payload)
        .await
        .expect("write tunnel payload");
    let mut response = vec![0; payload.len()];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut response))
        .await
        .expect("tunnel response timeout")
        .unwrap_or_else(|error| {
            panic!(
                "read {:?} tunnel response: {error}",
                String::from_utf8_lossy(payload)
            )
        });
    assert_eq!(response, payload);
}

async fn assert_echo(mut stream: TcpStream, payload: &[u8]) {
    echo_round_trip(&mut stream, payload).await;
}

async fn assert_stream_closed(mut stream: TcpStream) {
    let mut byte = [0_u8; 1];
    let result = timeout(TEST_TIMEOUT, stream.read(&mut byte))
        .await
        .expect("forwarded stream did not close during teardown");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "forwarded stream remained readable after teardown: {result:?}"
    );
}

async fn wait_for_allocated_port(state: &ServerState) -> u16 {
    timeout(TEST_TIMEOUT, async {
        loop {
            let port = state.allocated_port.load(Ordering::Acquire);
            if port != 0 {
                break port;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("remote allocated port")
}

async fn assert_listener_released(port: u16) {
    timeout(TEST_TIMEOUT, async {
        loop {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(listener) => break drop(listener),
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("forwarding listener was not released");
}

fn connection_config(
    directives: Vec<ForwardingDirective>,
    exit_on_failure: bool,
) -> SshConnectionConfig {
    SshConnectionConfig::new().with_forwarding_plan(ForwardingPlan {
        directives,
        clear_all: false,
        exit_on_failure,
        address_family: AddressFamily::V4,
    })
}

#[tokio::test]
async fn local_remote_dynamic_share_one_auth_and_teardown_without_leaks() {
    let ssh = TestSshServer::start().await;
    let echo = EchoServer::start().await;
    let local_port = unused_port().await;
    let dynamic_port = unused_port().await;
    let config = SshConfig::parse(&format!(
        "Host target\n    LocalForward {local_port} 127.0.0.1:{}\n    DynamicForward {dynamic_port}\n    RemoteForward 127.0.0.1:0 127.0.0.1:{}\n    ExitOnForwardFailure yes\n",
        echo.address.port(),
        echo.address.port()
    ))
    .expect("parse config-only forwards");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .resolve_for_host("target");

    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect("connect and make forwards ready");
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);

    let mut local_stream = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
        .await
        .expect("connect local forward");
    echo_round_trip(&mut local_stream, b"local-forward").await;

    let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, dynamic_port))
        .await
        .expect("connect dynamic forward");
    socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut greeting = [0_u8; 2];
    socks
        .read_exact(&mut greeting)
        .await
        .expect("SOCKS greeting reply");
    assert_eq!(greeting, [5, 0]);
    let [port_high, port_low] = echo.address.port().to_be_bytes();
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port_high, port_low])
        .await
        .expect("SOCKS connect");
    let mut socks_reply = [0_u8; 10];
    socks
        .read_exact(&mut socks_reply)
        .await
        .expect("SOCKS connect reply");
    assert_eq!(&socks_reply[..2], &[5, 0]);
    echo_round_trip(&mut socks, b"dynamic-forward").await;

    let allocated = wait_for_allocated_port(&ssh.state).await;
    let mut remote_stream = TcpStream::connect((Ipv4Addr::LOCALHOST, allocated))
        .await
        .expect("connect allocated remote forward");
    echo_round_trip(&mut remote_stream, b"remote-forward").await;

    client
        .execute("true")
        .await
        .expect("execute after forwarding setup");
    let events = ssh.state.events();
    let remote_index = events
        .iter()
        .position(|event| event.starts_with("remote:"))
        .expect("remote forward event");
    let session_index = events
        .iter()
        .position(|event| event == "session")
        .expect("session event");
    let exec_index = events
        .iter()
        .position(|event| event == "exec")
        .expect("exec event");
    assert!(remote_index < session_index, "events: {events:?}");
    assert!(remote_index < exec_index, "events: {events:?}");
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);

    client.disconnect().await.expect("disconnect client");
    assert_stream_closed(local_stream).await;
    assert_stream_closed(socks).await;
    assert_stream_closed(remote_stream).await;
    assert_listener_released(local_port).await;
    assert_listener_released(dynamic_port).await;
    assert_listener_released(allocated).await;
    assert!(
        ssh.state
            .events()
            .iter()
            .any(|event| event == &format!("cancel:{allocated}"))
    );

    echo.shutdown().await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn combined_cli_and_config_plan_carries_live_data() {
    let ssh = TestSshServer::start().await;
    let echo = EchoServer::start().await;
    let local_port = unused_port().await;
    let dynamic_port = unused_port().await;
    let config = SshConfig::parse(&format!(
        "Host target\n    LocalForward {local_port} 127.0.0.1:{}\n    ExitOnForwardFailure yes\n",
        echo.address.port()
    ))
    .expect("parse combined-plan config");
    let config = SshConnectionConfigResolver::new()
        .with_ssh_config(Some(config))
        .with_cli_forwarding_order(vec![ForwardingDirective::Dynamic(dynamic_port.to_string())])
        .with_cli_forwardings(Vec::new(), Vec::new(), vec![dynamic_port.to_string()])
        .resolve_for_host("target");

    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect("connect with combined forwarding plan");

    assert_echo(
        TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
            .await
            .expect("connect config local forward"),
        b"config-local",
    )
    .await;

    let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, dynamic_port))
        .await
        .expect("connect CLI dynamic forward");
    socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut greeting = [0_u8; 2];
    socks
        .read_exact(&mut greeting)
        .await
        .expect("SOCKS greeting reply");
    assert_eq!(greeting, [5, 0]);
    let [port_high, port_low] = echo.address.port().to_be_bytes();
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port_high, port_low])
        .await
        .expect("SOCKS connect");
    let mut reply = [0_u8; 10];
    socks
        .read_exact(&mut reply)
        .await
        .expect("SOCKS connect reply");
    assert_eq!(&reply[..2], &[5, 0]);
    assert_echo(socks, b"cli-dynamic").await;

    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    client.disconnect().await.expect("disconnect client");
    assert_listener_released(local_port).await;
    assert_listener_released(dynamic_port).await;
    echo.shutdown().await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn remote_request_failure_obeys_exit_policy_without_reauthentication() {
    let fatal_server = TestSshServer::start().await;
    fatal_server
        .state
        .reject_remote
        .store(true, Ordering::Release);
    let fatal_config = connection_config(
        vec![ForwardingDirective::Remote(
            "127.0.0.1:0:127.0.0.1:9".into(),
        )],
        true,
    );
    let error = Client::connect_with_ssh_config(
        fatal_server.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &fatal_config,
    )
    .await
    .expect_err("rejected remote forward must fail strict setup");
    assert!(
        error
            .to_string()
            .contains("Remote forwarding request failed")
    );
    assert_eq!(fatal_server.state.authentications.load(Ordering::SeqCst), 1);
    assert!(
        !fatal_server
            .state
            .events()
            .iter()
            .any(|event| event == "exec")
    );
    fatal_server.shutdown().await;

    let permissive_server = TestSshServer::start().await;
    permissive_server
        .state
        .reject_remote
        .store(true, Ordering::Release);
    let permissive_config = connection_config(
        vec![ForwardingDirective::Remote(
            "127.0.0.1:0:127.0.0.1:9".into(),
        )],
        false,
    );
    let client = Client::connect_with_ssh_config(
        permissive_server.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &permissive_config,
    )
    .await
    .expect("permissive setup continues after rejected remote forward");
    client.execute("true").await.expect("command still runs");
    assert_eq!(
        permissive_server
            .state
            .authentications
            .load(Ordering::SeqCst),
        1
    );
    client.disconnect().await.expect("disconnect client");
    permissive_server.shutdown().await;
}

#[tokio::test]
async fn exit_on_forward_failure_controls_session_start_without_reauthentication() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("occupy local port");
    let occupied_port = occupied.local_addr().expect("occupied address").port();

    let fatal_server = TestSshServer::start().await;
    let fatal_config = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{occupied_port}:127.0.0.1:9"
        ))],
        true,
    );
    let error = Client::connect_with_ssh_config(
        fatal_server.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &fatal_config,
    )
    .await
    .expect_err("ExitOnForwardFailure=yes must fail connection setup");
    assert!(error.to_string().contains("Forwarding"));
    assert_eq!(fatal_server.state.authentications.load(Ordering::SeqCst), 1);
    assert!(
        !fatal_server
            .state
            .events()
            .iter()
            .any(|event| event == "exec")
    );
    fatal_server.shutdown().await;

    let permissive_server = TestSshServer::start().await;
    let permissive_config = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{occupied_port}:127.0.0.1:9"
        ))],
        false,
    );
    let client = Client::connect_with_ssh_config(
        permissive_server.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &permissive_config,
    )
    .await
    .expect("ExitOnForwardFailure=no continues");
    client.execute("true").await.expect("command still runs");
    assert_eq!(
        permissive_server
            .state
            .authentications
            .load(Ordering::SeqCst),
        1
    );
    client.disconnect().await.expect("disconnect client");
    permissive_server.shutdown().await;
    drop(occupied);
}

#[tokio::test]
async fn pty_session_keeps_forwarding_alive_until_client_disconnect() {
    let ssh = TestSshServer::start().await;
    let echo = EchoServer::start().await;
    let local_port = unused_port().await;
    let config = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{local_port}:127.0.0.1:{}",
            echo.address.port()
        ))],
        true,
    );
    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &config,
    )
    .await
    .expect("connect PTY client with forwarding");
    let channel = client
        .request_interactive_shell("xterm", 80, 24)
        .await
        .expect("open interactive channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("request PTY");
    channel
        .request_shell(true)
        .await
        .expect("request interactive shell");

    let mut forwarded = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
        .await
        .expect("connect PTY-owned local forward");
    echo_round_trip(&mut forwarded, b"pty-forward-one").await;
    sleep(Duration::from_millis(25)).await;
    echo_round_trip(&mut forwarded, b"pty-forward-two").await;

    client.disconnect().await.expect("disconnect PTY client");
    assert_stream_closed(forwarded).await;
    assert_listener_released(local_port).await;
    assert!(ssh.state.events().iter().any(|event| event == "shell"));

    echo.shutdown().await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn high_level_command_paths_disconnect_and_release_forwarding() {
    let ssh = TestSshServer::start().await;
    let echo = EchoServer::start().await;
    let password = Arc::new(Password::new("test".to_string()).expect("test SSH password"));

    let normal_port = unused_port().await;
    let normal_connection = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{normal_port}:127.0.0.1:{}",
            echo.address.port()
        ))],
        true,
    );
    let normal_config = command_config(&normal_connection, Arc::clone(&password));
    let mut normal_client = high_level_client(ssh.address);
    normal_client
        .connect_and_execute_with_jump_hosts("true", &normal_config)
        .await
        .expect("normal command execution");
    assert_listener_released(normal_port).await;

    let streaming_port = unused_port().await;
    let streaming_connection = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{streaming_port}:127.0.0.1:{}",
            echo.address.port()
        ))],
        true,
    );
    let streaming_config = command_config(&streaming_connection, Arc::clone(&password));
    let mut streaming_client = high_level_client(ssh.address);
    let (output_tx, _output_rx) = tokio::sync::mpsc::channel(4);
    streaming_client
        .connect_and_execute_with_output_streaming("true", &streaming_config, output_tx)
        .await
        .expect("streaming command execution");
    assert_listener_released(streaming_port).await;

    let sudo_port = unused_port().await;
    let sudo_connection = connection_config(
        vec![ForwardingDirective::Local(format!(
            "{sudo_port}:127.0.0.1:{}",
            echo.address.port()
        ))],
        true,
    );
    let sudo_config = command_config(&sudo_connection, password);
    let mut sudo_client = high_level_client(ssh.address);
    let sudo_password = SudoPassword::new("sudo".to_string()).expect("test sudo password");
    let (sudo_tx, _sudo_rx) = tokio::sync::mpsc::channel(4);
    sudo_client
        .connect_and_execute_with_sudo("true", &sudo_config, sudo_tx, &sudo_password)
        .await
        .expect("sudo command execution");
    assert_listener_released(sudo_port).await;

    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 3);
    echo.shutdown().await;
    ssh.shutdown().await;
}

fn high_level_client(address: SocketAddr) -> SshClient {
    SshClient::new(address.ip().to_string(), address.port(), "test".to_string())
}

fn command_config<'a>(
    connection: &'a SshConnectionConfig,
    password: Arc<Password>,
) -> ConnectionConfig<'a> {
    ConnectionConfig {
        key_path: None,
        strict_mode: Some(StrictHostKeyChecking::No),
        use_agent: false,
        use_password: true,
        #[cfg(target_os = "macos")]
        use_keychain: false,
        timeout_seconds: Some(5),
        connect_timeout_seconds: Some(5),
        jump_hosts_spec: None,
        ssh_connection_config: Some(connection),
        ssh_connection_config_resolver: None,
        session_policy: None,
        ssh_password: Some(password),
    }
}
