use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use bssh::forwarding::ForwardingDirective;
use bssh::ssh::control::{
    AttachOutcome, ControlCommand, ControlPersist, ControlResponseKind, SessionOpenRequest,
    attach_session, send_control_command, start_control_master,
};
use bssh::ssh::tokio_client::{
    AddressFamily, AuthMethod, Client, ServerCheckMethod, SshConnectionConfig,
};
use bssh::ssh::{SessionPolicy, SessionRequest};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Msg, Server, Session};
use russh::{Channel, ChannelId};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ServerState {
    authentications: AtomicUsize,
    sessions: AtomicUsize,
    commands_completed: AtomicUsize,
    release_blocked_command: Notify,
}

#[derive(Clone)]
struct MultiplexTestServer {
    state: Arc<ServerState>,
}

impl Server for MultiplexTestServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl server::Handler for MultiplexTestServer {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        _user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.state.authentications.fetch_add(1, Ordering::SeqCst);
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
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.sessions.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, data.to_vec())?;
        if data == b"blocked" {
            self.state.release_blocked_command.notified().await;
        } else if data == b"slow" {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        self.state.commands_completed.fetch_add(1, Ordering::SeqCst);
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
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
        let mut server = MultiplexTestServer {
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

fn session(command: &str) -> (SessionPolicy, SessionOpenRequest) {
    let policy = SessionPolicy {
        environment: Vec::new(),
        local_command: None,
        forward_agent: false,
        request_pty: false,
        stdin_null: true,
        request: SessionRequest::Exec(command.to_string()),
    };
    let request = SessionOpenRequest::new(policy.clone(), None).expect("wire-safe session");
    (policy, request)
}

#[tokio::test]
async fn two_passengers_share_exactly_one_authenticated_transport() {
    let ssh = RunningSshServer::start().await;
    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &SshConnectionConfig::default(),
    )
    .await
    .expect("authenticate control master");
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);

    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("mux");
    let master = start_control_master(&path, client, false).expect("start control master");

    for command in ["first", "second"] {
        let (policy, request) = session(command);
        let outcome = timeout(TEST_TIMEOUT, attach_session(&path, request, &policy))
            .await
            .expect("passenger timed out")
            .expect("passenger failed");
        assert_eq!(outcome, AttachOutcome::ExitStatus(0));
    }
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    assert_eq!(ssh.state.sessions.load(Ordering::SeqCst), 2);

    let check = send_control_command(&path, ControlCommand::Check, Vec::new(), AddressFamily::Any)
        .await
        .expect("check control master");
    assert!(matches!(check, ControlResponseKind::Alive { .. }));

    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("reserve local forwarding port");
    let forwarding_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let directive = ForwardingDirective::Local(format!("127.0.0.1:{forwarding_port}:127.0.0.1:1"));
    let forward = send_control_command(
        &path,
        ControlCommand::Forward,
        vec![directive.clone()],
        AddressFamily::V4,
    )
    .await
    .expect("add control forwarding");
    assert_eq!(forward, ControlResponseKind::Ok);
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, forwarding_port))
            .await
            .is_err(),
        "forward command must not reply before its listener is ready"
    );
    let cancel = send_control_command(
        &path,
        ControlCommand::Cancel,
        vec![directive],
        AddressFamily::V4,
    )
    .await
    .expect("cancel control forwarding");
    assert_eq!(cancel, ControlResponseKind::Ok);
    TcpListener::bind((Ipv4Addr::LOCALHOST, forwarding_port))
        .await
        .expect("cancel command must release its listener before replying");

    let (slow_policy, slow_request) = session("slow");
    let slow_path = path.clone();
    let passenger =
        tokio::spawn(async move { attach_session(&slow_path, slow_request, &slow_policy).await });
    timeout(TEST_TIMEOUT, async {
        while ssh.state.sessions.load(Ordering::SeqCst) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("slow passenger did not open");

    send_control_command(&path, ControlCommand::Stop, Vec::new(), AddressFamily::Any)
        .await
        .expect("stop control master");
    timeout(Duration::from_millis(100), async {
        while path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stop did not unlink the listener promptly");
    assert!(
        !passenger.is_finished(),
        "stop must not cancel an active passenger"
    );
    assert_eq!(
        passenger.await.unwrap().unwrap(),
        AttachOutcome::ExitStatus(0)
    );
    timeout(
        TEST_TIMEOUT,
        master.finish_after_initial(ControlPersist::Forever, true),
    )
    .await
    .expect("master stop timed out")
    .expect("master stop failed");
    ssh.shutdown().await;
}

#[tokio::test]
async fn exit_immediately_cancels_active_passengers() {
    let ssh = RunningSshServer::start().await;
    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &SshConnectionConfig::default(),
    )
    .await
    .expect("authenticate control master");
    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("mux-exit");
    let master = start_control_master(&path, client, false).expect("start control master");
    let (policy, request) = session("slow");
    let passenger_path = path.clone();
    let passenger =
        tokio::spawn(async move { attach_session(&passenger_path, request, &policy).await });
    timeout(TEST_TIMEOUT, async {
        while ssh.state.sessions.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("slow passenger did not open");

    send_control_command(&path, ControlCommand::Exit, Vec::new(), AddressFamily::Any)
        .await
        .expect("exit control master");
    timeout(
        TEST_TIMEOUT,
        master.finish_after_initial(ControlPersist::Forever, true),
    )
    .await
    .expect("master exit timed out")
    .expect("master exit failed");
    assert!(!path.exists());
    assert!(
        passenger.await.unwrap().is_err(),
        "exit must cancel an active passenger"
    );
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    ssh.shutdown().await;
}

#[tokio::test]
async fn control_persist_timeout_resets_after_a_new_passenger() {
    let ssh = RunningSshServer::start().await;
    let client = Client::connect_with_ssh_config(
        ssh.address,
        "test",
        AuthMethod::with_password("test"),
        ServerCheckMethod::NoCheck,
        &SshConnectionConfig::default(),
    )
    .await
    .expect("authenticate control master");
    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("mux-persist");
    let master = start_control_master(&path, client, false).expect("start control master");
    let finish = tokio::spawn(
        master.finish_after_initial(ControlPersist::Timeout(Duration::from_millis(150)), false),
    );

    tokio::time::sleep(Duration::from_millis(90)).await;
    let (policy, request) = session("reset");
    assert_eq!(
        attach_session(&path, request, &policy).await.unwrap(),
        AttachOutcome::ExitStatus(0)
    );
    tokio::time::sleep(Duration::from_millis(90)).await;
    assert!(
        !finish.is_finished(),
        "a passenger must reset the idle timeout"
    );
    timeout(TEST_TIMEOUT, finish)
        .await
        .expect("persist timeout did not expire")
        .expect("persist task failed")
        .expect("persist shutdown failed");
    assert!(!path.exists());
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    ssh.shutdown().await;
}

async fn run_bssh_background(
    ssh: &RunningSshServer,
    control_path: Option<&Path>,
    password: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let isolated_home = TempDir::new().expect("isolated bssh home");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_bssh"));
    command
        .arg("--password")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-p")
        .arg(ssh.address.port().to_string())
        .args(extra_args);
    if let Some(path) = control_path {
        command.arg("-M").arg("-S").arg(path);
    }
    command
        .arg("test@127.0.0.1")
        .env("BSSH_PASSWORD", password)
        .env("HOME", isolated_home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bssh subprocess timed out")
        .expect("run bssh subprocess")
}

async fn run_bssh_existing_master_passenger(
    ssh: &RunningSshServer,
    control_path: &Path,
) -> std::process::Output {
    let isolated_home = TempDir::new().expect("isolated bssh passenger home");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_bssh"));
    command
        .arg("--password")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-p")
        .arg(ssh.address.port().to_string())
        .arg("-f")
        .arg("-S")
        .arg(control_path)
        .arg("test@127.0.0.1")
        .arg("blocked")
        // A fallback direct connection would fail, which also proves that the
        // passenger reused the master's authenticated transport.
        .env("BSSH_PASSWORD", "wrong")
        .env("HOME", isolated_home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bssh passenger subprocess timed out")
        .expect("run bssh passenger subprocess")
}

async fn run_bssh_direct_background_command(ssh: &RunningSshServer) -> std::process::Output {
    let isolated_home = TempDir::new().expect("isolated direct bssh home");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_bssh"));
    command
        .arg("--password")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-p")
        .arg(ssh.address.port().to_string())
        .arg("-f")
        .arg("test@127.0.0.1")
        .arg("blocked")
        .env("BSSH_PASSWORD", "test")
        .env("HOME", isolated_home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    timeout(Duration::from_secs(10), command.output())
        .await
        .expect("direct bssh subprocess timed out")
        .expect("run direct bssh subprocess")
}

async fn stop_background_master(path: &Path) {
    send_control_command(path, ControlCommand::Exit, Vec::new(), AddressFamily::Any)
        .await
        .expect("stop subprocess control master");
    timeout(TEST_TIMEOUT, async {
        while path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("background control socket was not removed");
}

#[tokio::test]
async fn fork_after_authentication_returns_only_after_one_ready_authentication() {
    let ssh = RunningSshServer::start().await;
    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("fork-after-auth");
    let output = run_bssh_background(
        &ssh,
        Some(&path),
        "test",
        &["-f", "-N", "-o", "ControlPersist=no"],
    )
    .await;
    assert!(
        output.status.success(),
        "-f failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(path.exists(), "-f returned before ControlPath was ready");
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    assert_eq!(ssh.state.sessions.load(Ordering::SeqCst), 0);

    stop_background_master(&path).await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn fork_after_authentication_detaches_direct_session_after_authentication() {
    let ssh = RunningSshServer::start().await;
    let output = run_bssh_direct_background_command(&ssh).await;
    assert!(
        output.status.success(),
        "direct -f failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    timeout(TEST_TIMEOUT, async {
        while ssh.state.sessions.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached direct command never opened its remote session");
    assert_eq!(ssh.state.commands_completed.load(Ordering::SeqCst), 0);

    ssh.state.release_blocked_command.notify_one();
    timeout(TEST_TIMEOUT, async {
        while ssh.state.commands_completed.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached direct command did not finish");
    ssh.shutdown().await;
}

#[tokio::test]
async fn fork_after_authentication_prepares_existing_master_session_before_detaching() {
    let ssh = RunningSshServer::start().await;
    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("fork-existing-master");
    let master = run_bssh_background(
        &ssh,
        Some(&path),
        "test",
        &["-f", "-N", "-o", "ControlPersist=no"],
    )
    .await;
    assert!(
        master.status.success(),
        "master setup failed: {}",
        String::from_utf8_lossy(&master.stderr)
    );

    let passenger = run_bssh_existing_master_passenger(&ssh, &path).await;
    assert!(
        passenger.status.success(),
        "existing-master -f failed: {}",
        String::from_utf8_lossy(&passenger.stderr)
    );
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    timeout(TEST_TIMEOUT, async {
        while ssh.state.sessions.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("prepared passenger never opened its remote session");
    assert_eq!(ssh.state.commands_completed.load(Ordering::SeqCst), 0);

    ssh.state.release_blocked_command.notify_one();
    timeout(TEST_TIMEOUT, async {
        while ssh.state.commands_completed.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached passenger did not finish its remote command");
    stop_background_master(&path).await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn control_persist_detaches_master_but_keeps_initial_exit_status_and_one_authentication() {
    let ssh = RunningSshServer::start().await;
    let directory = TempDir::new().expect("control tempdir");
    let path = directory.path().join("implicit-persist");
    let output = run_bssh_background(
        &ssh,
        Some(&path),
        "test",
        &["-M", "-N", "-o", "ControlPersist=yes"],
    )
    .await;
    assert!(
        output.status.success(),
        "ControlPersist failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        path.exists(),
        "persistent master did not remain in background"
    );
    assert_eq!(ssh.state.authentications.load(Ordering::SeqCst), 1);
    assert_eq!(ssh.state.sessions.load(Ordering::SeqCst), 0);

    stop_background_master(&path).await;
    ssh.shutdown().await;
}

#[tokio::test]
async fn fork_after_authentication_reports_bad_auth_in_foreground() {
    let ssh = RunningSshServer::start().await;
    let output = run_bssh_background(&ssh, None, "wrong", &["-f", "-N"]).await;
    assert_eq!(output.status.code(), Some(255));
    assert!(
        !output.stderr.is_empty(),
        "authentication failure should remain visible before detach"
    );
    ssh.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn no_remote_command_keeps_transport_until_ctrl_c_without_opening_a_session() {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    use std::os::unix::process::CommandExt as _;

    let ssh = RunningSshServer::start().await;
    let isolated_home = TempDir::new().expect("isolated bssh home");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_bssh"));
    command
        .arg("--password")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-p")
        .arg(ssh.address.port().to_string())
        .arg("-N")
        .arg("test@127.0.0.1")
        .env("BSSH_PASSWORD", "test")
        .env("HOME", isolated_home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().expect("spawn foreground -N");
    let child_pid = child.id().expect("foreground -N pid");

    timeout(TEST_TIMEOUT, async {
        while ssh.state.authentications.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("foreground -N did not authenticate");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        child.try_wait().expect("inspect foreground -N").is_none(),
        "-N must keep the authenticated transport alive"
    );
    assert_eq!(ssh.state.sessions.load(Ordering::SeqCst), 0);

    killpg(
        Pid::from_raw(i32::try_from(child_pid).expect("pid fits i32")),
        Signal::SIGINT,
    )
    .expect("interrupt foreground -N process group");
    timeout(TEST_TIMEOUT, child.wait())
        .await
        .expect("foreground -N did not exit after Ctrl-C")
        .expect("wait for foreground -N");
    ssh.shutdown().await;
}
