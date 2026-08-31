use std::net::{Ipv4Addr, SocketAddr};
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
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ServerState {
    authentications: AtomicUsize,
    sessions: AtomicUsize,
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
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.state.authentications.fetch_add(1, Ordering::SeqCst);
        Ok(server::Auth::Accept)
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
        if data == b"slow" {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
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
