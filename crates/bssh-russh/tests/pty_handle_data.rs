//! Regression test for the BSSH PTY fix re-ported onto russh 0.61.1.
//!
//! The fork exists to fix one problem: shell/PTY output written via
//! `Handle::data()` / `Channel::data()` from a task *other than* the server
//! session loop could fail to be delivered promptly, because the loop's
//! `tokio::select!` didn't always wake for the internal mpsc channel. The fix
//! is the `try_recv` batch-drain loop in `src/server/session.rs` that flushes
//! pending channel messages before entering `select!`.
//!
//! This test drives a real client<->server pair over a TCP loopback and floods
//! a large number of data chunks from a task distinct from the session loop,
//! then asserts every byte arrives intact. If the drain path ever loses or
//! stalls messages, `wait_for` hits its deadline and the test fails.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::{self, PrivateKey};
use russh::server::{self, Auth, Session};
use russh::{ChannelId, client};

const CHUNK: usize = 1024;
const N_CHUNKS: usize = 2000;
const TOTAL: usize = CHUNK * N_CHUNKS;
const FILL: u8 = b'x';

/// Client handler: tallies received bytes and flags any byte that isn't `FILL`.
struct ClientH {
    received: Arc<AtomicUsize>,
    corrupt: Arc<AtomicUsize>,
}

impl client::Handler for ClientH {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if data.iter().any(|&b| b != FILL) {
            self.corrupt.fetch_add(1, Ordering::SeqCst);
        }
        self.received.fetch_add(data.len(), Ordering::SeqCst);
        Ok(())
    }
}

/// Server handler: accept any pubkey and signal once authentication finishes.
struct ServerH {
    auth_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl server::Handler for ServerH {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        if let Some(tx) = self.auth_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}

/// Poll `counter` until it reaches `target`, panicking after a generous deadline
/// (a stalled/lossy drain path manifests here as a timeout).
async fn wait_for(counter: &AtomicUsize, target: usize, label: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let cur = counter.load(Ordering::SeqCst);
        if cur >= target {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for {label}: {cur}/{target} bytes"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_throughput_handle_data_from_task_is_fully_delivered() {
    let _ = env_logger::try_init();

    let received = Arc::new(AtomicUsize::new(0));
    let corrupt = Arc::new(AtomicUsize::new(0));

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    let mut config = server::Config::default();
    config.inactivity_timeout = None;
    config.auth_rejection_time = Duration::from_secs(3);
    config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let config = Arc::new(config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();

    // Server side: accept the connection and run the session loop (detached).
    let server_join = tokio::spawn(async move {
        let (stream, _) = socket.accept().await.unwrap();
        server::run_stream(
            config,
            stream,
            ServerH {
                auth_tx: Some(auth_tx),
            },
        )
        .await
        .map_err(|_| ())
        .unwrap()
    });

    // Client side: connect + authenticate.
    let received_c = received.clone();
    let corrupt_c = corrupt.clone();
    let client_join = tokio::spawn(async move {
        let cfg = Arc::new(client::Config::default());
        let mut session = client::connect(
            cfg,
            addr,
            ClientH {
                received: received_c,
                corrupt: corrupt_c,
            },
        )
        .await
        .map_err(|_| ())
        .unwrap();
        let authed = session
            .authenticate_publickey(
                "user",
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .unwrap();
        assert!(authed.success(), "client authentication failed");
        session
    });

    let (server_session, client_session) = tokio::join!(server_join, client_join);
    // `RunningSession::handle()` keeps the detached session loop reachable; the
    // client `Handle` must stay alive so the connection isn't torn down.
    let handle = server_session.unwrap().handle();
    let _client = client_session.unwrap();

    // The whole exchange must finish well within this bound.
    tokio::time::timeout(Duration::from_secs(45), async {
        auth_rx.await.unwrap();

        // Flood data from a task that is NOT the session loop — the fork's bug
        // scenario. `Channel::data()` enqueues onto the session loop's mpsc; the
        // drain loop is what must deliver all of it.
        let received_s = received.clone();
        let flood = tokio::spawn(async move {
            let ch = handle.channel_open_session().await.unwrap();
            let chunk = vec![FILL; CHUNK];
            for _ in 0..N_CHUNKS {
                ch.data(&chunk[..]).await.unwrap();
            }
            // Hold the channel open until the client has accounted for everything.
            wait_for(&received_s, TOTAL, "server-side confirmation").await;
            ch
        });

        wait_for(&received, TOTAL, "client receive").await;
        let _ch = flood.await.unwrap();
    })
    .await
    .expect("PTY data exchange timed out — drain loop did not deliver all messages");

    assert_eq!(
        received.load(Ordering::SeqCst),
        TOTAL,
        "expected exactly {TOTAL} bytes delivered"
    );
    assert_eq!(
        corrupt.load(Ordering::SeqCst),
        0,
        "received corrupted/misordered chunk(s)"
    );

    drop(_client);
}
