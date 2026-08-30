#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use log::debug;
    use ssh_key::PrivateKey;
    use tokio::net::TcpListener;

    use crate::cert::PublicKeyOrCertificate;
    // Import client types directly since we're in the client module
    use crate::Error;
    use crate::client::{Config, Handler, connect};
    use crate::keys::PrivateKeyWithHashAlg;
    use crate::server::{self, Auth, Handler as ServerHandler, Server, Session};
    use crate::{ChannelId, SshId}; // Import directly from crate root
    use rand::rng;

    #[derive(Clone)]
    struct TestServer {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), server::Handle>>>,
        id: usize,
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl ServerHandler for TestServer {
        type Error = Error;

        async fn channel_open_session(
            &mut self,
            channel: crate::channels::Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            reply.accept().await;
            Ok(())
        }

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(Auth::Accept)
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server received data: {:?}", std::str::from_utf8(data));
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    struct Client {}

    impl Handler for Client {
        type Error = Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct CountingClient {
        kex_count: Arc<AtomicUsize>,
    }

    impl Handler for CountingClient {
        type Error = Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn kex_done(
            &mut self,
            _: Option<&[u8]>,
            _: &crate::negotiation::Names,
            _: &mut crate::client::Session,
        ) -> Result<(), Self::Error> {
            self.kex_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_client_connects_to_protocol_1_99() {
        let _ = env_logger::try_init();

        // Create a client key
        let client_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // Configure the server
        let mut config = server::Config::default();
        config.auth_rejection_time = std::time::Duration::from_secs(1);
        config.server_id = SshId::Standard("SSH-1.99-CustomServer_1.0".into());
        config.inactivity_timeout = None;
        config
            .keys
            .push(PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        // Create server struct
        let mut server = TestServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        // Start the TCP listener for our mock server
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Spawn a separate task that will handle the server connection
        tokio::spawn(async move {
            // Accept a connection
            let (socket, _) = socket.accept().await.unwrap();

            // Handle the connection with the server
            let server_handler = server.new_client(None);
            server::run_stream(config, socket, server_handler)
                .await
                .unwrap();
        });

        println!("Server listening on {addr}");

        // Configure the client
        let client_config = Arc::new(Config::default());

        // Connect to the server
        let mut session = connect(client_config, addr, Client {}).await.unwrap();

        // Unfortunately, we can't directly verify the protocol version from the client API
        // The Protocol199Stream wrapper ensures the server sends SSH-1.99-CustomServer_1.0
        // The test passing means the client accepted this protocol version

        // Try to authenticate
        let auth_result = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_string()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap();

        assert!(auth_result.success());

        // Try opening a session channel
        let mut channel = session.channel_open_session().await.unwrap();

        // Send some data
        let test_data = b"Hello, 1.99 protocol server!";
        channel.data(&test_data[..]).await.unwrap();

        // Wait for response
        let msg = channel.wait().await.unwrap();
        match msg {
            crate::channels::ChannelMsg::Data { data: msg_data } => {
                assert_eq!(test_data.as_slice(), &msg_data[..]);
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    }

    #[tokio::test]
    async fn automatic_rekey_repeated_bidirectional_transfers_complete() {
        let client_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap();

        let mut server_config = server::Config::default();
        server_config.auth_rejection_time = std::time::Duration::from_millis(1);
        server_config.inactivity_timeout = None;
        server_config.limits = crate::Limits::new(
            8 * 1024,
            8 * 1024,
            std::time::Duration::from_secs(3600),
        );
        server_config
            .keys
            .push(PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let server_config = Arc::new(server_config);

        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let server = TestServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };
        let server_task = tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let running = server::run_stream(server_config, socket, server)
                .await
                .unwrap();
            running.await
        });

        let mut client_config = Config::default();
        client_config.limits = crate::Limits::new(
            8 * 1024,
            8 * 1024,
            std::time::Duration::from_secs(3600),
        );
        let kex_count = Arc::new(AtomicUsize::new(0));

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let mut session = connect(
                Arc::new(client_config),
                addr,
                CountingClient {
                    kex_count: Arc::clone(&kex_count),
                },
            )
            .await
            .unwrap();
            let authenticated = session
                .authenticate_publickey(
                    "rekey-user",
                    PrivateKeyWithHashAlg::new(
                        Arc::new(client_key),
                        session.best_supported_rsa_hash().await.unwrap().flatten(),
                    ),
            )
            .await
            .unwrap();
            assert!(authenticated.success());
            let kex_count_before_transfer = kex_count.load(Ordering::Relaxed);

            let mut channel = session.channel_open_session().await.unwrap();
            for round in 0_u8..6 {
                let payload = vec![round; 32 * 1024];
                channel.data(&payload[..]).await.unwrap();
                let mut echoed = Vec::with_capacity(payload.len());
                while echoed.len() < payload.len() {
                    match channel.wait().await.unwrap() {
                        crate::channels::ChannelMsg::Data { data } => {
                            echoed.extend_from_slice(&data)
                        }
                        message => panic!("unexpected message during rekey transfer: {message:?}"),
                    }
                }
                assert!(echoed == payload, "echo mismatch in rekey round {round}");
            }

            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while kex_count.load(Ordering::Relaxed) < kex_count_before_transfer + 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("byte thresholds must complete repeated rekeys during transfer");
            assert!(
                kex_count.load(Ordering::Relaxed) >= kex_count_before_transfer + 2,
                "six threshold-crossing rounds must observe repeated key exchanges"
            );

            session
                .disconnect(crate::Disconnect::ByApplication, "test complete", "")
                .await
                .unwrap();
        })
        .await
        .expect("repeated bidirectional rekeys must not stall");

        tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
            .await
            .expect("server session must stop after client disconnect")
            .unwrap()
            .unwrap();
    }
}
