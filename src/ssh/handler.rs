use thrussh::ChannelId;
use thrussh::client::{Session, Handler};
use thrussh_keys::key::PublicKey;

#[derive(Clone)]
pub struct BsshHandler {
    pub host: String,
}

impl BsshHandler {
    pub fn new(host: String) -> Self {
        Self { host }
    }
}

impl Handler for BsshHandler {
    type Error = anyhow::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), anyhow::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }

    fn check_server_key(self, _server_public_key: &PublicKey) -> Self::FutureBool {
        // TODO: Implement proper host key verification
        // For now, accept all keys (NOT SECURE - only for development)
        self.finished_bool(true)
    }

    fn channel_open_confirmation(
        self,
        _id: ChannelId,
        _max_packet_size: u32,
        _window_size: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn data(
        self,
        _channel: ChannelId,
        _data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn extended_data(
        self,
        _channel: ChannelId,
        _ext: u32,
        _data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn exit_status(
        self,
        _channel: ChannelId,
        _exit_status: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn channel_eof(
        self,
        _channel: ChannelId,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn channel_close(
        self,
        _channel: ChannelId,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }
}