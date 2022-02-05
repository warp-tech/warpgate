use std::pin::Pin;
use std::sync::Arc;

use bytes::BytesMut;
use futures::FutureExt;
use futures::future::{ready, Ready};
use thrussh::ChannelId;
use thrussh::server::{Auth, Session};
use tokio::sync::Mutex;

use crate::server_client::ServerClient;


pub struct ServerHandler {
    pub client: Arc<Mutex<ServerClient>>,
}

impl ServerHandler {
    pub async fn _data(
        self,
        channel: ChannelId,
        data: BytesMut,
        mut session: Session,
    ) -> anyhow::Result<(Self, Session)> {
        self.client
            .lock()
            .await
            ._data(channel, data, &mut session)
            .await;
        Ok((self, session))
    }

    pub async fn _finished(self, s: Session) -> anyhow::Result<(ServerHandler, Session)> {
        Ok((self, s))
    }

    pub async fn _channel_open_session(
        self,
        channel: ChannelId,
        mut session: Session,
    ) -> anyhow::Result<(ServerHandler, Session)> {
        self.client
            .lock()
            .await
            ._channel_open_session(channel, &mut session)
            .await;
        Ok((self, session))
    }
}

impl thrussh::server::Handler for ServerHandler {
    type Error = anyhow::Error;
    type FutureAuth = Ready<anyhow::Result<(Self, thrussh::server::Auth)>>;
    type FutureUnit = Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session)>> + Send>>;
    type FutureBool = Ready<anyhow::Result<(Self, Session, bool)>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        println!("Finished auth {:?}", auth);
        ready(Ok((self, auth)))
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        ready(Ok((self, s, b)))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        self._finished(s).boxed()
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self._channel_open_session(channel, session).boxed()
    }

    fn auth_publickey(self, user: &str, key: &thrussh_keys::key::PublicKey) -> Self::FutureAuth {
        println!("Auth {:?} with key {:?}", user, key);
        self.finished_auth(Auth::Accept)
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        println!("Auth {:?} with pw {:?}", user, password);
        self.finished_auth(Auth::Accept)
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        self._data(channel, data, session).boxed()
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        println!("Server handler dropped");
    }
}
