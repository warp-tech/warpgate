use std::pin::Pin;
use std::sync::Arc;

use bytes::BytesMut;
use futures::FutureExt;
use futures::future::{ready, Ready};
use thrussh::{ChannelId, Pty};
use thrussh::server::{Auth, Session};
use tokio::sync::Mutex;

use crate::server_client::ServerClient;


pub struct ServerHandler {
    pub client: Arc<Mutex<ServerClient>>,
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
        async {
            Ok((self, s))
        }.boxed()
    }

    fn channel_open_session(self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_open_session(channel, &mut session)
                .await?;
            Ok((self, session))
        }.boxed()
    }

    fn auth_publickey(self, user: &str, key: &thrussh_keys::key::PublicKey) -> Self::FutureAuth {
        println!("Auth {:?} with key {:?}", user, key);
        self.finished_auth(Auth::Accept)
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        println!("Auth {:?} with pw {:?}", user, password);
        self.finished_auth(Auth::Accept)
    }

    fn pty_request(
        self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        async move {
            self.client
                .lock()
                .await
                ._data(channel, data, &mut session)
                .await;
            Ok((self, session))
        }.boxed()
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        println!("Server handler dropped");
    }
}
