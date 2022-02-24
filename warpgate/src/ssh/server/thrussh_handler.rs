use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;

use bytes::BytesMut;
use futures::future::{ready, Ready};
use futures::FutureExt;
use tracing::*;
use thrussh::server::{Auth, Session};
use thrussh::{ChannelId, Pty};
use tokio::sync::Mutex;
use warpgate_common::SessionId;

use super::super::common::{PtyRequest, ServerChannelId};
use super::session::ServerSession;

pub struct ServerHandler {
    pub id: SessionId,
    pub client: Arc<Mutex<ServerSession>>,
}

impl thrussh::server::Handler for ServerHandler {
    type Error = anyhow::Error;
    type FutureAuth =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Auth)>> + Send>>;
    type FutureUnit =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session)>> + Send>>;
    type FutureBool = Ready<anyhow::Result<(Self, Session, bool)>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        println!("Finished auth {:?}", auth);
        async { Ok((self, auth)) }.boxed()
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        ready(Ok((self, s, b)))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        async { Ok((self, s)) }.boxed()
    }

    fn channel_open_session(self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_open_session(ServerChannelId(channel), &mut session)
                .await?;
            Ok((self, session))
        }
        .boxed()
    }

    fn subsystem_request(
        self,
        channel: ChannelId,
        name: &str,
        session: Session,
    ) -> Self::FutureUnit {
        let name = name.to_string();
        async move {
            self.client
                .lock()
                .await
                ._channel_subsystem_request(ServerChannelId(channel), name)
                .await;
            Ok((self, session))
        }
        .boxed()
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
        let term = term.to_string();
        let modes = modes.to_vec();
        async move {
            self.client
                .lock()
                .await
                ._channel_pty_request(
                    ServerChannelId(channel),
                    PtyRequest {
                        term,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        modes,
                    },
                )
                .await?;
            Ok((self, session))
        }
        .boxed()
    }

    fn shell_request(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_shell_request(ServerChannelId(channel))
                .await?;
            Ok((self, session))
        }
        .boxed()
    }

    fn auth_publickey(self, user: &str, key: &thrussh_keys::key::PublicKey) -> Self::FutureAuth {
        let user = user.to_string();
        let key = key.clone();
        async move {
            let result = self.client.lock().await._auth_publickey(user, &key).await;
            Ok((self, result))
        }
        .boxed()
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        println!("Auth {:?} with pw {:?}", user, password);
        async { Ok((self, Auth::Accept)) }.boxed()
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        async move {
            self.client
                .lock()
                .await
                ._data(ServerChannelId(channel), data)
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn extended_data(
        self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        async move {
            self.client
                .lock()
                .await
                ._extended_data(ServerChannelId(channel), code, data)
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_close(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_close(ServerChannelId(channel))
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._window_change_request(
                    ServerChannelId(channel),
                    PtyRequest {
                        term: "".to_string(),
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        modes: vec![],
                    },
                )
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_eof(
                    ServerChannelId(channel),
                )
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn signal(self, channel: ChannelId, signal_name: thrussh::Sig, session: Session) -> Self::FutureUnit {
        async move {
            self.client
                .lock()
                .await
                ._channel_signal(
                    ServerChannelId(channel),
                    signal_name,
                )
                .await;
            Ok((self, session))
        }
        .boxed()
    }

    fn exec_request(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        async move {
            self.client
                .lock()
                .await
                ._channel_exec_request(ServerChannelId(channel), data.freeze())
                .await?;
            Ok((self, session))
        }
        .boxed()
    }



    // -----

    // fn auth_none(self, user: &str) -> Self::FutureAuth {
    //     self.finished_auth(Auth::Reject)
    // }

    // fn auth_keyboard_interactive(
    //     self,
    //     user: &str,
    //     submethods: &str,
    //     response: Option<thrussh::server::Response>,
    // ) -> Self::FutureAuth {
    //     self.finished_auth(Auth::Reject)
    // }

    // fn channel_open_x11(
    //     self,
    //     channel: ChannelId,
    //     originator_address: &str,
    //     originator_port: u32,
    //     session: Session,
    // ) -> Self::FutureUnit {
    //     self.finished(session)
    // }

    // fn channel_open_direct_tcpip(
    //     self,
    //     channel: ChannelId,
    //     host_to_connect: &str,
    //     port_to_connect: u32,
    //     originator_address: &str,
    //     originator_port: u32,
    //     session: Session,
    // ) -> Self::FutureUnit {
    //     self.finished(session)
    // }

    // fn x11_request(
    //     self,
    //     channel: ChannelId,
    //     single_conection: bool,
    //     x11_auth_protocol: &str,
    //     x11_auth_cookie: &str,
    //     x11_screen_number: u32,
    //     session: Session,
    // ) -> Self::FutureUnit {
    //     self.finished(session)
    // }

    // fn env_request(
    //     self,
    //     channel: ChannelId,
    //     variable_name: &str,
    //     variable_value: &str,
    //     session: Session,
    // ) -> Self::FutureUnit {
    //     self.finished(session)
    // }
    // fn tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
    //     self.finished_bool(false, session)
    // }

    // fn cancel_tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
    //     self.finished_bool(false, session)
    // }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        debug!("Dropped");
        let client = self.client.clone();
        tokio::task::Builder::new().name(
            &format!("SSH S{} cleanup", self.id)
        ).spawn(async move {
            client.lock().await._disconnect().await;
        });
    }
}

impl Debug for ServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerHandler")
    }
}
