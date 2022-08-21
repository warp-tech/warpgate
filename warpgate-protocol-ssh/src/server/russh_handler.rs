use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{BytesMut, Bytes};
use futures::FutureExt;
use russh::server::{Auth, Handle, Session};
use russh::{ChannelId, Pty};
use russh_keys::key::PublicKey;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{oneshot, Mutex};
use tracing::*;
use warpgate_common::{Secret, SessionId};

use super::session::ServerSession;
use crate::common::{PtyRequest, ServerChannelId};
use crate::{DirectTCPIPParams, X11Request};

pub struct HandleWrapper(pub Handle);

impl Debug for HandleWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HandleWrapper")
    }
}

#[derive(Debug)]
pub enum ServerHandlerEvent {
    Authenticated(HandleWrapper),
    ChannelOpenSession(ServerChannelId, oneshot::Sender<bool>),
    PtyRequest(ServerChannelId, PtyRequest, oneshot::Sender<()>),
    ShellRequest(ServerChannelId, oneshot::Sender<()>),
    AuthPublicKey(Secret<String>, PublicKey, oneshot::Sender<Auth>),
    AuthPassword(Secret<String>, Secret<String>, oneshot::Sender<Auth>),
    AuthKeyboardInteractive(
        Secret<String>,
        Option<Secret<String>>,
        oneshot::Sender<Auth>,
    ),
    Data(ServerChannelId, Bytes, oneshot::Sender<()>),
    ExtendedData(ServerChannelId, Bytes, u32, oneshot::Sender<()>),
    Disconnect,
}

pub struct ServerHandler {
    pub id: SessionId,
    pub session: Arc<Mutex<ServerSession>>,
    pub event_tx: UnboundedSender<ServerHandlerEvent>,
}

#[derive(thiserror::Error, Debug)]
pub enum ServerHandlerError {
    #[error("channel disconnected")]
    ChannelSend,
}

impl russh::server::Handler for ServerHandler {
    type Error = anyhow::Error;
    type FutureAuth =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Auth)>> + Send>>;
    type FutureUnit =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session)>> + Send>>;
    type FutureBool =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session, bool)>> + Send>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        async { Ok((self, auth)) }.boxed()
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        async move { Ok((self, s, b)) }.boxed()
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        async { Ok((self, s)) }.boxed()
    }

    fn auth_succeeded(self, session: Session) -> Self::FutureUnit {
        let handle = session.handle();
        async {
            self.event_tx
                .send(ServerHandlerEvent::Authenticated(HandleWrapper(handle)))
                .map_err(|_| ServerHandlerError::ChannelSend)?;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureBool {
        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::ChannelOpenSession(
                    ServerChannelId(channel),
                    tx,
                ))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let allowed = rx.await.unwrap_or(false);
            Ok((self, session, allowed))
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
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_subsystem_request(ServerChannelId(channel), name)
                    .instrument(span)
                    .await?;
            }
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
        let modes = modes
            .iter()
            .take_while(|x| (x.0 as u8) > 0 && (x.0 as u8) < 160)
            .map(Clone::clone)
            .collect();

        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::PtyRequest(
                    ServerChannelId(channel),
                    PtyRequest {
                        term,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        modes,
                    },
                    tx,
                ))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn shell_request(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::ShellRequest(
                    ServerChannelId(channel),
                    tx,
                ))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn auth_publickey(self, user: &str, key: &russh_keys::key::PublicKey) -> Self::FutureAuth {
        let user = Secret::new(user.to_string());
        let key = key.clone();

        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::AuthPublicKey(user, key, tx))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
            Ok((self, result))
        }
        .boxed()
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        let user = Secret::new(user.to_string());
        let password = Secret::new(password.to_string());

        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::AuthPassword(user, password, tx))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
            Ok((self, result))
        }
        .boxed()
    }

    fn auth_keyboard_interactive(
        self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response>,
    ) -> Self::FutureAuth {
        let user = Secret::new(user.to_string());
        let response = response
            .and_then(|mut r| r.next())
            .and_then(|b| String::from_utf8(b.to_vec()).ok())
            .map(Secret::new);

        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::AuthKeyboardInteractive(
                    user, response, tx,
                ))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
            Ok((self, result))
        }
        .boxed()
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let channel = ServerChannelId(channel);
        let data = BytesMut::from(data).freeze();

        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::Data(channel, data, tx))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let _ = rx.await;
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
        let channel = ServerChannelId(channel);
        let data = BytesMut::from(data).freeze();
        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::ExtendedData(channel, data, code, tx))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_close(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_close(ServerChannelId(channel))
                    .instrument(span)
                    .await?;
            }
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
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
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
                    .instrument(span)
                    .await?;
            }
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_eof(ServerChannelId(channel))
                    .instrument(span)
                    .await?;
            }
            Ok((self, session))
        }
        .boxed()
    }

    fn signal(
        self,
        channel: ChannelId,
        signal_name: russh::Sig,
        session: Session,
    ) -> Self::FutureUnit {
        async move {
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_signal(ServerChannelId(channel), signal_name)
                    .instrument(span)
                    .await?;
            }
            Ok((self, session))
        }
        .boxed()
    }

    fn exec_request(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        async move {
            let reply = {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_exec_request_begin(ServerChannelId(channel), data.freeze())
                    .instrument(span)
                    .await?
            };

            // Break in ownership to allow event handling while session is started
            reply.await?;

            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_exec_request_finish(ServerChannelId(channel))
                    .instrument(span)
                    .await?
            };

            Ok((self, session))
        }
        .boxed()
    }

    fn env_request(
        self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: Session,
    ) -> Self::FutureUnit {
        let variable_name = variable_name.to_string();
        let variable_value = variable_value.to_string();
        async move {
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_env_request(ServerChannelId(channel), variable_name, variable_value)
                    .instrument(span)
                    .await?
            };
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_open_direct_tcpip(
        self,
        channel: ChannelId,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        mut session: Session,
    ) -> Self::FutureBool {
        let host_to_connect = host_to_connect.to_string();
        let originator_address = originator_address.to_string();
        async move {
            let allowed = {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_open_direct_tcpip(
                        ServerChannelId(channel),
                        DirectTCPIPParams {
                            host_to_connect,
                            port_to_connect,
                            originator_address,
                            originator_port,
                        },
                        &mut session,
                    )
                    .instrument(span)
                    .await?
            };
            Ok((self, session, allowed))
        }
        .boxed()
    }

    fn x11_request(
        self,
        channel: ChannelId,
        single_conection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: Session,
    ) -> Self::FutureUnit {
        let x11_auth_protocol = x11_auth_protocol.to_string();
        let x11_auth_cookie = x11_auth_cookie.to_string();
        async move {
            {
                let mut this_session = self.session.lock().await;
                let span = this_session.make_logging_span();
                this_session
                    ._channel_x11_request(
                        ServerChannelId(channel),
                        X11Request {
                            single_conection,
                            x11_auth_protocol,
                            x11_auth_cookie,
                            x11_screen_number,
                        },
                    )
                    .instrument(span)
                    .await?;
            }
            Ok((self, session))
        }
        .boxed()
    }

    // -----

    // fn auth_none(self, user: &str) -> Self::FutureAuth {
    //     self.finished_auth(Auth::Reject)
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
        let _ = self.event_tx.send(ServerHandlerEvent::Disconnect);
        // let client = self.session.clone();
        // tokio::task::Builder::new()
        //     .name(&format!("SSH {} cleanup", self.id))
        //     .spawn(async move {
        //         client.lock().await._disconnect().await;
        //     });
    }
}

impl Debug for ServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerHandler")
    }
}
