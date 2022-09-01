use std::fmt::Debug;
use std::pin::Pin;

use bytes::Bytes;
use futures::FutureExt;
use russh::server::{Auth, Handle, Session};
use russh::{ChannelId, Pty, Sig};
use russh_keys::key::PublicKey;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::*;
use warpgate_common::{Secret, SessionId};

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
    SubsystemRequest(ServerChannelId, String, oneshot::Sender<()>),
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
    ChannelClose(ServerChannelId, oneshot::Sender<()>),
    ChannelEof(ServerChannelId, oneshot::Sender<()>),
    WindowChangeRequest(ServerChannelId, PtyRequest, oneshot::Sender<()>),
    Signal(ServerChannelId, Sig, oneshot::Sender<()>),
    ExecRequest(ServerChannelId, Bytes, oneshot::Sender<()>),
    ChannelOpenDirectTcpIp(ServerChannelId, DirectTCPIPParams, oneshot::Sender<bool>),
    EnvRequest(ServerChannelId, String, String, oneshot::Sender<()>),
    X11Request(ServerChannelId, X11Request, oneshot::Sender<()>),
    Disconnect,
}

pub struct ServerHandler {
    pub id: SessionId,
    pub event_tx: UnboundedSender<ServerHandlerEvent>,
}

#[derive(thiserror::Error, Debug)]
pub enum ServerHandlerError {
    #[error("channel disconnected")]
    ChannelSend,
}

impl ServerHandler {
    fn send_event(&self, event: ServerHandlerEvent) -> Result<(), ServerHandlerError> {
        self.event_tx
            .send(event)
            .map_err(|_| ServerHandlerError::ChannelSend)
    }
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
            self.send_event(ServerHandlerEvent::Authenticated(HandleWrapper(handle)))?;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureBool {
        async move {
            let (tx, rx) = oneshot::channel();

            self.send_event(ServerHandlerEvent::ChannelOpenSession(
                ServerChannelId(channel),
                tx,
            ))?;

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
            let (tx, rx) = oneshot::channel();

            self.send_event(ServerHandlerEvent::SubsystemRequest(
                ServerChannelId(channel),
                name,
                tx,
            ))?;

            let _ = rx.await;
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

            self.send_event(ServerHandlerEvent::PtyRequest(
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
            ))?;

            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn shell_request(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        async move {
            let (tx, rx) = oneshot::channel();

            self.send_event(ServerHandlerEvent::ShellRequest(
                ServerChannelId(channel),
                tx,
            ))?;

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

            self.send_event(ServerHandlerEvent::AuthPublicKey(user, key, tx))?;

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

            self.send_event(ServerHandlerEvent::AuthPassword(user, password, tx))?;

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

            self.send_event(ServerHandlerEvent::AuthKeyboardInteractive(
                user, response, tx,
            ))?;

            let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
            Ok((self, result))
        }
        .boxed()
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let channel = ServerChannelId(channel);
        let data = Bytes::from(data.to_vec());

        async move {
            let (tx, rx) = oneshot::channel();

            self.send_event(ServerHandlerEvent::Data(channel, data, tx))?;

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
        let data = Bytes::from(data.to_vec());
        async move {
            let (tx, rx) = oneshot::channel();

            self.send_event(ServerHandlerEvent::ExtendedData(channel, data, code, tx))?;
            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_close(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        let channel = ServerChannelId(channel);
        async move {
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::ChannelClose(channel, tx))?;
            let _ = rx.await;
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
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::WindowChangeRequest(
                ServerChannelId(channel),
                PtyRequest {
                    term: "".to_string(),
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    modes: vec![],
                },
                tx,
            ))?;
            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        let channel = ServerChannelId(channel);
        async move {
            let (tx, rx) = oneshot::channel();

            self.event_tx
                .send(ServerHandlerEvent::ChannelEof(channel, tx))
                .map_err(|_| ServerHandlerError::ChannelSend)?;

            let _ = rx.await;
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
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::Signal(
                ServerChannelId(channel),
                signal_name,
                tx,
            ))?;
            let _ = rx.await;
            Ok((self, session))
        }
        .boxed()
    }

    fn exec_request(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = Bytes::from(data.to_vec());
        async move {
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::ExecRequest(
                ServerChannelId(channel),
                data,
                tx,
            ))?;
            let _ = rx.await;
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
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::EnvRequest(
                ServerChannelId(channel),
                variable_name,
                variable_value,
                tx,
            ))?;
            let _ = rx.await;
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
        session: Session,
    ) -> Self::FutureBool {
        let host_to_connect = host_to_connect.to_string();
        let originator_address = originator_address.to_string();
        async move {
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::ChannelOpenDirectTcpIp(
                ServerChannelId(channel),
                DirectTCPIPParams {
                    host_to_connect,
                    port_to_connect,
                    originator_address,
                    originator_port,
                },
                tx,
            ))?;
            let allowed = rx.await.unwrap_or(false);
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
            let (tx, rx) = oneshot::channel();
            self.send_event(ServerHandlerEvent::X11Request(
                ServerChannelId(channel),
                X11Request {
                    single_conection,
                    x11_auth_protocol,
                    x11_auth_cookie,
                    x11_screen_number,
                },
                tx,
            ))?;
            let _ = rx.await;
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
