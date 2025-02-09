use std::fmt::Debug;

use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::*;
use warpgate_common::Secret;

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
    SubsystemRequest(ServerChannelId, String, oneshot::Sender<bool>),
    PtyRequest(ServerChannelId, PtyRequest, oneshot::Sender<()>),
    ShellRequest(ServerChannelId, oneshot::Sender<bool>),
    AuthPublicKey(Secret<String>, PublicKey, oneshot::Sender<Auth>),
    AuthPublicKeyOffer(Secret<String>, PublicKey, oneshot::Sender<Auth>),
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
    ExecRequest(ServerChannelId, Bytes, oneshot::Sender<bool>),
    ChannelOpenDirectTcpIp(ServerChannelId, DirectTCPIPParams, oneshot::Sender<bool>),
    EnvRequest(ServerChannelId, String, String, oneshot::Sender<()>),
    X11Request(ServerChannelId, X11Request, oneshot::Sender<()>),
    TcpIpForward(String, u32, oneshot::Sender<bool>),
    CancelTcpIpForward(String, u32, oneshot::Sender<bool>),
    StreamlocalForward(String, oneshot::Sender<bool>),
    CancelStreamlocalForward(String, oneshot::Sender<bool>),
    Disconnect,
}

pub struct ServerHandler {
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

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let handle = session.handle();
        self.send_event(ServerHandlerEvent::Authenticated(HandleWrapper(handle)))?;
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::ChannelOpenSession(
            ServerChannelId(channel.id()),
            tx,
        ))?;

        let allowed = rx.await.unwrap_or(false);
        Ok(allowed)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let name = name.to_string();
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::SubsystemRequest(
            ServerChannelId(channel),
            name,
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?
        } else {
            session.channel_failure(channel)?
        }

        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let term = term.to_string();
        let modes = modes
            .iter()
            .take_while(|x| (x.0 as u8) > 0 && (x.0 as u8) < 160)
            .map(Clone::clone)
            .collect();

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
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::ShellRequest(
            ServerChannelId(channel),
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?
        } else {
            session.channel_failure(channel)?
        }

        Ok(())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKeyOffer(
            user,
            key.clone(),
            tx,
        ))?;

        Ok(rx.await.unwrap_or(Auth::Reject {
            proceed_with_methods: None,
        }))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPublicKey(user, key.clone(), tx))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let password = Secret::new(password.to_string());

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthPassword(user, password, tx))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let user = Secret::new(user.to_string());
        let response = response
            .and_then(|mut r| r.next())
            .and_then(|b| String::from_utf8(b.to_vec()).ok())
            .map(Secret::new);

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::AuthKeyboardInteractive(
            user, response, tx,
        ))?;

        let result = rx.await.unwrap_or(Auth::UnsupportedMethod);
        Ok(result)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = ServerChannelId(channel);
        let data = Bytes::from(data.to_vec());

        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::Data(channel, data, tx))?;

        let _ = rx.await;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = ServerChannelId(channel);
        let data = Bytes::from(data.to_vec());
        let (tx, rx) = oneshot::channel();

        self.send_event(ServerHandlerEvent::ExtendedData(channel, data, code, tx))?;
        let _ = rx.await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = ServerChannelId(channel);
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ChannelClose(channel, tx))?;
        let _ = rx.await;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
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
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel = ServerChannelId(channel);
        let (tx, rx) = oneshot::channel();

        self.event_tx
            .send(ServerHandlerEvent::ChannelEof(channel, tx))
            .map_err(|_| ServerHandlerError::ChannelSend)?;

        let _ = rx.await;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal_name: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::Signal(
            ServerChannelId(channel),
            signal_name,
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let data = Bytes::from(data.to_vec());
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ExecRequest(
            ServerChannelId(channel),
            data,
            tx,
        ))?;

        if rx.await.unwrap_or(false) {
            session.channel_success(channel)?
        } else {
            session.channel_failure(channel)?
        }

        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let variable_name = variable_name.to_string();
        let variable_value = variable_value.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::EnvRequest(
            ServerChannelId(channel),
            variable_name,
            variable_value,
            tx,
        ))?;
        let _ = rx.await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let host_to_connect = host_to_connect.to_string();
        let originator_address = originator_address.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::ChannelOpenDirectTcpIp(
            ServerChannelId(channel.id()),
            DirectTCPIPParams {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
            },
            tx,
        ))?;
        let allowed = rx.await.unwrap_or(false);
        Ok(allowed)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_conection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let x11_auth_protocol = x11_auth_protocol.to_string();
        let x11_auth_cookie = x11_auth_cookie.to_string();
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
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let address = address.to_string();
        let port = *port;
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::TcpIpForward(address, port, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success()
        } else {
            session.request_failure()
        }
        Ok(allowed)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let address = address.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::CancelTcpIpForward(address, port, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success()
        } else {
            session.request_failure()
        }
        Ok(allowed)
    }

    async fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let socket_path = socket_path.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::StreamlocalForward(socket_path, tx))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success()
        } else {
            session.request_failure()
        }
        Ok(allowed)
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let socket_path = socket_path.to_string();
        let (tx, rx) = oneshot::channel();
        self.send_event(ServerHandlerEvent::CancelStreamlocalForward(
            socket_path,
            tx,
        ))?;
        let allowed = rx.await.unwrap_or(false);
        if allowed {
            session.request_success()
        } else {
            session.request_failure()
        }
        Ok(allowed)
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        debug!("Dropped");
        let _ = self.event_tx.send(ServerHandlerEvent::Disconnect);
    }
}

impl Debug for ServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerHandler")
    }
}
