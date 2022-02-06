// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use futures::future::Future;
use thrussh_keys::key;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::pin;

use crate::session::*;
use crate::ssh_read::*;
use crate::sshbuffer::*;
use crate::*;

mod kex;
mod session;
pub use self::kex::*;
pub use self::session::*;
mod encrypted;

#[derive(Debug)]
/// Configuration of a server.
pub struct Config {
    /// The server ID string sent at the beginning of the protocol.
    pub server_id: String,
    /// Authentication methods proposed to the client.
    pub methods: auth::MethodSet,
    /// The authentication banner, usually a warning message shown to the client.
    pub auth_banner: Option<&'static str>,
    /// Authentication rejections must happen in constant time for
    /// security reasons. Thrussh does not handle this by default.
    pub auth_rejection_time: std::time::Duration,
    /// The server's keys. The first key pair in the client's preference order will be chosen.
    pub keys: Vec<key::KeyPair>,
    /// The bytes and time limits before key re-exchange.
    pub limits: Limits,
    /// The initial size of a channel (used for flow control).
    pub window_size: u32,
    /// The maximal size of a single packet.
    pub maximum_packet_size: u32,
    /// Lists of preferred algorithms.
    pub preferred: Preferred,
    /// Maximal number of allowed authentication attempts.
    pub max_auth_attempts: usize,
    /// Time after which the connection is garbage-collected.
    pub connection_timeout: Option<std::time::Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            server_id: format!(
                "SSH-2.0-{}_{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ),
            methods: auth::MethodSet::all(),
            auth_banner: None,
            auth_rejection_time: std::time::Duration::from_secs(1),
            keys: Vec::new(),
            window_size: 2097152,
            maximum_packet_size: 32768,
            limits: Limits::default(),
            preferred: Default::default(),
            max_auth_attempts: 10,
            connection_timeout: Some(std::time::Duration::from_secs(600)),
        }
    }
}

/// A client's response in a challenge-response authentication.
#[derive(Debug)]
pub struct Response<'a> {
    pos: thrussh_keys::encoding::Position<'a>,
    n: u32,
}

impl<'a> Iterator for Response<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            self.pos.read_string().ok()
        }
    }
}

use std::borrow::Cow;
/// An authentication result, in a challenge-response authentication.
#[derive(Debug, PartialEq, Eq)]
pub enum Auth {
    /// Reject the authentication request.
    Reject,
    /// Accept the authentication request.
    Accept,

    /// Method was not accepted, but no other check was performed.
    UnsupportedMethod,

    /// Partially accept the challenge-response authentication
    /// request, providing more instructions for the client to follow.
    Partial {
        /// Name of this challenge.
        name: Cow<'static, str>,
        /// Instructions for this challenge.
        instructions: Cow<'static, str>,
        /// A number of prompts to the user. Each prompt has a `bool`
        /// indicating whether the terminal must echo the characters
        /// typed by the user.
        prompts: Cow<'static, [(Cow<'static, str>, bool)]>,
    },
}

/// Server handler. Each client will have their own handler.
pub trait Handler: Sized {
    type Error: From<crate::Error> + Send;
    /// The type of authentications, which can be a future ultimately
    /// resolving to
    type FutureAuth: Future<Output = Result<(Self, Auth), Self::Error>> + Send;

    /// The type of units returned by some parts of this handler.
    type FutureUnit: Future<Output = Result<(Self, Session), Self::Error>> + Send;

    /// The type of future bools returned by some parts of this handler.
    type FutureBool: Future<Output = Result<(Self, Session, bool), Self::Error>> + Send;

    /// Convert an `Auth` to `Self::FutureAuth`. This is used to
    /// produce the default handlers.
    fn finished_auth(self, auth: Auth) -> Self::FutureAuth;

    /// Convert a `bool` to `Self::FutureBool`. This is used to
    /// produce the default handlers.
    fn finished_bool(self, b: bool, session: Session) -> Self::FutureBool;

    /// Produce a `Self::FutureUnit`. This is used to produce the
    /// default handlers.
    fn finished(self, session: Session) -> Self::FutureUnit;

    /// Check authentication using the "none" method. Thrussh makes
    /// sure rejection happens in time `config.auth_rejection_time`,
    /// except if this method takes more than that.
    #[allow(unused_variables)]
    fn auth_none(self, user: &str) -> Self::FutureAuth {
        self.finished_auth(Auth::Reject)
    }

    /// Check authentication using the "password" method. Thrussh
    /// makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        self.finished_auth(Auth::Reject)
    }

    /// Check authentication using the "publickey" method. This method
    /// should just check whether the public key matches the
    /// authorized ones. Thrussh then checks the signature. If the key
    /// is unknown, or the signature is invalid, Thrussh guarantees
    /// that rejection happens in constant time
    /// `config.auth_rejection_time`, except if this method takes more
    /// time than that.
    #[allow(unused_variables)]
    fn auth_publickey(self, user: &str, public_key: &key::PublicKey) -> Self::FutureAuth {
        self.finished_auth(Auth::Reject)
    }

    /// Check authentication using the "keyboard-interactive"
    /// method. Thrussh makes sure rejection happens in time
    /// `config.auth_rejection_time`, except if this method takes more
    /// than that.
    #[allow(unused_variables)]
    fn auth_keyboard_interactive(
        self,
        user: &str,
        submethods: &str,
        response: Option<Response>,
    ) -> Self::FutureAuth {
        self.finished_auth(Auth::Reject)
    }

    /// Called when the client closes a channel.
    #[allow(unused_variables)]
    fn channel_close(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the client sends EOF to a channel.
    #[allow(unused_variables)]
    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when a new session channel is created.
    #[allow(unused_variables)]
    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when a new X11 channel is created.
    #[allow(unused_variables)]
    fn channel_open_x11(
        self,
        channel: ChannelId,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when a new channel is created.
    #[allow(unused_variables)]
    fn channel_open_direct_tcpip(
        self,
        channel: ChannelId,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when a data packet is received. A response can be
    /// written to the `response` argument.
    #[allow(unused_variables)]
    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when an extended data packet is received. Code 1 means
    /// that this packet comes from stderr, other codes are not
    /// defined (see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-5.2)).
    #[allow(unused_variables)]
    fn extended_data(
        self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Called when the network window is adjusted, meaning that we
    /// can send more bytes.
    #[allow(unused_variables)]
    fn window_adjusted(
        self,
        channel: ChannelId,
        new_window_size: usize,
        mut session: Session,
    ) -> Self::FutureUnit {
        if let Some(ref mut enc) = session.common.encrypted {
            enc.flush_pending(channel);
        }
        self.finished(session)
    }

    /// Called when this server adjusts the network window. Return the
    /// next target window.
    #[allow(unused_variables)]
    fn adjust_window(&mut self, channel: ChannelId, current: u32) -> u32 {
        current
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    #[allow(unused_variables)]
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

    /// The client requests an X11 connection.
    #[allow(unused_variables)]
    fn x11_request(
        self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client wants to set the given environment variable. Check
    /// these carefully, as it is dangerous to allow any variable
    /// environment to be set.
    #[allow(unused_variables)]
    fn env_request(
        self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    fn shell_request(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client sends a command to execute, to be passed to a
    /// shell. Make sure to check the command before doing so.
    #[allow(unused_variables)]
    fn exec_request(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client asks to start the subsystem with the given name
    /// (such as sftp).
    #[allow(unused_variables)]
    fn subsystem_request(
        self,
        channel: ChannelId,
        name: &str,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Self::FutureUnit {
        self.finished(session)
    }

    /// The client is sending a signal (usually to pass to the
    /// currently running process).
    #[allow(unused_variables)]
    fn signal(self, channel: ChannelId, signal_name: Sig, session: Session) -> Self::FutureUnit {
        self.finished(session)
    }

    /// Used for reverse-forwarding ports, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
        self.finished_bool(false, session)
    }
    /// Used to stop the reverse-forwarding of a port, see
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7).
    #[allow(unused_variables)]
    fn cancel_tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
        self.finished_bool(false, session)
    }
}

/// Trait used to create new handlers when clients connect.
pub trait Server {
    /// The type of handlers.
    type Handler: Handler + Send;
    /// Called when a new client connects.
    fn new(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler;
}

/// Run a server.
/// Create a new `Connection` from the server's configuration, a
/// stream and a [`Handler`](trait.Handler.html).
pub async fn run<H: Server + Send + 'static>(
    config: Arc<Config>,
    addr: &str,
    mut server: H,
) -> Result<(), std::io::Error> {
    let addr = addr.to_socket_addrs().unwrap().next().unwrap();
    let socket = TcpListener::bind(&addr).await?;
    if config.maximum_packet_size > 65535 {
        error!(
            "Maximum packet size ({:?}) should not larger than a TCP packet (65535)",
            config.maximum_packet_size
        );
    }
    while let Ok((socket, _)) = socket.accept().await {
        let config = config.clone();
        let server = server.new(socket.peer_addr().ok());
        tokio::spawn(run_stream(config, socket, server));
    }
    Ok(())
}

use std::cell::RefCell;
thread_local! {
    static B1: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static B2: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

pub async fn timeout(delay: Option<std::time::Duration>) {
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await
    } else {
        futures::future::pending().await
    };
}

async fn start_reading<R: AsyncRead + Unpin>(
    mut stream_read: R,
    mut buffer: SSHBuffer,
    cipher: Arc<crate::cipher::CipherPair>,
) -> Result<(usize, R, SSHBuffer), Error> {
    buffer.buffer.clear();
    let n = cipher::read(&mut stream_read, &mut buffer, &cipher).await?;
    Ok((n, stream_read, buffer))
}

pub async fn run_stream<H: Handler, R>(
    config: Arc<Config>,
    mut stream: R,
    handler: H,
) -> Result<H, H::Error>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut handler = Some(handler);
    let delay = config.connection_timeout;
    // Writing SSH id.
    let mut decomp = CryptoVec::new();
    let mut write_buffer = SSHBuffer::new();
    write_buffer.send_ssh_id(config.as_ref().server_id.as_bytes());
    stream
        .write_all(&write_buffer.buffer[..])
        .await
        .map_err(crate::Error::from)?;

    // Reading SSH id and allocating a session.
    let mut stream = SshRead::new(&mut stream);
    let common = read_ssh_id(config, &mut stream).await?;
    let (sender, receiver) = tokio::sync::mpsc::channel(10);
    let mut session = Session {
        target_window_size: common.config.window_size,
        common,
        receiver,
        sender: server::session::Handle { sender },
        pending_reads: Vec::new(),
        pending_len: 0,
    };
    session.flush()?;
    stream
        .write_all(&session.common.write_buffer.buffer)
        .await
        .map_err(crate::Error::from)?;
    session.common.write_buffer.buffer.clear();

    let (stream_read, mut stream_write) = stream.split();
    let buffer = SSHBuffer::new();
    let reading = start_reading(stream_read, buffer, session.common.cipher.clone());
    pin!(reading);
    let mut is_reading = None;

    while !session.common.disconnected {
        tokio::select! {
            r = &mut reading => {
                let (stream_read, buffer) = match r {
                    Ok((_, stream_read, buffer)) => (stream_read, buffer),
                    Err(e) => return Err(e.into())
                };
                if buffer.buffer.len() < 5 {
                    is_reading = Some((stream_read, buffer));
                    break
                }
                let buf = if let Some(ref mut enc) = session.common.encrypted {
                    let d = enc.decompress.decompress(
                        &buffer.buffer[5..],
                        &mut decomp,
                    );
                    if let Ok(buf) = d {
                        buf
                    } else {
                        debug!("err = {:?}", d);
                        is_reading = Some((stream_read, buffer));
                        break
                    }
                } else {
                    &buffer.buffer[5..]
                };
                if !buf.is_empty() {
                    if buf[0] == crate::msg::DISCONNECT {
                        debug!("break");
                        is_reading = Some((stream_read, buffer));
                        break;
                    } else if buf[0] > 4 {
                        match reply(session, &mut handler, &buf[..]).await {
                            Ok(s) => session = s,
                            Err(e) => return Err(e),
                        }
                    }
                }
                reading.set(start_reading(stream_read, buffer, session.common.cipher.clone()));
            }
            _ = timeout(delay) => {
                debug!("timeout");
                break
            },
            msg = session.receiver.recv(), if !session.is_rekeying() => {
                match msg {
                    Some((id, ChannelMsg::Data { data })) => {
                        session.data(id, data);
                    }
                    Some((id, ChannelMsg::ExtendedData { ext, data })) => {
                        session.extended_data(id, ext, data);
                    }
                    Some((id, ChannelMsg::Eof)) => {
                        session.eof(id);
                    }
                    Some((id, ChannelMsg::Close)) => {
                        session.close(id);
                    }
                    Some((id, ChannelMsg::XonXoff { client_can_do })) => {
                        session.xon_xoff_request(id, client_can_do);
                    }
                    Some((id, ChannelMsg::ExitStatus { exit_status })) => {
                        session.exit_status_request(id, exit_status);
                    }
                    Some((id, ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, lang_tag })) => {
                        session.exit_signal_request(id, signal_name, core_dumped, &error_message, &lang_tag);
                    }
                    Some((id, ChannelMsg::WindowAdjusted { new_size })) => {
                        debug!("window adjusted to {:?} for channel {:?}", new_size, id);
                    }
                    Some((id, ChannelMsg::Success)) => {
                        debug!("channel success {:?}", id);
                    }
                    None => {
                        debug!("session.receiver: received None");
                    }
                }
            }
        }
        session.flush()?;
        stream_write
            .write_all(&session.common.write_buffer.buffer)
            .await
            .map_err(crate::Error::from)?;
        session.common.write_buffer.buffer.clear();
    }
    debug!("disconnected");
    // Shutdown
    stream_write.shutdown().await.map_err(crate::Error::from)?;
    loop {
        if let Some((stream_read, buffer)) = is_reading.take() {
            reading.set(start_reading(
                stream_read,
                buffer,
                session.common.cipher.clone(),
            ));
        }
        let (n, r, b) = (&mut reading).await?;
        is_reading = Some((r, b));
        if n == 0 {
            break;
        }
    }
    Ok(handler.unwrap())
}

async fn read_ssh_id<R: AsyncRead + Unpin>(
    config: Arc<Config>,
    read: &mut SshRead<R>,
) -> Result<CommonSession<Arc<Config>>, Error> {
    let sshid = if let Some(t) = config.connection_timeout {
        tokio::time::timeout(t, read.read_ssh_id()).await??
    } else {
        read.read_ssh_id().await?
    };
    let mut exchange = Exchange::new();
    exchange.client_id.extend(sshid);
    // Preparing the response
    exchange
        .server_id
        .extend(config.as_ref().server_id.as_bytes());
    let mut kexinit = KexInit {
        exchange: exchange,
        algo: None,
        sent: false,
        session_id: None,
    };
    let cipher = Arc::new(cipher::CLEAR_PAIR);
    let mut write_buffer = SSHBuffer::new();
    kexinit.server_write(config.as_ref(), cipher.as_ref(), &mut write_buffer)?;
    Ok(CommonSession {
        write_buffer,
        kex: Some(Kex::KexInit(kexinit)),
        auth_user: String::new(),
        auth_method: None, // Client only.
        cipher,
        encrypted: None,
        config: config,
        wants_reply: false,
        disconnected: false,
        buffer: CryptoVec::new(),
    })
}

async fn reply<H: Handler>(
    mut session: Session,
    handler: &mut Option<H>,
    buf: &[u8],
) -> Result<Session, H::Error> {
    // Handle key exchange/re-exchange.
    if session.common.encrypted.is_none() {
        match session.common.kex.take() {
            Some(Kex::KexInit(kexinit)) => {
                if kexinit.algo.is_some() || buf[0] == msg::KEXINIT {
                    session.common.kex = Some(kexinit.server_parse(
                        session.common.config.as_ref(),
                        &session.common.cipher,
                        &buf,
                        &mut session.common.write_buffer,
                    )?);
                    return Ok(session);
                } else {
                    // Else, i.e. if the other side has not started
                    // the key exchange, process its packets by simple
                    // not returning.
                    session.common.kex = Some(Kex::KexInit(kexinit))
                }
            }
            Some(Kex::KexDh(kexdh)) => {
                session.common.kex = Some(kexdh.parse(
                    session.common.config.as_ref(),
                    &session.common.cipher,
                    buf,
                    &mut session.common.write_buffer,
                )?);
                return Ok(session);
            }
            Some(Kex::NewKeys(newkeys)) => {
                if buf[0] != msg::NEWKEYS {
                    return Err(Error::Kex.into());
                }
                // Ok, NEWKEYS received, now encrypted.
                session.common.encrypted(
                    EncryptedState::WaitingServiceRequest {
                        sent: false,
                        accepted: false,
                    },
                    newkeys,
                );
                return Ok(session);
            }
            Some(kex) => {
                session.common.kex = Some(kex);
                return Ok(session);
            }
            None => {}
        }
        Ok(session)
    } else {
        Ok(session.server_read_encrypted(handler, buf).await?)
    }
}
