mod channel_direct_tcpip;
mod channel_session;
mod error;
mod handler;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use channel_direct_tcpip::DirectTCPIPChannel;
use channel_session::SessionChannel;
pub use error::SshClientError;
use futures::pin_mut;
use handler::ClientHandler;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey};
use russh::{kex, MethodKind, Preferred, Sig};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::*;
use uuid::Uuid;
use warpgate_common::{SSHTargetAuth, SessionId, TargetSSHOptions};
use warpgate_core::Services;

use self::handler::ClientHandlerEvent;
use super::{ChannelOperation, DirectTCPIPParams};
use crate::client::handler::ClientHandlerError;
use crate::{load_keys, ForwardedStreamlocalParams, ForwardedTcpIpParams};

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Host key mismatch")]
    HostKeyMismatch {
        received_key_type: russh::keys::Algorithm,
        received_key_base64: String,
        known_key_type: String,
        known_key_base64: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] russh::keys::Error),

    #[error(transparent)]
    Ssh(#[from] russh::Error),

    #[error("Could not resolve address")]
    Resolve,

    #[error("Internal error")]
    Internal,

    #[error("Aborted")]
    Aborted,

    #[error("Authentication failed")]
    Authentication,
}

#[derive(Debug)]
pub enum RCEvent {
    State(RCState),
    Output(Uuid, Bytes),
    Success(Uuid),
    ChannelFailure(Uuid),
    Eof(Uuid),
    Close(Uuid),
    Error(anyhow::Error),
    ExitStatus(Uuid, u32),
    ExitSignal {
        channel: Uuid,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    ExtendedData {
        channel: Uuid,
        data: Bytes,
        ext: u32,
    },
    ConnectionError(ConnectionError),
    // ForwardedTCPIP(Uuid, DirectTCPIPParams),
    Done,
    HostKeyReceived(PublicKey),
    HostKeyUnknown(PublicKey, oneshot::Sender<bool>),
    ForwardedTcpIp(Uuid, ForwardedTcpIpParams),
    ForwardedStreamlocal(Uuid, ForwardedStreamlocalParams),
    ForwardedAgent(Uuid),
    X11(Uuid, String, u32),
}

pub type RCCommandReply = oneshot::Sender<Result<(), SshClientError>>;

#[derive(Clone, Debug)]
pub enum RCCommand {
    Connect(TargetSSHOptions),
    Channel(Uuid, ChannelOperation),
    ForwardTCPIP(String, u32),
    CancelTCPIPForward(String, u32),
    StreamlocalForward(String),
    CancelStreamlocalForward(String),
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Debug)]
enum InnerEvent {
    RCCommand(RCCommand, Option<RCCommandReply>),
    ClientHandlerEvent(ClientHandlerEvent),
}

pub struct RemoteClient {
    id: SessionId,
    tx: UnboundedSender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_pipes: Arc<Mutex<HashMap<Uuid, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(Uuid, ChannelOperation)>,
    pending_forwards: Vec<(String, u32)>,
    pending_streamlocal_forwards: Vec<String>,
    state: RCState,
    abort_rx: UnboundedReceiver<()>,
    inner_event_rx: UnboundedReceiver<InnerEvent>,
    inner_event_tx: UnboundedSender<InnerEvent>,
    child_tasks: Vec<JoinHandle<Result<(), SshClientError>>>,
    services: Services,
}

pub struct RemoteClientHandles {
    pub event_rx: UnboundedReceiver<RCEvent>,
    pub command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    pub abort_tx: UnboundedSender<()>,
}

impl RemoteClient {
    pub fn create(id: SessionId, services: Services) -> io::Result<RemoteClientHandles> {
        let (event_tx, event_rx) = unbounded_channel();
        let (command_tx, mut command_rx) = unbounded_channel();
        let (abort_tx, abort_rx) = unbounded_channel();

        let (inner_event_tx, inner_event_rx) = unbounded_channel();

        let this = Self {
            id,
            tx: event_tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            pending_ops: vec![],
            pending_forwards: vec![],
            pending_streamlocal_forwards: vec![],
            state: RCState::NotInitialized,
            inner_event_rx,
            inner_event_tx: inner_event_tx.clone(),
            child_tasks: vec![],
            services,
            abort_rx,
        };

        tokio::spawn(
            {
                async move {
                    while let Some((e, response)) = command_rx.recv().await {
                        inner_event_tx.send(InnerEvent::RCCommand(e, response))?
                    }
                    Ok::<(), anyhow::Error>(())
                }
            }
            .instrument(Span::current()),
        );

        this.start()?;

        Ok(RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx,
        })
    }

    fn set_disconnected(&mut self) {
        self.session = None;
        for (id, op) in self.pending_ops.drain(..) {
            if let ChannelOperation::OpenShell = op {
                let _ = self.tx.send(RCEvent::Close(id));
            }
            if let ChannelOperation::OpenDirectTCPIP { .. } = op {
                let _ = self.tx.send(RCEvent::Close(id));
            }
        }
        let _ = self.set_state(RCState::Disconnected);
        let _ = self.tx.send(RCEvent::Done);
    }

    fn set_state(&mut self, state: RCState) -> Result<(), SshClientError> {
        self.state = state.clone();
        self.tx
            .send(RCEvent::State(state))
            .map_err(|_| SshClientError::MpscError)?;
        Ok(())
    }

    // fn map_channel(&self, ch: &ChannelId) -> Result<Uuid> {
    //     self.channel_map
    //         .get_by_left(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    // fn map_channel_reverse(&self, ch: &Uuid) -> Result<ChannelId> {
    //     self.channel_map
    //         .get_by_right(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    async fn apply_channel_op(
        &mut self,
        channel_id: Uuid,
        op: ChannelOperation,
    ) -> Result<(), SshClientError> {
        if self.state != RCState::Connected {
            self.pending_ops.push((channel_id, op));
            return Ok(());
        }

        match op {
            ChannelOperation::OpenShell => {
                self.open_shell(channel_id).await?;
            }
            ChannelOperation::OpenDirectTCPIP(params) => {
                self.open_direct_tcpip(channel_id, params).await?;
            }
            ChannelOperation::OpenDirectStreamlocal(path) => {
                self.open_direct_streamlocal(channel_id, path).await?;
            }
            op => {
                let mut channel_pipes = self.channel_pipes.lock().await;
                match channel_pipes.get(&channel_id) {
                    Some(tx) => {
                        if tx.send(op).is_err() {
                            channel_pipes.remove(&channel_id);
                        }
                    }
                    None => debug!(channel=%channel_id, "operation for unknown channel"),
                }
            }
        }
        Ok(())
    }

    pub fn start(mut self) -> io::Result<JoinHandle<anyhow::Result<()>>> {
        let name = format!("SSH {} client commands", self.id);
        tokio::task::Builder::new().name(&name).spawn(
            async move {
                async {
                    loop {
                        tokio::select! {
                            Some(event) = self.inner_event_rx.recv() => {
                                debug!(event=?event, "event");
                                if self.handle_event(event).await? {
                                    break
                                }
                            }
                            Some(_) = self.abort_rx.recv() => {
                                debug!("Abort requested");
                                self.disconnect().await;
                                break
                            }
                        };
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await
                .map_err(|error| {
                    error!(?error, "error in command loop");
                    let err = anyhow::anyhow!("Error in command loop: {error}");
                    let _ = self.tx.send(RCEvent::Error(error));
                    err
                })?;
                info!("Client session closed");
                Ok::<(), anyhow::Error>(())
            }
            .instrument(Span::current()),
        )
    }

    async fn handle_event(&mut self, event: InnerEvent) -> Result<bool> {
        match event {
            InnerEvent::RCCommand(cmd, reply) => {
                let result = self.handle_command(cmd).await;
                let brk = matches!(result, Ok(true));
                if let Some(reply) = reply {
                    let _ = reply.send(result.map(|_| ()));
                }
                return Ok(brk);
            }
            InnerEvent::ClientHandlerEvent(client_event) => {
                debug!("Client handler event: {:?}", client_event);
                match client_event {
                    ClientHandlerEvent::Disconnect => {
                        self._on_disconnect().await?;
                    }
                    ClientHandlerEvent::ForwardedTcpIp(channel, params) => {
                        info!("New forwarded connection: {params:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self.tx.send(RCEvent::ForwardedTcpIp(id, params));
                    }
                    ClientHandlerEvent::ForwardedStreamlocal(channel, params) => {
                        info!("New forwarded socket connection: {params:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self.tx.send(RCEvent::ForwardedStreamlocal(id, params));
                    }
                    ClientHandlerEvent::ForwardedAgent(channel) => {
                        info!("New forwarded agent connection");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self.tx.send(RCEvent::ForwardedAgent(id));
                    }
                    ClientHandlerEvent::X11(channel, originator_address, originator_port) => {
                        info!("New X11 connection from {originator_address}:{originator_port:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self
                            .tx
                            .send(RCEvent::X11(id, originator_address, originator_port));
                    }
                    event => {
                        error!(?event, "Unhandled client handler event");
                    }
                }
            }
        }
        Ok(false)
    }

    async fn setup_server_initiated_channel(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();

        let (tx, rx) = unbounded_channel();
        self.channel_pipes.lock().await.insert(id, tx);

        let session_channel = SessionChannel::new(channel, id, rx, self.tx.clone(), self.id);

        self.child_tasks.push(
            tokio::task::Builder::new()
                .name(&format!("SSH {} {:?} ops", self.id, id))
                .spawn(session_channel.run())?,
        );

        Ok(id)
    }

    async fn handle_command(&mut self, cmd: RCCommand) -> Result<bool, SshClientError> {
        match cmd {
            RCCommand::Connect(options) => match self.connect(options).await {
                Ok(_) => {
                    self.set_state(RCState::Connected)
                        .map_err(SshClientError::other)?;
                    let ops = self.pending_ops.drain(..).collect::<Vec<_>>();
                    for (id, op) in ops {
                        self.apply_channel_op(id, op).await?;
                    }

                    let forwards = self.pending_forwards.drain(..).collect::<Vec<_>>();
                    for (address, port) in forwards {
                        self.tcpip_forward(address, port).await?;
                    }

                    let forwards = self
                        .pending_streamlocal_forwards
                        .drain(..)
                        .collect::<Vec<_>>();
                    for socket_path in forwards {
                        self.streamlocal_forward(socket_path).await?;
                    }
                }
                Err(e) => {
                    debug!("Connect error: {}", e);
                    let _ = self.tx.send(RCEvent::ConnectionError(e));
                    self.set_disconnected();
                    return Ok(true);
                }
            },
            RCCommand::Channel(ch, op) => {
                self.apply_channel_op(ch, op).await?;
            }
            RCCommand::ForwardTCPIP(address, port) => {
                self.tcpip_forward(address, port).await?;
            }
            RCCommand::CancelTCPIPForward(address, port) => {
                self.cancel_tcpip_forward(address, port).await?;
            }
            RCCommand::StreamlocalForward(socket_path) => {
                self.streamlocal_forward(socket_path).await?;
            }
            RCCommand::CancelStreamlocalForward(socket_path) => {
                self.cancel_streamlocal_forward(socket_path).await?;
            }
            RCCommand::Disconnect => {
                self.disconnect().await;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn connect(&mut self, ssh_options: TargetSSHOptions) -> Result<(), ConnectionError> {
        let address_str = format!("{}:{}", ssh_options.host, ssh_options.port);
        let address = match address_str
            .to_socket_addrs()
            .map_err(ConnectionError::Io)
            .and_then(|mut x| x.next().ok_or(ConnectionError::Resolve))
        {
            Ok(address) => address,
            Err(error) => {
                error!(?error, address=%address_str, "Cannot resolve target address");
                self.set_disconnected();
                return Err(error);
            }
        };

        info!(?address, username = &ssh_options.username[..], "Connecting");
        let algos = if ssh_options.allow_insecure_algos.unwrap_or(false) {
            Preferred {
                kex: Cow::Borrowed(&[
                    kex::MLKEM768X25519_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::ECDH_SHA2_NISTP256,
                    kex::ECDH_SHA2_NISTP384,
                    kex::ECDH_SHA2_NISTP521,
                    kex::DH_G16_SHA512,
                    kex::DH_G14_SHA256, // non-default
                    kex::DH_GEX_SHA256,
                    kex::DH_G1_SHA1, // non-default
                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]),
                key: Cow::Borrowed(&[
                    russh::keys::Algorithm::Ed25519,
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP256,
                    },
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP384,
                    },
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP521,
                    },
                    russh::keys::Algorithm::Rsa {
                        hash: Some(russh::keys::HashAlg::Sha256),
                    },
                    russh::keys::Algorithm::Rsa {
                        hash: Some(russh::keys::HashAlg::Sha512),
                    },
                    russh::keys::Algorithm::Rsa { hash: None },
                ]),
                cipher: Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    russh::cipher::AES_256_GCM,
                    russh::cipher::AES_256_CTR,
                    russh::cipher::AES_256_CBC,
                    russh::cipher::AES_192_CTR,
                    russh::cipher::AES_192_CBC,
                    russh::cipher::AES_128_CTR,
                    russh::cipher::AES_128_CBC,
                    russh::cipher::TRIPLE_DES_CBC,
                ]),
                ..<_>::default()
            }
        } else {
            Preferred::default()
        };

        let mut config = russh::client::Config {
            preferred: algos,
            nodelay: true,
            ..Default::default()
        };
        if ssh_options.allow_insecure_algos.unwrap_or(false) {
            if let Ok(gex) = russh::client::GexParams::new(2048, 2048, 8192) {
                config.gex = gex;
            }
        }

        let config = Arc::new(config);

        let (event_tx, mut event_rx) = unbounded_channel();
        let handler = ClientHandler {
            ssh_options: ssh_options.clone(),
            event_tx,
            services: self.services.clone(),
            session_id: self.id,
        };

        let fut_connect = russh::client::connect(config, address, handler);
        pin_mut!(fut_connect);

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    match event {
                        ClientHandlerEvent::HostKeyReceived(key) => {
                            self.tx.send(RCEvent::HostKeyReceived(key)).map_err(|_| ConnectionError::Internal)?;
                        }
                        ClientHandlerEvent::HostKeyUnknown(key, reply) => {
                            self.tx.send(RCEvent::HostKeyUnknown(key, reply)).map_err(|_| ConnectionError::Internal)?;
                        }
                        _ => {}
                    }
                }
                Some(_) = self.abort_rx.recv() => {
                    info!("Abort requested");
                    self.set_disconnected();
                    return Err(ConnectionError::Aborted)
                }
                session = &mut fut_connect => {
                    let mut session = match session {
                        Ok(session) => session,
                        Err(error) => {
                            let connection_error = match error {
                                ClientHandlerError::ConnectionError(e) => e,
                                ClientHandlerError::Ssh(e) => ConnectionError::Ssh(e),
                                ClientHandlerError::Internal => ConnectionError::Internal,
                            };
                            error!(error=?connection_error, "Connection error");
                            return Err(connection_error);
                        }
                    };

                    let mut auth_result = false;
                    let mut auth_error: Option<String> = None;
                    match ssh_options.auth {
                        SSHTargetAuth::Password(auth) => {
                            let response = session
                                    .authenticate_password(
                                        ssh_options.username.clone(),
                                        auth.password.expose_secret()
                                    )
                                    .await?;
                            auth_result = self._handle_auth_result(
                                &mut session,
                                ssh_options.username.clone(),
                                response
                            ).await.unwrap_or(false);
                            if auth_result {
                                debug!(username=&ssh_options.username[..], "Authenticated with password");
                            }
                            auth_error = Some("Password authentication was rejected by the SSH target".to_string());
                        }
                        SSHTargetAuth::PublicKey(_) => {
                            let best_hash = session.best_supported_rsa_hash().await?.flatten();
                            #[allow(clippy::explicit_auto_deref)]
                            let keys = load_keys(
                                &*self.services.config.lock().await,
                                &self.services.global_params,
                                "client"
                            )?;
                            let allow_insecure_algos = ssh_options.allow_insecure_algos.unwrap_or(false);
                            for key in keys.into_iter() {
                                let key = Arc::new(key);
                                if key.key_data().is_rsa() && best_hash.is_none() && !allow_insecure_algos {
                                    info!("Skipping ssh-rsa (SHA1) key authentication since insecure SSH algos are not allowed for this target");
                                    continue;
                                }
                                let key_str = key.public_key().to_openssh().map_err(russh::Error::from)?;
                                let mut response  = session
                                    .authenticate_publickey(
                                        ssh_options.username.clone(),
                                        PrivateKeyWithHashAlg::new(key.clone(), best_hash),
                                    )
                                    .await?;

                                auth_result = self._handle_auth_result(
                                    &mut session,
                                    ssh_options.username.clone(),
                                    response
                                ).await.unwrap_or(false);

                                if !auth_result && key.key_data().is_rsa() && best_hash.is_some() && allow_insecure_algos {
                                    // Corner case: OpenSSH advertising rsa2-sha-* through server-sig-algs, but it being
                                    // disabled via PubkeyAcceptedAlgorithms. So far the only case is our own test suite.
                                    // In this case we retry with ssh-rsa (SHA1)
                                    response = session
                                        .authenticate_publickey(
                                            ssh_options.username.clone(),
                                            PrivateKeyWithHashAlg::new(key.clone(), None),
                                        ).await?;

                                    auth_result = self._handle_auth_result(
                                        &mut session,
                                        ssh_options.username.clone(),
                                        response
                                    ).await.unwrap_or(false);
                                }

                                if auth_result {
                                    debug!(username=&ssh_options.username[..], key=%key_str, "Authenticated with key");
                                    break;
                                } else {
                                    auth_error = Some(format!("PublicKey authentication was rejected by the SSH target"));
                                }
                            }
                        }
                    }

                    if !auth_result {
                        let reason = auth_error.unwrap_or_else(|| "Authentication was rejected by the SSH server".to_string());
                        error!(reason=%reason, "Warpgate could not authenticate with SSH target");
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "", "")
                            .await;
                        return Err(ConnectionError::Authentication);
                    }

                    self.session = Some(Arc::new(Mutex::new(session)));

                    info!(?address, "Connected");

                    tokio::spawn({
                        let inner_event_tx = self.inner_event_tx.clone();
                        async move {
                            while let Some(e) = event_rx.recv().await {
                                info!("{:?}", e);
                                inner_event_tx.send(InnerEvent::ClientHandlerEvent(e))?
                            }
                            Ok::<(), anyhow::Error>(())
                        }
                    }.instrument(Span::current()));

                    return Ok(())
                }
            }
        }
    }

    /// Handles an AuthResult from a password or public key authentication attempt.
    /// If presented with an additional keyboard-interactive challenge it will respond with empty
    /// strings. This ensures optional 2fa is respected, where this extra challenge always happens.
    ///
    /// TODO: Optionally implement forwarding the challenges to the user
    ///
    /// # Arguments
    ///
    /// * `session`: the session for which the initial result is
    /// * `username`: username of the authenticating user
    /// * `result`: the initial result received via the configured auth method
    async fn _handle_auth_result(
        &self,
        session: &mut Handle<ClientHandler>,
        username: String,
        result: AuthResult,
    ) -> Result<bool> {
        debug!("Handling AuthResult");
        match result {
            AuthResult::Success => {
                debug!("AuthResult is already success, no further handling needed");
                return Ok(true);
            }
            AuthResult::Failure {
                remaining_methods: methods,
                ..
            } => {
                debug!("Initial auth failed, checking remaining methods");
                for method in methods.iter() {
                    if matches!(method, MethodKind::KeyboardInteractive) {
                        debug!("Found keyboard-interactive challenge");
                        let mut kb_result = session
                            .authenticate_keyboard_interactive_start(username.clone(), None)
                            .await?;

                        while let KeyboardInteractiveAuthResponse::InfoRequest {
                            name: _name,
                            instructions: _instructions,
                            prompts,
                        } = kb_result
                        {
                            for prompt in prompts.iter().clone() {
                                debug!(
                                    prompt = prompt.prompt,
                                    echo = prompt.echo,
                                    "Prompt received for keyboard-interactive"
                                );
                            }
                            debug!("Responding with empty responses");
                            kb_result = session
                                .authenticate_keyboard_interactive_respond(vec![
                                    String::new();
                                    prompts.len()
                                ])
                                .await?;
                        }

                        match kb_result {
                            KeyboardInteractiveAuthResponse::Success => {
                                debug!("keyboard-interactive challenge successful");
                                return Ok(true);
                            }
                            KeyboardInteractiveAuthResponse::Failure {
                                remaining_methods: _remaining_methods,
                                ..
                            } => {
                                debug!("keyboard-interactive challenge failed");
                                return Ok(false);
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
            }
        }
        Ok(false)
    }

    async fn open_shell(&mut self, channel_id: Uuid) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session.channel_open_session().await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel = SessionChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn open_direct_tcpip(
        &mut self,
        channel_id: Uuid,
        params: DirectTCPIPParams,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session
                .channel_open_direct_tcpip(
                    params.host_to_connect,
                    params.port_to_connect,
                    params.originator_address,
                    params.originator_port,
                )
                .await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel =
                DirectTCPIPChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn open_direct_streamlocal(
        &mut self,
        channel_id: Uuid,
        path: String,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session.channel_open_direct_streamlocal(path).await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel =
                DirectTCPIPChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn tcpip_forward(&mut self, address: String, port: u32) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            session.tcpip_forward(address, port).await?;
        } else {
            self.pending_forwards.push((address, port));
        }
        Ok(())
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: String,
        port: u32,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.cancel_tcpip_forward(address, port).await?;
        } else {
            self.pending_forwards
                .retain(|x| x.0 != address || x.1 != port);
        }
        Ok(())
    }

    async fn streamlocal_forward(&mut self, socket_path: String) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            session.streamlocal_forward(socket_path).await?;
        } else {
            self.pending_streamlocal_forwards.push(socket_path);
        }
        Ok(())
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: String,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.cancel_streamlocal_forward(socket_path).await?;
        } else {
            self.pending_streamlocal_forwards
                .retain(|x| x != &socket_path);
        }
        Ok(())
    }

    async fn disconnect(&mut self) {
        if let Some(session) = &mut self.session {
            let _ = session
                .lock()
                .await
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            self.set_disconnected();
        }
    }

    async fn _on_disconnect(&mut self) -> Result<()> {
        self.set_disconnected();
        Ok(())
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        for task in self.child_tasks.drain(..) {
            task.abort();
        }
        info!("Closed connection");
        debug!("Dropped");
    }
}
