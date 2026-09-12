use std::net::SocketAddr;
use std::sync::Arc;

use mongo_common::auth::plain::parse_client_payload;
use mongo_common::bson::{Binary, BinarySubtype};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::{error, info, info_span, warn};
use url::Url;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{Protocol, Secret, TargetMongoOptions, UserSessionId};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    AdmittedTarget, ApprovedTarget, AuthOkPermit, DbAuthTransport, Services, WarpgateServerHandle,
    run_db_authorization,
};
use wirebson::{Bson, Document, RawBsonRef, RawDocument};

use mongowire::MessageBody;
use mongowire::api::response::op_msg;
use mongowire::api::{handshake_reply, ping_reply, query_handshake_reply};
use mongowire::messages::{Header, MsgFlags, Opcode, OpReply};

use crate::client::MongoClient;
use crate::error::MongoError;
use crate::stream::{MongoStream, MAX_MESSAGE_SIZE};

/// Which reply shape the outcome of a login has to travel in. Drivers either
/// attach PLAIN credentials to the first `hello` (`speculativeAuthenticate`)
/// or send a separate `saslStart`; MongoDB answers in the same shape.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthReplyMode {
    Sasl,
    SpeculativeHello,
}

/// A structured auth failure, rendered into whichever reply shape
/// [`AuthReplyMode`] calls for.
#[derive(Debug)]
struct AuthFailure {
    code: i32,
    code_name: &'static str,
    message: String,
}

impl AuthFailure {
    fn new(code: i32, code_name: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            code_name,
            message: message.into(),
        }
    }
}

pub struct MongoSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    stream: MongoStream<S>,
    username: Option<String>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    services: Services,
    remote_address: SocketAddr,
    /// PLAIN carries the password inside the saslStart payload, so the shared
    /// auth flow is handed it here instead of being able to prompt for a
    /// second one.
    handshake_password: Option<Secret<String>>,
    /// The client command the pending auth replies answer.
    pending_request_id: i32,
    /// Request-id counter for the replies this session builds itself.
    next_request_id: i32,
    auth_reply_mode: AuthReplyMode,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for MongoSession<S> {
    type Error = MongoError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    /// The password arrived inside the saslStart payload. There is no way to
    /// ask a MongoDB client again, so a repeat request denies the login.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, MongoError> {
        Ok(self.handshake_password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), MongoError> {
        let body = match self.auth_reply_mode {
            AuthReplyMode::Sasl => {
                let mut doc = Document::new();
                doc.add("conversationId", 1_i32);
                doc.add("done", true);
                doc.add("payload", empty_binary());
                doc.add("ok", 1.0_f64);
                command_body(doc)?
            }
            AuthReplyMode::SpeculativeHello => hello_with_speculative(None)?,
        };
        self.send_reply_body(self.pending_request_id, body).await
    }

    async fn external_url(&mut self) -> Result<Url, MongoError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    /// The MongoDB authentication exchange has no packet for showing the user
    /// a link, so a policy requiring web approval can't be satisfied here.
    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, MongoError> {
        warn!("Web user approval is not supported over MongoDB");
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), MongoError> {
        self.send_auth_failure(AuthFailure::new(
            18,
            "AuthenticationFailed",
            "Authentication failed.",
        ))
        .await
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> MongoSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();
        Self {
            services,
            stream: MongoStream::new(stream),
            server_handle,
            id,
            remote_address,
            username: None,
            handshake_password: None,
            pending_request_id: 0,
            next_request_id: 1,
            auth_reply_mode: AuthReplyMode::Sasl,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            info_span!("MongoDB", session=%self.id, session_username=%username, %client_ip)
        } else {
            info_span!("MongoDB", session=%self.id, %client_ip)
        }
    }

    pub async fn run(mut self) -> Result<(), MongoError> {
        let Some(approved) = self.run_authorization().await? else {
            // Denied or disconnected; the client has already been told.
            return Ok(());
        };
        self.run_authorized(approved).await
    }

    /// Handles handshake and authentication traffic until the login completes.
    /// MongoDB clients authenticate with PLAIN credentials carried either by
    /// the first `hello` (speculative authentication) or by a `saslStart`.
    async fn run_authorization(&mut self) -> Result<Option<ApprovedTarget>, MongoError> {
        loop {
            let Some((header, body)) = self.stream.recv().await? else {
                return Ok(None);
            };

            match body {
                MessageBody::Msg(msg) => {
                    let command = msg.document().command()?.to_owned();
                    match command.as_str() {
                        "hello" | "isMaster" | "ismaster" => {
                            let legacy = command != "hello";
                            match self.speculative_auth_selector(msg.document())? {
                                SpeculativeAuth::None => {
                                    let reply = handshake_reply(&[], MAX_MESSAGE_SIZE, legacy)?;
                                    self.send_reply(header.request_id, MessageBody::Msg(reply))
                                        .await?;
                                }
                                SpeculativeAuth::Attempted(attempt) => {
                                    self.pending_request_id = header.request_id;
                                    self.auth_reply_mode = AuthReplyMode::SpeculativeHello;
                                    match attempt {
                                        Ok(selector) => {
                                            return self.authorize(selector).await;
                                        }
                                        Err(failure) => {
                                            self.send_auth_failure(failure).await?;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                        "saslStart" => {
                            self.pending_request_id = header.request_id;
                            self.auth_reply_mode = AuthReplyMode::Sasl;
                            match self.sasl_start_selector(msg.document()) {
                                Ok(Some(selector)) => {
                                    return self.authorize(selector).await;
                                }
                                Ok(None) => {
                                    self.send_auth_failure(AuthFailure::new(
                                        18,
                                        "AuthenticationFailed",
                                        "missing SASL payload",
                                    ))
                                    .await?;
                                }
                                Err(failure) => {
                                    self.send_auth_failure(failure).await?;
                                }
                            }
                        }
                        "ping" => {
                            let reply = ping_reply()?;
                            self.send_reply(header.request_id, MessageBody::Msg(reply))
                                .await?;
                        }
                        "logout" => {
                            let mut doc = Document::new();
                            doc.add("ok", 1.0_f64);
                            self.send_reply(header.request_id, command_body(doc)?)
                                .await?;
                        }
                        _ => {
                            self.send_error(
                                header.request_id,
                                AuthFailure::new(
                                    13,
                                    "Unauthorized",
                                    format!("command {command} requires authentication"),
                                ),
                            )
                            .await?;
                        }
                    }
                }
                MessageBody::Query(query) => {
                    // OP_QUERY only ever carries the legacy handshake here.
                    let legacy_command = query.query.command()?;
                    if legacy_command == "isMaster" || legacy_command == "ismaster" {
                        let reply = handshake_reply(&[], MAX_MESSAGE_SIZE, true)?;
                        let reply = query_handshake_reply(reply.document().clone());
                        self.send_op_reply(header.request_id, reply).await?;
                    } else {
                        let mut doc = Document::new();
                        doc.add(
                            "$err",
                            format!("command {legacy_command} requires authentication"),
                        );
                        doc.add("code", 13_i32);
                        doc.add("ok", 0.0_f64);
                        let reply = query_handshake_reply(doc.encode()?);
                        self.send_op_reply(header.request_id, reply).await?;
                    }
                }
                MessageBody::Reply(_) => {
                    return Err(MongoError::ProtocolError(
                        "unexpected OP_REPLY from client".into(),
                    ));
                }
                MessageBody::Compressed(_) => {
                    return Err(MongoError::ProtocolError(
                        "compressed messages are not supported; disable compression on the client"
                            .into(),
                    ));
                }
            }
        }
    }

    async fn authorize(
        &mut self,
        selector: AuthSelector,
    ) -> Result<Option<ApprovedTarget>, MongoError> {
        let session_id = self.server_handle.lock().await.user_session_id();
        let services = self.services.clone();
        let remote_ip = self.remote_address.ip();
        run_db_authorization(self, &services, session_id, selector, remote_ip).await
    }

    /// Extracts PLAIN credentials from a hello's `speculativeAuthenticate`
    /// document, if present. A present-but-invalid attempt is reported back to
    /// the client rather than dropped, so drivers can retry with an explicit
    /// `saslStart` and surface the error message.
    fn speculative_auth_selector(
        &mut self,
        doc: &RawDocument,
    ) -> Result<SpeculativeAuth, MongoError> {
        let Some(spec) = doc.get("speculativeAuthenticate")? else {
            return Ok(SpeculativeAuth::None);
        };
        let RawBsonRef::Document(spec) = spec else {
            return Ok(SpeculativeAuth::Attempted(Err(auth_failure(
                "speculativeAuthenticate must be a document",
            ))));
        };
        match plain_credentials(&spec) {
            Ok((username, password)) => Ok(SpeculativeAuth::Attempted(Ok(
                self.stash_credentials(username, password)
            ))),
            Err(failure) => Ok(SpeculativeAuth::Attempted(Err(failure))),
        }
    }

    /// Extracts PLAIN credentials from a `saslStart`. `Ok(None)` means the
    /// command had no payload at all.
    fn sasl_start_selector(
        &mut self,
        doc: &RawDocument,
    ) -> Result<Option<AuthSelector>, AuthFailure> {
        let has_payload = doc
            .get("payload")
            .map_err(|e| auth_failure(e.to_string()))?
            .is_some();
        if !has_payload {
            return Ok(None);
        }
        let (username, password) = plain_credentials(doc)?;
        Ok(Some(self.stash_credentials(username, password)))
    }

    fn stash_credentials(&mut self, username: String, password: String) -> AuthSelector {
        self.username = Some(username.clone());
        self.handshake_password = Some(Secret::new(password));
        AuthSelector::from(username)
    }

    /// Sends an authentication failure in whichever shape the current
    /// exchange calls for, and keeps the connection open for a retry.
    async fn send_auth_failure(&mut self, failure: AuthFailure) -> Result<(), MongoError> {
        match self.auth_reply_mode {
            AuthReplyMode::Sasl => {
                let mut doc = Document::new();
                doc.add("ok", 0.0_f64);
                doc.add("errmsg", failure.message.clone());
                doc.add("code", failure.code);
                doc.add("codeName", failure.code_name);
                self.send_reply_body(self.pending_request_id, command_body(doc)?)
                    .await
            }
            AuthReplyMode::SpeculativeHello => {
                let body = hello_with_speculative(Some(&failure))?;
                self.send_reply_body(self.pending_request_id, body).await
            }
        }
    }

    async fn send_error(&mut self, request_id: i32, failure: AuthFailure) -> Result<(), MongoError> {
        let mut doc = Document::new();
        doc.add("ok", 0.0_f64);
        doc.add("errmsg", failure.message);
        doc.add("code", failure.code);
        doc.add("codeName", failure.code_name);
        self.send_reply_body(request_id, command_body(doc)?).await
    }

    async fn send_reply(&mut self, response_to: i32, body: MessageBody) -> Result<(), MongoError> {
        self.send_reply_body(response_to, body).await
    }

    async fn send_reply_body(
        &mut self,
        response_to: i32,
        body: MessageBody,
    ) -> Result<(), MongoError> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        let header = Header::new(request_id, response_to, body.opcode());
        self.stream.push(&header, &body)?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn send_op_reply(&mut self, response_to: i32, reply: OpReply) -> Result<(), MongoError> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        let header = Header::new(request_id, response_to, Opcode::Reply);
        self.stream.push(&header, &MessageBody::Reply(reply))?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn run_authorized(mut self, approved: ApprovedTarget) -> Result<(), MongoError> {
        let Ok(approved) = approved.narrow::<TargetMongoOptions>() else {
            warn!("Selected target is not a MongoDB target");
            self.send_error(
                self.pending_request_id,
                AuthFailure::new(
                    9001,
                    "WarpgateTargetError",
                    "Warpgate target is not a MongoDB target",
                ),
            )
            .await?;
            return Ok(());
        };

        let admitted = self
            .server_handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?;

        self.run_authorized_inner(admitted).await
    }

    async fn run_authorized_inner(
        mut self,
        admitted: AdmittedTarget<TargetMongoOptions>,
    ) -> Result<(), MongoError> {
        let mut client = match MongoClient::connect(admitted).await {
            Ok(client) => client,
            Err(error) => {
                error!(%error, "Target connection failed");
                self.send_error(
                    self.pending_request_id,
                    AuthFailure::new(
                        9001,
                        "WarpgateTargetError",
                        "Failed to connect to the target database",
                    ),
                )
                .await?;
                return Err(error);
            }
        };
        info!("Relay started");

        loop {
            tokio::select! {
                c2s = self.stream.recv() => match c2s? {
                    Some((header, body)) => {
                        Self::log_client_msg(&body);
                        client.push(&header, &body)?;
                        client.flush().await?;
                    }
                    None => break,
                },
                s2c = client.recv() => match s2c? {
                    Some((header, body)) => {
                        self.stream.push(&header, &body)?;
                        self.stream.flush().await?;
                    }
                    None => break,
                },
            }
        }

        Ok(())
    }

    fn log_client_msg(body: &MessageBody) {
        let MessageBody::Msg(msg) = body else {
            return;
        };
        let doc = msg.document();
        match doc.command() {
            Ok(command) => {
                let db = doc
                    .get("$db")
                    .ok()
                    .flatten()
                    .and_then(|value| match value {
                        RawBsonRef::String(db) => Some(db.to_owned()),
                        _ => None,
                    })
                    .unwrap_or_default();
                info!(%command, %db, "Mongo command");
            }
            Err(error) => warn!(%error, "Unparseable client command"),
        }
    }
}

/// The outcome of inspecting a hello for speculative authentication.
enum SpeculativeAuth {
    /// No authentication attempt rode on the hello.
    None,
    /// Credentials were present; `Err` carries why they could not be used.
    Attempted(Result<AuthSelector, AuthFailure>),
}

/// Extracts PLAIN credentials from a SASL command document.
fn plain_credentials(doc: &RawDocument) -> Result<(String, String), AuthFailure> {
    let mechanism = match doc.get("mechanism").map_err(|e| auth_failure(e.to_string()))? {
        Some(RawBsonRef::String(name)) => name.to_owned(),
        _ => return Err(auth_failure("missing SASL mechanism")),
    };
    if mechanism != "PLAIN" {
        return Err(AuthFailure::new(
            18,
            "AuthenticationFailed",
            format!(
                "Only the PLAIN mechanism is supported; add ?authMechanism=PLAIN \
                 to your connection string (got {mechanism})"
            ),
        ));
    }
    let payload = match doc.get("payload").map_err(|e| auth_failure(e.to_string()))? {
        Some(RawBsonRef::Binary(binary)) => binary.bytes,
        Some(RawBsonRef::String(payload)) => payload.as_bytes().to_vec(),
        _ => return Err(auth_failure("missing SASL payload")),
    };
    let message =
        parse_client_payload(&payload).map_err(|e| auth_failure(e.to_string()))?;
    Ok((message.authc_id, message.password))
}

/// The `hello` reply, extended with the `speculativeAuthenticate` outcome the
/// driver expects when it attached credentials to its handshake.
fn hello_with_speculative(failure: Option<&AuthFailure>) -> Result<MessageBody, MongoError> {
    let reply = handshake_reply(&[], MAX_MESSAGE_SIZE, false)?;
    let mut doc = reply.document().shallow()?;
    let mut spec = Document::new();
    match failure {
        None => {
            spec.add("ok", 1.0_f64);
        }
        Some(failure) => {
            spec.add("ok", 0.0_f64);
            spec.add("errmsg", failure.message.clone());
            spec.add("code", failure.code);
            spec.add("codeName", failure.code_name);
        }
    }
    doc.replace("speculativeAuthenticate", Bson::Document(spec));
    command_body(doc)
}

fn command_body(doc: Document) -> Result<MessageBody, MongoError> {
    Ok(MessageBody::Msg(op_msg(MsgFlags::empty(), doc.encode()?)?))
}

fn empty_binary() -> Bson {
    Bson::Binary(Binary {
        subtype: BinarySubtype::Generic,
        bytes: Vec::new(),
    })
}

fn auth_failure(message: impl Into<String>) -> AuthFailure {
    AuthFailure::new(18, "AuthenticationFailed", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_credentials_roundtrip() {
        let mut doc = Document::new();
        doc.add("mechanism", "PLAIN");
        doc.add(
            "payload",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: b"\0user\0pass".to_vec(),
            }),
        );
        let raw = doc.encode().unwrap();
        let (username, password) = plain_credentials(&raw).unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    #[test]
    fn string_payloads_are_accepted() {
        let mut doc = Document::new();
        doc.add("mechanism", "PLAIN");
        doc.add("payload", "\0user\0pass");
        let raw = doc.encode().unwrap();
        let (username, password) = plain_credentials(&raw).unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    #[test]
    fn scram_mechanisms_point_at_plain() {
        let mut doc = Document::new();
        doc.add("mechanism", "SCRAM-SHA-256");
        doc.add(
            "payload",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: b"n,,n=user,r=abc".to_vec(),
            }),
        );
        let raw = doc.encode().unwrap();
        let failure = plain_credentials(&raw).unwrap_err();
        assert!(failure.message.contains("authMechanism=PLAIN"));
    }

    #[test]
    fn plain_without_password_fails() {
        let mut doc = Document::new();
        doc.add("mechanism", "PLAIN");
        doc.add(
            "payload",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes: b"authzid\0user".to_vec(),
            }),
        );
        let raw = doc.encode().unwrap();
        assert!(plain_credentials(&raw).is_err());
    }

    #[test]
    fn hello_reply_carries_speculative_success() {
        let body = hello_with_speculative(None).unwrap();
        let MessageBody::Msg(msg) = &body else {
            panic!("expected OP_MSG")
        };
        let doc = msg.document().shallow().unwrap();
        let Some(Bson::Document(spec)) = doc.get("speculativeAuthenticate") else {
            panic!("missing speculativeAuthenticate")
        };
        assert_eq!(spec.get("ok"), Some(&Bson::Double(1.0)));
        // The core handshake fields must survive the extension.
        assert_eq!(doc.get("maxWireVersion"), Some(&Bson::Int32(21)));
        assert_eq!(doc.get("isWritablePrimary"), Some(&Bson::Bool(true)));
    }

    #[test]
    fn hello_reply_reports_speculative_failure() {
        let failure = AuthFailure::new(18, "AuthenticationFailed", "nope");
        let body = hello_with_speculative(Some(&failure)).unwrap();
        let MessageBody::Msg(msg) = &body else {
            panic!("expected OP_MSG")
        };
        let doc = msg.document().shallow().unwrap();
        let Some(Bson::Document(spec)) = doc.get("speculativeAuthenticate") else {
            panic!("missing speculativeAuthenticate")
        };
        assert_eq!(spec.get("ok"), Some(&Bson::Double(0.0)));
        assert_eq!(spec.get("errmsg"), Some(&Bson::String("nope".to_owned())));
        assert_eq!(spec.get("code"), Some(&Bson::Int32(18)));
    }
}
