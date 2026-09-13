use std::sync::Arc;

use bytes::Bytes;
use mongo_common::auth::scram::{ScramClient, ScramMechanism};
use mongo_common::bson::{Binary, BinarySubtype};
use tokio::net::TcpStream;
use tracing::{debug, info};
use warpgate_common::{DatabaseTargetAuth, TargetMongoOptions, WarpgateError};
use warpgate_core::AdmittedTarget;
use warpgate_tls::{MaybeTlsStream, TlsMode, configure_tls_connector};
use wirebson::{Bson, Document};

use mongowire::MessageBody;
use mongowire::api::response::op_msg;
use mongowire::messages::{Header, MsgFlags};

use crate::error::MongoError;
use crate::stream::MongoStream;

pub struct MongoClient {
    stream:
        MongoStream<MaybeTlsStream<TcpStream, warpgate_tls::ClientTlsStream<TcpStream>>>,
    request_id: i32,
}

impl MongoClient {
    pub async fn connect(approved: AdmittedTarget<TargetMongoOptions>) -> Result<Self, MongoError> {
        let target = approved.specific_target().options().clone();
        let stream = TcpStream::connect((target.host.clone(), target.port)).await?;
        stream.set_nodelay(true)?;

        let mut maybe = MaybeTlsStream::new(stream);
        // There is no in-protocol TLS upgrade in MongoDB: a port either speaks
        // TLS from the first byte or it does not, so any non-Disabled mode
        // means "connect with TLS".
        if target.tls.mode != TlsMode::Disabled {
            let accept_invalid_certs = !target.tls.verify;
            let accept_invalid_hostname = false; // ca + hostname verification
            let client_config = Arc::new(
                configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None)
                    .await?,
            );
            let server_name = target
                .host
                .clone()
                .try_into()
                .map_err(|_| MongoError::InvalidDomainName)?;
            maybe = maybe
                .upgrade((server_name, client_config), Bytes::new())
                .await?;
            info!("Target connection upgraded to TLS");
        }

        let mut client = Self {
            stream: MongoStream::new(maybe),
            request_id: 0,
        };
        client.authenticate(&target).await?;
        Ok(client)
    }

    pub fn push(&mut self, header: &Header, body: &MessageBody) -> Result<(), MongoError> {
        self.stream.push(header, body)
    }

    pub async fn recv(&mut self) -> Result<Option<(Header, MessageBody)>, MongoError> {
        self.stream.recv().await
    }

    pub async fn flush(&mut self) -> Result<(), MongoError> {
        Ok(self.stream.flush().await?)
    }

    /// Authenticates against the target with SCRAM-SHA-256 — the standard
    /// mechanism every MongoDB 4.0+ server accepts, with or without TLS —
    /// using the credentials stored on the target.
    async fn authenticate(&mut self, target: &TargetMongoOptions) -> Result<(), MongoError> {
        let password = match &target.auth {
            DatabaseTargetAuth::Password(auth) => auth
                .password
                .reveal()
                .map_err(WarpgateError::from)?
                .expose_secret()
                .clone(),
            DatabaseTargetAuth::IamRole(_) => {
                return Err(MongoError::UnsupportedUpstreamAuth(
                    "IAM role authentication is not supported for MongoDB targets".into(),
                ));
            }
        };
        let auth_db = target
            .auth_source
            .clone()
            .unwrap_or_else(|| "admin".to_owned());

        // Prime the connection with hello; a server that is not speaking
        // MongoDB fails here with a readable error.
        let mut hello = Document::new();
        hello.add("hello", 1_i32);
        hello.add("helloOk", true);
        hello.add("$db", "admin".to_owned());
        let (_, reply) = self.round_trip(hello).await?;
        let doc = reply_doc(&reply)?;
        require_ok(&doc, "hello")?;
        debug!("Target hello ok");

        let mut scram = ScramClient::new(ScramMechanism::Sha256, &target.username, &password)?;
        let client_first = scram.client_first_message()?;

        let mut sasl_start = Document::new();
        sasl_start.add("saslStart", 1_i32);
        sasl_start.add("mechanism", "SCRAM-SHA-256".to_owned());
        sasl_start.add("payload", binary_bson(client_first.into_bytes()));
        sasl_start.add("$db", auth_db.clone());
        let (_, reply) = self.round_trip(sasl_start).await?;
        let doc = reply_doc(&reply)?;
        require_ok(
            &doc,
            &format!(
                "saslStart (authenticating user '{}' against authSource '{}')",
                target.username, auth_db
            ),
        )?;
        let conversation_id = conversation_id(&doc)?;
        scram.receive_server_first(&payload_str(&doc)?)?;

        let client_final = scram.client_final_message()?;
        let mut sasl_continue = Document::new();
        sasl_continue.add("saslContinue", 1_i32);
        sasl_continue.add("conversationId", conversation_id);
        sasl_continue.add("payload", binary_bson(client_final.into_bytes()));
        sasl_continue.add("$db", auth_db.clone());
        let (_, reply) = self.round_trip(sasl_continue).await?;
        let doc = reply_doc(&reply)?;
        require_ok(&doc, "saslContinue")?;

        // The server-final signature rides on this reply, but MongoDB keeps
        // `done: false` until the client acknowledges with an empty-payload
        // saslContinue — without that round trip the server still considers
        // the exchange in progress and rejects subsequent commands.
        let mut server_final = payload_str(&doc).unwrap_or_default();
        if is_done(&doc) == Some(false) {
            let mut ack = Document::new();
            ack.add("saslContinue", 1_i32);
            ack.add("conversationId", conversation_id);
            ack.add("payload", binary_bson(Vec::new()));
            ack.add("$db", auth_db);
            let (_, reply) = self.round_trip(ack).await?;
            let doc = reply_doc(&reply)?;
            require_ok(&doc, "saslContinue")?;
            if server_final.is_empty() {
                server_final = payload_str(&doc)?;
            }
        }
        scram.receive_server_final(&server_final)?;

        info!(username=%target.username, "Authorized against the target");
        Ok(())
    }

    /// Sends one OP_MSG command document and reads the reply answering it.
    async fn round_trip(&mut self, doc: Document) -> Result<(Header, MessageBody), MongoError> {
        let raw = doc.encode()?;
        let body = MessageBody::Msg(op_msg(MsgFlags::empty(), raw)?);
        self.request_id = self.request_id.wrapping_add(1);
        let header = Header::new(self.request_id, 0, body.opcode());
        self.stream.push(&header, &body)?;
        self.stream.flush().await?;

        loop {
            let Some((header, body)) = self.stream.recv().await? else {
                return Err(MongoError::Eof);
            };
            if header.response_to != self.request_id {
                continue;
            }
            return Ok((header, body));
        }
    }
}

/// Decodes an OP_MSG reply into an eager document.
fn reply_doc(body: &MessageBody) -> Result<Document, MongoError> {
    match body {
        MessageBody::Msg(msg) => Ok(msg.document().shallow()?),
        _ => Err(MongoError::ProtocolError(
            "unexpected reply type from target".into(),
        )),
    }
}

fn require_ok(doc: &Document, command: &str) -> Result<(), MongoError> {
    let ok = match doc.get("ok") {
        Some(Bson::Double(value)) => *value == 1.0,
        Some(Bson::Int32(1)) | Some(Bson::Int64(1)) => true,
        _ => false,
    };
    if ok {
        return Ok(());
    }
    let message = match doc.get("errmsg") {
        Some(Bson::String(message)) => message.clone(),
        _ => "unknown error".to_owned(),
    };
    Err(MongoError::ProtocolError(format!(
        "target {command} failed: {message}"
    )))
}

/// `done` is absent on replies that complete the exchange.
fn is_done(doc: &Document) -> Option<bool> {
    match doc.get("done") {
        Some(Bson::Bool(done)) => Some(*done),
        _ => None,
    }
}

fn conversation_id(doc: &Document) -> Result<i32, MongoError> {
    match doc.get("conversationId") {
        Some(Bson::Int32(id)) => Ok(*id),
        Some(Bson::Int64(id)) => i32::try_from(*id)
            .map_err(|_| MongoError::InvalidAuthPayload("conversationId out of range".into())),
        _ => Err(MongoError::InvalidAuthPayload(
            "missing conversationId".into(),
        )),
    }
}

fn payload_str(doc: &Document) -> Result<String, MongoError> {
    match doc.get("payload") {
        Some(Bson::Binary(binary)) => String::from_utf8(binary.bytes.clone())
            .map_err(|_| MongoError::InvalidAuthPayload("non-UTF-8 SASL payload".into())),
        Some(Bson::String(payload)) => Ok(payload.clone()),
        _ => Err(MongoError::InvalidAuthPayload("missing SASL payload".into())),
    }
}

fn binary_bson(bytes: Vec<u8>) -> Bson {
    Bson::Binary(Binary {
        subtype: BinarySubtype::Generic,
        bytes,
    })
}
