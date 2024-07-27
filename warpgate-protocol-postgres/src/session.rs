use std::fmt::Debug;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use pgwire::messages::response::TransactionStatus;
use pgwire::messages::startup::PasswordMessageFamily;
use pgwire::messages::PgWireFrontendMessage;
use rustls::ServerConfig;
use scram_rs::scram_async::AsyncScramServer;
use scram_rs::{
    AsyncScramAuthServer, ScramNonce, ScramPassword, ScramResult, ScramResultServer,
    ScramSha256RustNative, SCRAM_TYPES,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthSelector, CredentialKind};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{Secret, TargetMySqlOptions, TargetOptions};
use warpgate_core::{authorize_ticket, consume_ticket, Services, WarpgateServerHandle};

use crate::error::PostgresError;
use crate::stream::{PgWireGenericFrontendMessage, PgWireStartupOrSslRequest, PostgresStream};

pub struct PostgresSession {
    stream: PostgresStream<TlsStream<TcpStream>>,
    tls_config: Arc<ServerConfig>,
    // capabilities: Capabilities,
    // challenge: [u8; 20],
    username: Option<String>,
    database: Option<String>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: Uuid,
    services: Services,
    remote_address: SocketAddr,
}

#[derive(Debug)]
struct ScramHandler {
    pub username: String,
}

#[async_trait::async_trait]
impl scram_rs::AsyncScramCbHelper for &ScramHandler {
    async fn get_tls_server_endpoint(&self) -> ScramResult<Vec<u8>> {
        scram_rs::HELPER_UNSUP_SERVER!("endpoint");
    }

    async fn get_tls_unique(&self) -> ScramResult<Vec<u8>> {
        scram_rs::HELPER_UNSUP_SERVER!("unique");
    }

    async fn get_tls_exporter(&self) -> ScramResult<Vec<u8>> {
        scram_rs::HELPER_UNSUP_SERVER!("exporter");
    }
}

#[async_trait::async_trait]
impl AsyncScramAuthServer<ScramSha256RustNative> for &ScramHandler {
    async fn get_password_for_user(&self, _: &str) -> ScramResult<ScramPassword> {
        info!("get_password_for_user: {:?}", self.username);
        return if self.username == "user" {
            Ok(ScramPassword::found_plaintext_password::<
                ScramSha256RustNative,
            >("password".to_string().as_bytes(), None)?)
        } else {
            ScramPassword::not_found::<ScramSha256RustNative>()
        };
    }
}

impl PostgresSession {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: TcpStream,
        tls_config: ServerConfig,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.id();

        Self {
            services,
            tls_config: Arc::new(tls_config),
            stream: PostgresStream::new(stream),
            username: None,
            database: None,
            server_handle,
            id,
            remote_address,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        match self.username {
            Some(ref username) => {
                info_span!("PostgreSQL", session=%self.id, session_username=%username, %client_ip)
            }
            None => info_span!("PostgreSQL", session=%self.id, %client_ip),
        }
    }

    pub async fn run(mut self) -> Result<(), PostgresError> {
        let Some(mut initial_message) = self.stream.recv::<PgWireStartupOrSslRequest>().await?
        else {
            return Err(PostgresError::Eof);
        };

        if let PgWireStartupOrSslRequest::SslRequest(_) = &initial_message {
            debug!("Received SslRequest");
            self.stream
                .push(pgwire::messages::response::SslResponse::Accept)?;
            self.stream.flush().await?;
            self.stream = self.stream.upgrade(self.tls_config.clone()).await?;
            debug!("TLS setup complete");

            let Some(next_message) = self.stream.recv::<PgWireStartupOrSslRequest>().await? else {
                return Err(PostgresError::Eof);
            };

            initial_message = next_message;
        }

        let PgWireStartupOrSslRequest::Startup(startup) = initial_message else {
            return Err(PostgresError::ProtocolError("expected Startup".into()));
        };

        let authenticated_username = _run_sasl_auth(&mut self.stream, &startup).await?;
        info!("Authenticated as {authenticated_username}");

        self.stream
            .push(pgwire::messages::startup::Authentication::Ok)?;
        self.stream
            .push(pgwire::messages::response::ReadyForQuery::new(
                TransactionStatus::Idle,
            ))?;
        self.stream.flush().await?;

        self.run_authorized().await
    }

    async fn run_authorized(mut self) -> Result<(), PostgresError> {
        let resp = loop {
            let Some(payload) = self.stream.recv::<PgWireGenericFrontendMessage>().await? else {
                return Err(PostgresError::Eof);
            };
        };
    }
}

async fn _run_sasl_auth(
    stream: &mut PostgresStream<TlsStream<TcpStream>>,
    startup: &pgwire::messages::startup::Startup,
) -> Result<String, PostgresError> {
    let username = startup.parameters.get("user").cloned().unwrap_or("".into());
    stream.push(pgwire::messages::startup::Authentication::SASL(vec![
        "SCRAM-SHA-512".into(),
        "SCRAM-SHA-256".into(),
    ]))?;
    stream.flush().await?;

    let sasl_initial_response = {
        let Some(message) = stream.recv::<PgWireGenericFrontendMessage>().await? else {
            return Err(PostgresError::Eof);
        };

        let PgWireFrontendMessage::PasswordMessageFamily(message) = message.0 else {
            return Err(PostgresError::UnexpectedMessage(message.0));
        };

        let sasl_inital_response = message.into_sasl_initial_response()?;

        debug!("auth payload: {:?}", sasl_inital_response);
        sasl_inital_response
    };

    let scram_handler = ScramHandler {
        username: username.clone(),
    };
    let scramtype = SCRAM_TYPES
        .get_scramtype(sasl_initial_response.auth_method)
        .map_err(PostgresError::Sasl)?;
    let mut server = AsyncScramServer::<ScramSha256RustNative, _, _>::new(
        &scram_handler,
        &scram_handler,
        ScramNonce::none(),
        scramtype,
    )
    .unwrap();

    {
        let mut sasl_inbound_data = if let Some(data) = sasl_initial_response.data {
            String::from_utf8(data.to_vec())?
        } else {
            return Err(PostgresError::ProtocolError(
                "expected SASLInitialResponse data".into(),
            ));
        };

        loop {
            let sasl_result = server.parse_response(&sasl_inbound_data).await;
            debug!("sasl_result: {:?}", sasl_result);

            match &sasl_result {
                ScramResultServer::Final(data) => {
                    let bytes = data.as_bytes().to_vec();
                    stream.push(pgwire::messages::startup::Authentication::SASLFinal(
                        Bytes::from(bytes),
                    ))?;
                    stream.flush().await?;
                    return Ok(username);
                }
                ScramResultServer::Data(data) => {
                    let bytes = data.as_bytes().to_vec();
                    stream.push(pgwire::messages::startup::Authentication::SASLContinue(
                        Bytes::from(bytes),
                    ))?;
                    stream.flush().await?;
                }
                ScramResultServer::Error(err) => {
                    let bytes = err.serv_err_value().as_bytes().to_vec();
                    stream.push(pgwire::messages::startup::Authentication::SASLFinal(
                        Bytes::from(bytes),
                    ))?;
                    stream.flush().await?;
                    return Err(PostgresError::Sasl(err.clone()));
                }
            }

            let sasl_result = {
                let Some(message) = stream.recv::<PgWireGenericFrontendMessage>().await? else {
                    return Err(PostgresError::Eof);
                };

                let PgWireFrontendMessage::PasswordMessageFamily(message) = message.0 else {
                    return Err(PostgresError::UnexpectedMessage(message.0));
                };

                let Ok(sasl_result) = message.into_sasl_response() else {
                    return Err(PostgresError::ProtocolError("expected SASLResponse".into()));
                };

                debug!("auth payload: {:?}", sasl_result);
                sasl_result
            };

            sasl_inbound_data = String::from_utf8(sasl_result.data.to_vec())?;
        }
    }
}
