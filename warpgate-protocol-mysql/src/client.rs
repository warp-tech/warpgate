use std::error::Error;
use std::sync::Arc;

use bytes::BytesMut;
use sqlx_core_guts::io::Decode;
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{Handshake, HandshakeResponse, SslRequest};
use sqlx_core_guts::mysql::protocol::response::ErrPacket;
use sqlx_core_guts::mysql::protocol::Capabilities;
use sqlx_core_guts::mysql::MySqlSslMode;
use tokio::net::TcpStream;
use tracing::*;

use crate::common::{compute_auth_challenge_response, parse_mysql_uri, InvalidMySqlTargetConfig};
use crate::stream::{MySqlStream, MySqlStreamError};
use crate::tls::{configure_tls_connector, MaybeTlsStreamError, RustlsSetupError};

#[derive(thiserror::Error, Debug)]
pub enum MySqlClientError {
    #[error("Invalid target config")]
    InvalidTargetConfig(#[from] InvalidMySqlTargetConfig),
    #[error("protocol error")]
    ProtocolError(String),
    #[error("sudden disconnection")]
    Eof,
    #[error("server doesn't offer TLS")]
    TlsNotSupported,
    #[error("TLS setup failed")]
    TlsSetup(#[from] RustlsSetupError),
    #[error("TLS stream error")]
    Tls(#[from] MaybeTlsStreamError),
    #[error("Invalid domain name")]
    InvalidDomainName,
    #[error("sqlx")]
    Sqlx(#[from] sqlx_core_guts::error::Error),
    #[error("MySQL stream")]
    MySqlStream(#[from] MySqlStreamError),
    #[error("I/O")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] Box<dyn Error + Send + Sync>),
}

impl MySqlClientError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}

pub struct MySqlClient {
    pub stream: MySqlStream<tokio_rustls::client::TlsStream<TcpStream>>,
    pub capabilities: Capabilities,
}

pub struct ConnectionOptions {
    pub collation: u8,
    pub database: Option<String>,
    pub max_packet_size: u32,
    pub capabilities: Capabilities,
}

impl MySqlClient {
    pub async fn connect(
        uri: &str,
        mut options: ConnectionOptions,
    ) -> Result<Self, MySqlClientError> {
        let opts = parse_mysql_uri(uri)?;
        let mut stream =
            MySqlStream::new(TcpStream::connect((opts.host.clone(), opts.port)).await?);

        options.capabilities.remove(Capabilities::SSL);
        if opts.ssl_mode != MySqlSslMode::Disabled {
            options.capabilities |= Capabilities::SSL;
        }

        let Some(payload) = stream.recv().await? else {
            return Err(MySqlClientError::Eof)
        };
        let handshake = Handshake::decode(payload)?;

        options.capabilities &= handshake.server_capabilities;
        if opts.ssl_mode != MySqlSslMode::Disabled
            && opts.ssl_mode != MySqlSslMode::Preferred
            && !options.capabilities.contains(Capabilities::SSL)
        {
            return Err(MySqlClientError::TlsNotSupported);
        }

        debug!(?handshake, "Received handshake");
        debug!(capabilities=?options.capabilities, "Capabilities");

        if options.capabilities.contains(Capabilities::SSL)
            && opts.ssl_mode != MySqlSslMode::Disabled
        {
            let accept_invalid_certs = opts.ssl_mode == MySqlSslMode::Preferred;
            let accept_invalid_hostname = opts.ssl_mode != MySqlSslMode::VerifyIdentity;
            let client_config = Arc::new(
                configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None)
                    .await?,
            );
            let req = SslRequest {
                collation: options.collation,
                max_packet_size: options.max_packet_size,
            };
            stream.push(&req, options.capabilities)?;
            stream.flush().await?;
            stream = stream
                .upgrade((
                    opts.host
                        .as_str()
                        .try_into()
                        .map_err(|_| MySqlClientError::InvalidDomainName)?,
                    client_config,
                ))
                .await?;
            info!("Target connection upgraded to TLS");
        }

        let mut response = HandshakeResponse {
            auth_plugin: None,
            auth_response: None,
            collation: options.collation,
            database: options.database,
            max_packet_size: options.max_packet_size,
            username: opts.username,
        };

        if handshake.auth_plugin == Some(AuthPlugin::MySqlNativePassword) {
            let scramble_bytes = [
                &handshake.auth_plugin_data.first_ref()[..],
                &handshake.auth_plugin_data.last_ref()[..],
            ]
            .concat();
            match scramble_bytes.try_into() as Result<[u8; 20], Vec<u8>> {
                Err(scramble_bytes) => {
                    warn!("Invalid scramble length ({})", scramble_bytes.len());
                }
                Ok(scramble) => {
                    let Some(password) = opts.password else {
                        return Err(InvalidMySqlTargetConfig::NoPassword.into())
                    };
                    response.auth_plugin = Some(AuthPlugin::MySqlNativePassword);
                    response.auth_response = Some(
                        BytesMut::from(
                            compute_auth_challenge_response(scramble, &password)
                                .map_err(MySqlClientError::other)?
                                .as_bytes(),
                        )
                        .freeze(),
                    );
                    trace!(response=?response.auth_response, ?scramble, "auth");
                }
            }
        }

        stream.push(&response, options.capabilities)?;
        stream.flush().await?;

        let Some(response) = stream.recv().await? else {
            return Err(MySqlClientError::Eof)
        };
        if response.get(0) == Some(&0) || response.get(0) == Some(&0xfe) {
            debug!("Authorized");
        } else if response.get(0) == Some(&0xff) {
            let error = ErrPacket::decode_with(response, options.capabilities)?;
            return Err(MySqlClientError::ProtocolError(format!(
                "Handshake failed: {:?}",
                error
            )));
        } else {
            return Err(MySqlClientError::ProtocolError(format!(
                "Unknown response type {:?}",
                response.get(0)
            )));
        }

        stream.reset_sequence_id();

        Ok(Self {
            stream,
            capabilities: options.capabilities,
        })
    }
}
