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

use crate::common::{compute_auth_challenge_response, parse_mysql_uri};
use crate::error::{MySqlError, InvalidMySqlTargetConfig};
use crate::stream::MySqlStream;
use crate::tls::configure_tls_connector;

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
    pub async fn connect(uri: &str, mut options: ConnectionOptions) -> Result<Self, MySqlError> {
        let opts = parse_mysql_uri(uri)?;
        let mut stream =
            MySqlStream::new(TcpStream::connect((opts.host.clone(), opts.port)).await?);

        options.capabilities.remove(Capabilities::SSL);
        if opts.ssl_mode != MySqlSslMode::Disabled {
            options.capabilities |= Capabilities::SSL;
        }

        let Some(payload) = stream.recv().await? else {
            return Err(MySqlError::Eof)
        };
        let handshake = Handshake::decode(payload)?;

        options.capabilities &= handshake.server_capabilities;
        if opts.ssl_mode != MySqlSslMode::Disabled
            && opts.ssl_mode != MySqlSslMode::Preferred
            && !options.capabilities.contains(Capabilities::SSL)
        {
            return Err(MySqlError::TlsNotSupported);
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
                        .map_err(|_| MySqlError::InvalidDomainName)?,
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
                                .map_err(MySqlError::other)?
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
            return Err(MySqlError::Eof)
        };
        if response.get(0) == Some(&0) || response.get(0) == Some(&0xfe) {
            debug!("Authorized");
        } else if response.get(0) == Some(&0xff) {
            let error = ErrPacket::decode_with(response, options.capabilities)?;
            return Err(MySqlError::ProtocolError(format!(
                "handshake failed: {:?}",
                error
            )));
        } else {
            return Err(MySqlError::ProtocolError(format!(
                "unknown response type {:?}",
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
