use std::sync::Arc;

use bytes::BytesMut;
use tokio::net::TcpStream;
use tracing::*;
use warpgate_common::{TargetMySqlOptions, TlsMode};
use warpgate_database_protocols::io::Decode;
use warpgate_database_protocols::mysql::protocol::auth::AuthPlugin;
use warpgate_database_protocols::mysql::protocol::connect::{
    Handshake, HandshakeResponse, SslRequest,
};
use warpgate_database_protocols::mysql::protocol::response::ErrPacket;
use warpgate_database_protocols::mysql::protocol::Capabilities;

use crate::common::compute_auth_challenge_response;
use crate::error::MySqlError;
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
    pub async fn connect(
        target: &TargetMySqlOptions,
        mut options: ConnectionOptions,
    ) -> Result<Self, MySqlError> {
        let mut stream =
            MySqlStream::new(TcpStream::connect((target.host.clone(), target.port)).await?);

        options.capabilities.remove(Capabilities::SSL);
        if target.tls.mode != TlsMode::Disabled {
            options.capabilities |= Capabilities::SSL;
        }

        let Some(payload) = stream.recv().await? else {
            return Err(MySqlError::Eof)
        };
        let handshake = Handshake::decode(payload)?;

        options.capabilities &= handshake.server_capabilities;
        if target.tls.mode == TlsMode::Required && !options.capabilities.contains(Capabilities::SSL)
        {
            return Err(MySqlError::TlsNotSupported);
        }

        info!(capabilities=?options.capabilities, "Target handshake");

        if options.capabilities.contains(Capabilities::SSL) && target.tls.mode != TlsMode::Disabled
        {
            let accept_invalid_certs = !target.tls.verify;
            let accept_invalid_hostname = false; // ca + hostname verification
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
                    target
                        .host
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
            username: target.username.clone(),
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
                    response.auth_plugin = Some(AuthPlugin::MySqlNativePassword);
                    response.auth_response = Some(
                        BytesMut::from(
                            compute_auth_challenge_response(
                                scramble,
                                target.password.as_deref().unwrap_or(""),
                            )
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
