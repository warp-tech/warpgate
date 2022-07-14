use anyhow::{Context, Result};
use bytes::BytesMut;
use sqlx_core_guts::io::Decode;
use sqlx_core_guts::mysql::options::MySqlConnectOptions;
use sqlx_core_guts::mysql::protocol::auth::AuthPlugin;
use sqlx_core_guts::mysql::protocol::connect::{Handshake, HandshakeResponse};
use sqlx_core_guts::mysql::protocol::response::ErrPacket;
use sqlx_core_guts::mysql::protocol::Capabilities;
use tokio::net::TcpStream;
use tracing::*;

use crate::common::compute_auth_challenge_response;
use crate::stream::MySQLStream;

pub struct MySQLClient {
    pub stream: MySQLStream,
    pub capabilities: Capabilities,
}

pub struct ConnectionOptions {
    pub collation: u8,
    pub database: Option<String>,
    pub max_packet_size: u32,
    pub capabilities: Capabilities,
}

impl MySQLClient {
    pub async fn connect(uri: &str, mut options: ConnectionOptions) -> Result<Self> {
        let opts: MySqlConnectOptions = uri.parse()?;
        let mut stream = MySQLStream::new(TcpStream::connect((opts.host, opts.port)).await?);

        let payload = stream.recv().await?;
        let handshake = Handshake::decode(payload)?;

        options.capabilities &= handshake.server_capabilities;
        options.capabilities |= Capabilities::SSL;

        debug!(?handshake, "Received handshake");
        debug!(capabilities=?options.capabilities, "Capabilities");

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
                        error!("Password not set in the connection URI");
                        anyhow::bail!("Password not set");
                    };
                    response.auth_plugin = Some(AuthPlugin::MySqlNativePassword);
                    response.auth_response = Some(
                        BytesMut::from(
                            compute_auth_challenge_response(scramble, &password)?.as_bytes(),
                        )
                        .freeze(),
                    );
                    trace!(response=?response.auth_response, ?scramble, "auth");
                }
            }
        }

        stream.push(&response, options.capabilities)?;
        stream.flush().await?;

        let response = stream.recv().await?;
        if response.get(0) == Some(&0) || response.get(0) == Some(&0xfe) {
            debug!("Authorized");
        } else if response.get(0) == Some(&0xff) {
            let error = ErrPacket::decode_with(response, options.capabilities)?;
            error!(?error, "Handshake failed");
            anyhow::bail!("Handshake failed");
        } else {
            anyhow::bail!("Unknown response type {:?}", response.get(0));
        }

        stream.reset_sequence_id();

        Ok(Self {
            stream,
            capabilities: options.capabilities,
        })
    }
}
