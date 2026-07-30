use std::sync::Arc;

use bytes::Bytes;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;
use tokio::net::TcpStream;
use tracing::{debug, info};
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{TargetMySqlOptions, WarpgateError};
use warpgate_database_protocols::io::Decode;
use warpgate_database_protocols::mysql::protocol::Capabilities;
use warpgate_database_protocols::mysql::protocol::auth::AuthPlugin;
use warpgate_database_protocols::mysql::protocol::connect::{
    AuthSwitchRequest, AuthSwitchResponse, Handshake, HandshakeResponse, SslRequest,
};
use warpgate_database_protocols::mysql::protocol::response::ErrPacket;
use warpgate_tls::{ClientTlsStream, TlsMode, configure_tls_connector};

use crate::common::{compute_auth_challenge_response, compute_sha2_auth_challenge_response};
use crate::error::MySqlError;
use crate::stream::MySqlStream;

pub struct MySqlClient {
    pub stream: MySqlStream<TcpStream, ClientTlsStream<TcpStream>>,
    pub capabilities: Capabilities,
}

pub struct ConnectionOptions {
    pub collation: u8,
    pub database: Option<String>,
    pub max_packet_size: u32,
    pub capabilities: Capabilities,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            collation: 33,
            database: None,
            max_packet_size: 0xffff_ffff,
            capabilities: Capabilities::PROTOCOL_41
                | Capabilities::PLUGIN_AUTH
                | Capabilities::FOUND_ROWS
                | Capabilities::LONG_FLAG
                | Capabilities::NO_SCHEMA
                | Capabilities::PLUGIN_AUTH_LENENC_DATA
                | Capabilities::CONNECT_WITH_DB
                | Capabilities::SESSION_TRACK
                | Capabilities::IGNORE_SPACE
                | Capabilities::INTERACTIVE
                | Capabilities::TRANSACTIONS
                | Capabilities::DEPRECATE_EOF
                | Capabilities::SECURE_CONNECTION
                | Capabilities::SSL,
        }
    }
}

impl MySqlClient {
    pub async fn connect(
        target: &TargetMySqlOptions,
        mut options: ConnectionOptions,
    ) -> Result<Self, MySqlError> {
        let stream = TcpStream::connect((target.host.clone(), target.port)).await?;
        stream.set_nodelay(true)?;

        let mut stream = MySqlStream::new(stream);

        options.capabilities.remove(Capabilities::SSL);
        if target.tls.mode != TlsMode::Disabled {
            options.capabilities |= Capabilities::SSL;
        }

        let Some(payload) = stream.recv().await? else {
            return Err(MySqlError::Eof);
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
                        .clone()
                        .try_into()
                        .map_err(|_| MySqlError::InvalidDomainName)?,
                    client_config,
                ))
                .await?;
            info!("Target connection upgraded to TLS");
        }

        // Resolve the effective password (may be an IAM-generated token or legacy field)
        let effective_password = match &target.effective_auth() {
            warpgate_common::DatabaseTargetAuth::Password(auth) => auth.password.clone(),
            warpgate_common::DatabaseTargetAuth::IamRole(_) => {
                warpgate_aws::generate_rds_auth_token(&target.host, target.port, &target.username)
                    .await
                    .map_err(WarpgateError::Aws)?
            }
        };

        // Servers without PLUGIN_AUTH are pre-plugin and expect mysql_native_password
        let mut auth_plugin = handshake
            .auth_plugin
            .unwrap_or(AuthPlugin::MySqlNativePassword);
        let mut nonce = [
            &handshake.auth_plugin_data.first_ref()[..],
            &handshake.auth_plugin_data.last_ref()[..],
        ]
        .concat();

        let response = HandshakeResponse {
            auth_plugin: Some(auth_plugin),
            auth_response: Some(Bytes::from(auth_response(
                auth_plugin,
                &nonce,
                &effective_password,
                stream.is_tls(),
            )?)),
            collation: options.collation,
            database: options.database,
            max_packet_size: options.max_packet_size,
            username: target.username.clone(),
        };

        stream.push(&response, options.capabilities)?;
        stream.flush().await?;

        loop {
            let Some(payload) = stream.recv().await? else {
                return Err(MySqlError::Eof);
            };
            match payload.first() {
                Some(&0) => {
                    debug!("Authorized");
                    break;
                }
                Some(&0xff) => {
                    let error = ErrPacket::decode_with(payload, options.capabilities)?;
                    return Err(MySqlError::ProtocolError(format!(
                        "handshake failed: {error:?}"
                    )));
                }
                Some(&0xfe) => {
                    let req = AuthSwitchRequest::decode(payload)?;
                    auth_plugin = req.plugin;
                    nonce = req.data.to_vec();
                    let response =
                        auth_response(auth_plugin, &nonce, &effective_password, stream.is_tls())?;
                    stream.push(&AuthSwitchResponse(response), options.capabilities)?;
                    stream.flush().await?;
                }
                Some(&1) if auth_plugin == AuthPlugin::CachingSha2Password => {
                    match payload.get(1) {
                        // Fast auth succeeded; an OK packet follows
                        Some(&3) => (),
                        // Server requests full authentication
                        Some(&4) => {
                            let response =
                                caching_sha2_full_auth(&mut stream, &nonce, &effective_password)
                                    .await?;
                            stream.push(&&response[..], ())?;
                            stream.flush().await?;
                        }
                        other => {
                            return Err(MySqlError::ProtocolError(format!(
                                "unknown caching_sha2_password status {other:?}"
                            )));
                        }
                    }
                }
                other => {
                    return Err(MySqlError::ProtocolError(format!(
                        "unknown response type {other:?}"
                    )));
                }
            }
        }

        stream.reset_sequence_id();

        Ok(Self {
            stream,
            capabilities: options.capabilities,
        })
    }
}

fn password_nul(password: &str) -> Vec<u8> {
    let mut bytes = password.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn auth_response(
    plugin: AuthPlugin,
    nonce: &[u8],
    password: &str,
    is_tls: bool,
) -> Result<Vec<u8>, MySqlError> {
    match plugin {
        AuthPlugin::MySqlNativePassword => {
            let nonce: [u8; 20] = nonce.try_into().map_err(|_| {
                MySqlError::ProtocolError(format!("invalid auth challenge length {}", nonce.len()))
            })?;
            Ok(compute_auth_challenge_response(nonce, password).to_vec())
        }
        AuthPlugin::CachingSha2Password => {
            Ok(compute_sha2_auth_challenge_response(nonce, password).to_vec())
        }
        // These plugins expect the password in cleartext, which is only
        // acceptable over an encrypted connection
        AuthPlugin::MySqlClearPassword | AuthPlugin::Sha256Password if is_tls => {
            Ok(password_nul(password))
        }
        AuthPlugin::MySqlClearPassword | AuthPlugin::Sha256Password => {
            Err(MySqlError::ProtocolError(format!(
                "target requests {} authentication, which is only supported over a TLS target connection",
                plugin.name()
            )))
        }
    }
}

/// cleartext over TLS, otherwise
/// RSA with a public key requested from the server
/// https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
async fn caching_sha2_full_auth(
    stream: &mut MySqlStream<TcpStream, ClientTlsStream<TcpStream>>,
    nonce: &[u8],
    password: &str,
) -> Result<Vec<u8>, MySqlError> {
    if stream.is_tls() {
        return Ok(password_nul(password));
    }

    stream.push(&&[2_u8][..], ())?;
    stream.flush().await?;
    let Some(payload) = stream.recv().await? else {
        return Err(MySqlError::Eof);
    };
    let pem = payload
        .get(1..)
        .filter(|_| payload.first() == Some(&1))
        .ok_or_else(|| {
            MySqlError::ProtocolError("expected an RSA public key response".to_owned())
        })?;
    let key =
        RsaPublicKey::from_public_key_pem(std::str::from_utf8(pem).map_err(MySqlError::other)?)
            .map_err(MySqlError::other)?;

    let mut masked_password = password_nul(password);
    masked_password
        .iter_mut()
        .zip(nonce.iter().cycle())
        .for_each(|(byte, nonce_byte)| *byte ^= *nonce_byte);

    key.encrypt(&mut get_crypto_rng(), Oaep::<Sha1>::new(), &masked_password)
        .map_err(MySqlError::other)
}
