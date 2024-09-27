use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use pgwire::messages::PgWireBackendMessage;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::*;
use warpgate_common::{configure_tls_connector, TargetPostgresOptions, TlsMode};

use crate::error::PostgresError;
use crate::stream::{PgWireGenericBackendMessage, PostgresEncode, PostgresStream};

pub struct PostgresClient {
    pub stream: PostgresStream<TlsStream<TcpStream>>,
}

pub struct ConnectionOptions {
    pub protocol_number_major: u16,
    pub protocol_number_minor: u16,
    pub parameters: BTreeMap<String, String>,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        ConnectionOptions {
            protocol_number_major: 3,
            protocol_number_minor: 0,
            parameters: BTreeMap::new(),
        }
    }
}

impl PostgresClient {
    pub async fn connect(
        target: &TargetPostgresOptions,
        options: ConnectionOptions,
    ) -> Result<Self, PostgresError> {
        let mut stream =
            PostgresStream::new(TcpStream::connect((target.host.clone(), target.port)).await?);

        if target.tls.mode != TlsMode::Disabled {
            stream.push(pgwire::messages::startup::SslRequest::new())?;
            stream.flush().await?;

            let Some(response) = stream
                .recv::<pgwire::messages::response::SslResponse>()
                .await?
            else {
                return Err(PostgresError::Eof);
            };

            match target.tls.mode {
                TlsMode::Disabled => unreachable!(),
                TlsMode::Required => {
                    if response == pgwire::messages::response::SslResponse::Refuse {
                        return Err(PostgresError::TlsNotSupported);
                    }
                }
                TlsMode::Preferred => {
                    if response == pgwire::messages::response::SslResponse::Refuse {
                        warn!("TLS not supported by target");
                    }
                }
            }

            if response == pgwire::messages::response::SslResponse::Accept {
                let accept_invalid_certs = !target.tls.verify;
                let accept_invalid_hostname = false; // ca + hostname verification
                let client_config = Arc::new(
                    configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None)
                        .await?,
                );

                stream = stream
                    .upgrade((
                        target
                            .host
                            .clone()
                            .try_into()
                            .map_err(|_| PostgresError::InvalidDomainName)?,
                        client_config,
                    ))
                    .await?;
                info!("Target connection upgraded to TLS");
            }
        }

        let mut startup = pgwire::messages::startup::Startup::new();
        startup.parameters = options.parameters.clone();
        startup
            .parameters
            .insert("user".to_owned(), target.username.clone());
        startup.protocol_number_major = options.protocol_number_major;
        startup.protocol_number_minor = options.protocol_number_minor;

        stream.push(startup)?;
        stream.flush().await?;

        loop {
            let Some(payload) = stream.recv::<PgWireGenericBackendMessage>().await? else {
                return Err(PostgresError::Eof);
            };

            match payload.0 {
                PgWireBackendMessage::ErrorResponse(err) => {
                    return Err(PostgresError::from(err));
                }
                PgWireBackendMessage::Authentication(auth) => {
                    match auth {
                        pgwire::messages::startup::Authentication::Ok => {
                            info!("Authenticated at target");
                            break;
                        }
                        pgwire::messages::startup::Authentication::CleartextPassword => {
                            // TODO test
                            let password = target
                                .password
                                .as_ref()
                                .ok_or(PostgresError::PasswordRequired)?;
                            let password_message =
                                pgwire::messages::startup::Password::new(password.into());
                            stream.push(password_message)?;
                            stream.flush().await?;
                        }
                        pgwire::messages::startup::Authentication::MD5Password(scramble) => {
                            // TODO test
                            let password = target
                                .password
                                .as_ref()
                                .ok_or(PostgresError::PasswordRequired)?;
                            let hashed = pgwire::api::auth::md5pass::hash_md5_password(
                                &target.username,
                                password,
                                &scramble,
                            );
                            let password_message = pgwire::messages::startup::Password::new(hashed);
                            stream.push(password_message)?;
                            stream.flush().await?;
                        }
                        // TODO SCRAM auth
                        x => {
                            return Err(PostgresError::ProtocolError(format!(
                                "Unsupported authentication method: {:?}",
                                x
                            )));
                        }
                    }
                }
                _ => {
                    return Err(PostgresError::ProtocolError(
                        "Expected authentication".to_owned(),
                    ));
                }
            }
        }

        Ok(Self { stream })
    }

    pub async fn recv(&mut self) -> Result<Option<PgWireGenericBackendMessage>, PostgresError> {
        self.stream
            .recv::<PgWireGenericBackendMessage>()
            .await
            .map_err(Into::into)
    }

    pub async fn send<M: PostgresEncode + Debug>(
        &mut self,
        message: M,
    ) -> Result<(), PostgresError> {
        self.stream.push(message)?;
        self.stream.flush().await?;
        Ok(())
    }
}
