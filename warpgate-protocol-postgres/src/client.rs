use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Write;
use std::sync::Arc;

use pgwire::messages::PgWireBackendMessage;
use rsasl::config::SASLConfig;
use rsasl::prelude::{Mechname, SASLClient};
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

struct SaslBufferWriter<'a>(&'a mut Option<Vec<u8>>);

impl Write for SaslBufferWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(data) = self.0.as_mut() {
            data.extend_from_slice(buf);
        } else {
            *self.0 = Some(buf.to_vec());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PostgresClient {
    pub async fn connect(
        target: &TargetPostgresOptions,
        options: ConnectionOptions,
    ) -> Result<Self, PostgresError> {
        let stream = TcpStream::connect((target.host.clone(), target.port)).await?;
        stream.set_nodelay(true)?;

        let mut stream = PostgresStream::new(stream);

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

            let get_password = || {
                target
                    .password
                    .as_ref()
                    .ok_or(PostgresError::PasswordRequired)
            };

            match payload.0 {
                PgWireBackendMessage::ErrorResponse(err) => {
                    return Err(PostgresError::from(err));
                }
                PgWireBackendMessage::Authentication(auth) => match auth {
                    pgwire::messages::startup::Authentication::Ok => {
                        info!("Authenticated at target");
                        break;
                    }
                    pgwire::messages::startup::Authentication::CleartextPassword => {
                        let password = get_password()?;
                        let password_message =
                            pgwire::messages::startup::Password::new(password.into());
                        stream.push(password_message)?;
                        stream.flush().await?;
                    }
                    pgwire::messages::startup::Authentication::MD5Password(scramble) => {
                        let password = get_password()?;
                        let hashed = pgwire::api::auth::md5pass::hash_md5_password(
                            &target.username,
                            password,
                            &scramble,
                        );
                        let password_message = pgwire::messages::startup::Password::new(hashed);
                        stream.push(password_message)?;
                        stream.flush().await?;
                    }
                    pgwire::messages::startup::Authentication::SASL(mechanisms) => {
                        let password = get_password()?;
                        PostgresClient::run_sasl_auth(
                            &mut stream,
                            mechanisms,
                            &target.username,
                            password,
                        )
                        .await?;
                    }
                    x => {
                        return Err(PostgresError::ProtocolError(format!(
                            "Unsupported authentication method: {:?}",
                            x
                        )));
                    }
                },
                _ => {
                    return Err(PostgresError::ProtocolError(
                        "Expected authentication".to_owned(),
                    ));
                }
            }
        }

        Ok(Self { stream })
    }

    async fn run_sasl_auth(
        stream: &mut PostgresStream<TlsStream<TcpStream>>,
        mechanisms: Vec<String>,
        username: &str,
        password: &str,
    ) -> Result<(), PostgresError> {
        let cfg = SASLConfig::with_credentials(None, username.into(), password.into())?;
        let sasl = SASLClient::new(cfg);
        let mut session = sasl.start_suggested(
            &mechanisms
                .iter()
                .map(|x| Mechname::parse(x.as_bytes()))
                .filter_map(Result::ok)
                .collect::<Vec<_>>(),
        )?;

        let mut data: Option<Vec<u8>> = None;
        if !session.are_we_first() {
            return Err(PostgresError::ProtocolError(
                "SASL mechanism expects server to send data first".to_owned(),
            ));
        }

        let mut is_first_response = true;
        while {
            let mut data_to_send = None;

            let state = {
                let mut writer = SaslBufferWriter(&mut data_to_send);
                session.step(data.as_deref(), &mut writer)?
            };

            if let Some(data) = data_to_send {
                if is_first_response {
                    let selected_mechanism = session.get_mechname();
                    debug!("Selected SASL mechanism: {selected_mechanism:?}");
                    stream.push(pgwire::messages::startup::SASLInitialResponse::new(
                        selected_mechanism.to_string(),
                        Some(data.into()),
                    ))?;
                    is_first_response = false;
                } else {
                    stream.push(pgwire::messages::startup::SASLResponse::new(data.into()))?;
                };
                stream.flush().await?;
            }

            state.is_running()
        } {
            let Some(payload) = stream.recv::<PgWireGenericBackendMessage>().await? else {
                return Err(PostgresError::Eof);
            };

            match payload.0 {
                PgWireBackendMessage::ErrorResponse(response) => return Err(response.into()),
                PgWireBackendMessage::Authentication(
                    pgwire::messages::startup::Authentication::SASLContinue(msg),
                ) => {
                    data = Some(msg.to_vec());
                }
                PgWireBackendMessage::Authentication(
                    pgwire::messages::startup::Authentication::SASLFinal(msg),
                ) => {
                    data = Some(msg.to_vec());
                }
                payload => {
                    return Err(PostgresError::ProtocolError(format!(
                        "Unexpected message: {payload:?}",
                    )));
                }
            }
        }

        Ok(())
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
