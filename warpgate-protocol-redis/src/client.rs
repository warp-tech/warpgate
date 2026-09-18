use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use redis_protocol::codec::Resp3;
use redis_protocol::resp3::types::BytesFrame;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::info;
use warpgate_common::{RedisIamAuthService, RedisTargetAuth, TargetRedisOptions, WarpgateError};
use warpgate_tls::{ClientTlsStream, MaybeTlsStream, TlsMode, configure_tls_connector};

use crate::error::RedisError;

pub struct RedisClient {
    framed: Framed<MaybeTlsStream<TcpStream, ClientTlsStream<TcpStream>>, Resp3>,
}

impl RedisClient {
    pub async fn connect(target: &TargetRedisOptions) -> Result<Self, RedisError> {
        let tcp = TcpStream::connect((target.host.clone(), target.port)).await?;
        tcp.set_nodelay(true)?;

        let mut stream = MaybeTlsStream::<TcpStream, ClientTlsStream<TcpStream>>::new(tcp);

        if target.tls.mode != TlsMode::Disabled {
            let accept_invalid_certs = !target.tls.verify;
            let accept_invalid_hostname = false; // CA + hostname verification
            let client_config = Arc::new(
                configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None)
                    .await?,
            );
            let domain = target
                .host
                .clone()
                .try_into()
                .map_err(|_| RedisError::InvalidDomainName)?;
            stream = stream
                .upgrade((domain, client_config), Bytes::new())
                .await?;
            info!("Target connection established over TLS");
        }

        let mut framed = Framed::new(stream, Resp3::default());

        if let Some(auth) = &target.auth {
            let password = match auth {
                RedisTargetAuth::Password(auth) => auth
                    .password
                    .reveal()
                    .map_err(WarpgateError::from)?
                    .expose_secret()
                    .clone(),
                RedisTargetAuth::IamRole(role) => {
                    let cluster_id = target
                        .iam_cluster_id
                        .clone()
                        .unwrap_or_else(|| target.host.clone());
                    let region = target.iam_region.clone().ok_or_else(|| {
                        RedisError::ProtocolError(
                            "iam_region is required for IAM role authentication".into(),
                        )
                    })?;
                    let username = target.username.clone().unwrap_or_default();
                    let service = match role.service {
                        RedisIamAuthService::ElastiCache => {
                            warpgate_aws::RedisIamService::ElastiCache
                        }
                        RedisIamAuthService::MemoryDb => warpgate_aws::RedisIamService::MemoryDb,
                    };
                    warpgate_aws::generate_redis_iam_auth_token(
                        service,
                        &region,
                        &cluster_id,
                        &username,
                    )
                    .await
                    .map_err(WarpgateError::Aws)?
                }
            };

            let mut auth_args = vec![command_arg("AUTH")];
            if let Some(username) = &target.username {
                auth_args.push(command_arg(username));
            }
            auth_args.push(command_arg(&password));

            framed
                .send(BytesFrame::Array {
                    data: auth_args,
                    attributes: None,
                })
                .await?;
            expect_ok(&mut framed, "AUTH").await?;
        }

        if let Some(db) = target.database {
            framed
                .send(BytesFrame::Array {
                    data: vec![command_arg("SELECT"), command_arg(&db.to_string())],
                    attributes: None,
                })
                .await?;
            expect_ok(&mut framed, "SELECT").await?;
        }

        Ok(Self { framed })
    }

    pub async fn send(&mut self, frame: BytesFrame) -> Result<(), RedisError> {
        self.framed.send(frame).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<BytesFrame>, RedisError> {
        match self.framed.next().await {
            Some(Ok(frame)) => Ok(Some(frame)),
            Some(Err(error)) => Err(error.into()),
            None => Ok(None),
        }
    }
}

async fn expect_ok(
    framed: &mut Framed<MaybeTlsStream<TcpStream, ClientTlsStream<TcpStream>>, Resp3>,
    command: &str,
) -> Result<(), RedisError> {
    match framed.next().await {
        Some(Ok(BytesFrame::SimpleString { .. })) => Ok(()),
        Some(Ok(BytesFrame::SimpleError { data, .. })) => {
            Err(RedisError::RemoteError(data.to_string()))
        }
        Some(Ok(other)) => Err(RedisError::ProtocolError(format!(
            "Unexpected reply to {command}: {other:?}"
        ))),
        Some(Err(error)) => Err(error.into()),
        None => Err(RedisError::Eof),
    }
}

fn command_arg(s: &str) -> BytesFrame {
    BytesFrame::BlobString {
        data: Bytes::copy_from_slice(s.as_bytes()),
        attributes: None,
    }
}
