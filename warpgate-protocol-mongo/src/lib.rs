mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use futures::future::BoxFuture;
use mongowire::messages::Opcode;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{
    MaybeTlsStream, PrefixedStream, ResolveServerCert, ServerTlsStream, TlsCertificateAndPrivateKey,
};

use crate::session::MongoSession;
use crate::session_handle::MongoSessionHandle;

/// The client-facing transport: whichever of the two legs the first bytes
/// turned out to speak.
type ClientStream =
    MaybeTlsStream<PrefixedStream<TcpStream>, ServerTlsStream<PrefixedStream<TcpStream>>>;

/// Whether the first bytes on a connection are a plaintext MongoDB wire
/// message rather than a TLS ClientHello. A wire header is 16 bytes of which
/// the last four are an opcode; TLS records start with 0x16 and their bytes
/// at the opcode position are handshake payload (effectively random), so a
/// valid opcode there is a reliable plaintext signal.
fn is_plaintext_mongo(chunk: &[u8]) -> bool {
    if chunk.len() < 16 {
        return false;
    }
    let message_length = i32::from_le_bytes(chunk[0..4].try_into().expect("16 bytes checked"));
    let op_code = i32::from_le_bytes(chunk[12..16].try_into().expect("16 bytes checked"));
    (16..=crate::stream::MAX_MESSAGE_SIZE).contains(&message_length)
        && Opcode::from_i32(op_code).is_some()
}

/// Reads from the socket until at least a wire header (or a TLS record
/// header) has arrived.
async fn read_first_chunk(stream: &mut TcpStream) -> std::io::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(1024);
    while buf.len() < 16 {
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            break;
        }
    }
    Ok(buf)
}

pub struct MongoProtocolServer {
    services: Services,
}

impl MongoProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for MongoProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("MongoDB requires a TLS certificate and key")?;

        let tls_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(NoClientAuth))
        .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
            certificate_and_key.into(),
        ))));

        let listener = address.tcp_accept_stream().await?;
        // TLS is optional on the client leg: the first bytes decide whether
        // the connection speaks TLS or plaintext MongoDB (a plaintext
        // connection carries PLAIN credentials unencrypted, so it is logged).
        let tls_config = Arc::new(tls_config);

        let services = self.services;
        Ok(async move {
            accept_loop(
                "MongoDB connection",
                listener,
                proxy_protocol,
                move |mut stream, remote_address| {
                    let tls_config = tls_config.clone();
                    let services = services.clone();
                    async move {
                        let first = read_first_chunk(&mut stream).await?;
                        let transport: ClientStream = if is_plaintext_mongo(&first) {
                            warn!("Client connected without TLS; PLAIN credentials are sent unencrypted");
                            MaybeTlsStream::Raw(PrefixedStream::new(stream, first.freeze()))
                        } else {
                            MaybeTlsStream::new(PrefixedStream::new(stream, first.freeze()))
                                .upgrade(tls_config, Bytes::new())
                                .await
                                .context("TLS handshake failed")?
                        };

                        let (session_handle, mut abort_rx) = MongoSessionHandle::new();

                        let (server_handle, wrapped_stream) =
                            State::register_user_session_with_stream(
                                &services.state,
                                crate::common::PROTOCOL_NAME,
                                UserSessionStateInit {
                                    remote_address: Some(remote_address),
                                    handle: Box::new(session_handle),
                                },
                                transport,
                            )
                            .await
                            .context("registering session")?;

                        let session =
                            MongoSession::new(server_handle, services, wrapped_stream, remote_address)
                                .await;
                        let span = session.make_logging_span();
                        tokio::select! {
                            result = session.run().instrument(span) => match result {
                                Ok(()) => info!("Session ended"),
                                Err(e) => error!(error=%e, "Session failed"),
                            },
                            _ = abort_rx.recv() => {
                                warn!("Session aborted by admin");
                            },
                        }

                        Ok(())
                    }
                },
            )
            .await;
            Ok(())
        }
        .boxed())
    }

    fn name(&self) -> &'static str {
        "MongoDB"
    }
}

impl Debug for MongoProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoProtocolServer").finish()
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use wirebson::Document;

    use super::*;

    fn plaintext_hello_frame() -> BytesMut {
        let mut doc = Document::new();
        doc.add("hello", 1_i32);
        let body = mongowire::MessageBody::Msg(
            mongowire::api::response::op_msg(mongowire::messages::MsgFlags::empty(), doc.encode().unwrap())
                .unwrap(),
        );
        let mut header = mongowire::messages::Header::new(1, 0, mongowire::messages::Opcode::Msg);
        let mut out = BytesMut::new();
        mongowire::framing::encode_message(&mut header, &body, false, &mut out).unwrap();
        out
    }

    #[test]
    fn plaintext_wire_frame_is_detected() {
        assert!(is_plaintext_mongo(&plaintext_hello_frame()));
    }

    #[test]
    fn tls_client_hello_is_not_plaintext() {
        // A TLS record: content type 0x16, legacy version 0x0301, then a
        // length — the bytes at the opcode position are handshake data.
        let hello: [u8; 16] = [
            0x16, 0x03, 0x01, 0x00, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(!is_plaintext_mongo(&hello));
    }

    #[test]
    fn short_chunks_are_not_plaintext() {
        assert!(!is_plaintext_mongo(&[]));
        assert!(!is_plaintext_mongo(&[0x0d, 0x00, 0x00]));
    }

    #[test]
    fn absurd_lengths_are_not_plaintext() {
        let mut chunk = [0u8; 16];
        chunk[0..4].copy_from_slice(&i32::MAX.to_le_bytes());
        chunk[12..16].copy_from_slice(&2013_i32.to_le_bytes());
        assert!(!is_plaintext_mongo(&chunk));
    }
}
