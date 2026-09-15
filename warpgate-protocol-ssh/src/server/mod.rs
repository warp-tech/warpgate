mod channel_registry;
mod channel_writer;
mod event_intake;
mod russh_handler;
mod service_output;
mod session;
mod session_handle;
mod target_menu;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::{MethodKind, MethodSet, Preferred};
pub use russh_handler::ServerHandler;
pub use session::ServerSession;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::unbounded_channel;
use tracing::*;
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{Services, State, UserSessionStateInit};
use warpgate_db_entities::Parameters;

use crate::keys::load_host_keys;
use crate::server::session_handle::SSHSessionHandle;

#[derive(Clone)]
struct RusshConfigInit {
    keys: Vec<PrivateKey>,
}

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    proxy_protocol: bool,
) -> Result<BoxFuture<'static, Result<()>>> {
    let russh_config_init = Arc::new({
        RusshConfigInit {
            keys: load_host_keys(&services.db).await?,
        }
    });

    let listener = address.tcp_accept_stream().await?;

    Ok(async move {
        accept_loop(
            "SSH connection",
            listener,
            proxy_protocol,
            move |stream, remote_address| {
                let russh_config_init = russh_config_init.clone();
                let services = services.clone();
                async move {
                    _handle_connection(services, russh_config_init, stream, remote_address).await
                }
            },
        )
        .await;
        Ok(())
    }
    .boxed())
}

async fn _handle_connection(
    services: Services,
    russh_config_init: Arc<RusshConfigInit>,
    stream: TcpStream,
    remote_address: SocketAddr,
) -> Result<()> {
    let (session_handle, session_handle_rx) = SSHSessionHandle::new();

    // A second descriptor on the client socket. Everything else Warpgate can
    // say to a client goes through russh, which cannot act on any of it while
    // its loop is parked in a write the client never drains; `shutdown(2)`
    // through this descriptor fails that write from underneath.
    let client_socket = std::net::TcpStream::from(stream.as_fd().try_clone_to_owned()?);

    let (server_handle, wrapped_stream) = State::register_user_session_with_stream(
        &services.state,
        crate::PROTOCOL_NAME,
        UserSessionStateInit {
            remote_address: Some(remote_address),
            handle: Box::new(session_handle),
        },
        stream,
    )
    .await
    .context("registering session")?;

    let id = server_handle.lock().await.user_session_id();

    let (event_tx, event_rx) = unbounded_channel();

    let banner = {
        let db = &services.db;
        // Normalize line endings for terminal display.
        Parameters::Entity::get(db)
            .await?
            .banner_text()
            .map(|text| format!("{}\r\n", text.replace("\r\n", "\n").replace('\n', "\r\n")))
    };

    let handler = ServerHandler { event_tx, banner };

    let session = match ServerSession::start(
        remote_address,
        &services,
        server_handle,
        session_handle_rx,
        event_rx,
        client_socket,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            error!(%error, "Error setting up session");
            return Err(error);
        }
    };

    let russh_config = {
        let config = services.config.lock().await;

        russh::server::Config {
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            inactivity_timeout: Some(
                config.store.ssh.inactivity_timeout
                // There is no traffic during admin approval hold that would
                // reset the inactivity timer, so the timeout needs to be at least that long
                + services.admin_approval_timeout().await?
                // Extra time for the "closing due to inactivity" message to be sent
                + Duration::from_secs(10),
            ),
            keepalive_interval: config.store.ssh.keepalive_interval,
            methods: get_allowed_auth_methods(&services).await?,
            keys: russh_config_init.keys.clone(),
            event_buffer_size: 100,
            nodelay: true,
            preferred: Preferred {
                key: Cow::Borrowed(&[
                    Algorithm::Ed25519,
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    Algorithm::Rsa { hash: None },
                ]),
                ..<_>::default()
            },
            ..<_>::default()
        }
    };

    let russh_config = Arc::new(russh_config);

    tokio::task::Builder::new()
        .name(&format!("SSH {id} session"))
        .spawn(session)?;

    tokio::task::Builder::new()
        .name(&format!("SSH {id} protocol"))
        .spawn(_run_stream(russh_config, wrapped_stream, handler))?;

    Ok(())
}

async fn _run_stream<R>(
    config: Arc<russh::server::Config>,
    socket: R,
    handler: ServerHandler,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ret = async move {
        let session = russh::server::run_stream(config, socket, handler).await?;
        session.await?;
        Ok(())
    }
    .await;

    if let Err(ref error) = ret {
        error!(%error, "Session failed");
    }

    ret
}

pub async fn get_allowed_auth_methods(services: &Services) -> Result<MethodSet> {
    let parameters = {
        let db = &services.db;
        Parameters::Entity::get(db).await?
    };

    let mut methods_vec: Vec<MethodKind> = Vec::new();
    if parameters.ssh_client_auth_publickey {
        methods_vec.push(MethodKind::PublicKey);
    }
    if parameters.ssh_client_auth_password {
        methods_vec.push(MethodKind::Password);
    }
    if parameters.ssh_client_auth_keyboard_interactive {
        methods_vec.push(MethodKind::KeyboardInteractive);
    }

    if methods_vec.is_empty() {
        warn!(
            "All SSH authentication methods are disabled in parameters. Enabling all methods as fallback."
        );
        methods_vec = vec![
            MethodKind::PublicKey,
            MethodKind::Password,
            MethodKind::KeyboardInteractive,
        ];
    }

    Ok(MethodSet::from(&methods_vec[..]))
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::fd::AsFd;

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// A write parked on a peer that never reads must fail once the duplicate
    /// descriptor is shut down; that wake-up is what ends a stalled client.
    #[tokio::test]
    async fn shutdown_through_duplicate_fd_releases_parked_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let dup = std::net::TcpStream::from(server.as_fd().try_clone_to_owned().unwrap());

        let writer = tokio::spawn(async move {
            let chunk = vec![0u8; 65536];
            loop {
                if let Err(e) = server.write_all(&chunk).await {
                    return e;
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(!writer.is_finished(), "write never parked");

        dup.shutdown(Shutdown::Both).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), writer)
            .await
            .expect("write still parked after shutdown")
            .unwrap();
    }
}
