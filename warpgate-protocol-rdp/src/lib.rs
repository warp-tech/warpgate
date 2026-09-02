#![feature(once_cell_try)]
//! In-workspace RDP integration for Warpgate.
//!
//! [`client`] drives IronRDP against a target host; [`server`] runs IronRDP's server state
//! machine for native RDP viewers (mstsc/FreeRDP) connecting to Warpgate's RDP port. Both
//! speak the shared [`DesktopEvent`]/[`DesktopInput`] streams, so the web-desktop manager
//! and browser canvas renderer work against either front end unchanged.

mod client;
mod clipboard;
mod server;
mod session_handle;

use anyhow::Context;
use futures::future::BoxFuture;
pub use server::bind_server;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tracing::{Instrument, error, info_span};
use warpgate_common::{ListenEndpoint, Protocol, TargetRdpOptions, TargetSessionId, WarpgateError};
use warpgate_core::{
    ApprovedTarget, DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopClientHandles, DesktopEvent,
    DesktopInput, DesktopState, LogonState, ProtocolServer, Services,
};
use warpgate_tls::TlsCertificateAndPrivateKey;

use crate::client::LogonWatcher;

pub const PROTOCOL_NAME: Protocol = Protocol::Rdp;

pub use warpgate_desktop_ui::DEFAULT_SIZE;

/// The native RDP server endpoint. Standard RDP clients (mstsc/FreeRDP) connect
/// directly to Warpgate's RDP port; per connection it brokers between the viewer-facing
/// RDP server and a target-facing client (see [`server`]).
pub struct RdpProtocolServer {
    services: Services,
}

impl RdpProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for RdpProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("RDP requires a TLS certificate and key")?;
        let cert_pem = String::from_utf8(certificate_and_key.certificate.bytes().to_vec())
            .context("RDP TLS certificate is not valid UTF-8 PEM")?;
        let key_pem = String::from_utf8(certificate_and_key.private_key.bytes().to_vec())
            .context("RDP TLS private key is not valid UTF-8 PEM")?;
        bind_server(self.services, address, proxy_protocol, cert_pem, key_pem).await
    }

    fn name(&self) -> &'static str {
        "RDP"
    }
}

impl std::fmt::Debug for RdpProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpProtocolServer").finish()
    }
}

/// Start an RDP client for a target and bridge it to normalised desktop streams.
pub fn connect(
    approved: ApprovedTarget<TargetRdpOptions>,
    size: (u16, u16),
    target_session_id: TargetSessionId,
) -> Result<DesktopClientHandles, WarpgateError> {
    let (user_info, target) = approved.into_parts();
    let (target, options) = target.into_parts();
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    // Autologon passes the credentials over CredSSP, so the session is logged on by the
    // time it is active; only an interactive-logon target starts at its sign-in screen.
    let sign_in = if options.interactive_logon {
        LogonState::at_logon_screen()
    } else {
        LogonState::logged_on()
    };
    let logon = LogonWatcher {
        target_session_id,
        target_id: target.id,
        target_name: target.name,
        user_id: user_info.id,
        username: user_info.username,
        sign_in: sign_in.clone(),
    };

    let span = info_span!("RDP-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) =
                client::run(options, size, event_tx.clone(), input_rx, abort_rx, logon).await
            {
                let error_chain = format!("{error:#}");
                error!(%error, %error_chain, "RDP client failed");
                let _ = event_tx.send(DesktopEvent::Error(error_chain)).await;
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    Ok(DesktopClientHandles {
        event_rx,
        input_tx,
        abort_tx,
        logon_state: sign_in,
    })
}
