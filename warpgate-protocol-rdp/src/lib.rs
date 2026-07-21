//! In-workspace RDP integration for Warpgate.
//!
//! [`client`] drives IronRDP against a target host; [`server`] runs IronRDP's server state
//! machine for native RDP viewers (mstsc/FreeRDP) connecting to Warpgate's RDP port. Both
//! speak the shared [`DesktopEvent`]/[`DesktopInput`] streams, so the web-desktop manager
//! and browser canvas renderer work against either front end unchanged.

mod client;
mod server;
mod session_handle;

use anyhow::Context;
use futures::future::BoxFuture;
pub use server::bind_server;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender, channel, unbounded_channel};
use tracing::{Instrument, error, info_span};
use warpgate_common::{ListenEndpoint, ProtocolName, TargetRdpOptions};
use warpgate_core::{
    DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopEvent, DesktopInput, DesktopState, ProtocolServer,
    Services,
};
use warpgate_tls::TlsCertificateAndPrivateKey;

pub static PROTOCOL_NAME: ProtocolName = "RDP";

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

/// Handles for driving a backend RDP client.
pub struct RdpClientHandles {
    pub event_rx: Receiver<DesktopEvent>,
    pub input_tx: Sender<DesktopInput>,
    pub abort_tx: UnboundedSender<()>,
}

/// Start an RDP client for a target and bridge it to normalised desktop streams.
pub fn connect(options: TargetRdpOptions, size: (u16, u16)) -> RdpClientHandles {
    let (event_tx, event_rx) = channel::<DesktopEvent>(1024);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    let span = info_span!("RDP-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) =
                client::run(options, size, event_tx.clone(), input_rx, abort_rx).await
            {
                error!(%error, "RDP client failed");
                let _ = event_tx.send(DesktopEvent::Error(error.to_string())).await;
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    RdpClientHandles {
        event_rx,
        input_tx,
        abort_tx,
    }
}
