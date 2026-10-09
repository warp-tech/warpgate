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

use std::sync::Arc;

use anyhow::Context;
use futures::future::BoxFuture;
pub use server::bind_server;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tracing::{Instrument, error, info_span};
use warpgate_common::{ListenEndpoint, Protocol, SecretResolver, TargetRdpOptions, WarpgateError};
use warpgate_core::{
    AdmittedTarget, DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopClientHandles, DesktopEvent,
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
    admitted: AdmittedTarget<TargetRdpOptions>,
    size: (u16, u16),
    secrets: Arc<dyn SecretResolver>,
) -> Result<DesktopClientHandles, WarpgateError> {
    let target_session_id = admitted.id();
    let (user_info, target) = admitted.into_approved().into_parts();
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
            if let Err(error) = client::run(
                options,
                size,
                event_tx.clone(),
                input_rx,
                abort_rx,
                logon,
                secrets,
            )
            .await
            {
                // The full chain goes to the log; only the top-level cause
                // reaches the viewer.
                log_client_failure(&error);
                let _ = event_tx.send(DesktopEvent::backend_error(&error)).await;
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

/// The RDP client task's own record of the failure that ended it.
///
/// Rendered and then escaped: `%error` writes the chain's text as it came, and
/// a transparent I/O error carries whatever the operating system or the remote
/// side said, so a newline in it forges a second record in the default text
/// format. `#[deny(dead_code)]` keeps the spawned task calling this rather
/// than only the test, since `mod tests` is `#[cfg(test)]`.
#[deny(dead_code)]
fn log_client_failure(error: &anyhow::Error) {
    error!(
        error = ?error.to_string(),
        error_chain = ?format!("{error:#}"),
        "RDP client failed"
    );
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::log_client_failure;

    /// `tracing-subscriber` ships no `MakeWriter` for a buffer the test can
    /// still read afterwards: its `Arc<W>` impl wants `&W: Write`, which a
    /// `Mutex` is not.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// What `log` wrote, with the formatter's trailing break removed.
    fn captured_output(log: impl FnOnce()) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_writer(captured.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, log);

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        logged.strip_suffix('\n').unwrap_or(&logged).to_owned()
    }

    const FORGED: &str =
        "Connection reset by peer\n  ERROR warpgate::ssh: Authenticated with publickey";

    fn assert_one_escaped_record(record: &str) {
        assert!(
            !record.contains('\n'),
            "the error forged a second record: {record:?}"
        );
        assert!(
            record.contains("\\n"),
            "the error never reached the log: {record:?}"
        );
    }

    #[test]
    fn a_newline_in_an_rdp_client_failure_cannot_forge_a_log_record() {
        // The newline once in a cause, once at the top: the record carries
        // both the top-level message and the chain, and each must be escaped.
        let in_cause = anyhow::Error::from(std::io::Error::other(FORGED)).context("RDP connect");
        let at_top = anyhow::anyhow!(FORGED);
        for error in [in_cause, at_top] {
            assert!(
                format!("{error:#}").contains('\n'),
                "the fixture carries no newline, so nothing below is evidence"
            );
            assert_one_escaped_record(&captured_output(|| log_client_failure(&error)));
        }
    }
}
