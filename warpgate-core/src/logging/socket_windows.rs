use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Identity;
use tracing_subscriber::registry::LookupSpan;
use warpgate_common::WarpgateConfig;

/// Log forwarding (`log.send_to`) uses a Unix datagram socket, which Windows
/// does not have. `main` refuses to start with `log.send_to` set, so this layer
/// never has anything to forward.
#[allow(clippy::unused_async, reason = "same signature as the Unix version")]
pub async fn make_socket_logger_layer<S>(_config: &WarpgateConfig) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    Identity::new()
}
