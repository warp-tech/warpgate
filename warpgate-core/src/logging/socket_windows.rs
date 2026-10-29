use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Identity;
use tracing_subscriber::registry::LookupSpan;
use warpgate_common::WarpgateConfig;

/// Log forwarding (`log.send_to`) uses a Unix datagram socket, which Windows
/// does not have; until it gets a Windows transport this layer does nothing.
#[allow(clippy::unused_async, reason = "same signature as the Unix version")]
pub async fn make_socket_logger_layer<S>(config: &WarpgateConfig) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    if config.store.log.send_to.is_some() {
        println!("Log forwarding (log.send_to) is not supported on Windows yet; ignoring it");
    }
    Identity::new()
}
