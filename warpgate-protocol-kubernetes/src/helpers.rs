use poem::Request;
use warpgate_core::WarpgateError;

/// Helper to build the correlation key from a request and target_name
pub type CorrelationKey = (String, String, String); // (username, target_name, ip)

pub async fn session_to_correlation_id(
    correlator: &crate::correlator::RequestCorrelator,
    request: &Request,
    target_name: &str,
) -> Option<CorrelationKey> {
    correlator.correlation_key_for_request(request, target_name).await.ok()
}
