use poem::handler;
use poem::http::StatusCode;
use poem::web::{Data, Json};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::cluster::ClusterNotification;

/// receiving endpoint for intra-cluster notifications
#[handler]
pub fn api_post_cluster_notification(
    ctx: Data<&AuthenticatedRequestContext>,
    Json(msg): Json<ClusterNotification>,
) -> poem::Result<()> {
    if !ctx.auth.is_cluster_peer() {
        return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
    }
    ctx.services().cluster.deliver_local(msg);
    Ok(())
}
