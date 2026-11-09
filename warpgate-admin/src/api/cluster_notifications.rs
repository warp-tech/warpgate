use poem::handler;
use poem::http::StatusCode;
use poem::web::{Data, Json};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::cluster::ClusterNotification;
use warpgate_core::{SessionsFilter, State};

fn require_cluster_peer(ctx: &AuthenticatedRequestContext) -> poem::Result<()> {
    if !ctx.auth.is_cluster_peer() {
        return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
    }
    Ok(())
}

/// receiving endpoint for intra-cluster notifications
#[handler]
pub fn api_post_cluster_notification(
    ctx: Data<&AuthenticatedRequestContext>,
    Json(msg): Json<ClusterNotification>,
) -> poem::Result<()> {
    require_cluster_peer(&ctx)?;
    ctx.services().cluster.deliver_local(msg);
    Ok(())
}

/// see Services::close_sessions
#[handler]
pub async fn api_post_cluster_close_sessions(
    ctx: Data<&AuthenticatedRequestContext>,
    Json(scope): Json<SessionsFilter>,
) -> poem::Result<()> {
    require_cluster_peer(&ctx)?;
    State::close_local_sessions(&ctx.services().state, &scope).await;
    Ok(())
}
