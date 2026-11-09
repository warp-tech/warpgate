use poem::web::{Data, Form};
use poem_openapi::param::Path;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::Deserialize;
use tracing::{info, warn};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::SessionsFilter;
use warpgate_db_entities::HttpSession;
use warpgate_sso::SsoClient;

pub struct Api;

#[derive(Deserialize)]
struct BackchannelLogoutForm {
    logout_token: String,
}

#[derive(ApiResponse)]
enum BackchannelLogoutResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 400)]
    InvalidToken,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    /// OpenID Connect Back-Channel Logout endpoint, called by the identity
    /// provider when a user's session there ends.
    #[oai(
        path = "/sso/providers/:name/backchannel-logout",
        method = "post",
        operation_id = "sso_backchannel_logout"
    )]
    async fn api_sso_backchannel_logout(
        &self,
        ctx: Data<&UnauthenticatedRequestContext>,
        name: Path<String>,
        form: Form<BackchannelLogoutForm>,
    ) -> Result<BackchannelLogoutResponse, WarpgateError> {
        let services = ctx.services();
        let name = name.0;
        let provider = services
            .config
            .lock()
            .await
            .store
            .sso_providers
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.provider.clone());
        let Some(provider) = provider else {
            return Ok(BackchannelLogoutResponse::NotFound);
        };

        let logout = match SsoClient::new(provider)?
            .verify_logout_token(&form.logout_token)
            .await
        {
            Ok(logout) => logout,
            Err(error) => {
                warn!(provider = %name, %error, "Rejected an SSO back-channel logout");
                return Ok(BackchannelLogoutResponse::InvalidToken);
            }
        };

        let mut query = HttpSession::Entity::find()
            .filter(HttpSession::Column::SsoProvider.eq(&name))
            .filter(HttpSession::Column::UserSessionId.is_not_null());
        if let Some(subject) = &logout.subject {
            query = query.filter(HttpSession::Column::SsoSubject.eq(subject));
        }
        if let Some(sid) = &logout.sid {
            query = query.filter(HttpSession::Column::SsoSid.eq(sid));
        }
        let session_ids: Vec<Option<UserSessionId>> = query
            .select_only()
            .column(HttpSession::Column::UserSessionId)
            .distinct()
            .into_tuple()
            .all(&services.db)
            .await?;

        info!(
            provider = %name,
            subject = ?logout.subject,
            sid = ?logout.sid,
            sessions = session_ids.len(),
            "SSO back-channel logout",
        );
        let ids: Vec<UserSessionId> = session_ids.into_iter().flatten().collect();
        if !ids.is_empty() {
            services
                .close_sessions(SessionsFilter::Sessions { ids })
                .await?;
        }
        Ok(BackchannelLogoutResponse::Ok)
    }
}
