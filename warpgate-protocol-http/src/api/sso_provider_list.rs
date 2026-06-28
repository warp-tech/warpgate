use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, Form};
use poem_openapi::param::Query;
use poem_openapi::payload::{Html, Json, Response};
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use warpgate_common::WarpgateError;
use warpgate_common::auth::{AuthCredential, AuthResult};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::SessionAuthorization;
use warpgate_core::ConfigProvider;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_sso::{RoleMapping, SsoClient, SsoInternalProviderConfig};

use super::sso_provider_detail::{SSO_CONTEXT_SESSION_KEY, SsoContext};
use crate::SsoLoginState;
use crate::api::common::{emit_unknown_authentication_failed_event, logout};
use crate::common::{
    SessionExt, authorize_session, get_or_create_auth_state_for_request, session_id_for_request,
};
use crate::session::SessionStore;

pub struct Api;

#[derive(Enum)]
pub enum SsoProviderKind {
    Google,
    Apple,
    Azure,
    Custom,
}

#[derive(Object)]
pub struct SsoProviderDescription {
    pub name: String,
    pub label: String,
    pub kind: SsoProviderKind,
}

#[derive(ApiResponse)]
enum GetSsoProvidersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoProviderDescription>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum ReturnToSsoResponse {
    #[oai(status = 307)]
    Ok,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum ReturnToSsoPostResponse {
    #[oai(status = 200)]
    Redirect(Html<String>),
}

#[derive(Deserialize)]
pub struct ReturnToSsoFormData {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[derive(Object)]
struct StartSloResponseParams {
    url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum StartSloResponse {
    #[oai(status = 200)]
    Ok(Json<StartSloResponseParams>),
    #[oai(status = 400)]
    NotInSsoSession,
    #[oai(status = 404)]
    NotFound,
}

fn make_redirect_url(err: &str) -> String {
    error!("SSO error: {err}");
    format!("/@warpgate?login_error={err}")
}

/// Only relative paths and absolute `http(s)` URLs are accepted as post-login
/// redirect targets. This rejects schemes such as `javascript:` or `data:` and
/// protocol-relative `//host` URLs.
fn is_safe_redirect_target(next: &str) -> bool {
    if let Some(rest) = next.strip_prefix('/') {
        // Relative path, but not protocol-relative ("//host")
        return !rest.starts_with('/');
    }
    url::Url::parse(next)
        .as_ref()
        .is_ok_and(|v| matches!(v.scheme(), "http" | "https"))
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers",
        method = "get",
        operation_id = "get_sso_providers"
    )]
    async fn api_get_all_sso_providers(
        &self,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> Result<GetSsoProvidersResponse, WarpgateError> {
        let mut providers = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        providers.sort_by(|a, b| a.label().cmp(b.label()));
        Ok(GetSsoProvidersResponse::Ok(Json(
            providers
                .into_iter()
                .map(|p| SsoProviderDescription {
                    name: p.name.clone(),
                    label: p.label().to_string(),
                    kind: match p.provider {
                        SsoInternalProviderConfig::Google { .. } => SsoProviderKind::Google,
                        SsoInternalProviderConfig::Apple { .. } => SsoProviderKind::Apple,
                        SsoInternalProviderConfig::Azure { .. } => SsoProviderKind::Azure,
                        SsoInternalProviderConfig::Custom { .. } => SsoProviderKind::Custom,
                    },
                })
                .collect(),
        )))
    }

    #[oai(path = "/sso/return", method = "get", operation_id = "return_to_sso")]
    async fn api_return_to_sso_get(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        code: Query<Option<String>>,
        state: Query<Option<String>>,
    ) -> Result<Response<ReturnToSsoResponse>, WarpgateError> {
        let url = self
            .api_return_to_sso_get_common(req, session, ctx, code.as_ref(), state.as_ref())
            .await?
            .unwrap_or_else(|x| make_redirect_url(&x));

        Ok(Response::new(ReturnToSsoResponse::Ok).header("Location", url))
    }

    #[oai(
        path = "/sso/return",
        method = "post",
        operation_id = "return_to_sso_with_form_data"
    )]
    async fn api_return_to_sso_post(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        data: Form<ReturnToSsoFormData>,
        state: Query<Option<String>>,
    ) -> Result<ReturnToSsoPostResponse, WarpgateError> {
        let url = self
            .api_return_to_sso_get_common(
                req,
                session,
                ctx,
                data.code.as_ref(),
                data.state.as_ref().or(state.as_ref()),
            )
            .await?
            .unwrap_or_else(|x| make_redirect_url(&x));
        let serialized_url = serde_json::to_string(&url)?;
        let attr_url = html_escape::encode_double_quoted_attribute(&url);
        let text_url = html_escape::encode_text(&url);
        Ok(ReturnToSsoPostResponse::Redirect(
            poem_openapi::payload::Html(format!(
                "<!doctype html>\n
                <html>
                    <script>
                        location.href = {serialized_url};
                    </script>
                    <body>
                        Redirecting to <a href=\"{attr_url}\">{text_url}</a>...
                    </body>
                </html>
            "
            )),
        ))
    }

    async fn api_return_to_sso_get_common(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        code: Option<&String>,
        state: Option<&String>,
    ) -> Result<Result<String, String>, WarpgateError> {
        // pull services locally for convenience
        let services = ctx.services();
        let Some(context) = session.get::<SsoContext>(SSO_CONTEXT_SESSION_KEY) else {
            return Ok(Err("Not in an active SSO process".to_string()));
        };

        let Some(code) = code else {
            return Ok(Err(
                "No authorization code in the return URL request".to_string()
            ));
        };

        let Some(state) = state else {
            return Ok(Err(
                "No SSO state parameter in the return request".to_string()
            ));
        };

        if !context.request.verify_state(state) {
            return Ok(Err("Invalid SSO state parameter".to_string()));
        }

        let response = context
            .request
            .verify_code((*code).clone())
            .await
            .inspect_err(|e| {
                warn!("Failed to verify SSO code: {e:?}");
            })?;

        if !response.email_verified.unwrap_or(true) {
            error!(
                "SSO login attempt with an unverified email: {:?}",
                response.email
            );
            error!(
                "The SSO provider did provide an email_verified claim, and it is false. Since the provider provides this claim, Warpgate requires the email to be verified."
            );
            return Ok(Err("The SSO account's e-mail is not verified".to_string()));
        }

        let Some(email) = response.email else {
            return Ok(Err("No e-mail information in the SSO response".to_string()));
        };

        info!("SSO login as {email}");

        let providers_config = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        let mut iter = providers_config.iter();
        let Some(provider_config) = iter.find(|x| x.name == context.provider) else {
            return Ok(Err(format!("No provider matching {}", context.provider)));
        };

        let cred = AuthCredential::Sso {
            provider: context.provider.clone(),
            email: email.clone(),
        };

        let username = services
            .config_provider
            .lock()
            .await
            .username_for_sso_credential(
                &cred,
                response.preferred_username,
                provider_config.clone(),
            )
            .await?;
        let Some(username) = username else {
            let session_id = session_id_for_request(req, &ctx).await?;
            emit_unknown_authentication_failed_event(
                session_id,
                req.remote_addr().as_socket_addr().map(|a| a.ip()),
                &email,
                &cred.safe_description(),
                "unknown user",
            );
            return Ok(Err(format!("No user matching {email}")));
        };

        let remote_ip = req.remote_addr().as_socket_addr().map(|a| a.ip());
        let state_arc = match get_or_create_auth_state_for_request(req, &username, &ctx).await {
            Ok(state) => state,
            Err(e) => {
                if matches!(e, WarpgateError::IpAddrNotAllowed(..)) {
                    let session_id = session_id_for_request(req, &ctx).await?;
                    emit_unknown_authentication_failed_event(
                        session_id,
                        remote_ip,
                        &username,
                        &cred.safe_description(),
                        "IP address not allowed",
                    );
                    return Ok(Err(
                        "Login denied: your IP address is not in the allowed range for this user"
                            .to_string(),
                    ));
                }
                return Err(e);
            }
        };

        let mut state = state_arc.lock().await;

        if !validate_and_add_credential(
            &mut state,
            &cred,
            &mut *ctx.services().config_provider.lock().await,
        )
        .await?
        {
            return Ok(Err(format!(
                "Failed to validate SSO credential for {username}"
            )));
        }

        if let AuthResult::Accepted { user_info } = state.verify() {
            let username_for_ttl = user_info.username.clone();
            authorize_session(req, &ctx, user_info).await?;
            if let (Some(secs), Some(ip)) = (
                provider_config.active_web_session_ttl_seconds,
                remote_ip,
            ) {
                ctx.services()
                    .active_web_sessions
                    .lock()
                    .await
                    .touch(
                        &username_for_ttl,
                        std::time::Duration::from_secs(secs),
                        ip,
                    );
            }
            state.emit_authenticated_event_once();
            let state_id = *state.id();
            drop(state);
            ctx.services()
                .auth_state_store
                .lock()
                .await
                .complete(&state_id)
                .await;
            session.set_sso_login_state(SsoLoginState {
                provider: context.provider,
                token: response.id_token,
                supports_single_logout: context.supports_single_logout,
            });
        }

        let mut cp = services.config_provider.lock().await;

        let mappings = provider_config.provider.role_mappings();
        if let Some(remote_groups) = response.access_roles {
            // If mappings is not set, all groups are subject to sync
            // and names won't be remapped
            let managed_role_names = mappings
                .as_ref()
                .map(|m| m.iter().flat_map(|(_, v)| v.roles()).collect::<Vec<_>>());

            let mut active_role_names: Vec<String> = if let Some(ref mappings) = mappings {
                // Apply wildcard "*" mapping if user has any groups
                let mut roles: Vec<String> = if remote_groups.is_empty() {
                    Vec::new()
                } else {
                    mappings
                        .get("*")
                        .map(RoleMapping::roles)
                        .unwrap_or_default()
                };

                // Apply specific group mappings
                for group in &remote_groups {
                    if let Some(mapping) = mappings.get(group) {
                        roles.extend(mapping.roles());
                    }
                }

                roles
            } else {
                // No mappings configured, pass through group names as-is
                remote_groups
            };

            active_role_names.sort();
            active_role_names.dedup();

            debug!(
                "SSO role mappings for {username}: active={active_role_names:?}, managed={managed_role_names:?}"
            );
            cp.apply_sso_role_mappings(&username, managed_role_names, active_role_names)
                .await?;
        }

        // import admin roles from claim if present
        if let Some(remote_admins) = response.admin_roles {
            let admin_map = provider_config.provider.admin_role_mappings();

            // compute managed list from mapping values (or all role names if no mapping provided)
            let managed_admin_names: Option<Vec<String>> = admin_map
                .as_ref()
                .map(|m| m.values().flat_map(RoleMapping::roles).collect());

            let active_admin_names: Vec<_> = if let Some(ref mappings) = admin_map {
                remote_admins
                    .iter()
                    .flat_map(|r| {
                        mappings
                            .get(r)
                            .map(RoleMapping::roles)
                            .into_iter()
                            .flatten()
                    })
                    .collect()
            } else {
                remote_admins.clone()
            };

            debug!(
                "SSO admin role mappings for {username}: active={active_admin_names:?}, managed={managed_admin_names:?}"
            );
            cp.apply_sso_admin_role_mappings(&username, managed_admin_names, active_admin_names)
                .await?;
        }

        let mut next_url = context
            .next_url
            .as_deref()
            .filter(|next| is_safe_redirect_target(next))
            .unwrap_or("/@warpgate#/login")
            .to_owned();

        if let Some(ref host) = context.return_host
            && next_url.starts_with('/')
        {
            next_url = format!("https://{host}{next_url}");
        }

        Ok(Ok(next_url))
    }

    #[oai(
        path = "/sso/logout",
        method = "get",
        operation_id = "initiate_sso_logout"
    )]
    async fn api_start_slo(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        session_middleware: Data<&Arc<Mutex<SessionStore>>>,
    ) -> Result<StartSloResponse, WarpgateError> {
        let Some(state) = session.get_sso_login_state() else {
            return Ok(StartSloResponse::NotInSsoSession);
        };

        let config = ctx.services().config.lock().await;

        let return_url = construct_external_url(Some(req), &config, None).await?;
        debug!("Return URL: {}", &return_url);

        let Some(provider_config) = config
            .store
            .sso_providers
            .iter()
            .find(|p| p.name == state.provider)
        else {
            return Ok(StartSloResponse::NotFound);
        };

        let client = SsoClient::new(provider_config.provider.clone())?;
        let logout_url = client.logout(state.token, return_url).await?;

        if let Some(SessionAuthorization::User { username, .. }) = session.get_auth() {
            ctx.services()
                .active_web_sessions
                .lock()
                .await
                .forget(&username);
        }
        logout(session, &mut *session_middleware.lock().await);

        Ok(StartSloResponse::Ok(Json(StartSloResponseParams {
            url: logout_url.to_string(),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::is_safe_redirect_target;

    #[test]
    fn accepts_relative_paths() {
        assert!(is_safe_redirect_target("/@warpgate#/login"));
        assert!(is_safe_redirect_target("/foo/bar?x=1"));
    }

    #[test]
    fn accepts_http_and_https_urls() {
        assert!(is_safe_redirect_target("https://example.com/path"));
        assert!(is_safe_redirect_target("http://example.com"));
    }

    #[test]
    fn rejects_dangerous_schemes_and_protocol_relative() {
        assert!(!is_safe_redirect_target("javascript:alert(1)"));
        assert!(!is_safe_redirect_target("data:text/html,<script>"));
        assert!(!is_safe_redirect_target("//evil.com"));
        assert!(!is_safe_redirect_target("ftp://example.com"));
    }
}
