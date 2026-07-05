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
use warpgate_common_http::auth::{AuthenticatedRequestContext, UnauthenticatedRequestContext};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::ConfigProvider;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_sso::{SsoClient, SsoInternalProviderConfig};

use super::sso_provider_detail::{SSO_CONTEXT_SESSION_KEY, SsoContext};
use crate::SsoLoginState;
use crate::api::AnySecurityScheme;
use crate::api::common::{emit_unknown_authentication_failed_event, logout};
use crate::common::{
    SessionExt, authorize_session, endpoint_auth, get_or_create_auth_state_for_request,
    session_id_for_request,
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

#[derive(Object)]
pub struct SsoKubernetesConfigDescription {
    pub name: String,
    pub label: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub client_secret: Option<String>,
}

#[derive(ApiResponse)]
enum GetSsoKubernetesConfigsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoKubernetesConfigDescription>>),
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

        let Some(ref email) = response.email else {
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
                response.preferred_username.clone(),
                provider_config.clone(),
            )
            .await?;
        let Some(username) = username else {
            let session_id = session_id_for_request(req, &ctx).await?;
            emit_unknown_authentication_failed_event(
                session_id,
                req.remote_addr().as_socket_addr().map(|a| a.ip()),
                email,
                &cred.safe_description(),
                "unknown user",
            );
            return Ok(Err(format!("No user matching {email}")));
        };

        let remote_ip = req.remote_addr().as_socket_addr().map(|a| a.ip());
        let state_arc = match get_or_create_auth_state_for_request(req, &username, &ctx, None).await
        {
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
            authorize_session(req, &ctx, user_info).await?;
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
                token: response.id_token.clone(),
                supports_single_logout: context.supports_single_logout,
            });
        }

        warpgate_core::resolve_and_map_sso_user(
            &mut *services.config_provider.lock().await,
            provider_config,
            &response,
        )
        .await?;

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

        logout(session, &mut *session_middleware.lock().await);

        Ok(StartSloResponse::Ok(Json(StartSloResponseParams {
            url: logout_url.to_string(),
        })))
    }

    #[oai(
        path = "/sso/kubernetes-configs",
        method = "get",
        operation_id = "get_sso_kubernetes_configs",
        transform = "endpoint_auth"
    )]
    async fn api_get_sso_kubernetes_configs(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetSsoKubernetesConfigsResponse, WarpgateError> {
        let mut providers = ctx
            .services()
            .config
            .lock()
            .await
            .store
            .sso_providers
            .clone();
        providers.sort_by(|a, b| a.label().cmp(b.label()));
        let configs = providers
            .iter()
            .filter_map(|p| {
                let k = p.kubernetes.as_ref()?;
                let issuer_url = p.provider.issuer_url().ok()?;
                Some(SsoKubernetesConfigDescription {
                    name: p.name.clone(),
                    label: p.label().to_string(),
                    issuer_url: issuer_url.to_string(),
                    client_id: k.client_id.clone(),
                    scopes: k.scopes_or_default(),
                    client_secret: k.client_secret.clone(),
                })
            })
            .collect();
        Ok(GetSsoKubernetesConfigsResponse::Ok(Json(configs)))
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
