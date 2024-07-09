use poem::session::Session;
use poem::web::{Data, Form};
use poem::Request;
use poem_openapi::param::Query;
use poem_openapi::payload::{Html, Json, Response};
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use serde::Deserialize;
use tracing::*;
use warpgate_common::auth::{AuthCredential, AuthResult};
use warpgate_core::Services;
use warpgate_sso::SsoInternalProviderConfig;

use super::sso_provider_detail::{SsoContext, SSO_CONTEXT_SESSION_KEY};
use crate::common::{authorize_session, get_auth_state_for_request, SessionExt};

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
}

fn make_redirect_url(err: &str) -> String {
    error!("SSO error: {err}");
    format!("/@warpgate?login_error={err}")
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
        services: Data<&Services>,
    ) -> poem::Result<GetSsoProvidersResponse> {
        let mut providers = services.config.lock().await.store.sso_providers.clone();
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
        services: Data<&Services>,
        code: Query<Option<String>>,
    ) -> poem::Result<Response<ReturnToSsoResponse>> {
        let url = self
            .api_return_to_sso_get_common(req, session, services, &code)
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
        services: Data<&Services>,
        data: Form<ReturnToSsoFormData>,
    ) -> poem::Result<ReturnToSsoPostResponse> {
        let url = self
            .api_return_to_sso_get_common(req, session, services, &data.code)
            .await?
            .unwrap_or_else(|x| make_redirect_url(&x));
        let serialized_url =
            serde_json::to_string(&url).map_err(poem::error::InternalServerError)?;
        Ok(ReturnToSsoPostResponse::Redirect(
            poem_openapi::payload::Html(format!(
                "<!doctype html>\n
                <html>
                    <script>
                        location.href = {serialized_url};
                    </script>
                    <body>
                        Redirecting to <a href='{url}'>{url}</a>...
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
        services: Data<&Services>,
        code: &Option<String>,
    ) -> poem::Result<Result<String, String>> {
        let Some(context) = session.get::<SsoContext>(SSO_CONTEXT_SESSION_KEY) else {
            return Ok(Err("Not in an active SSO process".to_string()));
        };

        let Some(ref code) = *code else {
            return Ok(Err(
                "No authorization code in the return URL request".to_string()
            ));
        };

        let response = context
            .request
            .verify_code((*code).clone())
            .await
            .map_err(poem::error::InternalServerError)?;

        if !response.email_verified.unwrap_or(true) {
            return Ok(Err("The SSO account's e-mail is not verified".to_string()));
        }

        let Some(email) = response.email else {
            return Ok(Err("No e-mail information in the SSO response".to_string()));
        };

        info!("SSO login as {email}");

        let provider = context.provider.clone();
        let cred = AuthCredential::Sso {
            provider: context.provider,
            email: email.clone(),
        };

        let username = services
            .config_provider
            .lock()
            .await
            .username_for_sso_credential(&cred)
            .await?;
        let Some(username) = username else {
            return Ok(Err(format!("No user matching {email}")));
        };

        let mut auth_state_store = services.auth_state_store.lock().await;
        let state_arc =
            get_auth_state_for_request(&username, session, &mut auth_state_store).await?;

        let mut state = state_arc.lock().await;
        let mut cp = services.config_provider.lock().await;

        if state.username() != username {
            return Ok(Err(format!(
                "Incorrect account for SSO authentication ({username})"
            )));
        }

        if cp.validate_credential(&username, &cred).await? {
            state.add_valid_credential(cred);
        }

        if let AuthResult::Accepted { username } = state.verify() {
            auth_state_store.complete(state.id()).await;
            authorize_session(req, username).await?;
            session.set_oidc_token(response.id_token);
        }

        let providers_config = services.config.lock().await.store.sso_providers.clone();
        let mut iter = providers_config.iter();
        let Some(provider_config) = iter.find(|x| x.name == provider) else {
            return Ok(Err(format!("No provider matching {provider}")));
        };

        let mappings = provider_config.provider.role_mappings();
        if let Some(remote_groups) = response.groups {
            // If mappings is not set, all groups are subject to sync
            // and names won't be remapped
            let managed_role_names = mappings
                .as_ref()
                .map(|m| m.iter().map(|x| x.1.clone()).collect::<Vec<_>>());

            let active_role_names: Vec<_> = remote_groups
                .iter()
                .filter_map({
                    |r| {
                        if let Some(ref mappings) = mappings {
                            mappings.get(r).cloned()
                        } else {
                            Some(r.clone())
                        }
                    }
                })
                .collect();

            debug!("SSO role mappings for {username}: active={active_role_names:?}, managed={managed_role_names:?}");
            cp.apply_sso_role_mappings(&username, managed_role_names, active_role_names)
                .await?;
        }

        Ok(Ok(context
            .next_url
            .as_deref()
            .unwrap_or("/@warpgate#/login")
            .to_owned()))
    }
}
