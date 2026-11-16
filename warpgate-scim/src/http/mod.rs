//! The SCIM HTTP app, mounted at `/@warpgate/scim/v2`.
//!
//! Plain `poem` rather than `poem-openapi`: SCIM has its own content type,
//! error envelope and schema vocabulary, and must stay out of the admin
//! OpenAPI surface and its compatibility gate.

mod auth;
mod discovery;
mod resources;

use std::collections::HashMap;

pub use auth::ScimPrincipal;
use poem::http::{HeaderValue, StatusCode, header};
use poem::web::Data;
use poem::{Body, Endpoint, EndpointExt, IntoResponse, Request, Response, Route};
use serde_json::Value;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{Services, SessionsFilter};

use crate::protocol::ScimError;
use crate::store::{Effects, Store};

/// Where the app is mounted, for `meta.location` and `$ref`.
pub const SCIM_PATH: &str = "/@warpgate/scim/v2";

pub const CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";

/// Request bodies larger than this are refused while being read.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The app. Every route is behind the bearer gate.
pub fn scim_app() -> impl Endpoint<Output = Response> {
    Route::new()
        .nest("/Users", resources::routes(resources::Kind::Users))
        .nest("/Groups", resources::routes(resources::Kind::Groups))
        .at(
            "/ServiceProviderConfig",
            poem::get(discovery::service_provider_config),
        )
        .at("/ResourceTypes", poem::get(discovery::resource_types))
        .at("/ResourceTypes/:id", poem::get(discovery::resource_type))
        .at("/Schemas", poem::get(discovery::schemas))
        .at("/Schemas/:id", poem::get(discovery::schema))
        .at("/Bulk", unsupported("bulk operations are not supported"))
        .at("/Me", unsupported("the /Me endpoint is not supported"))
        .around(auth::bearer_gate)
        .catch_error(|_: poem::error::NotFoundError| async {
            ScimError::not_found("no such SCIM endpoint").into_response()
        })
        .catch_error(|_: poem::error::MethodNotAllowedError| async {
            ScimError::Protocol {
                status: 405,
                scim_type: None,
                detail: "method not allowed".into(),
            }
            .into_response()
        })
        .around(|ep, req| async move {
            match ep.call(req).await {
                // A real failure: the gateway renders it with a correlation id.
                Err(err) if err.is::<WarpgateError>() => Err(err),
                // A refusal is a response, logged with its status, not a failure.
                Err(err) => Ok(err.into_response()),
                Ok(response) => Ok(response),
            }
        })
        .map_to_response()
}

fn unsupported(detail: &'static str) -> impl Endpoint<Output = Response> {
    poem::endpoint::make_sync(move |_| ScimError::not_implemented(detail).into_response())
}

/// A successful SCIM response.
pub struct ScimResponse {
    status: StatusCode,
    body: Option<Value>,
    location: Option<String>,
}

impl ScimResponse {
    pub const fn ok(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body: Some(body),
            location: None,
        }
    }

    pub fn created(body: Value) -> Self {
        let location = body
            .get("meta")
            .and_then(|meta| meta.get("location"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self {
            status: StatusCode::CREATED,
            body: Some(body),
            location,
        }
    }

    pub const fn no_content() -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            body: None,
            location: None,
        }
    }
}

fn scim_response(status: StatusCode, body: Option<&Value>) -> Response {
    let mut response = match body {
        Some(body) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .body(body.to_string()),
        None => Response::builder().status(status).finish(),
    };
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Bearer realm="warpgate""#),
        );
    }
    response
}

impl IntoResponse for ScimResponse {
    fn into_response(self) -> Response {
        let mut response = scim_response(self.status, self.body.as_ref());
        if let Some(location) = self.location.and_then(|l| HeaderValue::from_str(&l).ok()) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        response
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Protocol { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_REQUEST)
            }
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        scim_response(status, Some(&self.to_json()))
    }
}

/// Protocol errors become their envelope; internal ones go to the gateway's
/// error renderer, which logs them with a correlation id.
impl From<ScimError> for poem::Error {
    fn from(err: ScimError) -> Self {
        if let ScimError::Internal(inner) = err {
            return inner.into();
        }
        Self::from_response(err.into_response())
    }
}

/// The request body as JSON, whatever its declared content type: Okta sends
/// `application/json`, Entra ID `application/scim+json`.
async fn json_body(body: Body) -> Result<Value, ScimError> {
    let bytes = body
        .into_bytes_limit(MAX_BODY_BYTES)
        .await
        .map_err(|e| match e {
            poem::error::ReadBodyError::PayloadTooLarge => ScimError::Protocol {
                status: 413,
                scim_type: None,
                detail: "request body too large".into(),
            },
            other => ScimError::invalid_syntax(format!("could not read the body: {other}")),
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ScimError::invalid_syntax(format!("the body is not valid JSON: {e}")))
}

/// Absolute SCIM root for this request, falling back to the path alone when
/// the external host is not known.
async fn base_url(req: &Request, ctx: &UnauthenticatedRequestContext) -> String {
    let config = ctx.services().config.lock().await;
    match construct_external_url(Some(req), &config, None).await {
        Ok(mut url) => {
            url.set_path(SCIM_PATH);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string().trim_end_matches('/').to_owned()
        }
        Err(error) => {
            tracing::debug!(%error, "SCIM: no external URL, using a relative base");
            SCIM_PATH.to_owned()
        }
    }
}

fn store<'a>(
    ctx: &'a UnauthenticatedRequestContext,
    principal: &'a ScimPrincipal,
    base: &'a str,
) -> Store<'a> {
    Store {
        db: &ctx.services().db,
        base,
        sso_provider: principal.sso_provider.as_deref(),
    }
}

async fn apply_effects(services: &Services, effects: Effects) -> Result<(), WarpgateError> {
    for user_id in effects.close_sessions_of_users {
        services
            .close_sessions(SessionsFilter::User { user_id })
            .await?;
    }
    if effects.role_access_changed {
        services.close_sessions_without_role_access().await?;
    }
    Ok(())
}

type Params = HashMap<String, String>;

/// Extracts the request context the gateway attaches to every request.
async fn context(req: &Request) -> poem::Result<Data<&UnauthenticatedRequestContext>> {
    <Data<&UnauthenticatedRequestContext> as poem::FromRequest>::from_request_without_body(req)
        .await
}

#[cfg(test)]
mod tests;
