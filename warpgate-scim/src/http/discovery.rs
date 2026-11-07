use poem::web::{Data, Path};
use poem::{Request, handler};
use warpgate_common_http::auth::UnauthenticatedRequestContext;

use super::{ScimResponse, base_url};
use crate::protocol::{ScimError, discovery};

#[handler]
pub async fn service_provider_config(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
) -> ScimResponse {
    ScimResponse::ok(discovery::service_provider_config(
        &base_url(req, ctx).await,
    ))
}

#[handler]
pub async fn resource_types(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
) -> ScimResponse {
    ScimResponse::ok(discovery::list(&discovery::resource_types(
        &base_url(req, ctx).await,
    )))
}

#[handler]
pub async fn resource_type(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Path(id): Path<String>,
) -> poem::Result<ScimResponse> {
    discovery::resource_type_by_id(&base_url(req, ctx).await, &id)
        .map(ScimResponse::ok)
        .ok_or_else(|| ScimError::not_found(format!("no resource type {id}")).into())
}

#[handler]
pub async fn schemas(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
) -> ScimResponse {
    ScimResponse::ok(discovery::list(&discovery::schemas(
        &base_url(req, ctx).await,
    )))
}

#[handler]
pub async fn schema(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Path(id): Path<String>,
) -> poem::Result<ScimResponse> {
    discovery::schema_by_id(&base_url(req, ctx).await, &id)
        .map(ScimResponse::ok)
        .ok_or_else(|| ScimError::not_found(format!("no schema {id}")).into())
}
