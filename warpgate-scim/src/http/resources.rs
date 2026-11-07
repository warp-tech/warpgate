//! `/Users` and `/Groups`: the same handlers, told which kind by request data.

use poem::web::{Data, Path, Query};
use poem::{Body, Endpoint, EndpointExt, Request, Route, handler};
use serde_json::Value;
use uuid::Uuid;
use warpgate_common_http::auth::UnauthenticatedRequestContext;

use super::{Params, ScimPrincipal, ScimResponse, apply_effects, base_url, json_body, store};
use crate::protocol::resource::list_response;
use crate::protocol::{ListQuery, PatchRequest, ScimError};
use crate::store::{Effects, Store};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Users,
    Groups,
}

impl Kind {
    async fn list(
        self,
        store: &Store<'_>,
        query: &ListQuery,
    ) -> Result<(Vec<Value>, usize), ScimError> {
        match self {
            Self::Users => store.list_users(query).await,
            Self::Groups => store.list_groups(query).await,
        }
    }

    async fn get(self, store: &Store<'_>, id: Uuid) -> Result<Option<Value>, ScimError> {
        match self {
            Self::Users => store.get_user(id).await,
            Self::Groups => store.get_group(id).await,
        }
    }

    async fn create(self, store: &Store<'_>, body: &Value) -> Result<(Value, Effects), ScimError> {
        match self {
            Self::Users => store.create_user(body).await,
            Self::Groups => store.create_group(body).await,
        }
    }

    async fn replace(
        self,
        store: &Store<'_>,
        id: Uuid,
        body: &Value,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        match self {
            Self::Users => store.replace_user(id, body).await,
            Self::Groups => store.replace_group(id, body).await,
        }
    }

    async fn patch(
        self,
        store: &Store<'_>,
        id: Uuid,
        request: &PatchRequest,
    ) -> Result<Option<(Value, Effects)>, ScimError> {
        match self {
            Self::Users => store.patch_user(id, request).await,
            Self::Groups => store.patch_group(id, request).await,
        }
    }

    async fn delete(self, store: &Store<'_>, id: Uuid) -> Result<Option<Effects>, ScimError> {
        match self {
            Self::Users => store.delete_user(id).await,
            Self::Groups => store.delete_group(id).await,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Users => "user",
            Self::Groups => "group",
        }
    }
}

pub fn routes(kind: Kind) -> impl Endpoint {
    Route::new()
        .at("/", poem::get(list).post(create))
        .at("/.search", poem::post(search))
        .at(
            "/:id",
            poem::get(get).put(replace).patch(patch).delete(delete),
        )
        .data(kind)
}

fn not_found(kind: Kind, id: &str) -> ScimError {
    ScimError::not_found(format!("no {} with id {id}", kind.name()))
}

/// An id that is not a UUID can't name anything.
fn parse_id(kind: Kind, id: &str) -> Result<Uuid, ScimError> {
    Uuid::parse_str(id).map_err(|_| not_found(kind, id))
}

#[handler]
async fn list(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    Query(params): Query<Params>,
) -> poem::Result<ScimResponse> {
    let query = ListQuery::from_params(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
    respond_list(req, ctx, principal, *kind, &query).await
}

#[handler]
async fn search(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    body: Body,
) -> poem::Result<ScimResponse> {
    let query = ListQuery::from_search_request(&json_body(body).await?)?;
    respond_list(req, ctx, principal, *kind, &query).await
}

async fn respond_list(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    principal: &ScimPrincipal,
    kind: Kind,
    query: &ListQuery,
) -> poem::Result<ScimResponse> {
    let base = base_url(req, ctx).await;
    let (page, total) = kind.list(&store(ctx, principal, &base), query).await?;
    Ok(ScimResponse::ok(list_response(
        &page,
        total,
        query.start_index,
    )))
}

#[handler]
async fn get(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    Path(id): Path<String>,
) -> poem::Result<ScimResponse> {
    let uuid = parse_id(*kind, &id)?;
    let base = base_url(req, ctx).await;
    let resource = kind
        .get(&store(ctx, principal, &base), uuid)
        .await?
        .ok_or_else(|| not_found(*kind, &id))?;
    Ok(ScimResponse::ok(resource))
}

#[handler]
async fn create(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    body: Body,
) -> poem::Result<ScimResponse> {
    let body = json_body(body).await?;
    let base = base_url(req, ctx).await;
    let (resource, effects) = kind.create(&store(ctx, principal, &base), &body).await?;
    apply_effects(ctx.services(), effects)
        .await
        .map_err(ScimError::Internal)?;
    Ok(ScimResponse::created(resource))
}

#[handler]
async fn replace(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    Path(id): Path<String>,
    body: Body,
) -> poem::Result<ScimResponse> {
    let uuid = parse_id(*kind, &id)?;
    let body = json_body(body).await?;
    let base = base_url(req, ctx).await;
    let (resource, effects) = kind
        .replace(&store(ctx, principal, &base), uuid, &body)
        .await?
        .ok_or_else(|| not_found(*kind, &id))?;
    apply_effects(ctx.services(), effects)
        .await
        .map_err(ScimError::Internal)?;
    Ok(ScimResponse::ok(resource))
}

#[handler]
async fn patch(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    Path(id): Path<String>,
    body: Body,
) -> poem::Result<ScimResponse> {
    let uuid = parse_id(*kind, &id)?;
    let request = PatchRequest::parse(&json_body(body).await?)?;
    let base = base_url(req, ctx).await;
    let (resource, effects) = kind
        .patch(&store(ctx, principal, &base), uuid, &request)
        .await?
        .ok_or_else(|| not_found(*kind, &id))?;
    apply_effects(ctx.services(), effects)
        .await
        .map_err(ScimError::Internal)?;
    Ok(ScimResponse::ok(resource))
}

#[handler]
async fn delete(
    req: &Request,
    Data(ctx): Data<&UnauthenticatedRequestContext>,
    Data(principal): Data<&ScimPrincipal>,
    Data(kind): Data<&Kind>,
    Path(id): Path<String>,
) -> poem::Result<ScimResponse> {
    let uuid = parse_id(*kind, &id)?;
    let base = base_url(req, ctx).await;
    let effects = kind
        .delete(&store(ctx, principal, &base), uuid)
        .await?
        .ok_or_else(|| not_found(*kind, &id))?;
    apply_effects(ctx.services(), effects)
        .await
        .map_err(ScimError::Internal)?;
    Ok(ScimResponse::no_content())
}
