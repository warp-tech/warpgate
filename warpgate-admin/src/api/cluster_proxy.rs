//! Cross-node proxy for node-owned resources.
//!
//! An in-progress recording's data, and a live session's handle, exist only on
//! the node that owns the connection. For these to be reachable from other
//! nodes, the requests are proxied between nodes.
//!
//! A URL handler on another node calls [`proxy_or_serve`] (or [`proxy_or_serve_websocket`])
//! after auth. If the resource is on another node, it forwards the request there,
//! otherwise it runs the local serve logic.
//!
//! Cross-node proxy requests are authenticated with the cluster token (see
//! `require_cluster_or_admin_permission`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures::future::join_all;
use futures::{StreamExt, TryStreamExt};
use poem::http::header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TRANSFER_ENCODING, UPGRADE};
use poem::http::{HeaderName, StatusCode};
use poem::web::websocket::WebSocket;
use poem::{Body, IntoResponse, Request, Response};
use poem_openapi::types::ParseFromJSON;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::time::timeout;
use tokio_tungstenite::{Connector, client_async_tls_with_config, tungstenite};
use tracing::warn;
use uuid::Uuid;
use warpgate_ca::CLUSTER_TLS_SNI_NAME;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::may_forward_header;
use warpgate_common::{NodeId, Secret, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, X_WARPGATE_CLUSTER_CLIENT_IP,
    X_WARPGATE_CLUSTER_IDENTITY, X_WARPGATE_CLUSTER_TOKEN, is_cluster_peer_request,
};
use warpgate_core::Services;
use warpgate_db_entities::{Node, Parameters, TargetSession};
use warpgate_tls::configure_cluster_tls_connector;

pub struct RemoteNode {
    pub address: String,
    /// SPKI pin from the node's registry row; peer TLS verification fails
    /// closed when a node has not published one.
    pub tls_spki_sha256: Option<String>,
}

/// Which node owns a node-local resource (an in-progress recording, a live session)
pub enum Owner {
    Local,
    Remote(RemoteNode),
}

impl From<Node::Model> for RemoteNode {
    fn from(node: Node::Model) -> Self {
        Self {
            address: node.address,
            tls_spki_sha256: node.tls_spki_sha256,
        }
    }
}

impl Owner {
    pub const fn local() -> Self {
        Self::Local
    }

    pub fn remote(node: Node::Model) -> Self {
        Self::Remote(node.into())
    }
}

/// resolve a node UUID into an [Owner::Local]/[Owner::Remote],
/// handling invalid IDs (warn and fall back to local)
pub async fn node_owner(
    ctx: &UnauthenticatedRequestContext,
    node_id: Option<NodeId>,
) -> Result<Owner, WarpgateError> {
    let services = ctx.services();
    let Some(node_id) = node_id else {
        return Ok(Owner::Local);
    };
    if node_id.0.is_nil() || node_id == services.cluster.node_id {
        return Ok(Owner::Local);
    }
    let Some(node) = Node::Entity::find_by_id(node_id).one(&services.db).await? else {
        warn!(%node_id, "Owner node is gone from the cluster; serving locally");
        return Ok(Owner::Local);
    };
    Ok(Owner::remote(node))
}

pub async fn session_owner(
    ctx: &UnauthenticatedRequestContext,
    session: &TargetSession::Model,
) -> Result<Owner, WarpgateError> {
    node_owner(ctx, session.node_id).await
}

/// Who a forwarded request acts as on the peer.
enum ForwardIdentity<'a> {
    /// An authenticated request: the peer runs it as this user and re-checks
    /// ownership of whatever the path names. The browser session cookie is
    /// dropped — peer hops authenticate via the cluster token, not the cookie.
    User(&'a RequestAuthorization),
    /// An in-progress, not-yet-authenticated login: there is no identity to
    /// stamp, and the session cookie is forwarded instead so the peer resolves
    /// the same session and reaches the auth state only it holds.
    PendingLogin,
}

impl ForwardIdentity<'_> {
    fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::User(auth) => auth.as_full_user().map(|u| u.user_id()),
            Self::PendingLogin => None,
        }
    }

    const fn forwards_cookie(&self) -> bool {
        matches!(self, Self::PendingLogin)
    }
}

/// Serve a request with `serve_local`, or if the resource is owned by another
/// node, forward the request there instead.
pub async fn proxy_or_serve<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    proxy_or_serve_as(
        ctx,
        ForwardIdentity::User(&ctx.auth),
        req,
        owner,
        body,
        serve_local,
    )
    .await
}

/// [`proxy_or_serve`] for a login step that has not authenticated yet: the peer
/// is reached as the browser session rather than as a user.
pub async fn proxy_or_serve_pending_login<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    proxy_or_serve_as(
        ctx,
        ForwardIdentity::PendingLogin,
        req,
        owner,
        body,
        serve_local,
    )
    .await
}

async fn proxy_or_serve_as<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    ctx: &UnauthenticatedRequestContext,
    identity: ForwardIdentity<'_>,
    req: &Request,
    owner: Owner,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    match owner {
        Owner::Remote(remote) => {
            let response = forward_http_inner(
                ctx.services(),
                req,
                &path_and_query(req),
                remote,
                &ctx.services().cluster_token,
                identity,
                body.map(|b| serde_json::to_vec(&b))
                    .transpose()
                    .context("serializing body for forwarding")?,
            )
            .await?;

            Ok(R::reparse_forwarded_response(response).await?)
        }
        Owner::Local => serve_local().await,
    }
}

pub async fn proxy_or_serve_websocket<F, Fut>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    ws: WebSocket,
    owner: Owner,
    serve_local: F,
) -> poem::Result<Response>
where
    F: FnOnce(WebSocket) -> Fut,
    Fut: Future<Output = poem::Result<Response>>,
{
    match owner {
        Owner::Remote(remote) => {
            forward_websocket(ctx, req, ws, remote, &ctx.services().cluster_token).await
        }
        Owner::Local => serve_local(ws).await,
    }
}

/// How long a single peer gets to answer. A node that is registered but
/// unreachable must not hold up the rest of a fan-out.
const PEER_TIMEOUT: Duration = Duration::from_secs(10);

/// [fan_out_to_peers] but expect a specific HTTP response code
/// and return a list of (hostname, code) of responses that did not match
pub async fn fan_out_to_peers_expecting(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    expected: StatusCode,
) -> Vec<(String, StatusCode)> {
    fan_out_to_peers(ctx, req, req.original_uri().path())
        .await
        .into_iter()
        .map(|(hostname, response)| (hostname, response.status()))
        .filter(|(_, status)| *status != expected)
        .collect()
}

/// Forwards `req` as `path` to every other registered node and collects what
/// they answer, paired with the node's hostname for logging.
///
/// Best effort: a node can be registered but already gone (a crashed node stays
/// in the registry until the reaper drops it), so an unreachable peer is logged,
/// not raised. Callers must not fan out a request that arrived from a peer -
/// see [`reject_second_hop`].
pub async fn fan_out_to_peers(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    path: &str,
) -> Vec<(String, Response)> {
    let services = ctx.services();
    let peers = Node::Entity::find()
        .filter(Node::Column::Id.ne(services.cluster.node_id))
        .all(&services.db)
        .await;
    let peers = match peers {
        Ok(peers) => peers,
        Err(error) => {
            warn!(%error, "Failed to list cluster nodes");
            return vec![];
        }
    };

    // Concurrently, so the fan-out costs one slow peer rather than their sum.
    join_all(peers.into_iter().map(|peer| {
        let hostname = peer.hostname.clone();
        async move {
            let forward = forward_http_to(ctx, req, path, peer.into(), &services.cluster_token);
            match timeout(PEER_TIMEOUT, forward).await {
                Ok(Ok(response)) => Some((hostname, response)),
                Ok(Err(error)) => {
                    warn!(node = %hostname, %error, "Cluster node request failed");
                    None
                }
                Err(_) => {
                    warn!(node = %hostname, "Cluster node request timed out");
                    None
                }
            }
        }
    }))
    .await
    .into_iter()
    .flatten()
    .collect()
}

fn reject_second_hop(req: &Request, services: &Services) -> poem::Result<()> {
    if is_cluster_peer_request(req, &services.cluster_token) {
        return Err(poem::Error::from_string(
            "Refusing to forward an already-forwarded cluster request",
            StatusCode::BAD_GATEWAY,
        ));
    }
    Ok(())
}

/// Peer TLS config plus every address `owner.address` resolves to, so callers
/// can try each rather than only the first record.
async fn peer_connection(
    services: &Services,
    owner: &RemoteNode,
) -> poem::Result<(rustls::ClientConfig, Vec<SocketAddr>)> {
    let Some(pin) = owner.tls_spki_sha256.clone() else {
        return Err(anyhow!(
            "The peer node has not published a cluster TLS key pin (is it running an older version?)"
        )
        .into());
    };
    let params = Parameters::Entity::get(&services.db)
        .await
        .map_err(poem::error::InternalServerError)?;
    let tls = configure_cluster_tls_connector(params.ca_certificate_pem.as_bytes(), pin)
        .map_err(poem::error::InternalServerError)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&owner.address)
        .await
        .map_err(poem::error::BadGateway)?
        .collect();
    if addrs.is_empty() {
        return Err(poem::error::BadGateway(std::io::Error::other(format!(
            "cannot resolve peer address {}",
            owner.address
        ))));
    }
    Ok((tls, addrs))
}

/// The peer port, shared across every resolved address (they differ only by IP).
fn peer_port(addrs: &[SocketAddr]) -> poem::Result<u16> {
    addrs
        .first()
        .map(SocketAddr::port)
        .ok_or_else(|| poem::error::BadGateway(std::io::Error::other("no peer address")))
}

/// Connect to the first reachable resolved address.
async fn connect_any(
    addrs: &[SocketAddr],
) -> Result<tokio::net::TcpStream, Option<std::io::Error>> {
    let mut last_error = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error)
}

/// Forwards `req` to `path` on the peer rather than the request's own path - for
/// when the peer's copy of the request needs different parameters.
pub(crate) async fn forward_http_to(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    path: &str,
    owner: RemoteNode,
    token: &Secret<String>,
) -> poem::Result<Response> {
    forward_http_inner(
        ctx.services(),
        req,
        path,
        owner,
        token,
        ForwardIdentity::User(&ctx.auth),
        None,
    )
    .await
}

/// Forwards `req` to `owner` as `identity`.
async fn forward_http_inner(
    services: &Services,
    req: &Request,
    path: &str,
    owner: RemoteNode,
    token: &Secret<String>,
    identity: ForwardIdentity<'_>,
    body: Option<Vec<u8>>,
) -> poem::Result<Response> {
    reject_second_hop(req, services)?;
    let (tls, addrs) = peer_connection(services, &owner).await?;
    let url = format!(
        "https://{CLUSTER_TLS_SNI_NAME}:{}{path}",
        peer_port(&addrs)?,
    );

    let mut headers = poem::http::HeaderMap::new();
    for (name, value) in req.headers() {
        if should_forward(name) || (identity.forwards_cookie() && name == COOKIE) {
            headers.insert(name.clone(), value.clone());
        }
    }

    // Per-request client: the TLS config pins one specific peer, so a shared
    // pooled client cannot be reused across nodes. reqwest tries the resolved
    // addresses in order.
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .resolve_to_addrs(CLUSTER_TLS_SNI_NAME, &addrs)
        .build()
        .map_err(poem::error::InternalServerError)?;

    let mut request = client
        .request(req.method().clone(), &url)
        .headers(headers)
        .header(X_WARPGATE_CLUSTER_TOKEN.clone(), token.expose_secret());
    if let Some(user_id) = identity.user_id() {
        request = request.header(X_WARPGATE_CLUSTER_IDENTITY.clone(), user_id.to_string());
    }
    // The peer's TCP peer is this node, so pass on who the client really is.
    if let Some(client_ip) = get_client_ip(req, services).await {
        request = request.header(X_WARPGATE_CLUSTER_CLIENT_IP.clone(), client_ip);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request.send().await.map_err(poem::error::BadGateway)?;

    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        if should_forward(name) {
            builder = builder.header(name, value);
        }
    }
    Ok(builder.body(Body::from_bytes_stream(
        response.bytes_stream().map_err(std::io::Error::other),
    )))
}

pub async fn forward_websocket(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    ws: WebSocket,
    owner: RemoteNode,
    token: &Secret<String>,
) -> poem::Result<Response> {
    reject_second_hop(req, ctx.services())?;
    let (tls, addrs) = peer_connection(ctx.services(), &owner).await?;
    let host = format!("{CLUSTER_TLS_SNI_NAME}:{}", peer_port(&addrs)?);
    let url = format!("wss://{host}{}", path_and_query(req));

    let mut builder = poem::http::Request::builder()
        .uri(&url)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(poem::http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            poem::http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        .header(HOST, host)
        .header(X_WARPGATE_CLUSTER_TOKEN.clone(), token.expose_secret());
    if let Some(user_id) = ctx.auth.as_full_user().map(|x| x.user_id()) {
        builder = builder.header(X_WARPGATE_CLUSTER_IDENTITY.clone(), user_id.to_string());
    }
    let request = builder.body(()).map_err(poem::error::InternalServerError)?;

    let stream = connect_any(&addrs).await.map_err(|e| {
        poem::error::BadGateway(e.unwrap_or_else(|| std::io::Error::other("no peer address")))
    })?;

    let (peer, _) = client_async_tls_with_config(
        request,
        stream,
        None,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .map_err(poem::error::BadGateway)?;

    Ok(ws
        .on_upgrade(move |socket| async move {
            let (peer_sink, peer_source) = peer.split();
            let (client_sink, client_source) = socket.split();
            let identity = |msg| Box::pin(async move { anyhow::Ok(msg) });
            let mut to_client = tokio::spawn(pump_websocket(peer_source, client_sink, identity));
            let mut to_peer = tokio::spawn(pump_websocket(client_source, peer_sink, identity));
            tokio::select! {
                _ = &mut to_client => to_peer.abort(),
                _ = &mut to_peer => to_client.abort(),
            }
        })
        .into_response())
}

fn path_and_query(req: &Request) -> String {
    req.original_uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default()
}

/// Cluster-hop header filter: everything the general proxy deny-list blocks
/// (connection management plus any `x-warpgate-*` credential), plus message
/// framing — the body is re-streamed, so the original framing headers don't
/// apply — and the client's cookies: the peer hop is authorized by the cluster
/// token alone.
fn should_forward(name: &HeaderName) -> bool {
    may_forward_header(name)
        && name != CONTENT_LENGTH
        && name != TRANSFER_ENCODING
        && name != COOKIE
}

pub trait ReparseForwardedResponse: Sized {
    fn reparse_forwarded_response(
        response: Response,
    ) -> impl Future<Output = poem::Result<Self>> + Send;
}

/// Parses a forwarded response body as a poem-openapi object, which have no
/// serde impls of their own.
pub async fn parse_forwarded_body<T: ParseFromJSON>(response: Response) -> poem::Result<T> {
    let bytes = response
        .into_body()
        .into_bytes()
        .await
        .map_err(poem::error::InternalServerError)?;
    let value = serde_json::from_slice(&bytes).map_err(poem::error::InternalServerError)?;
    T::parse_from_json(Some(value))
        .map_err(|e| poem::Error::from_string(e.into_message(), StatusCode::INTERNAL_SERVER_ERROR))
}

/// A peer response outside the endpoint's own set of outcomes, surfaced with the
/// peer's status and body rather than parsed as one of them.
pub async fn forwarded_error(response: Response) -> poem::Error {
    let status = response.status();
    let body = response.into_body().into_string().await.unwrap_or_default();
    poem::Error::from_string(body, status)
}

impl ReparseForwardedResponse for Response {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        Ok(response)
    }
}
