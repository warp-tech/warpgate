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

use anyhow::anyhow;
use futures::{StreamExt, TryStreamExt};
use poem::http::header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TRANSFER_ENCODING, UPGRADE};
use poem::http::{HeaderName, StatusCode};
use poem::web::websocket::WebSocket;
use poem::{Body, IntoResponse, Request, Response};
use sea_orm::EntityTrait;
use tokio_tungstenite::{Connector, client_async_tls_with_config, tungstenite};
use warpgate_ca::CLUSTER_TLS_SNI_NAME;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::may_forward_header;
use warpgate_common::{Secret, WarpgateError};
use warpgate_common_http::{
    AuthenticatedRequestContext, X_WARPGATE_CLUSTER_TOKEN, X_WARPGATE_TOKEN,
};
use warpgate_db_entities::{Node, Parameters, Session};
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

impl Owner {
    pub fn local() -> Self {
        Self::Local
    }

    pub fn remote(node: Node::Model) -> Self {
        Self::Remote(RemoteNode {
            address: node.address,
            tls_spki_sha256: node.tls_spki_sha256,
        })
    }
}

/// Which node owns a session's live handle. `Local` also covers sessions with
/// no recorded owner (from before clustering).
pub async fn session_owner(
    ctx: &AuthenticatedRequestContext,
    session: &Session::Model,
) -> Result<Owner, WarpgateError> {
    let services = ctx.services();
    let Some(owner_id) = session.node_id else {
        return Ok(Owner::Local);
    };
    if owner_id == services.cluster.node_id {
        return Ok(Owner::Local);
    }
    let Some(node) = Node::Entity::find_by_id(owner_id).one(&services.db).await? else {
        return Err(WarpgateError::NodeGone(owner_id));
    };
    Ok(Owner::remote(node))
}

/// Serve a request with `serve_local`, or if data is owned
/// by another node, forward the request there instead
pub async fn proxy_or_serve<F, Fut>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    serve_local: F,
) -> poem::Result<Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<Response>>,
{
    match owner {
        Owner::Remote(remote) => {
            forward_http(ctx, req, remote, &ctx.services().cluster_token).await
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

/// Error for a peer status a [`FromProxiedStatus`] impl doesn't recognise.
pub fn unexpected_proxied_status(status: StatusCode) -> poem::Error {
    poem::Error::from_string(
        format!("Unexpected response from the owner node: {status}"),
        StatusCode::BAD_GATEWAY,
    )
}

/// Reconstructs a typed OpenAPI response from the HTTP status a peer node
/// returned. Implemented once per `ApiResponse` enum that is reachable
/// cross-node, next to the enum, so its status↔variant mapping lives in one
/// place. [`local_or_forward`] uses it to bridge the raw proxied response back
/// into the handler's typed world.
pub trait FromProxiedStatus: Sized {
    fn from_proxied_status(status: StatusCode) -> poem::Result<Self>;
}

/// Forward `req` to a specific owner node and translate the peer's status into
/// the caller's typed response. For handlers that resolve the owner themselves
/// (e.g. via an identity check) rather than through an [`Owner`].
pub async fn forward_and_translate<R: FromProxiedStatus>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    remote: RemoteNode,
) -> poem::Result<R> {
    let response = forward_http(ctx, req, remote, &ctx.services().cluster_token).await?;
    R::from_proxied_status(response.status())
}

/// The typed-response analogue of [`proxy_or_serve`]: serve the response locally
/// when this node owns the resource, otherwise forward the request to the owner
/// and translate its status back into the handler's `ApiResponse` type.
///
/// OpenAPI handlers can't use `proxy_or_serve` directly — that yields a raw
/// `Response`, but an `#[oai]` method must return its typed response enum.
pub async fn local_or_forward<R, L, Fut>(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    owner: Owner,
    serve_local: L,
) -> poem::Result<R>
where
    R: FromProxiedStatus,
    L: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    match owner {
        Owner::Local => serve_local().await,
        Owner::Remote(remote) => forward_and_translate(ctx, req, remote).await,
    }
}

/// Peer TLS config plus every address `owner.address` resolves to, so callers
/// can try each rather than only the first record.
async fn peer_connection(
    ctx: &AuthenticatedRequestContext,
    owner: &RemoteNode,
) -> poem::Result<(rustls::ClientConfig, Vec<SocketAddr>)> {
    let Some(pin) = owner.tls_spki_sha256.clone() else {
        return Err(anyhow!(
            "The peer node has not published a cluster TLS key pin (is it running an older version?)"
        )
        .into());
    };
    let params = Parameters::Entity::get(&ctx.services().db)
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
        )))
        .into());
    }
    Ok((tls, addrs))
}

/// The peer port, shared across every resolved address (they differ only by IP).
fn peer_port(addrs: &[SocketAddr]) -> poem::Result<u16> {
    addrs
        .first()
        .map(SocketAddr::port)
        .ok_or_else(|| poem::error::BadGateway(std::io::Error::other("no peer address")).into())
}

/// Connect to the first reachable resolved address.
async fn connect_any(addrs: &[SocketAddr]) -> poem::Result<tokio::net::TcpStream> {
    let mut last_error = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(poem::error::BadGateway(
        last_error.unwrap_or_else(|| std::io::Error::other("no peer address")),
    )
    .into())
}

/// Per-request client: the TLS config pins one specific peer, so a shared
/// pooled client cannot be reused across nodes. reqwest tries the resolved
/// addresses in order.
fn peer_reqwest_client(
    tls: rustls::ClientConfig,
    addrs: &[SocketAddr],
) -> poem::Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .resolve_to_addrs(CLUSTER_TLS_SNI_NAME, addrs)
        .build()
        .map_err(poem::error::InternalServerError)
        .map_err(Into::into)
}

/// POSTs a JSON body to a purpose-built internal endpoint on a peer node,
/// authenticated by the cluster token alone, and returns the response status.
/// Unlike [`forward_http`], nothing of the incoming request is forwarded —
/// the body carries the entire meaning.
pub async fn post_json_to_peer<B: serde::Serialize + ?Sized>(
    ctx: &AuthenticatedRequestContext,
    node: Node::Model,
    path: &str,
    body: &B,
) -> poem::Result<poem::http::StatusCode> {
    let remote = RemoteNode {
        address: node.address,
        tls_spki_sha256: node.tls_spki_sha256,
    };
    let (tls, addrs) = peer_connection(ctx, &remote).await?;
    let url = format!(
        "https://{CLUSTER_TLS_SNI_NAME}:{}{path}",
        peer_port(&addrs)?
    );
    let client = peer_reqwest_client(tls, &addrs)?;
    let response = client
        .post(&url)
        .json(body)
        .header(
            X_WARPGATE_CLUSTER_TOKEN.clone(),
            ctx.services().cluster_token.expose_secret(),
        )
        .send()
        .await
        .map_err(poem::error::BadGateway)?;
    Ok(response.status())
}

pub async fn forward_http(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    owner: RemoteNode,
    token: &Secret<String>,
) -> poem::Result<Response> {
    let (tls, addrs) = peer_connection(ctx, &owner).await?;
    let url = format!(
        "https://{CLUSTER_TLS_SNI_NAME}:{}{}",
        peer_port(&addrs)?,
        path_and_query(req)
    );

    let mut headers = poem::http::HeaderMap::new();
    for (name, value) in req.headers() {
        if should_forward(name) {
            headers.insert(name.clone(), value.clone());
        }
    }

    let client = peer_reqwest_client(tls, &addrs)?;

    let response = client
        .request(req.method().clone(), &url)
        .headers(headers)
        .header(X_WARPGATE_CLUSTER_TOKEN.clone(), token.expose_secret())
        // Typed (OpenAPI) peer endpoints require a token/cookie security scheme
        // to be *present* before the handler runs; the cluster token — checked
        // ahead of it in the auth order — is the actual authorization, so this
        // header only unlocks the schema check.
        .header(X_WARPGATE_TOKEN.clone(), token.expose_secret())
        .send()
        .await
        .map_err(poem::error::BadGateway)?;

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

async fn forward_websocket(
    ctx: &AuthenticatedRequestContext,
    req: &Request,
    ws: WebSocket,
    owner: RemoteNode,
    token: &Secret<String>,
) -> poem::Result<Response> {
    let (tls, addrs) = peer_connection(ctx, &owner).await?;
    let host = format!("{CLUSTER_TLS_SNI_NAME}:{}", peer_port(&addrs)?);
    let url = format!("wss://{host}{}", path_and_query(req));

    let request = poem::http::Request::builder()
        .uri(&url)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(poem::http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            poem::http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        .header(HOST, host)
        .header(X_WARPGATE_CLUSTER_TOKEN.clone(), token.expose_secret())
        .body(())
        .map_err(poem::error::InternalServerError)?;

    let stream = connect_any(&addrs).await?;
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
