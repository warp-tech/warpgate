use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use cookie::Cookie;
use data_encoding::BASE64;
use delegate::delegate;
use futures::{StreamExt, TryStreamExt};
use http::header::HeaderName;
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderValue, StatusCode, Uri};
use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::WebSocket;
use poem::{Body, FromRequest, IntoResponse, Request, Response};
use tokio::sync::Mutex;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite};
use tracing::{debug, error, warn};
use url::{Url, form_urlencoded};
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::{
    X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO, may_forward_header,
};
use warpgate_common::{TargetHTTPOptions, WarpgateError, try_block};
use warpgate_common_http::logging::{get_client_ip, log_request_result};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_tls::{TlsMode, configure_tls_connector};
use warpgate_web::lookup_built_file;

use crate::client_cache::HttpClientCache;
use crate::common::SessionExt;
use crate::session::SessionStore;

static X_WARPGATE_USERNAME: HeaderName = HeaderName::from_static("x-warpgate-username");
static X_WARPGATE_AUTHENTICATION_TYPE: HeaderName =
    HeaderName::from_static("x-warpgate-authentication-type");

trait SomeResponse {
    fn status(&self) -> http::StatusCode;
    fn headers(&self) -> &http::HeaderMap;
}

impl SomeResponse for reqwest::Response {
    delegate! {
        to self {
            fn status(&self) -> http::StatusCode;
            fn headers(&self) -> &http::HeaderMap;
        }
    }
}

impl<B> SomeResponse for http::Response<B> {
    delegate! {
        to self {
            fn status(&self) -> http::StatusCode;
            fn headers(&self) -> &http::HeaderMap;
        }
    }
}

trait SomeRequestBuilder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>;
}

impl SomeRequestBuilder for reqwest::RequestBuilder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header(k, v)
    }
}

impl SomeRequestBuilder for http::request::Builder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header(k, v)
    }
}

fn strip_warpgate_internal_query_params(pq: &PathAndQuery) -> Result<PathAndQuery> {
    let Some(query) = pq.query() else {
        return Ok(pq.clone());
    };
    let query = form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key != "warpgate-target" && key != "warpgate-ticket")
        .fold(form_urlencoded::Serializer::new(String::new()), |mut s, (k, v)| {
            s.append_pair(&k, &v);
            s
        })
        .finish();
    let path = pq.path();
    let rebuilt = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    Ok(PathAndQuery::from_str(&rebuilt)?)
}

fn construct_uri(req: &Request, options: &TargetHTTPOptions, websocket: bool) -> Result<Uri> {
    let target_uri = Uri::try_from(options.url.clone())?;
    let source_uri = req.uri().clone();

    let authority = target_uri
        .authority()
        .context("No authority in the URL")?
        .to_string();

    let authority: Authority = authority.try_into()?;
    let path_and_query = strip_warpgate_internal_query_params(
        source_uri.path_and_query().context("No path in the URL")?,
    )?;
    let mut uri = http::uri::Builder::new()
        .authority(authority)
        .path_and_query(path_and_query);

    let scheme = match options.tls.mode {
        TlsMode::Disabled => &Scheme::HTTP,
        TlsMode::Preferred => target_uri.scheme().context("No scheme in the URL")?,
        TlsMode::Required => &Scheme::HTTPS,
    };
    uri = uri.scheme(scheme.clone());

    #[allow(clippy::unwrap_used)]
    if websocket {
        uri = uri.scheme(
            Scheme::from_str(if scheme == &Scheme::from_str("http").unwrap() {
                "ws"
            } else {
                "wss"
            })
            .unwrap(),
        );
    }

    Ok(uri.build()?)
}

fn copy_client_response<R: SomeResponse>(
    client_response: &R,
    server_response: &mut poem::Response,
) {
    let mut headers = client_response.headers().clone();
    for h in client_response.headers() {
        if !may_forward_header(h.0)
            && let http::header::Entry::Occupied(e) = headers.entry(h.0)
        {
            e.remove_entry();
        }
    }
    server_response.headers_mut().extend(headers);

    server_response.set_status(client_response.status());
}

fn rewrite_request<B: SomeRequestBuilder>(mut req: B, options: &TargetHTTPOptions) -> Result<B> {
    if let Some(ref headers) = options.headers {
        for (k, v) in headers {
            req = req.header(HeaderName::try_from(k)?, v);
        }
    }
    Ok(req)
}

fn rewrite_response(
    resp: &mut Response,
    options: &TargetHTTPOptions,
    source_uri: &Uri,
) -> Result<()> {
    let target_uri = Uri::try_from(options.url.clone())?;
    let headers = resp.headers_mut();

    if let Some(value) = headers.get_mut(http::header::LOCATION) {
        let location = Url::parse(&source_uri.to_string())?.join(value.to_str()?)?;
        let redirect_uri = Uri::try_from(location.to_string())?;

        if redirect_uri.authority() == target_uri.authority() {
            let old_value = value.clone();
            *value = Uri::builder()
                .path_and_query(
                    redirect_uri
                        .path_and_query()
                        .context("No path in URL")?
                        .clone(),
                )
                .build()?
                .to_string()
                .parse()?;
            debug!("Rewrote a redirect from {:?} to {:?}", old_value, value);
        }
    }

    if let http::header::Entry::Occupied(mut entry) = headers.entry(http::header::SET_COOKIE) {
        for value in entry.iter_mut() {
            try_block!({
                let mut cookie = Cookie::parse(value.to_str()?)?;
                // Some apps clear a cookie by re-setting it with an expiration
                // in the past. We keep these as-is
                // https://github.com/warp-tech/warpgate/issues/2112
                if let Some(cookie::Expiration::DateTime(expires)) = cookie.expires()
                    && expires >= cookie::time::OffsetDateTime::now_utc()
                {
                    cookie.set_expires(cookie::Expiration::Session);
                }
                // the domain set by the target isn't going to match the actual host anyway
                // https://github.com/warp-tech/warpgate/issues/2048
                cookie.unset_domain();
                *value = cookie.to_string().parse()?;
            } catch (error: anyhow::Error) {
                warn!(?error, header=?value, "Failed to parse response cookie");
            });
        }
    }

    Ok(())
}

fn copy_server_request<B: SomeRequestBuilder>(req: &Request, mut target: B) -> B {
    for k in req.headers().keys() {
        if !may_forward_header(k) {
            continue;
        }
        target = target.header(
            k.clone(),
            req.headers()
                .get_all(k)
                .iter()
                .map(|v| v.to_str().map(|x| x.to_string()))
                .filter_map(|x| x.ok())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    target
}

fn inject_forwarding_headers<B: SomeRequestBuilder>(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    mut target: B,
) -> B {
    if let Some(host) = ctx.trusted_host_header(req) {
        target = target.header(X_FORWARDED_HOST.clone(), host);
    }
    target = target.header(X_FORWARDED_PROTO.clone(), ctx.trusted_proto(req).as_str());
    if let Some(addr) = req.remote_addr().as_socket_addr() {
        target = target.header(X_FORWARDED_FOR.clone(), addr.ip().to_string());
    }
    target
}

async fn inject_own_headers<B: SomeRequestBuilder>(req: &Request, mut target: B) -> Result<B> {
    let session = <&Session>::from_request_without_body(req).await?;
    if let Some(auth) = session.get_auth() {
        target = target.header(&X_WARPGATE_USERNAME, auth.username()).header(
            &X_WARPGATE_AUTHENTICATION_TYPE,
            match auth {
                SessionAuthorization::Ticket { .. } => "ticket",
                SessionAuthorization::User { .. } => "user",
            },
        );
    }
    Ok(target)
}

pub async fn proxy_normal_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    body: Body,
    target_name: &str,
    options: &TargetHTTPOptions,
    client_cache: &HttpClientCache,
) -> poem::Result<Response> {
    let uri = construct_uri(req, options, false)?;

    tracing::debug!("URI: {:?}", uri);

    let client = client_cache.client_for(target_name, options).await?;

    let (authorization_header, uri) = extract_basic_auth(uri)?;

    let mut client_request = client.request(req.method().into(), uri.to_string());

    client_request = copy_server_request(req, client_request);
    client_request = inject_forwarding_headers(req, ctx, client_request);
    client_request = inject_own_headers(req, client_request).await?;
    client_request = rewrite_request(client_request, options)?;
    if let Some(authorization_header) = authorization_header {
        client_request = client_request.header(http::header::AUTHORIZATION, authorization_header);
    }

    client_request = client_request.body(reqwest::Body::wrap_stream(body.into_bytes_stream()));

    let client_request = client_request.build().context("Could not build request")?;
    let client_response = client
        .execute(client_request)
        .await
        .map_err(|e| anyhow::anyhow!("Could not execute request: {e}"))?;
    let status = client_response.status();

    let mut response: Response = "".into();

    copy_client_response(&client_response, &mut response);

    let embed_session_menu = {
        let db = &ctx.services().db;
        warpgate_db_entities::Parameters::Entity::get(&db)
            .await
            .map(|p| p.show_session_menu)
            .unwrap_or(true)
    };
    copy_client_body(client_response, &mut response, embed_session_menu).await?;

    log_request_result(
        req.method(),
        req.original_uri(),
        get_client_ip(req, ctx.services()).await.as_deref(),
        status,
    );

    rewrite_response(&mut response, options, &uri)?;
    Ok(response)
}

async fn copy_client_body(
    client_response: reqwest::Response,
    response: &mut Response,
    embed_session_menu: bool,
) -> Result<()> {
    if embed_session_menu
        && response
            .content_type()
            .is_some_and(|c| c.starts_with("text/html"))
        && response.status() == 200
    {
        copy_client_body_and_embed(client_response, response).await?;
        return Ok(());
    }

    response.set_body(Body::from_bytes_stream(
        client_response
            .bytes_stream()
            .map_err(std::io::Error::other),
    ));
    Ok(())
}

async fn copy_client_body_and_embed(
    client_response: reqwest::Response,
    response: &mut Response,
) -> Result<()> {
    let content = client_response.text().await?;

    let script_manifest = lookup_built_file("src/embed/index.ts")?;

    let mut inject = format!(
        r#"<script type="module" src="/@warpgate/{}"></script>"#,
        script_manifest.file
    );
    for css_file in script_manifest.css.unwrap_or_default() {
        let _ = write!(
            &mut inject,
            r#"<link rel="stylesheet" href="/@warpgate/{css_file}" />"#
        );
    }

    let before = "</head>";
    let content = content.replacen(before, &format!("{inject}{before}"), 1);

    response.headers_mut().remove(http::header::CONTENT_LENGTH);
    response
        .headers_mut()
        .remove(http::header::CONTENT_ENCODING);
    response.headers_mut().remove(http::header::CONTENT_TYPE);
    response
        .headers_mut()
        .remove(http::header::TRANSFER_ENCODING);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse()?,
    );
    response.set_body(content);
    Ok(())
}

pub async fn proxy_websocket_request(
    req: &Request,
    ws: WebSocket,
    ctx: &AuthenticatedRequestContext,
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let uri = construct_uri(req, options, true)?;
    proxy_ws_inner(req, ws, uri.clone(), ctx, options)
        .await
        .map_err(|error| {
            tracing::error!(?uri, ?error, "WebSocket proxy failed");
            error
        })
}

/// Remove the username/password from the URL before using it for the Host header
fn extract_basic_auth(uri: Uri) -> anyhow::Result<(Option<HeaderValue>, Uri)> {
    let uri_authority = uri
        .authority()
        .ok_or(WarpgateError::NoHostInUrl)?
        .to_string();
    let parts = uri_authority.split('@').collect::<Vec<_>>();

    let host = parts.last().context("URL authority is empty")?;

    let uri = {
        let mut parts = uri.into_parts();
        parts.authority = Some(Authority::from_str(host)?);
        Uri::from_parts(parts)?
    };

    if parts.len() == 1 {
        return Ok((None, uri));
    }

    #[allow(clippy::indexing_slicing)] // checked
    let creds = parts[0];

    let auth_header = format!("Basic {}", BASE64.encode(creds.as_bytes()));

    let auth_value = HeaderValue::from_str(&auth_header)?;

    Ok((Some(auth_value), uri))
}

async fn proxy_ws_inner(
    req: &Request,
    ws: WebSocket,
    uri: Uri,
    ctx: &AuthenticatedRequestContext,
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await?
        .clone();
    let session = <&Session>::from_request_without_body(req).await?;
    let mut close_rx = session_middleware.lock().await.close_receiver_for(session);
    if close_rx.is_none()
        && matches!(
            &ctx.auth,
            RequestAuthorization::Session(SessionAuthorization::User { .. })
        )
    {
        return Err(poem::Error::from_status(StatusCode::UNAUTHORIZED));
    }

    let (authorization_header, uri) = extract_basic_auth(uri)?;
    let mut client_request = http::request::Builder::new()
        .uri(uri.clone())
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        // tungstenite requires an explicit Host header
        .header(
            http::header::HOST,
            uri.authority()
                .ok_or(WarpgateError::NoHostInUrl)
                .context("no authority in the URL")?
                .to_string(),
        );

    if let Some(authorization_header) = authorization_header {
        client_request = client_request.header(http::header::AUTHORIZATION, authorization_header);
    }

    client_request = copy_server_request(req, client_request);
    client_request = inject_forwarding_headers(req, ctx, client_request);
    client_request = inject_own_headers(req, client_request).await?;
    client_request = rewrite_request(client_request, options)?;

    let tls_config = configure_tls_connector(!options.tls.verify, false, None)
        .await
        .map_err(poem::error::InternalServerError)?;
    let connector = Connector::Rustls(Arc::new(tls_config));

    let (client, client_response) = connect_async_tls_with_config(
        client_request
            .body(())
            .map_err(poem::error::InternalServerError)?,
        None,
        true,
        Some(connector),
    )
    .await
    .map_err(poem::error::BadGateway)?;

    tracing::info!("{:?} {:?} - WebSocket", client_response.status(), uri);

    let mut response = ws
        .on_upgrade(|socket| async move {
            let (client_sink, client_source) = client.split();
            let (server_sink, server_source) = socket.split();

            if let Err(error) = {
                let mut server_to_client =
                    tokio::spawn(pump_websocket(server_source, client_sink, |msg| {
                        Box::pin(async {
                            tracing::debug!("Server: {:?}", msg);
                            anyhow::Ok(msg)
                        })
                    }));

                let mut client_to_server =
                    tokio::spawn(pump_websocket(client_source, server_sink, |msg| {
                        Box::pin(async {
                            tracing::debug!("Client: {:?}", msg);
                            anyhow::Ok(msg)
                        })
                    }));

                let (server_finished, pump_result): (
                    bool,
                    Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
                ) = tokio::select! {
                    result = &mut server_to_client => {
                        (true, Some(result))
                    }
                    result = &mut client_to_server => {
                        (false, Some(result))
                    }
                    _ = async {
                        match close_rx.as_mut() {
                            Some(close_rx) => {
                                let _ = close_rx.recv().await;
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        (false, None)
                    }
                };

                match pump_result {
                    Some(result) if server_finished => {
                        client_to_server.abort();
                        let _ = client_to_server.await;
                        result.context("server-to-client WebSocket pump task failed")??;
                    }
                    Some(result) => {
                        server_to_client.abort();
                        let _ = server_to_client.await;
                        result.context("client-to-server WebSocket pump task failed")??;
                    }
                    None => {
                        debug!("Closing WebSocket stream after HTTP session ended");
                        server_to_client.abort();
                        client_to_server.abort();
                        let _ = server_to_client.await;
                        let _ = client_to_server.await;
                    }
                }
                debug!("Closing Websocket stream");

                Ok::<_, anyhow::Error>(())
            } {
                error!(?error, "Websocket stream error");
            }
            Ok::<_, anyhow::Error>(())
        })
        .into_response();

    copy_client_response(&client_response, &mut response);
    rewrite_response(&mut response, options, &uri)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_options(url: &str) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: url.to_string(),
            tls: Default::default(),
            headers: None,
            external_host: None,
        }
    }

    #[test]
    fn rewrite_response_strips_cookie_domain() {
        let mut resp = poem::Response::builder()
            .header(
                http::header::SET_COOKIE,
                "lsws_uid=abc; HttpOnly; Secure; Path=/; Domain=100.0.0.1",
            )
            .body(());

        let options = make_options("https://100.0.0.1:7080");
        let source_uri = Uri::try_from("https://100.0.0.1:7080/login.php").unwrap();

        rewrite_response(&mut resp, &options, &source_uri).unwrap();

        let cookie_headers: Vec<_> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();

        assert_eq!(cookie_headers.len(), 1);
        let cookie = Cookie::parse(cookie_headers[0].as_str()).unwrap();
        assert_eq!(cookie.name(), "lsws_uid");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
    }

    fn rewrite_cookie(set_cookie: &str) -> Cookie<'static> {
        let mut resp = poem::Response::builder()
            .header(http::header::SET_COOKIE, set_cookie)
            .body(());
        let options = make_options("https://100.0.0.1:7080");
        let source_uri = Uri::try_from("https://100.0.0.1:7080/index.php").unwrap();
        rewrite_response(&mut resp, &options, &source_uri).unwrap();
        let cookie_headers: Vec<_> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookie_headers.len(), 1);
        Cookie::parse(cookie_headers[0].clone()).unwrap()
    }

    #[test]
    fn rewrite_response_keeps_past_expiration() {
        // A past-dated deletion cookie would otherwise drop the live session
        // cookie and cause a login loop. https://github.com/warp-tech/warpgate/issues/2112
        let cookie =
            rewrite_cookie("lsws_uid=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(cookie.value(), "deleted");
        assert!(matches!(
            cookie.expires(),
            Some(cookie::Expiration::DateTime(_))
        ));
    }

    #[test]
    fn rewrite_response_removes_future_expiration() {
        // A genuine persistent cookie must keep the expiry the origin set.
        let cookie = rewrite_cookie("lsws_uid=abc; Path=/; Expires=Tue, 01 Jan 2999 00:00:00 GMT");
        assert_eq!(cookie.expires(), None);
    }

    fn strip(pq: &str) -> String {
        strip_warpgate_internal_query_params(&PathAndQuery::from_str(pq).unwrap())
            .unwrap()
            .to_string()
    }

    #[test]
    fn strip_reserved_query_params() {
        assert_eq!(strip("/"), "/");
        assert_eq!(strip("/?a=1&b=2"), "/?a=1&b=2");
        assert_eq!(strip("/?warpgate-target=es"), "/");
        assert_eq!(strip("/search?warpgate-target=es&q=x"), "/search?q=x");
        assert_eq!(strip("/?q=x&warpgate-ticket=abc"), "/?q=x");
        assert_eq!(strip("/?warpgate-target=a&warpgate-ticket=b"), "/");
    }
}
