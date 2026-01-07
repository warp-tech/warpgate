use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use cookie::Cookie;
use data_encoding::BASE64;
use delegate::delegate;
use futures::{SinkExt, StreamExt, TryStreamExt};
use http::header::HeaderName;
use http::uri::{Authority, Scheme};
use http::{HeaderValue, Uri};
use once_cell::sync::Lazy;
use poem::session::Session;
use poem::web::websocket::{Message, WebSocket};
use poem::web::Data;
use poem::{Body, FromRequest, IntoResponse, Request, Response};
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite, Connector};
use tracing::*;
use url::Url;
use warpgate_common::{try_block, TargetHTTPOptions, WarpgateError};
use warpgate_core::logging::http::{get_client_ip, log_request_result};
use warpgate_core::Services;
use warpgate_tls::{configure_tls_connector, TlsMode};
use warpgate_web::lookup_built_file;

use crate::common::{SessionAuthorization, SessionExt};

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

static DONT_FORWARD_HEADERS: Lazy<HashSet<HeaderName>> = Lazy::new(|| {
    #[allow(clippy::mutable_key_type)]
    let mut s = HashSet::new();
    s.insert(http::header::ACCEPT_ENCODING);
    s.insert(http::header::SEC_WEBSOCKET_EXTENSIONS);
    s.insert(http::header::SEC_WEBSOCKET_ACCEPT);
    s.insert(http::header::SEC_WEBSOCKET_KEY);
    s.insert(http::header::SEC_WEBSOCKET_VERSION);
    s.insert(http::header::UPGRADE);
    s.insert(http::header::HOST);
    s.insert(http::header::CONNECTION);
    s.insert(http::header::STRICT_TRANSPORT_SECURITY);
    s.insert(http::header::UPGRADE_INSECURE_REQUESTS);
    s
});

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

fn construct_uri(req: &Request, options: &TargetHTTPOptions, websocket: bool) -> Result<Uri> {
    let target_uri = Uri::try_from(options.url.clone())?;
    let source_uri = req.uri().clone();

    let authority = target_uri
        .authority()
        .context("No authority in the URL")?
        .to_string();

    let authority: Authority = authority.try_into()?;
    let mut uri = http::uri::Builder::new()
        .authority(authority)
        .path_and_query(
            source_uri
                .path_and_query()
                .context("No path in the URL")?
                .clone(),
        );

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
    for h in client_response.headers().iter() {
        if DONT_FORWARD_HEADERS.contains(h.0) {
            if let http::header::Entry::Occupied(e) = headers.entry(h.0) {
                e.remove_entry();
            }
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
                cookie.set_expires(cookie::Expiration::Session);
                *value = cookie.to_string().parse()?;
            } catch (error: anyhow::Error) {
                warn!(?error, header=?value, "Failed to parse response cookie")
            })
        }
    }

    Ok(())
}

fn copy_server_request<B: SomeRequestBuilder>(req: &Request, mut target: B) -> B {
    for k in req.headers().keys() {
        if DONT_FORWARD_HEADERS.contains(k) {
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

fn inject_forwarding_headers<B: SomeRequestBuilder>(req: &Request, mut target: B) -> Result<B> {
    #[allow(clippy::unwrap_used)]
    if let Some(host) = req.headers().get(http::header::HOST) {
        target = target.header(
            X_FORWARDED_HOST.clone(),
            host.to_str()?.split(':').next().unwrap(),
        );
    }
    target = target.header(X_FORWARDED_PROTO.clone(), req.scheme().as_str());
    if let Some(addr) = req.remote_addr().as_socket_addr() {
        target = target.header(X_FORWARDED_FOR.clone(), addr.ip().to_string());
    }
    Ok(target)
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
    body: Body,
    options: &TargetHTTPOptions,
) -> poem::Result<Response> {
    let uri = construct_uri(req, options, false)?;
    let services = Data::<&Services>::from_request_without_body(req).await?;

    tracing::debug!("URI: {:?}", uri);

    let mut client = reqwest::Client::builder()
        .gzip(true)
        .redirect(reqwest::redirect::Policy::none())
        .connection_verbose(true);

    if let TlsMode::Required = options.tls.mode {
        client = client.https_only(true);
    }

    client = client.redirect(reqwest::redirect::Policy::custom({
        let tls_mode = options.tls.mode;
        let uri = uri.clone();
        move |attempt| {
            if tls_mode == TlsMode::Preferred
                && uri.scheme() == Some(&Scheme::HTTP)
                && attempt.url().scheme() == "https"
            {
                debug!("Following HTTP->HTTPS redirect");
                attempt.follow()
            } else {
                attempt.stop()
            }
        }
    }));

    if !options.tls.verify {
        client = client.danger_accept_invalid_certs(true);
    }

    let client = client.build().context("Could not build request")?;

    let (authorization_header, uri) = extract_basic_auth(uri)?;

    let mut client_request = client.request(req.method().into(), uri.to_string());

    client_request = copy_server_request(req, client_request);
    client_request = inject_forwarding_headers(req, client_request)?;
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
    copy_client_body(client_response, &mut response).await?;

    log_request_result(
        req.method(),
        req.original_uri(),
        get_client_ip(req, Some(*services)).await.as_deref(),
        &status,
    );

    rewrite_response(&mut response, options, &uri)?;
    Ok(response)
}

async fn copy_client_body(
    client_response: reqwest::Response,
    response: &mut Response,
) -> Result<()> {
    if response.content_type().map(|c| c.starts_with("text/html")) == Some(true)
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
        inject += &format!(r#"<link rel="stylesheet" href="/@warpgate/{css_file}" />"#,);
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
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let uri = construct_uri(req, options, true)?;
    proxy_ws_inner(req, ws, uri.clone(), options)
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
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
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
    client_request = inject_forwarding_headers(req, client_request)?;
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
            let (mut client_sink, mut client_source) = client.split();

            let (mut server_sink, mut server_source) = socket.split();

            if let Err(error) = {
                let server_to_client = tokio::spawn(async move {
                    while let Some(msg) = server_source.next().await {
                        tracing::debug!("Server: {:?}", msg);
                        match msg? {
                            Message::Binary(data) => {
                                client_sink
                                    .send(tungstenite::Message::Binary(data.into()))
                                    .await?;
                            }
                            Message::Text(text) => {
                                client_sink
                                    .send(tungstenite::Message::Text(text.into()))
                                    .await?;
                            }
                            Message::Ping(data) => {
                                client_sink
                                    .send(tungstenite::Message::Ping(data.into()))
                                    .await?;
                            }
                            Message::Pong(data) => {
                                client_sink
                                    .send(tungstenite::Message::Pong(data.into()))
                                    .await?;
                            }
                            Message::Close(data) => {
                                client_sink
                                    .send(tungstenite::Message::Close(data.map(|data| {
                                        tungstenite::protocol::CloseFrame {
                                            code: u16::from(data.0).into(),
                                            reason: Utf8Bytes::from(data.1),
                                        }
                                    })))
                                    .await?;
                            }
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                });

                let client_to_server = tokio::spawn(async move {
                    while let Some(msg) = client_source.next().await {
                        tracing::debug!("Client: {:?}", msg);
                        match msg? {
                            tungstenite::Message::Binary(data) => {
                                server_sink.send(Message::Binary(data.to_vec())).await?;
                            }
                            tungstenite::Message::Text(text) => {
                                server_sink.send(Message::Text(text.to_string())).await?;
                            }
                            tungstenite::Message::Ping(data) => {
                                server_sink.send(Message::Ping(data.to_vec())).await?;
                            }
                            tungstenite::Message::Pong(data) => {
                                server_sink.send(Message::Pong(data.to_vec())).await?;
                            }
                            tungstenite::Message::Close(data) => {
                                server_sink
                                    .send(Message::Close(data.map(|data| {
                                        (u16::from(data.code).into(), data.reason.to_string())
                                    })))
                                    .await?;
                            }
                            tungstenite::Message::Frame(_) => unreachable!(),
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                });

                server_to_client.await??;
                client_to_server.await??;
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
