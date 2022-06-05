use anyhow::Result;
use cookie::Cookie;
use delegate::delegate;
use futures::{SinkExt, StreamExt};
use http::header::HeaderName;
use http::uri::{Authority, Scheme};
use http::Uri;
use poem::session::Session;
use poem::web::websocket::{CloseCode, Message, WebSocket};
use poem::web::{Data, Html};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use warpgate_web::lookup_built_file;
use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;
use tokio_tungstenite::{connect_async_with_config, tungstenite};
use tracing::*;
use warpgate_common::{try_block, Services, Target, TargetHTTPOptions, TargetOptions};

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
    fn header(self, k: HeaderName, v: String) -> Self;
}

impl SomeRequestBuilder for reqwest::RequestBuilder {
    delegate! {
        to self {
            fn header(self, k: HeaderName, v: String) -> Self;
        }
    }
}

impl SomeRequestBuilder for http::request::Builder {
    delegate! {
        to self {
            fn header(self, k: HeaderName, v: String) -> Self;
        }
    }
}

static TARGET_SESSION_KEY: &str = "target";

#[derive(Deserialize)]
struct QueryParams {
    warpgate_target: Option<String>,
}

#[handler]
pub async fn test_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    session: &Session,
    body: Body,
    services: Data<&Services>,
) -> poem::Result<Response> {
    let params: QueryParams = req.params()?;

    if let Some(target_name) = params.warpgate_target {
        session.set(TARGET_SESSION_KEY, target_name);
    }

    let Some(target_name) = session.get::<String>(TARGET_SESSION_KEY) else {
        return Ok(target_select_view().into_response());
    };

    let target = {
        services
            .config
            .lock()
            .await
            .store
            .targets
            .iter()
            .filter_map(|t| match t.options {
                TargetOptions::Http(ref options) => Some((t, options)),
                _ => None,
            })
            .find(|(t, _)| t.name == target_name)
            .map(|(t, opt)| (t.clone(), opt.clone()))
    };

    let Some((target, options)) = target else {
        return Ok(target_select_view().into_response());
    };

    Ok(match ws {
        Some(ws) => proxy_ws(req, ws, options).await?.into_response(),
        None => proxy_normal(req, body, target, options)
            .await?
            .into_response(),
    })
}

pub fn target_select_view() -> impl IntoResponse {
    Html("No target selected")
}

lazy_static::lazy_static! {
    static ref DEMO_TARGET: Target = Target {
        allow_roles: vec![],
        options: TargetOptions::Http(TargetHTTPOptions {
            url: "https://ci.elements.tv/".to_string(),
        }),
        name: String::from("Target"),
    };

    static ref DONT_FORWARD_HEADERS: HashSet<HeaderName> = {
        let mut s = HashSet::new();
        s.insert(http::header::ACCEPT_ENCODING);
        s.insert(http::header::SEC_WEBSOCKET_EXTENSIONS);
        s.insert(http::header::SEC_WEBSOCKET_ACCEPT);
        s.insert(http::header::SEC_WEBSOCKET_KEY);
        s.insert(http::header::SEC_WEBSOCKET_VERSION);
        s.insert(http::header::UPGRADE);
        s.insert(http::header::CONNECTION);
        s.insert(http::header::STRICT_TRANSPORT_SECURITY);
        s
    };
}

fn construct_uri(req: &Request, options: &TargetHTTPOptions, websocket: bool) -> Uri {
    let target_uri = Uri::try_from(options.url.clone()).unwrap();
    let source_uri = req.uri().clone();

    let authority = target_uri.authority().unwrap().to_string();
    let authority = authority.split("@").last().unwrap();
    let authority: Authority = authority.try_into().unwrap();
    let mut uri = http::uri::Builder::new()
        .authority(authority)
        .path_and_query(source_uri.path_and_query().unwrap().clone());

    uri = uri.scheme(target_uri.scheme().unwrap().clone());

    if websocket {
        uri = uri.scheme(
            Scheme::from_str(
                if target_uri.scheme().unwrap() == &Scheme::from_str("http").unwrap() {
                    "ws"
                } else {
                    "wss"
                },
            )
            .unwrap(),
        );
    }

    uri.build().unwrap()
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
    server_response.headers_mut().extend(headers.into_iter());

    server_response.set_status(client_response.status());
}

fn rewrite_response(resp: &mut Response, target: &Target) -> Result<()> {
    let TargetOptions::Http(ref options) = target.options else {panic!();};

    let target_uri = Uri::try_from(options.url.clone()).unwrap();
    let headers = resp.headers_mut();

    if let Some(value) = headers.get_mut(http::header::LOCATION) {
        let redirect_uri = Uri::try_from(value.as_bytes()).unwrap();
        if redirect_uri.authority() == target_uri.authority() {
            let old_value = value.clone();
            *value = Uri::builder()
                .path_and_query(redirect_uri.path_and_query().unwrap().clone())
                .build()
                .unwrap()
                .to_string()
                .parse()
                .unwrap();
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
            // {
            // }
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
                .map(|v| v.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    target
}

pub async fn proxy_normal(
    req: &Request,
    body: Body,
    target: Target,
    options: TargetHTTPOptions,
) -> poem::Result<Response> {
    let uri = construct_uri(req, &options, false).to_string();

    tracing::debug!("URI: {:?}", uri);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connection_verbose(true)
        .build()
        .unwrap();
    let mut client_request = client.request(req.method().into(), uri.clone());

    client_request = copy_server_request(&req, client_request);

    client_request = client_request.body(reqwest::Body::wrap_stream(body.into_bytes_stream()));

    let client_request = client_request.build().unwrap();
    let client_response = client.execute(client_request).await.unwrap();

    let mut response: Response = "".into();

    tracing::info!(
        "{:?} {:?} - {:?}",
        client_response.status(),
        uri,
        client_response.content_length().unwrap_or(0)
    );

    copy_client_response(&client_response, &mut response);
    copy_client_body(client_response, &mut response).await?;

    rewrite_response(&mut response, &target)?;
    Ok(response)
}

async fn copy_client_body(client_response: reqwest::Response, response: &mut Response) -> Result<()> {
    if response.content_type().map(|c| c.starts_with("text/html")) == Some(true) && response.status() == 200 {
        copy_client_body_and_embed(client_response, response).await?;
        return Ok(())
    }

    response.set_body(Body::from_bytes_stream(client_response.bytes_stream()));
    Ok(())
}

async fn copy_client_body_and_embed(client_response: reqwest::Response, response: &mut Response) -> Result<()> {
    let content = client_response.text().await?;

    let script_name = lookup_built_file("src/main.embed.ts")?;

    let inject = format!(r#"<script type="module" src="/@warpgate/{}"></script>"#, script_name);
    let before = "</head>";
    let content = content.replacen(before, &format!("{}{}", inject, before), 1);

    response.headers_mut().remove(http::header::CONTENT_LENGTH);
    response.headers_mut().remove(http::header::CONTENT_ENCODING);
    response.headers_mut().remove(http::header::CONTENT_TYPE);
    response.headers_mut().remove(http::header::TRANSFER_ENCODING);
    response.headers_mut().insert(http::header::CONTENT_TYPE, "text/html; charset=utf-8".parse()?);
    response.set_body(content);
    Ok(())
}

async fn proxy_ws(
    req: &Request,
    ws: WebSocket,
    options: TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let uri = construct_uri(req, &options, true);
    proxy_ws_inner(req, ws, uri.clone()).await.map_err(|error| {
        tracing::error!(?uri, ?error, "WebSocket proxy failed");
        error
    })
}

async fn proxy_ws_inner(req: &Request, ws: WebSocket, uri: Uri) -> poem::Result<impl IntoResponse> {
    let mut client_request = http::request::Builder::new()
        .uri(uri.clone())
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        );
    client_request = copy_server_request(&req, client_request);

    let (client, client_response) = connect_async_with_config(
        client_request
            .body(())
            .map_err(poem::error::InternalServerError)?,
        None,
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
                                client_sink.send(tungstenite::Message::Binary(data)).await?;
                            }
                            Message::Text(text) => {
                                client_sink.send(tungstenite::Message::Text(text)).await?;
                            }
                            Message::Ping(data) => {
                                client_sink.send(tungstenite::Message::Ping(data)).await?;
                            }
                            Message::Pong(data) => {
                                client_sink.send(tungstenite::Message::Pong(data)).await?;
                            }
                            Message::Close(data) => {
                                client_sink
                                    .send(tungstenite::Message::Close(data.map(|data| {
                                        tungstenite::protocol::CloseFrame {
                                            code: data.0.into(),
                                            reason: Cow::Owned(data.1),
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
                                server_sink.send(Message::Binary(data)).await?;
                            }
                            tungstenite::Message::Text(text) => {
                                server_sink.send(Message::Text(text)).await?;
                            }
                            tungstenite::Message::Ping(data) => {
                                server_sink.send(Message::Ping(data)).await?;
                            }
                            tungstenite::Message::Pong(data) => {
                                server_sink.send(Message::Pong(data)).await?;
                            }
                            tungstenite::Message::Close(data) => {
                                server_sink
                                    .send(Message::Close(data.map(|data| {
                                        (
                                            CloseCode::from(data.code),
                                            data.reason.to_owned().to_string(),
                                        )
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

    Ok(response)
}
