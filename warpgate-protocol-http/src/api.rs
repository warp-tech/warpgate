use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;
use anyhow::Result;
use cookie::Cookie;
use delegate::delegate;
use futures::{SinkExt, StreamExt};
use http::header::HeaderName;
use http::uri::{Authority, Scheme};
use http::Uri;
use poem::web::websocket::{CloseCode, Message, WebSocket};
use poem::{handler, Body, IntoResponse, Request, Response};
use tokio_tungstenite::{connect_async_with_config, tungstenite};
use tracing::*;
use warpgate_common::{Target, TargetHTTPOptions};

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

#[handler]
pub async fn test_endpoint(
    req: &Request,
    ws: Option<WebSocket>,
    body: Body,
) -> poem::Result<Response> {
    Ok(match ws {
        Some(ws) => proxy_ws(req, ws).await?.into_response(),
        None => proxy_normal(req, body).await?.into_response(),
    })
}

pub async fn proxy_normal(req: &Request, body: Body) -> poem::Result<Response> {
    let mut res = String::new();
    let mut has_auth = false;
    for h in req.headers().iter() {
        if h.0 == "Authorization" {
            // println!("Found {:?} {:?}", h.0, h.1);
            // let v = BASE64
            // .decode(h.1.as_bytes())
            // .map_err(poem::error::BadRequest)?;
            // println!("v: {:?}", v);
            if h.1 == "Basic dGVzdDpwdw==" {
                has_auth = true;
            }
        }
        res.push_str(&format!("{}: {:?}\n", h.0, h.1));
    }
    res.push('\n');
    res.push_str(&req.original_uri().to_string());

    proxy_request(req, body).await
    // let mut r = res.into_response();
    // if !has_auth {
    //     r.headers_mut().insert(
    //         "WWW-Authenticate",
    //         HeaderValue::try_from("Basic realm=\"Test\"".to_string()).unwrap(),
    //     );
    //     r.set_status(StatusCode::UNAUTHORIZED);
    // }
    // Ok(r)
}

lazy_static::lazy_static! {
    static ref DEMO_TARGET: Target = Target {
        allow_roles: vec![],
        http: Some(TargetHTTPOptions {
            url: "https://ci.elements.tv/".to_string(),
        }),
        name: String::from("Target"),
        ssh: None,
        web_admin: None,
    };

    static ref DONT_FORWARD_HEADERS: HashSet<HeaderName> = {
        let mut s = HashSet::new();
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

fn construct_uri(req: &Request, target: &Target, websocket: bool) -> Uri {
    let target_uri = Uri::try_from(target.http.clone().unwrap().url).unwrap();
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
    let target_uri = Uri::try_from(target.http.clone().unwrap().url).unwrap();
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
            if let Result::<()>::Err(error) = try {
                let mut cookie = Cookie::parse(value.to_str()?)?;
                cookie.set_expires(cookie::Expiration::Session);
                *value = cookie.to_string().parse()?;
            } {
                warn!(?error, header=?value, "Failed to parse response cookie")
            }
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

async fn proxy_request(req: &Request, body: Body) -> poem::Result<Response> {
    let target = DEMO_TARGET.clone();

    let uri = construct_uri(req, &target, false).to_string();

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
    response.set_body(Body::from_bytes_stream(client_response.bytes_stream()));

    rewrite_response(&mut response, &target);
    Ok(response)
}

async fn proxy_ws(req: &Request, ws: WebSocket) -> poem::Result<impl IntoResponse> {
    let target = DEMO_TARGET.clone();
    let uri = construct_uri(req, &target, true);
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
