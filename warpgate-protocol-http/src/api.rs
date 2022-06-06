use crate::proxy::{proxy_normal_request, proxy_websocket_request};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use poem::session::Session;
use poem::web::websocket::WebSocket;
use poem::web::{Data, Redirect};
use poem::{handler, Body, IntoResponse, Request, Response};
use serde::Deserialize;
use warpgate_common::{Services, TargetOptions};

static TARGET_SESSION_KEY: &str = "target";

#[derive(Deserialize)]
struct QueryParams {
    warpgate_target: Option<String>,
}

#[handler]
pub async fn catchall_endpoint(
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
        return Ok(target_select_redirect(req).into_response());
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
            .map(|(t, o)| (t.clone(), o.clone()))
    };

    let Some((_, options)) = target else {
        return Ok(target_select_redirect(req).into_response());
    };

    Ok(match ws {
        Some(ws) => proxy_websocket_request(req, ws, &options)
            .await?
            .into_response(),
        None => proxy_normal_request(req, body, &options)
            .await?
            .into_response(),
    })
}

pub fn target_select_redirect(req: &Request) -> Response {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or("".into());

    let path = format!(
        "/@warpgate?next={}",
        utf8_percent_encode(&path, NON_ALPHANUMERIC)
    );

    Redirect::temporary(path).into_response()
}
