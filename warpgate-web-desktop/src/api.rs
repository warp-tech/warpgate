use std::sync::Arc;

use poem::http::StatusCode;
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Path};
use poem::{IntoResponse, handler};
use warpgate_common::UserSessionId;
use warpgate_common_http::SessionKeepalive;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::DesktopInput;
use warpgate_web_clients_common::{ClientManager, run_stream_loop};

use crate::manager::WebDesktopClientManager;
use crate::protocol::{ClientMessage, WsPayload};

#[handler]
pub async fn ws_handler(
    Path(session_id): Path<UserSessionId>,
    ctx: Data<&AuthenticatedRequestContext>,
    manager: Data<&Arc<WebDesktopClientManager>>,
    session_keepalive: Option<Data<&SessionKeepalive>>,
    ws: WebSocket,
) -> poem::Result<impl IntoResponse> {
    let Some(session) = manager
        .lookup_user_session(session_id, ctx.auth.user_id())
        .await
    else {
        return Err(poem::Error::from_string(
            "Session not found",
            StatusCode::NOT_FOUND,
        ));
    };

    session.cancel_disconnect_timer().await;

    let registry = ClientManager::clone(&manager);
    let session_keepalive = session_keepalive.map(|x| x.guard());

    Ok(ws.on_upgrade(move |socket| async move {
        // Hand the viewer a base image before anything else. Without it a fresh attach —
        // a page reload, or a backend that painted before the socket arrived — would apply
        // deltas to a blank canvas and show a black screen until the target next repainted
        // the full surface, which it may never do.
        if let Some(keyframe) = session.keyframe().await {
            session.push(keyframe).await;
        }
        session.replay_phase().await;

        let input_session = session.clone();
        run_stream_loop(
            &session,
            registry,
            socket,
            |msg| match msg.ws_payload() {
                WsPayload::Binary(bytes) => Message::Binary(bytes),
                WsPayload::Text(json) => Message::Text(json),
            },
            move |text| {
                let session = input_session.clone();
                async move {
                    if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                        // Answer a refresh from our own surface as well as asking the
                        // backend. RDP has no repaint request wired through the helper,
                        // so forwarding alone would leave the viewer stuck on black.
                        if matches!(client_msg, ClientMessage::Refresh)
                            && let Some(keyframe) = session.keyframe().await
                        {
                            session.push(keyframe).await;
                        }
                        if let Some(input) = Option::<DesktopInput>::from(client_msg) {
                            session.send_input(input).await;
                        }
                    }
                }
            },
        )
        .await;

        drop(session_keepalive);
    }))
}
