use std::sync::Arc;

use poem::http::StatusCode;
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Path};
use poem::{IntoResponse, handler};
use uuid::Uuid;
use warpgate_common::UserSessionId;
use warpgate_common_http::SessionKeepalive;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_web_clients_common::{ClientManager, run_stream_loop};

use crate::manager::WebSshClientManager;
use crate::protocol::{ClientMessage, ServerMessage};
use crate::session::WebSshSession;

#[handler]
pub async fn ws_handler(
    Path(session_id): Path<Uuid>,
    ctx: Data<&AuthenticatedRequestContext>,
    manager: Data<&Arc<WebSshClientManager>>,
    session_keepalive: Option<Data<&SessionKeepalive>>,
    ws: WebSocket,
) -> poem::Result<impl IntoResponse> {
    let Some(session) = manager
        .lookup_user_session(UserSessionId(session_id), ctx.auth.user_id())
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
        session.replay_phase().await;

        let input_session = session.clone();
        run_stream_loop(
            &session,
            registry,
            socket,
            |msg| Message::Text(serde_json::to_string(msg).unwrap_or_default()),
            move |text| {
                let session = input_session.clone();
                async move {
                    if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                        handle_client_message(&session, client_msg).await;
                    }
                }
            },
        )
        .await;

        // reject any pending host key prompt on disconnect
        if let Some(pending) = session.take_pending_host_key().await {
            let _ = pending.reply.send(false);
        }

        drop(session_keepalive);
    }))
}

async fn handle_client_message(session: &WebSshSession, msg: ClientMessage) {
    match msg {
        ClientMessage::OpenChannel { cols, rows } => {
            let cols = cols.unwrap_or(80);
            let rows = rows.unwrap_or(24);
            if let Some(channel_id) = session.open_shell_channel(cols, rows).await {
                session
                    .push(ServerMessage::ChannelOpened { channel_id })
                    .await;
            }
        }
        ClientMessage::Input { channel_id, data } => {
            session.send_input(channel_id, data).await;
        }
        ClientMessage::Resize {
            channel_id,
            cols,
            rows,
        } => {
            session.resize_channel(channel_id, cols, rows).await;
        }
        ClientMessage::CloseChannel { channel_id } => {
            session.close_channel(channel_id);
        }
        ClientMessage::AcceptHostKey => {
            if let Some(pending) = session.take_pending_host_key().await {
                let _ = pending.reply.send(true);
            }
        }
        ClientMessage::RejectHostKey => {
            if let Some(pending) = session.take_pending_host_key().await {
                let _ = pending.reply.send(false);
            }
        }
    }
}
