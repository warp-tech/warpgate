use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Path};
use poem::{IntoResponse, handler};
use uuid::Uuid;
use warpgate_common_http::auth::AuthenticatedRequestContext;

use crate::manager::WebSshClientManager;
use crate::protocol::{ClientMessage, ServerMessage};

#[handler]
pub async fn ws_handler(
    Path(session_id): Path<Uuid>,
    ctx: Data<&AuthenticatedRequestContext>,
    manager: Data<&Arc<WebSshClientManager>>,
    ws: WebSocket,
) -> poem::Result<impl IntoResponse> {
    let requesting_user_id = ctx.auth.user_id();

    let session = manager
        .get_session(session_id)
        .await
        .ok_or_else(|| poem::Error::from_string("Session not found", StatusCode::NOT_FOUND))?;

    if session.user_id() != requesting_user_id {
        return Err(poem::Error::from_string(
            "Session not found",
            StatusCode::NOT_FOUND,
        ));
    }

    session.cancel_disconnect_timer().await;

    let manager = (*manager).clone();

    Ok(ws.on_upgrade(move |socket| async move {
        let (mut sink, mut stream) = socket.split();

        // drain buffered events first (in case of a reconnect)
        for msg in session.drain_buffer().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                let _ = sink.send(Message::Text(json)).await;
            }
        }

        let mut keepalive = tokio::time::interval(Duration::from_secs(30));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                _ = session.wait_buffer() => {
                    let msgs = session.drain_buffer().await;
                    for msg in msgs {
                        if let Ok(json) = serde_json::to_string(&msg)
                            && sink.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    if session.is_dead() {
                        break;
                    }
                }

                maybe_msg = stream.next() => {
                    match maybe_msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text)
                                && let Some(reply) = handle_client_message(&session, client_msg).await
                                && let Ok(json) = serde_json::to_string(&reply) {
                                if sink.send(Message::Text(json)).await.is_err() {
                                    break;
                                }

                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }

                _ = keepalive.tick() => {
                    if sink.send(Message::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            }
        }

        session.start_disconnect_timer(manager.clone()).await;
    }))
}

async fn handle_client_message(
    session: &crate::session::WebSshSession,
    msg: ClientMessage,
) -> Option<ServerMessage> {
    match msg {
        ClientMessage::OpenChannel { cols, rows } => {
            let cols = cols.unwrap_or(80);
            let rows = rows.unwrap_or(24);
            let channel_id = session.open_shell_channel(cols, rows).await;
            Some(ServerMessage::ChannelOpened { channel_id })
        }
        ClientMessage::Input { channel_id, data } => {
            session.send_input(channel_id, data.0).await;
            None
        }
        ClientMessage::Resize {
            channel_id,
            cols,
            rows,
        } => {
            session.resize_channel(channel_id, cols, rows).await;
            None
        }
        ClientMessage::CloseChannel { channel_id } => {
            session.close_channel(channel_id).await;
            None
        }
    }
}
