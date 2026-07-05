use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Path};
use poem::{IntoResponse, handler};
use uuid::Uuid;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::DesktopInput;

use crate::manager::WebDesktopClientManager;
use crate::protocol::{ClientMessage, WsPayload};

#[handler]
pub async fn ws_handler(
    Path(session_id): Path<Uuid>,
    ctx: Data<&AuthenticatedRequestContext>,
    manager: Data<&Arc<WebDesktopClientManager>>,
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

        // The loop below drains the (reconnect) buffer at the top of its first iteration.
        let mut keepalive = tokio::time::interval(Duration::from_secs(30));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            // Register interest in new frames *before* draining, so a frame pushed while
            // we're sending isn't a missed wakeup (`notify_waiters` drops otherwise).
            let notified = session.wait_buffer();
            tokio::pin!(notified);
            notified.as_mut().enable();

            // Always flush queued frames at the top of every iteration. Outbound delivery
            // must never sit behind inbound input: while the user drags a window the client
            // floods us with pointer events, and if sending frames only happened in a
            // `select!` branch, that branch would be starved for the whole drag — frames
            // would pile up unsent and only burst out once the input stopped.
            let mut closed = false;
            for msg in session.drain_buffer().await {
                let sent = match msg.ws_payload() {
                    WsPayload::Binary(bytes) => sink.send(Message::Binary(bytes)).await,
                    WsPayload::Text(json) => sink.send(Message::Text(json)).await,
                };
                if sent.is_err() {
                    closed = true;
                    break;
                }
            }
            if closed || session.is_dead() {
                break;
            }

            tokio::select! {
                // Woken by a new frame; the loop re-drains at the top.
                _ = notified.as_mut() => {}

                maybe_msg = stream.next() => {
                    match maybe_msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text)
                                && let Some(input) = Option::<DesktopInput>::from(client_msg) {
                                session.send_input(input).await;
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
