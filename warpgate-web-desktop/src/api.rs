use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Path};
use poem::{IntoResponse, handler};
use warpgate_common::UserSessionId;
use warpgate_common_http::SessionKeepalive;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::DesktopInput;
use warpgate_web_clients_common::SessionAccess;

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
    // Someone else's session reads as absent: a stream request must not
    // reveal that the id exists.
    let session = match manager
        .access(session_id, ctx.auth.user_id())
        .await
    {
        SessionAccess::Granted(session) => session,
        SessionAccess::NotFound | SessionAccess::Forbidden => {
            return Err(poem::Error::from_string(
                "Session not found",
                StatusCode::NOT_FOUND,
            ));
        }
    };

    session.cancel_disconnect_timer().await;

    let manager = (*manager).clone();
    let session_keepalive = session_keepalive.map(|x| x.guard());

    Ok(ws.on_upgrade(move |socket| async move {
        let (mut sink, mut stream) = socket.split();

        // Hand the viewer a base image before anything else. Without it a fresh attach —
        // a page reload, or a backend that painted before the socket arrived — would apply
        // deltas to a blank canvas and show a black screen until the target next repainted
        // the full surface, which it may never do.
        if let Some(keyframe) = session.keyframe().await
            && let WsPayload::Binary(bytes) = keyframe.ws_payload()
            && sink.send(Message::Binary(bytes)).await.is_err()
        {
            return;
        }

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
            //
            // Messages are fed into the sink and flushed once per batch: a burst of small
            // tiles becomes one write instead of a write+flush per tile.
            let mut closed = false;
            let batch = session.drain_buffer().await;
            let had_messages = !batch.is_empty();
            for msg in batch {
                let sent = match msg.ws_payload() {
                    WsPayload::Binary(bytes) => sink.feed(Message::Binary(bytes)).await,
                    WsPayload::Text(json) => sink.feed(Message::Text(json)).await,
                };
                if sent.is_err() {
                    closed = true;
                    break;
                }
            }
            if !closed && had_messages && sink.flush().await.is_err() {
                closed = true;
            }
            if closed || session.is_dead() {
                break;
            }

            tokio::select! {
                // Woken by a new frame; the loop re-drains at the top.
                () = notified.as_mut() => {}

                maybe_msg = stream.next() => {
                    match maybe_msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                                // Answer a refresh from our own surface as well as asking the
                                // backend. RDP has no repaint request wired through the helper,
                                // so forwarding alone would leave the viewer stuck on black.
                                if matches!(client_msg, ClientMessage::Refresh)
                                    && let Some(keyframe) = session.keyframe().await {
                                    session.push(keyframe).await;
                                }
                                if let Some(input) = Option::<DesktopInput>::from(client_msg) {
                                    session.send_input(input).await;
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

        drop(session_keepalive);
    }))
}
