use std::io::SeekFrom;
use std::path::Path;
use std::time::{Duration, Instant};

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use poem::error::{InternalServerError, NotFoundError};
use poem::web::websocket::{Message, WebSocket, WebSocketStream};
use poem::web::{Data, Redirect, StaticFileRequest};
use poem::{IntoResponse, handler};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::broadcast;
use tracing::error;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::recordings::{LiveChunk, RecordingFile};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::Session;

use super::AnySecurityScheme;
use crate::api::cluster_proxy::{Owner, proxy_or_serve, proxy_or_serve_websocket, session_owner};
use crate::api::common::require_cluster_or_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetRecordingResponse {
    #[oai(status = 200)]
    Ok(Json<Recording::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/recordings/:id",
        method = "get",
        operation_id = "get_recording"
    )]
    async fn api_get_recording(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: poem_openapi::param::Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetRecordingResponse> {
        require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

        let db = &ctx.services().db;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(db)
            .await
            .map_err(InternalServerError)?;

        match recording {
            Some(recording) => Ok(GetRecordingResponse::Ok(Json(recording))),
            None => Ok(GetRecordingResponse::NotFound),
        }
    }
}

async fn find_recording(
    ctx: &AuthenticatedRequestContext,
    id: Uuid,
    kind: Option<RecordingKind>,
) -> poem::Result<Recording::Model> {
    let mut q = Recording::Entity::find_by_id(id);
    if let Some(kind) = kind {
        q = q.filter(Recording::Column::Kind.eq(kind));
    }
    q.one(&ctx.services().db)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| NotFoundError.into())
}

#[handler]
pub async fn api_get_recording_tcpdump(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, Some(RecordingKind::Traffic)).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, || {
        serve_recording_file(&ctx, &recording, RecordingFile::TcpDumpData, static_req)
    })
    .await
}

#[handler]
pub async fn api_get_recording_data(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, || {
        serve_recording_file(&ctx, &recording, RecordingFile::NDJsonData, static_req)
    })
    .await
}

#[handler]
pub async fn api_get_recording_index(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, || {
        serve_recording_file(&ctx, &recording, RecordingFile::Index, static_req)
    })
    .await
}

async fn serve_recording_file(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
    file: RecordingFile,
    static_req: StaticFileRequest,
) -> poem::Result<poem::Response> {
    let access = ctx
        .services()
        .recordings
        .lock()
        .await
        .access(recording, file)
        .await
        .map_err(InternalServerError)?;

    if let Some(url) = access
        .external_access_url()
        .await
        .map_err(InternalServerError)?
    {
        Ok(Redirect::temporary(url).into_response())
    } else if let Some(path) = access.local_path() {
        Ok(static_req
            .create_response(path, false, false)?
            .with_content_type(file.mime_type())
            .into_response())
    } else {
        Err(InternalServerError(std::io::Error::other(
            "recording file access has neither an external URL nor a local path",
        )))
    }
}

/// Messages pushed to a recording live-view WebSocket, serialised with a `type`
/// discriminator the player switches on.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LiveStreamMessage {
    /// Sent first: whether the session is currently being recorded on this node.
    Start { live: bool },
    /// One raw recording item plus its end byte offset in `data.ndjson`.
    Data {
        data: serde_json::Value,
        offset: u64,
    },
    /// The recording ended.
    End,
}

/// Send one message, false = client disconnected (not an error)
async fn send_message<S: futures::Sink<Message> + Unpin>(
    sink: &mut S,
    message: &LiveStreamMessage,
) -> anyhow::Result<bool> {
    Ok(sink
        .send(Message::Text(serde_json::to_string(message)?))
        .await
        .is_ok())
}

/// next item retained in the received, ignoring Lagged errors
/// None if the receiver is closed (recording ended)
async fn next_retained(receiver: &mut broadcast::Receiver<LiveChunk>) -> Option<LiveChunk> {
    loop {
        match receiver.recv().await {
            Ok(chunk) => return Some(chunk),
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

const LAG_REPLAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on a single lag replay. Beyond this, a viewer is treated as unable to
/// keep up and is fast-forwarded to live with a gap rather than served an
/// ever-growing backlog of stale history.
const MAX_LAG_REPLAY_SPAN: u64 = 16 * 1024 * 1024;

/// Replay a part of the scratch recording between two points
/// If the last portion has not been written yet, try to wait for a while
/// for it to get written
async fn replay_scratch_span_awaiting<S: futures::Sink<Message> + Unpin>(
    sink: &mut S,
    path: &Path,
    sent: &mut u64,
    target: u64,
    timeout: Duration,
) -> anyhow::Result<bool> {
    let mut deadline = Instant::now() + timeout;

    while *sent < target {
        let read_from = *sent;
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(SeekFrom::Start(*sent)).await?;
        // Line-at-a-time buffered read: the missed span can be arbitrarily
        // large, so memory use must be bounded by one item, not the span
        let mut reader = BufReader::new(file.take(target - *sent));
        let mut line = Vec::new();
        loop {
            line.clear();
            reader.read_until(b'\n', &mut line).await?;
            // the last line will have no newline at the end if it's incomplete
            let Some(item) = line.strip_suffix(b"\n") else {
                // at this point we need to wait and try again
                break;
            };
            let end = *sent + line.len() as u64;
            if !item.is_empty()
                && !send_message(
                    sink,
                    &LiveStreamMessage::Data {
                        data: serde_json::from_slice(item)?,
                        offset: end,
                    },
                )
                .await?
            {
                return Ok(false);
            }
            *sent = end;
        }

        if *sent < target {
            // The timeout only limits waiting on the file to grow, not the
            // (client-paced) sending above
            if *sent > read_from {
                deadline = Instant::now() + timeout;
            } else if Instant::now() > deadline {
                tracing::warn!("Recording file lags its live stream; leaving a gap for the viewer");
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(true)
}

/// Relay a recording live broadcast into a socket
async fn serve_live_stream(
    mut sink: SplitSink<WebSocketStream, Message>,
    mut source: SplitStream<WebSocketStream>,
    mut receiver: broadcast::Receiver<LiveChunk>,
    path: &Path,
) -> anyhow::Result<()> {
    // Everything already in the scratch has been fetched by the
    // client separately - start at the end of the scratch
    let mut sent = tokio::fs::metadata(&path).await?.len();
    loop {
        let chunk = tokio::select! {
            item = receiver.recv() => match item {
                Ok(chunk) => Some(chunk),
                // Client is lagging - replay everything it has missed
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let chunk = next_retained(&mut receiver).await;
                    let end = match &chunk {
                        Some(chunk) => chunk.offset - chunk.data.len() as u64,
                        // Recording ended - just replay to the end
                        None => tokio::fs::metadata(&path).await?.len(),
                    };
                    // A viewer too slow to keep up would grow this span without
                    // bound and only ever watch stale history. Past a cap, drop the
                    // completeness guarantee: skip to the retained item's line
                    // boundary and resume live, leaving one gap.
                    if end.saturating_sub(sent) > MAX_LAG_REPLAY_SPAN {
                        tracing::warn!(
                            "Live viewer too far behind; skipping {} bytes to resume live",
                            end - sent
                        );
                        sent = end;
                    } else if !replay_scratch_span_awaiting(&mut sink, &path, &mut sent, end, LAG_REPLAY_TIMEOUT).await? {
                        return Ok(());
                    }
                    chunk
                }
                Err(broadcast::error::RecvError::Closed) => None,
            },
            // Pump the recv stream to detect disconnection
            frame = source.next() => match frame {
                None | Some(Err(_)) => return Ok::<(), anyhow::Error>(()),
                Some(Ok(_)) => continue,
            },
        };
        let message = match chunk {
            Some(LiveChunk { offset, data }) => {
                // Already replayed from the file after a lag
                if offset <= sent {
                    continue;
                }
                sent = offset;
                LiveStreamMessage::Data {
                    data: serde_json::from_slice(&data)?,
                    offset,
                }
            }
            None => LiveStreamMessage::End,
        };
        if !send_message(&mut sink, &message).await? || matches!(message, LiveStreamMessage::End) {
            return Ok(());
        }
    }
}

fn live_stream_response(
    ws: WebSocket,
    live: Option<(broadcast::Receiver<LiveChunk>, std::path::PathBuf)>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let (mut sink, source) = socket.split();

        sink.send(Message::Text(serde_json::to_string(
            &LiveStreamMessage::Start {
                live: live.is_some(),
            },
        )?))
        .await?;

        if let Some((receiver, path)) = live {
            tokio::spawn(async move {
                if let Err(error) = serve_live_stream(sink, source, receiver, &path).await {
                    error!(%error, "Livestream error:");
                }
            });
        }

        Ok::<(), anyhow::Error>(())
    })
}

#[handler]
pub async fn api_get_recording_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    let owner = recording_owner(&ctx, &recording).await?;

    proxy_or_serve_websocket(&ctx, req, ws, owner, async move |ws| {
        let recordings = ctx.services().recordings.lock().await;
        let live = match recordings.subscribe_live(&id).await {
            Some(receiver) => {
                // An in-progress recording is always a local file on the owner
                // node (S3 uploads stream from a local scratch), and only the
                // owner has a live subscription.
                let access = recordings
                    .access(&recording, RecordingFile::NDJsonData)
                    .await
                    .map_err(InternalServerError)?;
                let path = access.local_path().ok_or_else(|| {
                    InternalServerError(std::io::Error::other(
                        "in-progress recording has no local file",
                    ))
                })?;
                Some((receiver, path.to_owned()))
            }
            None => None,
        };

        Ok(live_stream_response(ws, live).into_response())
    })
    .await
}

pub async fn recording_owner(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
) -> Result<Owner, WarpgateError> {
    // Completed recordings live in S3 / on disk and are served by any node.
    if recording.ended.is_some() {
        return Ok(Owner::Local);
    }
    let Some(session) = Session::Entity::find_by_id(recording.session_id)
        .one(&ctx.services().db)
        .await?
    else {
        return Ok(Owner::Local);
    };
    session_owner(ctx, &session).await
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    /// `replay_scratch_span_awaiting` replays exactly the complete lines in `sent..target`,
    /// with each offset being the line's end position in the file.
    #[tokio::test]
    async fn file_span_replay() {
        let path = std::env::temp_dir().join(format!("warpgate-test-{}", Uuid::new_v4()));
        //                offsets:  8 ---------- 16 ---------- 24 --- partial tail
        tokio::fs::write(&path, b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n{\"d\"")
            .await
            .unwrap();

        let (mut sink, stream) = futures::channel::mpsc::unbounded::<Message>();
        let mut sent = 8;
        assert!(
            replay_scratch_span_awaiting(&mut sink, &path, &mut sent, 24, LAG_REPLAY_TIMEOUT)
                .await
                .unwrap()
        );
        drop(sink);
        tokio::fs::remove_file(&path).await.unwrap();

        assert_eq!(sent, 24);
        let messages: Vec<String> = stream
            .map(|m| match m {
                Message::Text(text) => text,
                other => panic!("unexpected message {other:?}"),
            })
            .collect()
            .await;
        assert_eq!(
            messages,
            vec![
                r#"{"type":"data","data":{"b":2},"offset":16}"#,
                r#"{"type":"data","data":{"c":3},"offset":24}"#,
            ]
        );
    }
}
