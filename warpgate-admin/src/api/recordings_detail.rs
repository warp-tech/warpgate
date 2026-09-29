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
use warpgate_azure::AzureError;
use warpgate_core::recordings::{Error as RecordingsError, LiveChunk, RecordingFile};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::TargetSession;

use super::ClusterOrAdminContext;
use crate::api::cluster_proxy::{Owner, proxy_or_serve, proxy_or_serve_websocket};
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
        admin: ClusterOrAdminContext,
        id: poem_openapi::param::Path<Uuid>,
    ) -> poem::Result<GetRecordingResponse> {
        admin.require(AdminPermission::RecordingsView)?;

        let db = &admin.services().db;

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
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::TcpDumpData, static_req, req.header("Range"))
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
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::NDJsonData, static_req, req.header("Range"))
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
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::Index, static_req, req.header("Range"))
    })
    .await
}

async fn serve_recording_file(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
    file: RecordingFile,
    static_req: StaticFileRequest,
    range: Option<&str>,
) -> poem::Result<poem::Response> {
    let access = ctx
        .services()
        .recordings
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
        stream_recording_file(&access, file, range).await
    }
}

/// The start and optional inclusive end of a single byte range.
///
/// Only the first range of a `Range` header is honoured: a multipart response
/// is not something the players ask for.
fn parse_byte_range(header: &str) -> Option<(u64, Option<u64>)> {
    let spec = header.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split(',').next()?.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let end = end.trim();
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse().ok()?)
    };
    Some((start, end))
}

/// Serve a recording's bytes through Warpgate rather than redirecting.
///
/// The players fetch with `Range: bytes=N-` and seek by reopening at a new
/// offset (`rangeStream.ts`), so a backend served this way has to answer 206
/// and 416 the way the static-file handler does for the disk backend.
async fn stream_recording_file(
    access: &warpgate_core::recordings::FileAccess,
    file: RecordingFile,
    range: Option<&str>,
) -> poem::Result<poem::Response> {
    let requested = range.and_then(parse_byte_range);
    let start = requested.map_or(0, |(start, _)| start);

    // A range starting at or past the end is unsatisfiable, and the player
    // depends on the 416 to know it has reached the end of the recording. The
    // backend reports it rather than the caller pre-checking, because finding
    // out costs a round trip either way and only the backend knows for certain.
    let read = match access.open_read_from(start).await {
        Ok(read) => read,
        Err(RecordingsError::Azure(AzureError::RangeNotSatisfiable { total })) => {
            return Ok(poem::Response::builder()
                .status(poem::http::StatusCode::RANGE_NOT_SATISFIABLE)
                .header("content-range", format!("bytes */{total}"))
                .header("accept-ranges", "bytes")
                .finish());
        }
        Err(e) => return Err(InternalServerError(e)),
    }
    .ok_or_else(|| {
        InternalServerError(std::io::Error::other(
            "recording file access has neither an external URL nor a local path",
        ))
    })?;

    let Some((_, end)) = requested else {
        return Ok(poem::Response::builder()
            .status(poem::http::StatusCode::OK)
            .content_type(file.mime_type())
            .header("accept-ranges", "bytes")
            .header("content-length", read.total.to_string())
            .body(poem::Body::from_async_read(read.reader)));
    };

    // The end is inclusive on the wire; clamp it to the last byte that exists.
    let last = end.unwrap_or(read.total.saturating_sub(1)).min(read.total.saturating_sub(1));
    let len = last.saturating_sub(start) + 1;

    Ok(poem::Response::builder()
        .status(poem::http::StatusCode::PARTIAL_CONTENT)
        .content_type(file.mime_type())
        .header("accept-ranges", "bytes")
        .header("content-length", len.to_string())
        .header(
            "content-range",
            format!("bytes {start}-{last}/{}", read.total),
        )
        .body(poem::Body::from_async_read(read.reader.take(len))))
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
                    } else if !replay_scratch_span_awaiting(&mut sink, path, &mut sent, end, LAG_REPLAY_TIMEOUT).await? {
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
        let recordings = &ctx.services().recordings;
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
    let Some(session) = TargetSession::Entity::find_by_id(recording.session_id)
        .one(&ctx.services().db)
        .await?
    else {
        return Ok(Owner::Local);
    };
    ctx.services().cluster.owner(session.node_id).await
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    /// The shape the players actually send (`rangeStream.ts`): an open-ended
    /// range from the offset it wants to resume at.
    #[test]
    fn an_open_ended_range_is_read_as_a_start_offset() {
        assert_eq!(parse_byte_range("bytes=0-"), Some((0, None)));
        assert_eq!(parse_byte_range("bytes=4096-"), Some((4096, None)));
    }

    #[test]
    fn a_closed_range_keeps_its_inclusive_end() {
        assert_eq!(parse_byte_range("bytes=10-19"), Some((10, Some(19))));
    }

    /// Only the first range is honoured; a multipart response is not something
    /// the players ask for, so the rest is ignored rather than mishandled.
    #[test]
    fn only_the_first_range_of_a_set_is_taken() {
        assert_eq!(parse_byte_range("bytes=0-9,20-29"), Some((0, Some(9))));
    }

    #[test]
    fn a_malformed_range_is_declined_rather_than_guessed() {
        assert_eq!(parse_byte_range("items=0-9"), None);
        assert_eq!(parse_byte_range("bytes=abc-"), None);
        assert_eq!(parse_byte_range("bytes="), None);
        assert_eq!(parse_byte_range(""), None);
    }

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
