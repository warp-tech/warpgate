use anyhow::Context;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use poem::error::{InternalServerError, NotFoundError};
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tracing::error;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::recordings::{AsciiCast, TerminalRecordingItem};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_protocol_kubernetes::recording::{
    KubernetesRecordingItem, KubernetesRecordingItemApiObject,
};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetRecordingResponse {
    #[oai(status = 200)]
    Ok(Json<Recording::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetKubernetesRecordingResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<KubernetesRecordingItemApiObject>>),
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
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetRecordingResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

        let db = ctx.services().db.lock().await;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(InternalServerError)?;

        match recording {
            Some(recording) => Ok(GetRecordingResponse::Ok(Json(recording))),
            None => Ok(GetRecordingResponse::NotFound),
        }
    }

    #[oai(
        path = "/recordings/:id/kubernetes",
        method = "get",
        operation_id = "get_kubernetes_recording"
    )]
    async fn api_get_recording_kubernetes(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetKubernetesRecordingResponse> {
        require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

        let db = ctx.services().db.lock().await;
        let recordings = ctx.services().recordings.lock().await;

        let recording = Recording::Entity::find_by_id(id.0)
            .filter(Recording::Column::Kind.eq(RecordingKind::Kubernetes))
            .one(&*db)
            .await
            .map_err(InternalServerError)?;

        let Some(recording) = recording else {
            return Err(NotFoundError.into());
        };

        let path = recordings.data_path_for(&recording);

        let file = File::open(&path).await.map_err(InternalServerError)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut content = Vec::new();

        while let Some(line) = lines.next_line().await.context("reading recording")? {
            let item: KubernetesRecordingItem =
                serde_json::from_str(&line).context("deserializing recording item")?;
            content.push(KubernetesRecordingItemApiObject::from(item));
        }

        Ok(GetKubernetesRecordingResponse::Ok(Json(content)))
    }
}

#[handler]
pub async fn api_get_recording_cast(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> poem::Result<String> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let db = ctx.services().db.lock().await;

    let recording = Recording::Entity::find_by_id(id.0)
        .filter(Recording::Column::Kind.eq(RecordingKind::Terminal))
        .one(&*db)
        .await
        .map_err(InternalServerError)?;

    let Some(recording) = recording else {
        return Err(NotFoundError.into());
    };

    let path = {
        ctx.services()
            .recordings
            .lock()
            .await
            .data_path_for(&recording)
    };

    let mut response = vec![];

    let mut last_size = (0, 0);
    let file = File::open(&path).await.map_err(InternalServerError)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await.map_err(InternalServerError)? {
        let entry: TerminalRecordingItem =
            serde_json::from_str(&line[..]).map_err(InternalServerError)?;
        let asciicast: AsciiCast = entry.into();
        response.push(serde_json::to_string(&asciicast).map_err(InternalServerError)?);
        if let AsciiCast::Header { width, height, .. } = asciicast {
            last_size = (width, height);
        }
    }

    response.insert(
        0,
        serde_json::to_string(&AsciiCast::Header {
            time: 0.0,
            version: 2,
            width: last_size.0,
            height: last_size.1,
            title: recording.name,
        })
        .map_err(InternalServerError)?,
    );

    Ok(response.join("\n"))
}

#[handler]
pub async fn api_get_recording_tcpdump(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> poem::Result<Bytes> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let db = ctx.services().db.lock().await;

    let recording = Recording::Entity::find_by_id(id.0)
        .filter(Recording::Column::Kind.eq(RecordingKind::Traffic))
        .one(&*db)
        .await
        .map_err(InternalServerError)?;

    let Some(recording) = recording else {
        return Err(NotFoundError.into());
    };

    let path = {
        ctx.services()
            .recordings
            .lock()
            .await
            .data_path_for(&recording)
    };

    let content = std::fs::read(path).map_err(InternalServerError)?;

    Ok(Bytes::from(content))
}

/// Parse a single `Range: bytes=start-[end]` spec. Returns `(start, Some(end))` or
/// `(start, None)` for an open-ended range. Only the first spec is honoured.
// Used by the raw `#[handler]` routes (wired in lib.rs); the spec-printer bin doesn't
// route those, so it sees these helpers as dead.
#[allow(dead_code)]
fn parse_byte_range(value: &str) -> Option<(u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?.split(',').next()?.trim();
    let (start, end) = spec.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let end = end.trim();
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse().ok()?)
    };
    Some((start, end))
}

#[allow(dead_code)]
async fn find_desktop_recording(
    ctx: &AuthenticatedRequestContext,
    id: Uuid,
) -> poem::Result<Recording::Model> {
    let db = ctx.services().db.lock().await;
    Recording::Entity::find_by_id(id)
        .filter(Recording::Column::Kind.eq(RecordingKind::Desktop))
        .one(&*db)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| NotFoundError.into())
}

#[handler]
pub async fn api_get_recording_desktop(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recording = find_desktop_recording(&ctx, id.0).await?;
    let path = { ctx.services().recordings.lock().await.data_path_for(&recording) };

    // Framebuffer recordings are large; stream the file, and honour Range requests so the
    // player can seek to a keyframe offset without downloading everything.
    let mut file = File::open(&path).await.map_err(InternalServerError)?;
    let total = file.metadata().await.map_err(InternalServerError)?.len();

    let range = req
        .headers()
        .get(poem::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_byte_range);

    let Some((start, end)) = range else {
        return Ok(poem::Response::builder()
            .content_type("application/x-ndjson")
            .header(poem::http::header::ACCEPT_RANGES, "bytes")
            .body(poem::Body::from_async_read(file)));
    };

    if start >= total {
        return Ok(poem::Response::builder()
            .status(poem::http::StatusCode::RANGE_NOT_SATISFIABLE)
            .header(poem::http::header::CONTENT_RANGE, format!("bytes */{total}"))
            .finish());
    }
    let end = end.unwrap_or(total.saturating_sub(1)).min(total.saturating_sub(1));
    let len = end - start + 1;
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(InternalServerError)?;
    Ok(poem::Response::builder()
        .status(poem::http::StatusCode::PARTIAL_CONTENT)
        .content_type("application/x-ndjson")
        .header(poem::http::header::ACCEPT_RANGES, "bytes")
        .header(
            poem::http::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        )
        .header(poem::http::header::CONTENT_LENGTH, len)
        .body(poem::Body::from_async_read(file.take(len))))
}

#[handler]
pub async fn api_get_recording_desktop_index(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> poem::Result<poem::Response> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recording = find_desktop_recording(&ctx, id.0).await?;
    // gen-1 desktop has no index → 404, which tells the player it's not playable.
    let Some(index_path) = ({ ctx.services().recordings.lock().await.index_path_for(&recording) })
    else {
        return Err(NotFoundError.into());
    };
    // Missing (not yet flushed) also reads as 404.
    let file = File::open(&index_path)
        .await
        .map_err(|_| poem::Error::from(NotFoundError))?;
    Ok(poem::Response::builder()
        .content_type("application/x-ndjson")
        .body(poem::Body::from_async_read(file)))
}

#[handler]
pub async fn api_get_recording_desktop_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> poem::Result<impl IntoResponse> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recordings = ctx.services().recordings.lock().await;
    let receiver = recordings.subscribe_live(&id).await;

    Ok(ws.on_upgrade(|socket| async move {
        let (mut sink, _) = socket.split();

        sink.send(Message::Text(serde_json::to_string(&json!({
            "start": true,
            "live": receiver.is_some(),
        }))?))
        .await?;

        if let Some(mut receiver) = receiver {
            tokio::spawn(async move {
                if let Err(error) = async {
                    while let Ok(data) = receiver.recv().await {
                        // Each broadcast line is a serialised DesktopRecordingItem.
                        let item: serde_json::Value = serde_json::from_slice(&data)?;
                        let msg = serde_json::to_string(&json!({ "data": item }))?;
                        sink.send(Message::Text(msg)).await?;
                    }
                    sink.send(Message::Text(serde_json::to_string(&json!({
                        "end": true,
                    }))?))
                    .await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    error!(%error, "Livestream error:");
                }
            });
        }

        Ok::<(), anyhow::Error>(())
    }))
}

#[handler]
pub async fn api_get_recording_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recordings = ctx.services().recordings.lock().await;
    let receiver = recordings.subscribe_live(&id).await;

    Ok(ws.on_upgrade(|socket| async move {
        let (mut sink, _) = socket.split();

        sink.send(Message::Text(serde_json::to_string(&json!({
            "start": true,
            "live": receiver.is_some(),
        }))?))
        .await?;

        if let Some(mut receiver) = receiver {
            tokio::spawn(async move {
                if let Err(error) = async {
                    while let Ok(data) = receiver.recv().await {
                        let content: TerminalRecordingItem = serde_json::from_slice(&data)?;
                        let cast: AsciiCast = content.into();
                        let msg = serde_json::to_string(&json!({ "data": cast }))?;
                        sink.send(Message::Text(msg)).await?;
                    }
                    sink.send(Message::Text(serde_json::to_string(&json!({
                        "end": true,
                    }))?))
                    .await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    error!(%error, "Livestream error:");
                }
            });
        }

        Ok::<(), anyhow::Error>(())
    }))
}
