use futures::{SinkExt, StreamExt};
use poem::error::{InternalServerError, NotFoundError};
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Redirect, StaticFileRequest};
use poem::{IntoResponse, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json as OpenApiJson;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::broadcast;
use tracing::error;
use uuid::Uuid;
use warpgate_common::AdminPermission;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::recordings::{LiveChunk, RecordingFile};
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
    Ok(OpenApiJson<Recording::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetKubernetesRecordingResponse {
    #[oai(status = 200)]
    Ok(OpenApiJson<Vec<KubernetesRecordingItemApiObject>>),
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

        let db = &ctx.services().db;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(db)
            .await
            .map_err(InternalServerError)?;

        match recording {
            Some(recording) => Ok(GetRecordingResponse::Ok(OpenApiJson(recording))),
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

        let db = &ctx.services().db;

        let recording = Recording::Entity::find_by_id(id.0)
            .filter(Recording::Column::Kind.eq(RecordingKind::Kubernetes))
            .one(db)
            .await
            .map_err(InternalServerError)?;

        let Some(recording) = recording else {
            return Err(NotFoundError.into());
        };

        let reader = {
            let recordings = ctx.services().recordings.lock().await;
            recordings
                .access(&recording, RecordingFile::NDJsonData)
                .await
                .map_err(InternalServerError)?
                .open_read()
                .await
                .map_err(InternalServerError)?
        };

        let mut content = Vec::new();
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await.map_err(InternalServerError)? {
            if line.is_empty() {
                continue;
            }
            let item: KubernetesRecordingItem =
                serde_json::from_str(&line).map_err(InternalServerError)?;
            content.push(KubernetesRecordingItemApiObject::from(item));
        }

        Ok(GetKubernetesRecordingResponse::Ok(OpenApiJson(content)))
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
) -> poem::Result<poem::Response> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recording = find_recording(&ctx, id.0, Some(RecordingKind::Traffic)).await?;
    serve_recording_file(&ctx, &recording, RecordingFile::TcpDumpData, static_req).await
}

#[handler]
pub async fn api_get_recording_data(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
) -> poem::Result<poem::Response> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    serve_recording_file(&ctx, &recording, RecordingFile::NDJsonData, static_req).await
}

#[handler]
pub async fn api_get_recording_index(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
) -> poem::Result<poem::Response> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    serve_recording_file(&ctx, &recording, RecordingFile::Index, static_req).await
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

/// Relay a recording's live broadcast to a WebSocket: a `Start` frame, then one
/// `Data` frame per item, then `End`. Terminal and desktop share this — both just
/// forward the raw item + offset; the player renders it per its own format.
fn live_stream_response(
    ws: WebSocket,
    receiver: Option<broadcast::Receiver<LiveChunk>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let (mut sink, _) = socket.split();

        sink.send(Message::Text(serde_json::to_string(
            &LiveStreamMessage::Start {
                live: receiver.is_some(),
            },
        )?))
        .await?;

        if let Some(mut receiver) = receiver {
            tokio::spawn(async move {
                if let Err(error) = async {
                    while let Ok(LiveChunk { offset, data }) = receiver.recv().await {
                        let item: serde_json::Value = serde_json::from_slice(&data)?;
                        sink.send(Message::Text(serde_json::to_string(
                            &LiveStreamMessage::Data { data: item, offset },
                        )?))
                        .await?;
                    }
                    sink.send(Message::Text(serde_json::to_string(
                        &LiveStreamMessage::End,
                    )?))
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
    })
}

#[handler]
pub async fn api_get_recording_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
) -> poem::Result<impl IntoResponse> {
    require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

    let receiver = ctx
        .services()
        .recordings
        .lock()
        .await
        .subscribe_live(&id)
        .await;

    Ok(live_stream_response(ws, receiver))
}
