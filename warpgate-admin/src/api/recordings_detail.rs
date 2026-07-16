use futures::{SinkExt, StreamExt};
use poem::error::{InternalServerError, NotFoundError};
use poem::web::websocket::{Message, WebSocket};
use poem::web::{Data, Redirect, StaticFileRequest};
use poem::{IntoResponse, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::sync::broadcast;
use tracing::error;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::recordings::{LiveChunk, RecordingFile};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::{Node, Session};

use super::AnySecurityScheme;
use crate::api::cluster_proxy::{Owner, proxy_or_serve, proxy_or_serve_websocket};
use crate::api::common::require_recording_access;

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
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetRecordingResponse> {
        require_recording_access(&ctx).await?;

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
    require_recording_access(&ctx).await?;

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
    require_recording_access(&ctx).await?;

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
    require_recording_access(&ctx).await?;

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
                    loop {
                        match receiver.recv().await {
                            Ok(LiveChunk { offset, data }) => {
                                let item: serde_json::Value = serde_json::from_slice(&data)?;
                                sink.send(Message::Text(serde_json::to_string(
                                    &LiveStreamMessage::Data { data: item, offset },
                                )?))
                                .await?;
                            }
                            // A slow viewer fell behind the broadcast ring: skip the
                            // dropped items and keep tailing. This leaves a gap the
                            // client can only heal by reloading the snapshot, but it is
                            // not the recording ending, so don't send `End`.
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
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
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_recording_access(&ctx).await?;

    let recording = find_recording(&ctx, id.0, None).await?;
    let owner = recording_owner(&ctx, &recording).await?;

    proxy_or_serve_websocket(&ctx, req, ws, owner, async move |ws| {
        let receiver = ctx
            .services()
            .recordings
            .lock()
            .await
            .subscribe_live(&id)
            .await;

        Ok(live_stream_response(ws, receiver).into_response())
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
    let services = ctx.services();
    let db = &services.db;
    let owner_id = Session::Entity::find_by_id(recording.session_id)
        .one(db)
        .await?
        .and_then(|s| s.node_id);
    let Some(owner_id) = owner_id else {
        return Ok(Owner::Local);
    };
    if owner_id == services.cluster.node_id {
        return Ok(Owner::Local);
    }
    let Some(node) = Node::Entity::find_by_id(owner_id).one(db).await? else {
        return Err(WarpgateError::NodeGone(owner_id));
    };

    Ok(Owner::remote(node))
}
