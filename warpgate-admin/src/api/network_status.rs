use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use warpgate_common::http_headers::X_FORWARDED_FOR;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::logging::{get_client_ip, raw_remote_ip};
use warpgate_core::ListenerStatus;

use super::AdminContext;

pub struct Api;

#[derive(ApiResponse)]
enum GetListenerStatesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ListenerStatus>>),
}

#[derive(Object)]
struct IpEchoInfo {
    /// The peer IP of the connection as the server sees it.
    peer_ip: Option<String>,
    x_forwarded_for: Option<String>,
    trust_x_forwarded_headers: bool,
    /// The client IP after applying the X-Forwarded-For trust setting.
    client_ip: Option<String>,
}

#[derive(ApiResponse)]
enum GetIpEchoResponse {
    #[oai(status = 200)]
    Ok(Json<IpEchoInfo>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/network/listeners",
        method = "get",
        operation_id = "get_listener_states"
    )]
    async fn api_get_listener_states(
        &self,
        admin: AdminContext,
    ) -> Result<GetListenerStatesResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let mut listeners: Vec<ListenerStatus> = admin
            .services()
            .listener_status
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        listeners.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(GetListenerStatesResponse::Ok(Json(listeners)))
    }

    #[oai(
        path = "/network/ip-echo",
        method = "get",
        operation_id = "get_ip_echo"
    )]
    async fn api_get_ip_echo(
        &self,
        admin: AdminContext,
        req: &Request,
    ) -> Result<GetIpEchoResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;

        let trust_x_forwarded_headers = {
            let config = admin.services().config.lock().await;
            config.store.http.trust_x_forwarded_headers
        };
        Ok(GetIpEchoResponse::Ok(Json(IpEchoInfo {
            peer_ip: raw_remote_ip(req),
            x_forwarded_for: req.header(&X_FORWARDED_FOR).map(str::to_string),
            trust_x_forwarded_headers,
            client_ip: get_client_ip(req, admin.services()).await,
        })))
    }
}
