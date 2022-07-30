use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::Services;

use crate::common::{SessionAuthorization, SessionExt};

pub struct Api;

#[derive(Serialize, Object)]
pub struct PortsInfo {
    ssh: Option<u16>,
    http: Option<u16>,
    mysql: Option<u16>,
}

#[derive(Serialize, Object)]
pub struct Info {
    version: String,
    username: Option<String>,
    selected_target: Option<String>,
    external_host: Option<String>,
    ports: PortsInfo,
    authorized_via_ticket: bool,
}

#[derive(ApiResponse)]
enum InstanceInfoResponse {
    #[oai(status = 200)]
    Ok(Json<Info>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/info", method = "get", operation_id = "get_info")]
    async fn api_get_info(
        &self,
        req: &Request,
        session: &Session,
        services: Data<&Services>,
    ) -> poem::Result<InstanceInfoResponse> {
        let config = services.config.lock().await;
        let external_host = config
            .store
            .external_host
            .as_deref()
            .or_else(|| req.header(http::header::HOST))
            .or_else(|| req.original_uri().host());
        Ok(InstanceInfoResponse::Ok(Json(Info {
            version: env!("CARGO_PKG_VERSION").to_string(),
            username: session.get_username(),
            selected_target: session.get_target_name(),
            external_host: external_host.map(&str::to_string),
            authorized_via_ticket: matches!(
                session.get_auth(),
                Some(SessionAuthorization::Ticket { .. })
            ),
            ports: if session.is_authenticated() {
                PortsInfo {
                    ssh: if config.store.ssh.enable {
                        Some(config.store.ssh.listen.port())
                    } else {
                        None
                    },
                    http: if config.store.http.enable {
                        Some(config.store.http.listen.port())
                    } else {
                        None
                    },
                    mysql: if config.store.mysql.enable {
                        Some(config.store.mysql.listen.port())
                    } else {
                        None
                    },
                }
            } else {
                PortsInfo {
                    ssh: None,
                    http: None,
                    mysql: None,
                }
            },
        })))
    }
}
