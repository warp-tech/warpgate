use anyhow::Context;
use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::Serialize;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_common::version::warpgate_version;
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::Parameters;

use crate::common::{is_user_admin, RequestAuthorization, SessionAuthorization, SessionExt};

pub struct Api;

#[derive(Serialize, Object)]
pub struct PortsInfo {
    ssh: Option<u16>,
    http: Option<u16>,
    mysql: Option<u16>,
    postgres: Option<u16>,
}

#[derive(Serialize, Object, Debug)]
pub struct SetupState {
    has_targets: bool,
    has_users: bool,
}

impl SetupState {
    pub fn completed(&self) -> bool {
        self.has_targets && self.has_users
    }
}

#[derive(Serialize, Object)]
pub struct Info {
    version: Option<String>,
    username: Option<String>,
    selected_target: Option<String>,
    external_host: Option<String>,
    ports: PortsInfo,
    authorized_via_ticket: bool,
    authorized_via_sso_with_single_logout: bool,
    own_credential_management_allowed: bool,
    setup_state: Option<SetupState>,
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
        request_authorization: Option<Data<&RequestAuthorization>>,
    ) -> poem::Result<InstanceInfoResponse> {
        let config = services.config.lock2().await;
        let external_host = config
            .construct_external_url(Some(req), None)
            .ok()
            .as_ref()
            .and_then(|x| x.host())
            .map(|x| x.to_string());

        let parameters = {
            Parameters::Entity::get(&*services.db.lock2().await)
                .await
                .context("loading parameters")?
        };

        let setup_state = {
            let (users, targets) = {
                let mut p = services.config_provider.lock2().await;
                let users = p.list_users().await?;
                let targets = p.list_targets().await?;
                (users, targets)
            };
            let user_is_admin = if let Some(auth) = request_authorization {
                is_user_admin(req, &auth).await?
            } else {
                false
            };
            if user_is_admin {
                let state = SetupState {
                    has_targets: targets.len() > 1,
                    has_users: users.len() > 1,
                };
                if !state.completed() {
                    Some(state)
                } else {
                    None
                }
            } else {
                None
            }
        };

        Ok(InstanceInfoResponse::Ok(Json(Info {
            version: session
                .is_authenticated()
                .then(|| warpgate_version().to_string()),
            username: session.get_username(),
            selected_target: session.get_target_name(),
            external_host,
            authorized_via_ticket: matches!(
                session.get_auth(),
                Some(SessionAuthorization::Ticket { .. })
            ),
            authorized_via_sso_with_single_logout: session
                .get_sso_login_state()
                .is_some_and(|state| state.supports_single_logout),
            ports: if session.is_authenticated() {
                PortsInfo {
                    ssh: if config.store.ssh.enable {
                        Some(config.store.ssh.external_port())
                    } else {
                        None
                    },
                    http: if config.store.http.enable {
                        Some(config.store.http.external_port())
                    } else {
                        None
                    },
                    mysql: if config.store.mysql.enable {
                        Some(config.store.mysql.external_port())
                    } else {
                        None
                    },
                    postgres: if config.store.postgres.enable {
                        Some(config.store.postgres.external_port())
                    } else {
                        None
                    },
                }
            } else {
                PortsInfo {
                    ssh: None,
                    http: None,
                    mysql: None,
                    postgres: None,
                }
            },
            own_credential_management_allowed: parameters.allow_own_credential_management,
            setup_state,
        })))
    }
}
