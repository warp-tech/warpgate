pub mod api;
mod catchall;
mod common;
mod error;
mod logging;
mod middleware;
mod proxy;
mod session;
mod session_handle;

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use common::{inject_request_authorization, page_admin_auth};
pub use common::{SsoLoginState, PROTOCOL_NAME};
use http::HeaderValue;
use logging::{get_client_ip, log_request_error, log_request_result, span_for_request};
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{Listener, RustlsConfig};
use poem::middleware::SetHeader;
use poem::session::{CookieConfig, MemoryStorage, ServerSession, Session};
use poem::web::Data;
use poem::{Endpoint, EndpointExt, FromRequest, IntoEndpoint, IntoResponse, Route, Server};
use poem_openapi::OpenApiService;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_admin::admin_api_app;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_common::version::warpgate_version;
use warpgate_common::{
    load_certificate_and_key, ListenEndpoint, Target, TargetOptions, WarpgateConfig,
};
use warpgate_core::{ProtocolServer, Services, TargetTestError};
use warpgate_web::Assets;

use crate::common::{endpoint_admin_auth, endpoint_auth, page_auth, SESSION_COOKIE_NAME};
use crate::error::error_page;
use crate::middleware::{CookieHostMiddleware, TicketMiddleware};
use crate::session::{SessionStore, SharedSessionStorage};

pub struct HTTPProtocolServer {
    services: Services,
}

impl HTTPProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(HTTPProtocolServer {
            services: services.clone(),
        })
    }
}

fn make_session_storage() -> SharedSessionStorage {
    SharedSessionStorage(Arc::new(Mutex::new(Box::<MemoryStorage>::default())))
}

async fn make_rustls_config(config: &WarpgateConfig) -> Result<RustlsConfig> {
    let certificate_and_key = load_certificate_and_key(&config.store.http, config)
        .await
        .with_context(|| {
            format!(
                "loading TLS certificate and key: {}",
                config.store.http.certificate,
            )
        })?;

    let mut cfg = RustlsConfig::new().fallback(certificate_and_key.into());
    for sni in &config.store.http.sni_certificates {
        let certificate_and_key = load_certificate_and_key(sni, config)
            .await
            .with_context(|| format!("loading SNI TLS certificate: {sni:?}",))?;

        for name in certificate_and_key.certificate.sni_names()? {
            debug!(?name, source=?sni, "Adding SNI certificate");
            cfg = cfg.certificate(name, certificate_and_key.clone().into());
        }
    }
    Ok(cfg)
}

impl ProtocolServer for HTTPProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        let admin_api_app = admin_api_app(&self.services).into_endpoint();
        let api_service =
            OpenApiService::new(crate::api::get(), "Warpgate user API", warpgate_version())
                .server("/@warpgate/api");
        let ui = api_service.stoplight_elements();
        let spec = api_service.spec_endpoint();

        let session_storage = make_session_storage();
        let session_store = SessionStore::new();
        let db = self.services.db.clone();

        let cache_bust = || {
            SetHeader::new().overriding(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("must-revalidate,no-cache,no-store"),
            )
        };

        let cache_static = || {
            SetHeader::new().overriding(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=86400"),
            )
        };

        let (cookie_max_age, session_max_age) = {
            let config = self.services.config.lock2().await;
            (
                config.store.http.cookie_max_age,
                config.store.http.session_max_age,
            )
        };

        let app = Route::new()
            .nest(
                "/@warpgate",
                Route::new()
                    .nest("/api/playground", ui)
                    .nest("/api", api_service.with(cache_bust()))
                    .nest("/api/openapi.json", spec)
                    .nest_no_strip(
                        "/assets",
                        EmbeddedFilesEndpoint::<Assets>::new().with(cache_static()),
                    )
                    .nest(
                        "/admin/api",
                        endpoint_auth(endpoint_admin_auth(admin_api_app)).with(cache_bust()),
                    )
                    .at(
                        "/admin",
                        page_auth(page_admin_auth(EmbeddedFileEndpoint::<Assets>::new(
                            "src/admin/index.html",
                        )))
                        .with(cache_bust()),
                    )
                    .at(
                        "/api/auth/web-auth-requests/stream",
                        endpoint_auth(api::auth::api_get_web_auth_requests_stream),
                    )
                    .at(
                        "",
                        EmbeddedFileEndpoint::<Assets>::new("src/gateway/index.html")
                            .with(cache_bust()),
                    )
                    .around(move |ep, req| async move {
                        let method = req.method().clone();
                        let url = req.original_uri().clone();
                        let client_ip = get_client_ip(&req).await?;

                        let response = ep.call(req).await.inspect_err(|e| {
                            log_request_error(&method, &url, &client_ip, e);
                        })?;

                        log_request_result(&method, &url, &client_ip, &response.status());
                        Ok(response)
                    }),
            )
            .nest_no_strip(
                "/",
                page_auth(catchall::catchall_endpoint).around(move |ep, req| async move {
                    Ok(match ep.call(req).await {
                        Ok(response) => response.into_response(),
                        Err(error) => error_page(error).into_response(),
                    })
                }),
            )
            .around(inject_request_authorization)
            .around(move |ep, req| async move {
                let sm = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(&req)
                    .await?
                    .clone();

                let req = { sm.lock2().await.process_request(req).await? };

                let span = span_for_request(&req).await?;

                ep.call(req).instrument(span).await
            })
            .with(
                SetHeader::new()
                    .overriding(http::header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
            )
            .with(TicketMiddleware::new())
            .with(ServerSession::new(
                CookieConfig::default()
                    .secure(false)
                    .max_age(cookie_max_age)
                    .name(SESSION_COOKIE_NAME),
                session_storage.clone(),
            ))
            .with(CookieHostMiddleware::new())
            .data(self.services.clone())
            .data(session_store.clone())
            .data(session_storage)
            .data(db);

        tokio::spawn(async move {
            loop {
                session_store.lock2().await.vacuum(session_max_age).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        let rustls_config = {
            let config = self.services.config.lock2().await;
            make_rustls_config(&config).await.context("rustls setup")?
        };

        Server::new(address.poem_listener().await?.rustls(rustls_config))
            .run(app)
            .await?;

        Ok(())
    }

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::Http(options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not an HTTP target".to_owned(),
            ));
        };

        let mut request = poem::Request::builder().uri_str("http://host/").finish();
        request.extensions_mut().insert(Session::default());
        crate::proxy::proxy_normal_request(&request, poem::Body::empty(), &options)
            .await
            .map_err(|e| TargetTestError::ConnectionError(format!("{e}")))?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "HTTP"
    }
}

impl Debug for HTTPProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTPProtocolServer")
    }
}
