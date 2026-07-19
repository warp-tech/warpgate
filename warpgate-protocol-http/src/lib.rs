pub mod api;
mod approval_gate;
mod catchall;
mod client_cache;
mod common;
mod error;
mod middleware;
pub mod proxy;
mod session;
mod session_handle;

use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use common::inject_request_authorization;
pub use common::{PROTOCOL_NAME, SsoLoginState};
use futures::future::BoxFuture;
use futures::{FutureExt, future, stream};
use http::HeaderValue;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::listener::{AcceptorExt, Listener, RustlsConfig};
use poem::middleware::SetHeader;
use poem::session::{CookieConfig, MemoryStorage, ServerSession};
use poem::web::Data;
use poem::{Endpoint, EndpointExt, FromRequest, IntoEndpoint, IntoResponse, Route, Server};
use poem_openapi::OpenApiService;
use tokio::sync::Mutex;
use tracing::{Instrument, debug};
use warpgate_admin::admin_api_app;
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::proxy_protocol::ProxyProtocolAcceptor;
use warpgate_common::version::warpgate_version;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::logging::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_common_http::warpgate_csp_with_connect_src;
use warpgate_core::{ProtocolServer, Services};
use warpgate_db_entities::Parameters::RecordingsStorageConfig;
use warpgate_tls::{TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey};
use warpgate_web::Assets;
use warpgate_web_desktop::WebDesktopClientManager;
use warpgate_web_desktop::api::ws_handler as desktop_web_client_ws_handler;
use warpgate_web_ssh::WebSshClientManager;
use warpgate_web_ssh::api::ws_handler as ssh_web_client_ws_handler;

use crate::client_cache::{HTTP_CLIENT_CACHE_VACUUM_INTERVAL, HttpClientCache};
use crate::common::{SESSION_COOKIE_NAME, endpoint_auth, page_auth};
use crate::error::error_page;
use crate::middleware::{
    ContentSecurityPolicyMiddleware, CookieHostMiddleware, TicketMiddleware,
    WARPGATE_PLAYGROUND_CSP,
};
use crate::session::{SessionStore, SharedSessionStorage};
use crate::session_handle::warpgate_server_handle_for_request;

pub struct HTTPProtocolServer {
    services: Services,
}

impl HTTPProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

/// The S3 bucket origin to allow-list in the admin document CSP, or `None` when
/// recordings are on disk (or the config can't be read). Read live so a storage
/// config change takes effect on the next admin page load.
async fn recordings_s3_browser_origin(ctx: &UnauthenticatedRequestContext) -> Option<String> {
    match ctx
        .parameters()
        .await
        .ok()?
        .recordings_storage_config()
        .ok()?
    {
        RecordingsStorageConfig::S3(s3) => s3.browser_origin(),
        RecordingsStorageConfig::Disk(_) => None,
    }
}

fn make_session_storage() -> SharedSessionStorage {
    SharedSessionStorage(Arc::new(Mutex::new(Box::<MemoryStorage>::default())))
}

fn make_rustls_config(tls: Vec<TlsCertificateAndPrivateKey>) -> Result<RustlsConfig> {
    let mut certificates = tls.into_iter();
    let primary = certificates
        .next()
        .context("HTTP requires a TLS certificate and key")?;

    let mut cfg = RustlsConfig::new().fallback(primary.into());
    for certificate_and_key in certificates {
        for name in certificate_and_key.certificate.sni_names()? {
            debug!(?name, "Adding SNI certificate");
            cfg = cfg.certificate(name, certificate_and_key.clone().into());
        }
    }
    Ok(cfg)
}

impl ProtocolServer for HTTPProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        mut tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        // Present the cluster identity certificate along other SNI certs
        if !tls.is_empty() {
            // catch the weird case of no cert at all
            let identity = &self.services.cluster.tls_identity;
            tls.push(TlsCertificateAndPrivateKey {
                certificate: TlsCertificateBundle::from_bytes(
                    identity.certificate_pem.clone().into_bytes(),
                )?,
                private_key: TlsPrivateKey::from_bytes(
                    identity.private_key_pem.clone().into_bytes(),
                )?,
            });
        }

        let session_storage = make_session_storage();
        let session_store = SessionStore::new();
        let http_client_cache = HttpClientCache::default();

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
            let config = self.services.config.lock().await;
            (
                config.store.http.cookie_max_age,
                config.store.http.session_max_age,
            )
        };

        // Set cookie domain to base host (e.g., ".warp.tavahealth.com") so it works for
        // the base host and all its subdomains (e.g., "foo.warp.tavahealth.com").
        // This is more restrictive than using the parent domain and ensures cookies only
        // work for the base host and its subdomains, not sibling domains.
        let base_cookie_domain: Option<String> = {
            let config = self.services.config.lock().await;
            match construct_external_url(None, &config, None).await {
                Ok(url) => {
                    if let Some(host) = url.host_str() {
                        // Use the base host directly with a leading dot (e.g., ".warp.tavahealth.com")
                        // This allows cookies to work for:
                        // - warp.tavahealth.com (exact match)
                        // - foo.warp.tavahealth.com (subdomain)
                        // - bar.warp.tavahealth.com (subdomain)
                        // But NOT for:
                        // - tavahealth.com (parent domain)
                        // - reporting.tavahealth.com (sibling domain)
                        let domain = format!(".{host}");
                        tracing::info!(
                            "Cookie domain configured: {} (base host: {}) - cookies will work for {} and all its subdomains",
                            domain,
                            host,
                            host
                        );
                        Some(domain)
                    } else {
                        tracing::warn!(
                            "Failed to determine cookie domain - external_host may not be configured. Cookies will be scoped to request host, which may prevent cross-subdomain authentication."
                        );
                        None
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to construct external URL for cookie domain: {:?}. Cookies will be scoped to request host.",
                        e
                    );
                    None
                }
            }
        };

        // /@warpgate/ routes
        let web_ssh_manager = Arc::new(WebSshClientManager::new());
        let web_desktop_manager = Arc::new(WebDesktopClientManager::new());
        let at_warpgate_endpoints = || {
            let services = self.services.clone();
            let web_ssh_manager = web_ssh_manager.clone();
            let web_desktop_manager = web_desktop_manager.clone();
            let api_service = {
                OpenApiService::new(crate::api::get(), "Warpgate user API", warpgate_version())
                    .server("/@warpgate/api")
            };
            let openapi_ui_route = api_service.stoplight_elements();
            let openapi_spec_route = api_service.spec_endpoint();
            let admin_api_app = admin_api_app().into_endpoint();

            Route::new()
                .nest(
                    "/api/playground",
                    openapi_ui_route.with(SetHeader::new().overriding(
                        http::header::CONTENT_SECURITY_POLICY,
                        WARPGATE_PLAYGROUND_CSP,
                    )),
                )
                .nest("/api", api_service.with(cache_bust()))
                .nest("/api/openapi.json", openapi_spec_route)
                .nest_no_strip(
                    "/assets",
                    EmbeddedFilesEndpoint::<Assets>::new().with(cache_static()),
                )
                .nest(
                    "/admin/api",
                    endpoint_auth(admin_api_app).with(cache_bust()),
                )
                .at(
                    // Served unauthenticated like the gateway shell: the admin API is
                    // auth-gated, and the SPA redirects to login client-side so the login
                    // `next` can include its hash route (a server redirect can't see it).
                    "/admin",
                    EmbeddedFileEndpoint::<Assets>::new("src/admin/index.html")
                        .with(cache_bust())
                        .around(move |ep, req| async move {
                            // The recording player fetches S3-backed recordings directly
                            // via presigned URLs, so the bucket origin must be allow-listed
                            // in this document's CSP.
                            let origin = match Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await {
                                Ok(ctx) => recordings_s3_browser_origin(ctx.0).await,
                                Err(_) => None,
                            };
                            let mut resp = ep.call(req).await?.into_response();
                            let csp = warpgate_csp_with_connect_src(origin.as_deref());
                            if let Ok(value) = HeaderValue::from_str(&csp) {
                                resp.headers_mut()
                                    .insert(http::header::CONTENT_SECURITY_POLICY, value);
                            }
                            Ok(resp)
                        }),
                )
                .at(
                    "/api/auth/web-auth-requests/stream",
                    endpoint_auth(api::auth::api_get_web_auth_requests_stream),
                )
                .at(
                    "/api/web-ssh/sessions/:session_id/stream",
                    endpoint_auth(ssh_web_client_ws_handler),
                )
                .at(
                    "/api/web-desktop/sessions/:session_id/stream",
                    endpoint_auth(desktop_web_client_ws_handler),
                )
                .at(
                    "",
                    EmbeddedFileEndpoint::<Assets>::new("src/gateway/index.html")
                        .with(cache_bust()),
                )
                .around({
                    let services = services;
                    move |ep, req| {
                        let services = services.clone();
                        async move {
                            let method = req.method().clone();
                            let url = req.original_uri().clone();
                            let client_ip = get_client_ip(&req, &services).await;

                            let response = ep.call(req).await.inspect_err(|e| {
                                log_request_error(&method, &url, client_ip.as_deref(), e);
                            })?;

                            log_request_result(
                                &method,
                                &url,
                                client_ip.as_deref(),
                                response.status(),
                            );
                            Ok(response)
                        }
                    }
                })
                .data(web_ssh_manager)
                .data(web_desktop_manager)
                .with(ContentSecurityPolicyMiddleware)
        };

        let app = Route::new()
            .nest("/@warpgate", at_warpgate_endpoints())
            .nest("/_warpgate", at_warpgate_endpoints())
            .nest_no_strip(
                "/",
                page_auth(catchall::catchall_endpoint).around(move |ep, req| async move {
                    Ok(match Box::pin(ep.call(req)).await {
                        Ok(response) => response.into_response(),
                        Err(ref error) => error_page(error).into_response(),
                    })
                }),
            )
            .around(inject_request_authorization)
            .around(move |ep, req| async move {
                let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
                    .await?
                    .clone();
                let sm = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(&req)
                    .await?
                    .clone();

                let req = { sm.lock().await.process_request(req).await? };
                let handle = warpgate_server_handle_for_request(&req).await.ok();
                let span = match handle {
                    Some(ref handle) => {
                        let handle = handle.lock().await;
                        span_for_request(&req, ctx.services(), Some(&*handle)).await?
                    }
                    None => span_for_request(&req, ctx.services(), None).await?,
                };

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
            .with(CookieHostMiddleware::new(base_cookie_domain))
            .data(UnauthenticatedRequestContext::new(self.services.clone()).await)
            .data(http_client_cache.clone())
            .data(session_store.clone())
            .data(session_storage);

        tokio::spawn(async move {
            loop {
                session_store.lock().await.vacuum(session_max_age);
                http_client_cache.vacuum().await;
                tokio::time::sleep(HTTP_CLIENT_CACHE_VACUUM_INTERVAL).await;
            }
        });

        let rustls_config = make_rustls_config(tls).context("rustls setup")?;

        // Bind the socket now (errors here are non-fatal to the supervisor); the
        // returned future drives the accept loop (errors there restart the listener).
        let acceptor = address.poem_listener()?.into_acceptor().await?;
        let acceptor = ProxyProtocolAcceptor::new(acceptor, proxy_protocol)
            .rustls(stream::once(future::ready(rustls_config)));

        Ok(async move {
            Server::new_with_acceptor(acceptor).run(app).await?;
            Ok(())
        }
        .boxed())
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
