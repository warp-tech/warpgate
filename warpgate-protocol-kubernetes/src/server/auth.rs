use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use poem::Request;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;
use warpgate_aws::EksClusterInfo;
use warpgate_ca::{deserialize_certificate, serialize_certificate_serial};
use warpgate_common::auth::{AuthResult, AuthState, CredentialKind};
use warpgate_common::{Protocol, TargetKubernetesOptions, User, UserSessionId, WarpgateError};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, Services, TargetAuthorization, authorize_for_target,
    vet_credential_bearer, wait_for_auth_completion,
};
use warpgate_db_entities::{CertificateCredential, CertificateRevocation, Parameters};

use crate::server::client_certs::RequestCertificateExt;

pub fn unauthorized() -> poem::Error {
    poem::Error::from_string(
        "Unauthorized: provide a valid Bearer token or client certificate",
        poem::http::StatusCode::UNAUTHORIZED,
    )
}

/// What kind of credential the client presented, for audit and rate-limiting.
/// `None` means no credential was presented at all — an unauthenticated probe,
/// not a failed login attempt.
fn presented_credential_kind(req: &Request) -> Option<&'static str> {
    let has_bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if has_bearer {
        Some("token")
    } else if req.client_certificate().is_some() {
        Some("certificate")
    } else {
        None
    }
}

/// Emit the shared `UserAuthenticationFailed1` audit event. A failed Kubernetes
/// auth has no established session, so a fresh id tags this attempt.
fn emit_authentication_failed(client_ip: Option<IpAddr>, credential_type: &str, reason: &str) {
    let client_ip = client_ip.map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string());
    info!(
        target: "audit",
        _type = "UserAuthenticationFailed1",
        session = %Uuid::new_v4(),
        client_ip = %client_ip,
        username = "",
        credentials = %credential_type,
        reason = %reason,
        "Authentication failed",
    );
}

/// Resolve and vet the caller's identity from the request's transport credentials
/// (API token / OIDC token / client certificate). Runs on *every* request — it
/// must, both to attribute the request to a session and to re-check the credential
/// and account status — so it is deliberately cheap: no auth state, no web
/// approval. `Err(unauthorized)` on any failure.
pub async fn authenticate_kubernetes_user(
    req: &Request,
    services: &Services,
) -> poem::Result<User> {
    let client_ip = get_client_ip_addr(req, services).await;

    // Fail closed if login protection currently has this source IP blocked.
    if let Some(ip) = client_ip
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await?
            .is_some()
    {
        warn!(ip = %ip, "Kubernetes auth attempt from blocked IP");
        return Err(unauthorized());
    }

    let credential_kind = presented_credential_kind(req);

    let Some(user) = authenticate(req, services).await? else {
        // A presented-but-invalid credential counts toward brute-force
        // protection and is audited; a request with no credential at all is a
        // plain unauthenticated probe and is neither recorded nor audited.
        if let (Some(ip), Some(kind)) = (client_ip, credential_kind) {
            let _ = services
                .login_protection
                .record_failed_attempt(FailedAttemptInfo {
                    username: String::new(),
                    remote_ip: ip,
                    protocol: crate::PROTOCOL_NAME,
                    credential_type: kind.to_string(),
                })
                .await;
            emit_authentication_failed(client_ip, kind, "no matching credential");
        }
        return Err(unauthorized());
    };

    // Account lockout and the user's IP allow-list, both fail-closed.
    if !vet_credential_bearer(&services.login_protection, &user, client_ip).await? {
        return Err(unauthorized());
    }

    // A validated transport credential clears the failed-attempt counter.
    if let Some(ip) = client_ip {
        let _ = services
            .login_protection
            .clear_failed_attempts(&ip, &user.username)
            .await;
    }

    Ok(user)
}

/// Authorize an already-authenticated user for a Kubernetes target, applying the
/// credential policy — in practice a web-approval factor, which may block. This is
/// the expensive step, so the caller caches the result per correlated session so it
/// runs once per session (one approval per `kubectl` command's fan-out of requests)
/// rather than once per request.
///
/// `session_id` is that of the session the caller has registered for this
/// request: the auth state is keyed by it, which is what lets a web approval
/// raised on another node be routed back to the waiting request.
pub async fn authorize_kubernetes_target(
    req: &Request,
    user: &User,
    target_name: &str,
    session_id: UserSessionId,
    services: &Services,
) -> poem::Result<TargetAuthorization<TargetKubernetesOptions>> {
    let client_ip = get_client_ip_addr(req, services).await;

    // When the user has a Kubernetes credential policy, enforce its web-approval
    // factor on top of the transport identity; otherwise use the identity directly.
    let identity =
        authorize_kubernetes_identity(services, user, client_ip, target_name, session_id).await?;
    lookup_authorized_k8s_target(services.config_provider.as_ref(), target_name, &identity).await
}

/// Turn a validated Kubernetes identity into an [`AuthorizedIdentity`], applying
/// the user's Kubernetes credential policy when one is configured.
///
/// Transport authentication (WG API token, OIDC token, or client certificate)
/// establishes *who* the caller is — it is the identity, verified out of band by
/// [`authenticate`]. The Kubernetes credential policy only layers an optional
/// web-approval factor on top, the one factor a non-interactive client can
/// satisfy, so no transport credential is ever submitted to the auth state here.
///
/// With no policy the transport identity is used directly — unless global MFA
/// enforcement adds a factor for Kubernetes (see `mfa_required_factor`).
/// Otherwise a fresh auth state enforces the web approval, cleared either by a
/// cached grace-period bypass or by the user approving the pending request in
/// the Warpgate UI while the request waits (kubectl has no default client
/// timeout; the auth-state TTL bounds the wait).
async fn authorize_kubernetes_identity(
    services: &Services,
    user: &User,
    client_ip: Option<IpAddr>,
    target_name: &str,
    session_id: UserSessionId,
) -> poem::Result<AuthorizedIdentity> {
    let policy_configured = user
        .credential_policy
        .as_ref()
        .and_then(|p| p.kubernetes.as_ref())
        .is_some_and(|kinds| !kinds.is_empty());

    if !policy_configured {
        let parameters = Parameters::Entity::get(&services.db)
            .await
            .map_err(WarpgateError::from)?;
        if services
            .mfa_required_factor(&parameters, user.id, Protocol::Kubernetes)
            .await?
            .is_none()
        {
            return Ok(AuthorizedIdentity::for_authenticated_session(
                user.into(),
                crate::PROTOCOL_NAME,
            ));
        }
    }

    let state_arc = services
        .create_auth_state(
            &session_id,
            &user.username,
            crate::PROTOCOL_NAME,
            target_name,
            &[CredentialKind::WebUserApproval],
            client_ip,
            None,
        )
        .await?;

    await_kubernetes_web_approval(services, user, &state_arc).await
}

/// Blocks until the pending web approval resolves, either from a cached
/// grace-period bypass or from the user acting on the request in the UI.
async fn await_kubernetes_web_approval(
    services: &Services,
    user: &User,
    state_arc: &Arc<Mutex<AuthState>>,
) -> poem::Result<AuthorizedIdentity> {
    loop {
        let verification = state_arc.lock().await.verify();
        match verification {
            AuthResult::Accepted { .. } => {
                return AuthorizedIdentity::from_auth_state(&*state_arc.lock().await)
                    .ok_or_else(unauthorized);
            }
            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::WebUserApproval) => {
                if services.try_web_approval_bypass(state_arc).await? {
                    continue;
                }
                if !matches!(
                    wait_for_auth_completion(state_arc).await,
                    AuthResult::Accepted { .. }
                ) {
                    warn!(username = %user.username, "Kubernetes web approval not granted");
                    return Err(unauthorized());
                }
            }
            // Kubernetes only enforces web approval on top of transport auth; a
            // policy that requires any other factor can't be collected for a
            // non-interactive client and is denied. The policy editor should not
            // offer such a combination.
            AuthResult::Need(_) | AuthResult::Rejected => {
                warn!(username = %user.username, "Kubernetes credential policy not satisfiable");
                return Err(unauthorized());
            }
        }
    }
}

/// Resolve the caller's identity from the request's transport credentials (WG API
/// token, OIDC bearer token, or client certificate). Each is verified here and
/// establishes *who* the caller is; that transport auth is the identity, so the
/// caller doesn't re-validate it against a credential policy (a policy only layers
/// web approval on top). Returns `None` if no presented credential validated;
/// genuine lookup/verification errors propagate rather than being treated as a
/// failure.
async fn authenticate(req: &Request, services: &Services) -> poem::Result<Option<User>> {
    // Bearer token authentication (API tokens, then OIDC ID tokens).
    if let Some(auth_header) = req.headers().get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        if let Ok(Some(user)) = services.config_provider.validate_api_token(token).await {
            return Ok(Some(user));
        }

        // API token did not match — try OIDC ID token validation against any SSO
        // provider that has opted into Kubernetes OIDC.
        let sso_providers = {
            let config = services.config.lock().await;
            config.store.sso_providers.clone()
        };

        // Routing hint: only a provider whose issuer matches the token can
        // verify it, so we avoid issuer-discovery network calls to the others.
        let token_issuer = warpgate_sso::unverified_issuer(token);

        for provider_config in sso_providers.iter().filter(|p| p.kubernetes.is_some()) {
            if let Some(ref token_issuer) = token_issuer
                && let Ok(provider_issuer) = provider_config.provider.issuer_url()
                && provider_issuer.url().as_str().trim_end_matches('/')
                    != token_issuer.trim_end_matches('/')
            {
                continue;
            }

            let client = match warpgate_sso::SsoClient::new(provider_config.provider.clone()) {
                Ok(c) => c,
                Err(e) => {
                    debug!(provider = %provider_config.name, error = %e, "Skipping SSO provider (client init failed)");
                    continue;
                }
            };

            let response = match client.verify_id_token_to_response(token).await {
                Ok(r) => r,
                Err(e) => {
                    // Wrong issuer / audience / signature for this provider — try the next.
                    debug!(provider = %provider_config.name, error = %e, "OIDC token not valid for provider");
                    continue;
                }
            };

            let Some(username) = warpgate_core::resolve_and_map_sso_user(
                services.config_provider.as_ref(),
                provider_config,
                &response,
            )
            .await
            .map_err(|e| {
                poem::Error::from_string(
                    format!("SSO user resolution failed: {e}"),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?
            else {
                continue;
            };

            // The verified OIDC token is the identity; it is not re-checked against
            // the stored-SSO-linkage `validate_credential` arm, which would deny
            // legitimately-authenticated users resolved via preferred-username or
            // role mapping.
            return Ok(Some(user_for_username(services, &username).await?));
        }
    }

    // Client certificate authentication, using the certificate extracted by the
    // middleware if present.
    if let Some(client_cert) = req.client_certificate() {
        debug!("Found client certificate from middleware, validating against database");

        match validate_client_certificate(&client_cert.der_bytes, services).await {
            Ok(Some(user)) => return Ok(Some(user)),
            Ok(None) => debug!("Client certificate provided but not found in database"),
            // A rejected certificate returns `Ok(None)`; an `Err` is a fault in the
            // certificate store (DB) or an unparseable cert, not a credential
            // decision. Surfacing it as 500 keeps an outage from masquerading as a
            // bad certificate.
            Err(e) => {
                return Err(poem::Error::from_string(
                    format!("Client certificate validation failed: {e}"),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        }
    } else {
        debug!("No client certificate provided in TLS connection");
    }

    Ok(None)
}

/// Look up a Kubernetes target by name and prove the user is authorized for it.
/// Shared by the API-token, OIDC and client-certificate auth paths.
async fn lookup_authorized_k8s_target<C: ConfigProvider + Send>(
    config_provider: &C,
    target_name: &str,
    identity: &AuthorizedIdentity,
) -> poem::Result<TargetAuthorization<TargetKubernetesOptions>> {
    let not_found = || {
        poem::Error::from_string(
            format!("Kubernetes target not found: {target_name}"),
            poem::http::StatusCode::NOT_FOUND,
        )
    };
    let target = config_provider
        .get_target_by_name(target_name)
        .await
        .context("looking up target")?
        .ok_or_else(not_found)?;

    authorize_for_target(config_provider, identity, target)
        .await?
        .ok_or_else(|| {
            poem::Error::from_string(
                format!("Access denied to target: {target_name}"),
                poem::http::StatusCode::FORBIDDEN,
            )
        })?
        .narrow()
        .map_err(|_| not_found())
}

/// Load a resolved SSO user by username.
async fn user_for_username(services: &Services, username: &str) -> poem::Result<User> {
    let db = &services.db;
    let model = warpgate_db_entities::User::Entity::find()
        .filter(warpgate_db_entities::User::Entity::username_eq_ci(username))
        .one(db)
        .await
        .context("looking up user in database")?
        .ok_or_else(|| {
            poem::Error::from_string(
                format!("User not found after SSO resolution: {username}"),
                poem::http::StatusCode::UNAUTHORIZED,
            )
        })?;
    User::try_from(model).map_err(|e| {
        poem::Error::from_string(
            format!("Failed to convert user model: {e}"),
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

pub async fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: Option<&String>,
    _services: &Services,
) -> anyhow::Result<reqwest::ClientBuilder> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        "Creating authenticated Kubernetes client"
    );

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if !k8s_options.tls.verify {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    match &k8s_options.auth {
        warpgate_common::KubernetesTargetAuth::Token(auth) => {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    auth.token.reveal()?.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
        warpgate_common::KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.reveal()?;
            let pem_bundle = format!(
                "{}\n{}\n",
                cert_pem.trim_end_matches('\n'),
                key_pem.expose_secret().trim_end_matches('\n')
            );

            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
        warpgate_common::KubernetesTargetAuth::IamRole(_) => {
            // EKS IAM role authentication: generate a token from the cluster URL
            let EksClusterInfo { name, region } =
                warpgate_aws::find_eks_cluster_by_url(&k8s_options.cluster_url)
                    .await
                    .context("EKS cluster lookup")?;

            let token = warpgate_aws::generate_eks_token(&name, &region)
                .await
                .context("EKS token generation")?;

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("setting Authorization header for EKS token")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
    }

    Ok(client_builder)
}

/// True if `now` falls within the certificate's `[not_before, not_after]`
/// validity window (bounds inclusive).
fn cert_is_currently_valid(not_before: SystemTime, not_after: SystemTime, now: SystemTime) -> bool {
    now >= not_before && now <= not_after
}

// Helper function to validate client certificate against database
pub async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<User>> {
    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der);

    let db = &services.db;

    let cert = deserialize_certificate(&cert_pem)?;

    // Reject certificates outside their validity period.
    let validity = &cert.tbs_certificate.validity;
    if !cert_is_currently_valid(
        validity.not_before.to_system_time(),
        validity.not_after.to_system_time(),
        SystemTime::now(),
    ) {
        warn!("Client certificate is outside its validity period");
        return Ok(None);
    }

    // Check if certificate is revoked (by serial number)
    let serial_b64 = serialize_certificate_serial(&cert);
    if CertificateRevocation::Entity::find()
        .filter(CertificateRevocation::Column::SerialNumberBase64.eq(&serial_b64))
        .one(db)
        .await?
        .is_some()
    {
        warn!(serial = %serial_b64, "Client certificate is revoked");
        return Ok(None);
    }

    // Find all certificate credentials and match against the provided certificate
    let cert_credentials = CertificateCredential::Entity::find()
        .find_with_related(warpgate_db_entities::User::Entity)
        .all(db)
        .await?;

    for (cert_credential, users) in cert_credentials {
        if let Some(user) = users.into_iter().next() {
            // Normalize both certificates for comparison
            let stored_cert = normalize_certificate_pem(&cert_credential.certificate_pem);
            let provided_cert = normalize_certificate_pem(&cert_pem);

            if stored_cert == provided_cert {
                debug!(
                    user = user.username,
                    cert_label = cert_credential.label,
                    "Client certificate validated for user"
                );

                // Update last_used timestamp
                let mut active_model: CertificateCredential::ActiveModel = cert_credential.into();
                active_model.last_used = Set(Some(OffsetDateTime::now_utc()));
                if let Err(e) = active_model.update(db).await {
                    warn!("Failed to update certificate last_used timestamp: {}", e);
                }

                return Ok(Some(User::try_from(user)?));
            }
        }
    }

    Ok(None)
}

fn der_to_pem(der_bytes: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose;
    let cert_b64 = general_purpose::STANDARD.encode(der_bytes);
    let cert_lines: Vec<String> = cert_b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();

    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        cert_lines.join("\n")
    )
}

fn normalize_certificate_pem(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}
