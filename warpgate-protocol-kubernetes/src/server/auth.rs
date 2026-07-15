use anyhow::Context;
use poem::Request;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use tracing::{debug, warn};
use warpgate_aws::EksClusterInfo;
use warpgate_ca::{deserialize_certificate, serialize_certificate_serial};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetKubernetesOptions, TargetOptions, User};
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::{CertificateCredential, CertificateRevocation};

use crate::server::client_certs::RequestCertificateExt;

pub async fn authenticate_and_get_target(
    req: &Request,
    target_name: &str,
    services: &Services,
) -> poem::Result<(AuthStateUserInfo, Target)> {
    // Check for Bearer token authentication (API tokens)
    if let Some(auth_header) = req.headers().get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let mut config_provider = services.config_provider.lock().await;
        if let Ok(Some(user)) = config_provider.validate_api_token(token).await {
            let target =
                lookup_authorized_k8s_target(&mut *config_provider, target_name, &user.username)
                    .await?;
            return Ok(((&user).into(), target));
        }
        drop(config_provider);

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

            let mut config_provider = services.config_provider.lock().await;
            let Some(username) = warpgate_core::resolve_and_map_sso_user(
                &mut *config_provider,
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

            let target =
                lookup_authorized_k8s_target(&mut *config_provider, target_name, &username).await?;
            drop(config_provider);

            return Ok((user_info_for_username(services, &username).await?, target));
        }
    }

    // Check for client certificate authentication
    // Use certificate extracted by middleware if present
    if let Some(client_cert) = req.client_certificate() {
        debug!("Found client certificate from middleware, validating against database");

        match validate_client_certificate(&client_cert.der_bytes, services).await {
            Ok(Some(user_info)) => {
                // Look up the specific target by name from the URL
                let mut config_provider = services.config_provider.lock().await;
                let target = lookup_authorized_k8s_target(
                    &mut *config_provider,
                    target_name,
                    &user_info.username,
                )
                .await?;
                return Ok((user_info, target));
            }
            Ok(None) => {
                debug!("Client certificate provided but not found in database");
            }
            Err(e) => {
                warn!(error = %e, "Error validating client certificate");
            }
        }
    } else {
        debug!("No client certificate provided in TLS connection");
    }

    // Return unauthorized if no valid authentication found
    Err(poem::Error::from_string(
        "Unauthorized: Please provide either a valid Bearer token or a client certificate",
        poem::http::StatusCode::UNAUTHORIZED,
    ))
}

/// Look up a Kubernetes target by name and ensure `username` is authorized for
/// it. Shared by the API-token, OIDC and client-certificate auth paths.
async fn lookup_authorized_k8s_target<C: ConfigProvider + Send + ?Sized>(
    config_provider: &mut C,
    target_name: &str,
    username: &str,
) -> poem::Result<Target> {
    let target = config_provider
        .get_target_by_name(target_name)
        .await
        .context("looking up target")?
        .filter(|t| matches!(t.options, TargetOptions::Kubernetes(_)))
        .ok_or_else(|| {
            poem::Error::from_string(
                format!("Kubernetes target not found: {target_name}"),
                poem::http::StatusCode::NOT_FOUND,
            )
        })?;

    if !config_provider
        .authorize_target(username, &target.name)
        .await
        .unwrap_or(false)
    {
        return Err(poem::Error::from_string(
            format!("Access denied to target: {target_name}"),
            poem::http::StatusCode::FORBIDDEN,
        ));
    }

    Ok(target)
}

/// Load a resolved SSO user's `AuthStateUserInfo` by username.
async fn user_info_for_username(
    services: &Services,
    username: &str,
) -> poem::Result<AuthStateUserInfo> {
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
    let user = User::try_from(model).map_err(|e| {
        poem::Error::from_string(
            format!("Failed to convert user model: {e}"),
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;
    Ok((&user).into())
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
                    auth.token.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
        warpgate_common::KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.expose_secret();
            let pem_bundle = format!(
                "{}\n{}\n",
                cert_pem.trim_end_matches('\n'),
                key_pem.trim_end_matches('\n')
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

// Helper function to validate client certificate against database
pub async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<AuthStateUserInfo>> {
    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der);

    let db = &services.db;

    // Check if certificate is revoked (by serial number)
    let cert = deserialize_certificate(&cert_pem)?;
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

                return Ok(Some((&User::try_from(user)?).into()));
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
