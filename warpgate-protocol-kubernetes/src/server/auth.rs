use std::sync::Arc;

use anyhow::{Context, Result};
use base64;
use poem::Request;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetKubernetesOptions, TargetOptions, User};
use warpgate_core::{ConfigProvider, Services, State};
use warpgate_db_entities::CertificateCredential;

use crate::server::cert_auth::RequestCertificateExt;

pub async fn authenticate_and_get_target(
    req: &Request,
    target_name: &str,
    _state: &Arc<Mutex<State>>,
    services: &Services,
) -> poem::Result<(AuthStateUserInfo, Target)> {
    // Check for Bearer token authentication (API tokens)
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut config_provider = services.config_provider.lock().await;
                if let Ok(Some(user)) = config_provider.validate_api_token(token).await {
                    // Look up the specific target by name from the URL
                    let targets = config_provider
                        .list_targets()
                        .await
                        .context("listing targets")?;

                    // Find the target with the specified name
                    for target in targets {
                        if target.name == target_name
                            && matches!(target.options, TargetOptions::Kubernetes(_))
                        {
                            if config_provider
                                .authorize_target(&user.username, &target.name)
                                .await
                                .unwrap_or(false)
                            {
                                return Ok(((&user).into(), target));
                            } else {
                                return Err(poem::Error::from_string(
                                    format!("Access denied to target: {}", target_name),
                                    poem::http::StatusCode::FORBIDDEN,
                                ));
                            }
                        }
                    }

                    return Err(poem::Error::from_string(
                        format!("Kubernetes target not found: {}", target_name),
                        poem::http::StatusCode::NOT_FOUND,
                    ));
                }
            }
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
                let targets = config_provider
                    .list_targets()
                    .await
                    .context("listing targets")?;

                // Find the target with the specified name
                for target in targets {
                    if target.name == target_name
                        && matches!(target.options, TargetOptions::Kubernetes(_))
                    {
                        if config_provider
                            .authorize_target(&user_info.username, &target.name)
                            .await
                            .unwrap_or(false)
                        {
                            return Ok((user_info, target));
                        } else {
                            return Err(poem::Error::from_string(
                                format!("Access denied to target: {}", target_name),
                                poem::http::StatusCode::FORBIDDEN,
                            ));
                        }
                    }
                }

                return Err(poem::Error::from_string(
                    format!("Kubernetes target not found: {}", target_name),
                    poem::http::StatusCode::NOT_FOUND,
                ));
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

pub fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: &Option<String>,
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
            let mut pem_bundle = String::new();
            pem_bundle.push_str(cert_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }
            pem_bundle.push_str(key_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }

            info!("Configuring Kubernetes client with mTLS (certificate auth)");
            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
    }

    Ok(client_builder)
}

// Helper function to validate client certificate against database
pub async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<AuthStateUserInfo>> {
    // TODO check revocation lists

    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der)?;

    let db = services.db.lock().await;

    // Find all certificate credentials and match against the provided certificate
    let cert_credentials = CertificateCredential::Entity::find()
        .find_with_related(warpgate_db_entities::User::Entity)
        .all(&*db)
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
                active_model.last_used = Set(Some(chrono::Utc::now()));
                if let Err(e) = active_model.update(&*db).await {
                    warn!("Failed to update certificate last_used timestamp: {}", e);
                }

                return Ok(Some((&User::try_from(user)?).into()));
            }
        }
    }

    Ok(None)
}

fn der_to_pem(der_bytes: &[u8]) -> Result<String, anyhow::Error> {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    let cert_b64 = general_purpose::STANDARD.encode(der_bytes);
    let cert_lines: Vec<String> = cert_b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();

    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        cert_lines.join("\n")
    ))
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
