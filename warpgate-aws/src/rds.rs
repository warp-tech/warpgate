use anyhow::{Context, Result};
use tracing::debug;

use crate::region::parse_rds_region;

/// Generate an RDS IAM authentication token.
///
/// This token is a presigned URL that can be used as a password to connect
/// to an RDS instance using IAM authentication.
pub async fn generate_rds_auth_token(
    host: &str,
    port: u16,
    username: &str,
) -> Result<String> {
    let region_name = parse_rds_region(host)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine AWS region from RDS hostname: {host}"))?;

    let region = aws_sdk_sts::config::Region::new(region_name.clone());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;

    // Use STS presigned URL approach for RDS IAM auth token generation
    // The token is a presigned URL for the `connect` action on the RDS endpoint.
    use aws_sigv4::http_request::{sign, SigningSettings, SignableBody, SignableRequest, SignatureLocation};
    use aws_sigv4::sign::v4;
    use aws_credential_types::provider::ProvideCredentials;
    use std::time::SystemTime;

    let credentials = config
        .credentials_provider()
        .ok_or_else(|| anyhow::anyhow!("No AWS credentials available"))?
        .provide_credentials()
        .await
        .context("Failed to resolve AWS credentials")?;

    let identity = aws_credential_types::Credentials::from(credentials).into();

    let mut signing_settings = SigningSettings::default();
    signing_settings.signature_location = SignatureLocation::QueryParams;
    signing_settings.expires_in = Some(std::time::Duration::from_secs(900));

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&region_name)
        .name("rds-db")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
        .context("Failed to build signing params")?;

    let url = format!(
        "https://{host}:{port}/?Action=connect&DBUser={username}"
    );

    let signable_request = SignableRequest::new(
        "GET",
        &url,
        std::iter::empty(),
        SignableBody::Bytes(&[]),
    ).context("Failed to create signable request")?;

    let (signing_instructions, _signature) = sign(signable_request, &signing_params.into())
        .context("Failed to sign RDS auth request")?
        .into_parts();

    let mut request = http::Request::builder()
        .method("GET")
        .uri(&url)
        .body(())
        .context("Failed to build HTTP request")?;
    signing_instructions.apply_to_request_http1x(&mut request);

    // The auth token is the presigned URL without the scheme (https://)
    let signed_url = request.uri().to_string();
    let token = signed_url
        .strip_prefix("https://")
        .unwrap_or(&signed_url)
        .to_string();

    debug!(host, port, username, "Generated RDS IAM auth token");
    Ok(token)
}
