use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::region::parse_eks_region;

/// Find the EKS cluster name that matches the given API server URL.
pub async fn find_eks_cluster_by_url(cluster_url: &str) -> Result<(String, String)> {
    let region_name = parse_eks_region(cluster_url)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine AWS region from EKS cluster URL: {cluster_url}"))?;

    let region = aws_sdk_eks::config::Region::new(region_name.clone());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;
    let client = aws_sdk_eks::Client::new(&config);

    let clusters = client
        .list_clusters()
        .send()
        .await
        .context("Failed to list EKS clusters")?;

    let normalized_url = cluster_url.trim_end_matches('/');

    for cluster_name in clusters.clusters() {
        let describe = client
            .describe_cluster()
            .name(cluster_name)
            .send()
            .await;

        if let Ok(output) = describe {
            if let Some(cluster) = output.cluster() {
                if let Some(endpoint) = cluster.endpoint() {
                    if endpoint.trim_end_matches('/') == normalized_url {
                        info!(cluster_name, "Matched EKS cluster by endpoint URL");
                        return Ok((cluster_name.to_string(), region_name));
                    }
                }
            }
        }
    }

    anyhow::bail!("No EKS cluster found matching endpoint URL: {cluster_url}")
}

/// Generate an EKS authentication token using a presigned STS GetCallerIdentity request.
///
/// This produces a token in the format `k8s-aws-v1.<base64url(presigned_url)>`,
/// compatible with the `aws-iam-authenticator` / EKS token exchange.
pub async fn generate_eks_token(cluster_name: &str, region: &str) -> Result<String> {
    use aws_sigv4::http_request::{sign, SigningSettings, SignableBody, SignableRequest, SignatureLocation};
    use aws_sigv4::sign::v4;
    use aws_credential_types::provider::ProvideCredentials;
    use std::time::SystemTime;

    let region_obj = aws_sdk_sts::config::Region::new(region.to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_obj)
        .load()
        .await;

    let credentials = config
        .credentials_provider()
        .ok_or_else(|| anyhow::anyhow!("No AWS credentials available"))?
        .provide_credentials()
        .await
        .context("Failed to resolve AWS credentials")?;

    let identity = aws_credential_types::Credentials::from(credentials).into();

    // Build the presigned URL for STS GetCallerIdentity
    let mut signing_settings = SigningSettings::default();
    signing_settings.signature_location = SignatureLocation::QueryParams;
    signing_settings.expires_in = Some(std::time::Duration::from_secs(60));

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("sts")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
        .context("Failed to build signing params")?;

    // The URL we want to presign
    let url = format!(
        "https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    );

    let signable_request = SignableRequest::new(
        "GET",
        &url,
        [("x-k8s-aws-id", cluster_name)].into_iter(),
        SignableBody::Bytes(&[]),
    ).context("Failed to create signable request")?;

    let (signing_instructions, _signature) = sign(signable_request, &signing_params.into())
        .context("Failed to sign request")?
        .into_parts();

    // Build an http::Request and apply signing instructions to get the presigned URL
    let mut request = http::Request::builder()
        .method("GET")
        .uri(&url)
        .header("x-k8s-aws-id", cluster_name)
        .body(())
        .context("Failed to build HTTP request")?;
    signing_instructions.apply_to_request_http1x(&mut request);

    // Base64url-encode the full presigned URI (no padding)
    let signed_url = request.uri().to_string();
    let token = format!(
        "k8s-aws-v1.{}",
        data_encoding::BASE64URL_NOPAD.encode(signed_url.as_bytes())
    );

    debug!(cluster_name, "Generated EKS authentication token");
    Ok(token)
}
