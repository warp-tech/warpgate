use std::time::{Duration, SystemTime};

use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign};
use aws_sigv4::sign::v4;
use tracing::debug;

use crate::AwsError;

/// Which AWS service's IAM auth scheme to sign a Redis `AUTH` token for.
/// Neither service has an RDS-style SDK convenience method for this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisIamService {
    ElastiCache,
    MemoryDb,
}

impl RedisIamService {
    fn sigv4_name(self) -> &'static str {
        match self {
            Self::ElastiCache => "elasticache",
            Self::MemoryDb => "memorydb",
        }
    }
}

/// Generate an IAM authentication token for ElastiCache/MemoryDB for Redis.
///
/// Neither service exposes a convenience SDK method like RDS's
/// `AuthTokenGenerator`, so - as with [`crate::generate_eks_token`] - the
/// token is a manually SigV4-signed presigned request: a `GET` to
/// `https://<cluster_id>/?Action=connect&User=<username>`, signed with the
/// `elasticache`/`memorydb` SigV4 service name, with the `https://` scheme
/// stripped from the result. That string is used as the RESP `AUTH` password.
pub async fn generate_redis_iam_auth_token(
    service: RedisIamService,
    region: &str,
    cluster_id: &str,
    username: &str,
) -> Result<String, AwsError> {
    let region_obj = aws_sdk_sts::config::Region::new(region.to_string());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_obj)
        .load()
        .await;

    let credentials = config
        .credentials_provider()
        .ok_or(AwsError::NoCredentials)?
        .provide_credentials()
        .await?;

    let identity = credentials.into();

    let mut signing_settings = SigningSettings::default();
    signing_settings.signature_location = SignatureLocation::QueryParams;
    signing_settings.expires_in = Some(Duration::from_secs(900));

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service.sigv4_name())
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()?;

    let url = format!("https://{cluster_id}/?Action=connect&User={username}");

    let signable_request =
        SignableRequest::new("GET", &url, std::iter::empty(), SignableBody::Bytes(&[]))?;

    let (signing_instructions, _signature) =
        sign(signable_request, &signing_params.into())?.into_parts();

    let mut request = http::Request::builder().method("GET").uri(&url).body(())?;
    signing_instructions.apply_to_request_http1x(&mut request);

    let signed_url = request.uri().to_string();
    let token = signed_url
        .strip_prefix("https://")
        .unwrap_or(&signed_url)
        .to_string();

    debug!(cluster_id, ?service, "Generated Redis IAM auth token");
    Ok(token)
}
