use std::time::SystemTime;

use anyhow::{Context, Result};
use aws_credential_types::provider::ProvideCredentials;
use aws_sdk_rds::auth_token::AuthTokenGenerator;
use aws_sigv4::http_request::{
    sign, SignableBody, SignableRequest, SignatureLocation, SigningSettings,
};
use aws_sigv4::sign::v4;
use tracing::debug;

use crate::region::parse_rds_region;

/// Generate an RDS IAM authentication token.
///
/// This token is a presigned URL that can be used as a password to connect
/// to an RDS instance using IAM authentication.
pub async fn generate_rds_auth_token(host: &str, port: u16, username: &str) -> Result<String> {
    let region_name = parse_rds_region(host)
        .ok_or_else(|| anyhow::anyhow!("Cannot determine AWS region from RDS hostname: {host}"))?;

    let region = aws_sdk_sts::config::Region::new(region_name.clone());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;

    let generator = AuthTokenGenerator::new(
        aws_sdk_rds::auth_token::Config::builder()
            .hostname(host)
            .port(port as u64)
            .username(user)
            .build()?,
    );
    let token = generator.auth_token(&config).await?;

    Ok(token.to_string())
}
