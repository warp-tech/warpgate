use aws_sdk_rds::auth_token::AuthTokenGenerator;

use crate::region::parse_rds_region;
use crate::AwsError;

/// Generate an RDS IAM authentication token.
///
/// This token is a presigned URL that can be used as a password to connect
/// to an RDS instance using IAM authentication.
pub async fn generate_rds_auth_token(
    host: &str,
    port: u16,
    username: &str,
) -> Result<String, AwsError> {
    let region_name = parse_rds_region(host).ok_or_else(|| AwsError::RegionUnknown(host.into()))?;

    let region = aws_sdk_sts::config::Region::new(region_name.clone());
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .load()
        .await;

    let generator = AuthTokenGenerator::new(
        aws_sdk_rds::auth_token::Config::builder()
            .hostname(host)
            .port(u64::from(port))
            .username(username)
            .build()
            .map_err(AwsError::from)?,
    );
    let token = generator
        .auth_token(&config)
        .await
        .map_err(AwsError::from)?;

    Ok(token.to_string())
}
