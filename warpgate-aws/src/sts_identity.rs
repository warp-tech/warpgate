use std::collections::HashMap;
use std::time::SystemTime;

use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use tracing::debug;

use crate::error::AwsError;

const STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// A signed `sts:GetCallerIdentity` request, in the four parts a verifier needs
/// to replay it against STS and learn who signed it.
///
/// The signature is what proves identity — no credential is disclosed — which is
/// why this can be handed to a third party such as Vault's AWS auth method.
#[derive(Debug)]
pub struct StsIdentityRequest {
    pub method: &'static str,
    pub url: String,
    pub body: String,
    pub headers: HashMap<String, String>,
}

/// Signs a `GetCallerIdentity` call with whatever the default credential chain
/// provides — on EC2 that is the instance role, whose credentials are short-lived
/// and never touch disk. Static access keys work too, but reintroduce exactly the
/// long-lived secret this authentication method exists to avoid.
///
/// `server_id` is bound into the signature as the `X-Vault-AWS-IAM-Server-ID`
/// header when set, so a signed request captured by one verifier cannot be
/// replayed against another.
///
/// `region` selects the regional STS endpoint. Leave it unset unless the verifier
/// is configured for one specific region: a signature scoped to a region is
/// rejected when the verifier replays it against the global endpoint, which is
/// what Vault does by default.
pub async fn sign_sts_identity_request(
    region: Option<&str>,
    server_id: Option<&str>,
) -> Result<StsIdentityRequest, AwsError> {
    // The global endpoint expects signatures scoped to us-east-1.
    let (host, signing_region) = match region {
        Some(region) => (format!("sts.{region}.amazonaws.com"), region),
        None => ("sts.amazonaws.com".to_owned(), "us-east-1"),
    };
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sts::config::Region::new(signing_region.to_string()))
        .load()
        .await;

    let credentials = config
        .credentials_provider()
        .ok_or(AwsError::NoCredentials)?
        .provide_credentials()
        .await?;

    if credentials.session_token().is_none() {
        return Err(AwsError::StaticCredentialsDisallowed);
    }

    let identity = credentials.into();

    let url = format!("https://{host}/");

    let mut headers = vec![
        (
            "content-type",
            "application/x-www-form-urlencoded".to_owned(),
        ),
        ("host", host.clone()),
    ];
    if let Some(server_id) = server_id {
        headers.push(("x-vault-aws-iam-server-id", server_id.to_owned()));
    }

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(signing_region)
        .name("sts")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()?;

    let signable_request = SignableRequest::new(
        "POST",
        &url,
        headers.iter().map(|(name, value)| (*name, value.as_str())),
        SignableBody::Bytes(STS_BODY.as_bytes()),
    )?;

    let (signing_instructions, _signature) =
        sign(signable_request, &signing_params.into())?.into_parts();

    let mut request = http::Request::builder().method("POST").uri(&url);
    for (name, value) in &headers {
        request = request.header(*name, value);
    }
    let mut request = request.body(())?;
    signing_instructions.apply_to_request_http1x(&mut request);

    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();

    debug!(signing_region, "Signed an STS GetCallerIdentity request");

    Ok(StsIdentityRequest {
        method: "POST",
        url,
        body: STS_BODY.to_owned(),
        headers,
    })
}
