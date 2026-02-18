use std::time::SystemTime;

use openidconnect::reqwest;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::SsoInternalProviderConfig;
use crate::SsoError;

#[derive(Debug, Serialize)]
struct ServiceAccountClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryGroupsResponse {
    #[serde(default)]
    groups: Vec<DirectoryGroup>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DirectoryGroup {
    email: String,
}

const DIRECTORY_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.group.readonly";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DIRECTORY_GROUPS_URL: &str = "https://admin.googleapis.com/admin/directory/v1/groups";

/// Fetches the user's Google Workspace group memberships via the Directory API.
///
/// Requires `service_account_email`, `service_account_key`, and `admin_email`
/// to be configured on the Google SSO provider. These values should be
/// resolved by the deployment environment before Warpgate reads the config.
///
/// Returns `Ok(None)` if not a Google provider or service account is not configured.
pub async fn fetch_groups_if_configured(
    config: &SsoInternalProviderConfig,
    user_email: Option<&str>,
) -> Result<Option<Vec<String>>, SsoError> {
    let SsoInternalProviderConfig::Google {
        service_account_email: Some(ref sa_email),
        service_account_key: Some(ref sa_key),
        admin_email: Some(ref admin_email),
        ..
    } = config
    else {
        return Ok(None);
    };

    let Some(user_email) = user_email else {
        warn!("Google group sync configured but user email not available from OIDC claims");
        return Ok(None);
    };

    debug!("Fetching Google groups for {user_email}");

    let http_client = reqwest::ClientBuilder::new().build()?;
    let access_token = get_access_token(&http_client, sa_email, sa_key, admin_email).await?;
    let groups = fetch_user_groups(&http_client, &access_token, user_email).await?;

    debug!("Google groups for {user_email}: {groups:?}");
    Ok(Some(groups))
}

async fn parse_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, SsoError> {
    let body = response
        .text()
        .await
        .map_err(|e| SsoError::GoogleDirectory(format!("{context} read failed: {e}")))?;
    serde_json::from_str(&body)
        .map_err(|e| SsoError::GoogleDirectory(format!("{context} parse failed: {e}")))
}

async fn get_access_token(
    http_client: &reqwest::Client,
    service_account_email: &str,
    private_key_pem: &str,
    admin_email: &str,
) -> Result<String, SsoError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| SsoError::Other(Box::new(e)))?
        .as_secs();

    let claims = ServiceAccountClaims {
        iss: service_account_email,
        sub: admin_email,
        scope: DIRECTORY_SCOPE,
        aud: GOOGLE_TOKEN_URL,
        iat: now,
        exp: now + 3600,
    };

    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| SsoError::ConfigError(format!("Invalid Google service account key: {e}")))?;

    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let assertion = jsonwebtoken::encode(&header, &claims, &key)?;

    let response = http_client
        .post(GOOGLE_TOKEN_URL)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await
        .map_err(|e| SsoError::GoogleDirectory(format!("token request failed: {e}")))?
        .error_for_status()
        .map_err(|e| SsoError::GoogleDirectory(format!("token exchange failed: {e}")))?;

    let resp: TokenResponse = parse_json_response(response, "token response").await?;
    Ok(resp.access_token)
}

async fn fetch_user_groups(
    http_client: &reqwest::Client,
    access_token: &str,
    user_email: &str,
) -> Result<Vec<String>, SsoError> {
    let mut all_groups = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut req = http_client
            .get(DIRECTORY_GROUPS_URL)
            .bearer_auth(access_token)
            .query(&[("userKey", user_email)]);

        if let Some(ref token) = page_token {
            req = req.query(&[("pageToken", token.as_str())]);
        }

        let response = req
            .send()
            .await
            .map_err(|e| SsoError::GoogleDirectory(format!("group lookup failed: {e}")))?
            .error_for_status()
            .map_err(|e| SsoError::GoogleDirectory(format!("group lookup failed: {e}")))?;

        let resp: DirectoryGroupsResponse =
            parse_json_response(response, "group response").await?;

        all_groups.extend(resp.groups.into_iter().map(|g| g.email));

        if let Some(token) = resp.next_page_token {
            if !token.is_empty() {
                page_token = Some(token);
                continue;
            }
        }
        break;
    }

    Ok(all_groups)
}
