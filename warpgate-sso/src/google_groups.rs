use openidconnect::reqwest;
use serde::Deserialize;
use tracing::{debug, warn};
use yup_oauth2::{ServiceAccountAuthenticator, ServiceAccountKey};

use crate::SsoError;
use crate::config::SsoInternalProviderConfig;

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
        service_account_email: Some(sa_email),
        service_account_key: Some(sa_key),
        admin_email: Some(admin_email),
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
    let access_token = get_access_token(sa_email, sa_key, admin_email).await?;
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
    service_account_email: &str,
    private_key_pem: &str,
    admin_email: &str,
) -> Result<String, SsoError> {
    let key = ServiceAccountKey {
        key_type: None,
        project_id: None,
        private_key_id: None,
        private_key: private_key_pem.to_string(),
        client_email: service_account_email.to_string(),
        client_id: None,
        auth_uri: None,
        token_uri: GOOGLE_TOKEN_URL.to_string(),
        auth_provider_x509_cert_url: None,
        client_x509_cert_url: None,
    };

    let auth = ServiceAccountAuthenticator::builder(key)
        .subject(admin_email.to_string())
        .build()
        .await
        .map_err(|e| SsoError::GoogleDirectory(format!("authenticator init failed: {e}")))?;

    let token = auth
        .token(&[DIRECTORY_SCOPE])
        .await
        .map_err(|e| SsoError::GoogleDirectory(format!("service account token request failed: {e}"))).inspect_err(|_| {
            warn!("Ensure that domain-wide delegation is enabled for your service account's client ID with a {DIRECTORY_SCOPE} scope and that Admin SDK API is enabled for your Google Cloud project: https://console.cloud.google.com/apis/library/admin.googleapis.com");
        })?;

    Ok(token
        .token()
        .ok_or(SsoError::GoogleDirectory("no access token received".into()))?
        .to_string())
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
            .map_err(|e| SsoError::GoogleDirectory(format!("group lookup failed: {e}")))?;

        if response.status() != 200 {
            return Err(SsoError::GoogleDirectory(format!(
                "Google group lookup failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let response = response
            .error_for_status()
            .map_err(|e| SsoError::GoogleDirectory(format!("group lookup failed: {e}")))?;

        let resp: DirectoryGroupsResponse = parse_json_response(response, "group response").await?;

        all_groups.extend(resp.groups.into_iter().map(|g| g.email));

        if let Some(token) = resp.next_page_token
            && !token.is_empty()
        {
            page_token = Some(token);
            continue;
        }
        break;
    }

    Ok(all_groups)
}
