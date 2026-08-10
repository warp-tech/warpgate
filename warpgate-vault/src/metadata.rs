use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

fn with_query(base: &str, path: &str, params: &[(&str, &str)]) -> Result<Url> {
    let mut url = Url::parse(base)?.join(path)?;
    url.query_pairs_mut().extend_pairs(params);
    Ok(url)
}

#[derive(Deserialize)]
struct AzureAccessToken {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureInstance {
    pub subscription_id: String,
    pub resource_group_name: String,
    pub name: String,
    #[serde(default)]
    pub vm_scale_set_name: String,
}

/// The pieces Vault's Azure auth method needs: a token proving the VM's managed
/// identity, and the ARM coordinates it is checked against.
///
/// `base` comes from the configuration, so an operator who can edit
/// `warpgate.yaml` can point these requests at a host of their choosing. That is
/// no more access than editing the config already grants, but it is why the
/// client refuses redirects.
pub async fn azure_login_material(
    http: &reqwest::Client,
    base: &str,
    resource: &str,
) -> Result<(Zeroizing<String>, AzureInstance)> {
    let token: AzureAccessToken = http
        .get(with_query(
            base,
            "/metadata/identity/oauth2/token",
            &[("api-version", "2018-02-01"), ("resource", resource)],
        )?)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?
        .json()
        .await?;

    let instance: AzureInstance = http
        .get(with_query(
            base,
            "/metadata/instance/compute",
            &[("api-version", "2021-02-01")],
        )?)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?
        .json()
        .await?;

    Ok((Zeroizing::new(token.access_token), instance))
}

/// A GCE instance identity token, signed by Google for this specific audience.
/// `full` format includes the instance details Vault's `gce` auth type checks.
pub async fn gcp_identity_token(
    http: &reqwest::Client,
    base: &str,
    audience: &str,
) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        http.get(with_query(
            base,
            "/computeMetadata/v1/instance/service-accounts/default/identity",
            &[("audience", audience), ("format", "full")],
        )?)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?
        .text()
        .await?
        .trim()
        .to_owned(),
    ))
}
