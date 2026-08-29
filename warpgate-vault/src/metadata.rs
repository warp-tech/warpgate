use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::client::{read_bounded, read_bounded_json};
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

/// Reads the same way the Vault client does — bounded, and into a buffer that
/// is wiped on drop. These responses carry an identity token, and the address
/// they come from is configuration like any other.
///
/// The main client's reader gained this bound and this file did not; mirroring
/// it here is the point.
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
    let token = http
        .get(with_query(
            base,
            "/metadata/identity/oauth2/token",
            &[("api-version", "2018-02-01"), ("resource", resource)],
        )?)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?;
    let token: AzureAccessToken = read_bounded_json(token).await?;
    // Wrapped here, not at the return.
    //
    // The instance-metadata call below is three fallible steps, and wrapping
    // after it would drop the access token as a plain `String`, unwiped, on
    // exactly the paths where something has already gone wrong. GCP's
    // equivalent has no such window: nothing fallible sits between reading and
    // wrapping there.
    let access_token = Zeroizing::new(token.access_token);

    let instance = http
        .get(with_query(
            base,
            "/metadata/instance/compute",
            &[("api-version", "2021-02-01")],
        )?)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?;
    let instance: AzureInstance = read_bounded_json(instance).await?;

    Ok((access_token, instance))
}

/// A GCE instance identity token, signed by Google for this specific audience.
/// `full` format includes the instance details Vault's `gce` auth type checks.
pub async fn gcp_identity_token(
    http: &reqwest::Client,
    base: &str,
    audience: &str,
) -> Result<Zeroizing<String>> {
    let response = http
        .get(with_query(
            base,
            "/computeMetadata/v1/instance/service-accounts/default/identity",
            &[("audience", audience), ("format", "full")],
        )?)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()
        .map_err(VaultError::Request)?;

    // Bounded and wiped for the same reasons the Vault client's own reader is:
    // this is an identity token, and whatever answers on `metadata_address` is
    // no more trusted than whatever answers on the Vault address.
    let raw = read_bounded(response).await?;
    let text = std::str::from_utf8(&raw).map_err(|_| VaultError::OversizedResponse)?;
    Ok(Zeroizing::new(text.trim().to_owned()))
}
