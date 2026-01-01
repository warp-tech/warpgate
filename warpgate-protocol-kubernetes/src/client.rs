use anyhow::{Context, Result};
use kube::{Client, Config};
use warpgate_common::{KubernetesTargetAuth, TargetKubernetesOptions};
use warpgate_tls::TlsMode;

pub async fn test_connection(options: &TargetKubernetesOptions) -> Result<()> {
    let config = create_kube_config(options).await?;
    let client = Client::try_from(config)?;

    // Test basic connectivity by listing namespaces
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);
    let _namespaces = api.list(&Default::default()).await?;

    Ok(())
}

pub async fn create_kube_config(options: &TargetKubernetesOptions) -> Result<Config> {
    let mut config = Config::new(
        options
            .cluster_url
            .parse()
            .context("parsing k8s cluster URL")?,
    );

    // Set the cluster URL
    config.cluster_url = options.cluster_url.parse()?;

    // Configure TLS verification
    match options.tls.mode {
        TlsMode::Disabled => {
            config.accept_invalid_certs = true;
        }
        TlsMode::Preferred => {
            if !options.tls.verify {
                config.accept_invalid_certs = true;
            }
        }
        TlsMode::Required => {
            if !options.tls.verify {
                config.accept_invalid_certs = true;
            }
        }
    }

    // Configure authentication
    match &options.auth {
        KubernetesTargetAuth::Token(auth) => {
            config.auth_info.token = Some(secrecy::SecretBox::new(
                auth.token.expose_secret().clone().into(),
            ));
        }
        KubernetesTargetAuth::Certificate(auth) => {
            config.auth_info.client_key_data = Some(secrecy::SecretBox::new(
                auth.private_key.expose_secret().clone().into(),
            ));
            config.auth_info.client_certificate_data =
                auth.certificate.expose_secret().clone().into()
        }
    }

    Ok(config)
}
