use anyhow::Result;
use kube::{Client, Config};
use warpgate_common::{KubernetesTargetAuth, TargetKubernetesOptions, TlsMode};

pub async fn test_connection(options: &TargetKubernetesOptions) -> Result<()> {
    let config = create_kube_config(options).await?;
    let client = Client::try_from(config)?;

    // Test basic connectivity by listing namespaces
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);
    let _namespaces = api.list(&Default::default()).await?;

    Ok(())
}

pub async fn create_kube_config(options: &TargetKubernetesOptions) -> Result<Config> {
    let mut config = Config::infer().await.unwrap_or_else(|_| {
        // If infer fails, create a basic config
        Config::new(options.cluster_url.parse().unwrap())
    });

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
        KubernetesTargetAuth::Certificate(_) => {
            // Certificate-based auth will be handled by user credentials
            // For target testing, we'll try without auth first
        }
    }

    Ok(config)
}
