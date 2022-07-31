use openidconnect::{ClientId, ClientSecret};
use warpgate_sso::{SsoClient, SsoInternalProviderConfig, SsoProviderConfig, SsoLoginRequest};

#[tokio::main]
pub async fn main() {
    let sso = SsoClient::new(
        SsoInternalProviderConfig::Google {
            client_id: ClientId::new("1058261555608-jfn491md4b74njf6hrrinpl8edp58rrv.apps.googleusercontent.com"
                .to_string()),
            client_secret: ClientSecret::new("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".to_string()),
        }
    );

    let req = sso.start_login("https://warpgate.com:8888/@warpgate/api/sso/return".to_string()).await.unwrap();

    println!("req: {:?}", req);
    let req: SsoLoginRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()) .unwrap();
    println!("req: {:?}", req);


    println!("{}", req.auth_url());

    let mut code = "".to_string();
    let _ = std::io::stdin().read_line(&mut code).unwrap();
    code = code.trim().to_string();

    let resp = req.verify_code(code).await;

    println!("resp {resp:?}");
}
