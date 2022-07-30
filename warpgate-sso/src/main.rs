use warpgate_sso::{SsoClient, SsoProviderConfig};

#[tokio::main]
pub async fn main() {
    let sso = SsoClient::new(
        SsoProviderConfig::Google {
            client_id:"1058261555608-jfn491md4b74njf6hrrinpl8edp58rrv.apps.googleusercontent.com".to_string(),
            client_secret: "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".to_string(),
        }
        .unwrap(),
    )
    .await;

    let req = sso.start_login();

    println!("{}", req.auth_url());

    let mut code = "".to_string();
    let _ = std::io::stdin().read_line(&mut code).unwrap();
    code = code.trim().to_string();
    println!("code: {:?}", code);

    let resp = req.verify_code(code).await;

    println!("resp {resp:?}");
}
