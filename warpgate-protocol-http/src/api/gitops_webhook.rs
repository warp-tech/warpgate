//! Lets a git host trigger a GitOps sync on push, authenticated with the
//! webhook secret:
//! - an HMAC-SHA256 of the body in `X-Hub-Signature-256` (GitHub, Gitea,
//!   Forgejo) or `X-Hub-Signature` (Bitbucket)
//! - the secret itself in `X-Gitlab-Token` (GitLab)
//! - the secret as the Basic auth password, any username (Azure DevOps)

use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use futures::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use poem::http::{HeaderMap, StatusCode};
use poem::web::Data;
use poem::{Body, handler};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;

/// GitHub's own cap on a delivery
const MAX_BODY: usize = 25 * 1024 * 1024;

/// Answers before the sync finishes: git hosts give up on a delivery after
/// about 10 s, and the outcome is recorded in the sync history.
#[handler]
pub async fn api_post_gitops_webhook(
    ctx: Data<&UnauthenticatedRequestContext>,
    headers: &HeaderMap,
    body: Body,
) -> Result<StatusCode, WarpgateError> {
    let parameters = ctx.parameters().await?;
    let (Some(secret), Some(_)) = (&parameters.gitops_webhook_secret, &parameters.gitops_source)
    else {
        return Ok(StatusCode::NOT_FOUND);
    };
    if !is_signed(secret.reveal()?.expose_secret().as_bytes(), headers, body).await {
        return Ok(StatusCode::UNAUTHORIZED);
    }

    ctx.services().request_gitops_sync();
    Ok(StatusCode::ACCEPTED)
}

async fn is_signed(secret: &[u8], headers: &HeaderMap, body: Body) -> bool {
    if let Some(token) = headers.get("x-gitlab-token") {
        return token.as_bytes().ct_eq(secret).into();
    }
    if let Some(authorization) = headers.get(poem::http::header::AUTHORIZATION) {
        return basic_password(authorization.as_bytes())
            .is_some_and(|password| password.ct_eq(secret).into());
    }
    // Bitbucket's `X-Hub-Signature` is SHA-256 too, despite the name GitHub
    // uses for SHA-1
    let Some(signature) = headers
        .get("x-hub-signature-256")
        .or_else(|| headers.get("x-hub-signature"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("sha256="))
        .and_then(|hex| HEXLOWER_PERMISSIVE.decode(hex.as_bytes()).ok())
    else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    // Hashed as it arrives, so an unauthenticated caller can't make us buffer it
    let mut read = 0;
    let mut chunks = body.into_bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let Ok(chunk) = chunk else {
            return false;
        };
        read += chunk.len();
        if read > MAX_BODY {
            return false;
        }
        mac.update(&chunk);
    }
    mac.verify_slice(&signature).is_ok()
}

/// The password of a `Basic` authorization header
fn basic_password(header: &[u8]) -> Option<Vec<u8>> {
    let encoded = header.strip_prefix(b"Basic ")?;
    let decoded = BASE64.decode(encoded).ok()?;
    let colon = decoded.iter().position(|b| *b == b':')?;
    decoded.get(colon + 1..).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use poem::http::HeaderValue;

    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef";
    const BODY: &str = r#"{"ref":"refs/heads/main"}"#;

    async fn check(header: &'static str, value: &str) -> bool {
        let mut headers = HeaderMap::new();
        headers.insert(header, HeaderValue::from_str(value).unwrap());
        is_signed(SECRET, &headers, Body::from_string(BODY.into())).await
    }

    #[tokio::test]
    async fn accepts_only_the_right_signature_or_token() {
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(BODY.as_bytes());
        let signature = HEXLOWER_PERMISSIVE.encode(&mac.finalize().into_bytes());

        assert!(check("x-hub-signature-256", &format!("sha256={signature}")).await);
        assert!(
            check(
                "x-hub-signature-256",
                &format!("sha256={}", signature.to_uppercase())
            )
            .await
        );
        assert!(!check("x-hub-signature-256", &signature).await);
        assert!(!check("x-hub-signature-256", &format!("sha256={}", "0".repeat(64))).await);
        assert!(check("x-hub-signature", &format!("sha256={signature}")).await);
        assert!(check("x-gitlab-token", "0123456789abcdef").await);
        let basic = |credentials: &str| format!("Basic {}", BASE64.encode(credentials.as_bytes()));
        assert!(check("authorization", &basic("azure:0123456789abcdef")).await);
        assert!(check("authorization", &basic(":0123456789abcdef")).await);
        assert!(!check("authorization", &basic("azure:0123456789abcde")).await);
        assert!(!check("authorization", &basic("0123456789abcdef")).await);
        assert!(!check("authorization", "Bearer 0123456789abcdef").await);
        assert!(!check("x-gitlab-token", "0123456789abcde").await);
        assert!(!is_signed(SECRET, &HeaderMap::new(), Body::from_string(BODY.into())).await);
    }
}
