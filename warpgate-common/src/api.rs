use poem_openapi::auth::ApiKey;
use poem_openapi::SecurityScheme;

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "X-Warpgate-Token", key_in = "header")]
#[allow(dead_code)]
pub struct TokenSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "warpgate-http-session", key_in = "cookie")]
#[allow(dead_code)]
pub struct CookieSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[allow(dead_code)]
pub enum AnySecurityScheme {
    Token(TokenSecurityScheme),
    Cookie(CookieSecurityScheme),
}
