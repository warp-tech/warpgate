#[derive(Clone, Debug)]
pub struct SsoLoginResponse {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}
