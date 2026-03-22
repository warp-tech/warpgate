use crate::WarpgateIdToken;

#[derive(Clone, Debug)]
pub struct SsoLoginResponse {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub access_roles: Option<Vec<String>>,
    pub admin_roles: Option<Vec<String>>,
    pub id_token: WarpgateIdToken,
    pub preferred_username: Option<String>,
}
