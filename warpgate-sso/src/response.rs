use crate::WarpgateIdToken;

#[derive(Clone, Debug)]
pub struct SsoLoginResponse {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub access_roles: Option<Vec<String>>,
    pub admin_roles: Option<Vec<String>>,
    pub id_token: WarpgateIdToken,
    /// The OAuth access token, when the provider issued one. Absent for flows
    /// that verify a bare ID token (e.g. the kubectl bearer-token path), where
    /// no code exchange happens and therefore no access token exists.
    pub access_token: Option<String>,
    pub preferred_username: Option<String>,
}
