use warpgate_common::WarpgateError;
use warpgate_common::auth::{AuthCredential, AuthState};

use crate::ConfigProvider;

pub async fn validate_and_add_credential<C: ConfigProvider>(
    state: &mut AuthState,
    credential: &AuthCredential,
    cp: &C,
) -> Result<bool, WarpgateError> {
    let credential_valid = cp
        .validate_credential(&state.user_info().username, credential)
        .await?;

    if credential_valid {
        state.add_valid_credential(credential.clone());
    }

    if !credential_valid {
        state.emit_authentication_failed_event(Some(credential), "invalid credential");
    }

    Ok(credential_valid)
}
