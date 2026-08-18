use warpgate_common::WarpgateError;
use warpgate_common::auth::{AuthCredential, AuthState, SubmitOutcome};

use crate::ConfigProvider;

pub async fn submit_credential<C: ConfigProvider>(
    state: &mut AuthState,
    credential: AuthCredential,
    cp: &C,
) -> Result<SubmitOutcome, WarpgateError> {
    state
        .submit_credential(credential, |username, credential| async move {
            cp.validate_credential(&username, &credential).await
        })
        .await
}
