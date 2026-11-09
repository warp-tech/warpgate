//! The target's own sign-in state, as reported by the Save Session Info PDU
//! ([MS-RDPBCGR] 2.2.10.1). Until the target sends it, the session is sitting at the
//! target's sign-in screen — which is where the user types credentials that Warpgate never
//! sees, and which the recording must not keep.

use tracing::debug;
use uuid::Uuid;
use warpgate_common::TargetSessionId;
use warpgate_common::audit::AuditEvent;
use warpgate_core::LogonState;

pub(crate) struct LogonWatcher {
    pub target_session_id: TargetSessionId,
    pub target_id: Uuid,
    pub target_name: String,
    pub user_id: Uuid,
    pub username: String,
    pub sign_in: LogonState,
}

impl LogonWatcher {
    /// `logon_complete` and `session_id` are the Save Session Info outputs of one
    /// notification; IronRDP keeps the PDU itself (and the account it names) private.
    pub fn notify_logon(&self, logon_complete: bool, session_id: Option<u32>) {
        if !logon_complete {
            debug!("Target sent extended logon info");
            return;
        }

        self.sign_in.mark_logged_on();

        AuditEvent::TargetLogon {
            session_id: self.target_session_id.0,
            target_id: self.target_id,
            target_name: self.target_name.clone(),
            user_id: self.user_id,
            username: self.username.clone(),
            target_account: None,
            target_session_id: session_id,
        }
        .emit();
    }
}
