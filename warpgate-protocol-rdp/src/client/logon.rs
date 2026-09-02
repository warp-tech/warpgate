//! The target's own sign-in state, as reported by the Save Session Info PDU
//! ([MS-RDPBCGR] 2.2.10.1). Until the target sends it, the session is sitting at the
//! target's sign-in screen — which is where the user types credentials that Warpgate never
//! sees, and which the recording must not keep.

use ironrdp::pdu::rdp::session_info::{InfoData, LogonInfo, SaveSessionInfoPdu};
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
    pub fn notify_logon_pdu(&self, pdu: &SaveSessionInfoPdu) {
        let info = match &pdu.info_data {
            InfoData::LogonInfoV1(info) => Some(&info.logon_info),
            InfoData::LogonInfoV2(info) => Some(&info.logon_info),
            InfoData::PlainNotify => None,
            InfoData::LogonExtended(extended) => {
                debug!(?extended, "Target sent extended logon info");
                return;
            }
        };

        self.sign_in.mark_logged_on();

        AuditEvent::TargetLogon {
            session_id: self.target_session_id.0,
            target_id: self.target_id,
            target_name: self.target_name.clone(),
            user_id: self.user_id,
            username: self.username.clone(),
            target_account: info.and_then(account),
            target_session_id: info.map(|info| info.session_id),
        }
        .emit();
    }
}

fn account(info: &LogonInfo) -> Option<String> {
    if info.user_name.is_empty() {
        return None;
    }
    Some(if info.domain_name.is_empty() {
        info.user_name.clone()
    } else {
        format!("{}\\{}", info.domain_name, info.user_name)
    })
}
