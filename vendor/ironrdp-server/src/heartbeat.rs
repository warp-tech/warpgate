//! Server-side Heartbeat PDU emission (MS-RDPBCGR 2.2.16).

/// Configuration for periodic Server Heartbeat PDUs (MS-RDPBCGR 2.2.16.1).
///
/// Heartbeats let the client monitor connection health in real time: when it
/// stops receiving them (and everything else) for long enough, it can warn
/// the user or start a reconnect attempt. They ride the MCS message channel
/// and are only sent while the connection is otherwise idle; ordinary
/// traffic doubles as the liveness signal.
///
/// The specification mandates no particular values, so the defaults are this
/// library's own choice: a 5-second period keeps idle-link detection
/// responsive at negligible traffic cost (8 bytes of payload per interval),
/// `warning_count` = 3 puts a client-side warning at roughly 15 seconds of
/// silence, and `reconnect_count` = 5 a reconnect attempt at roughly
/// 40 seconds. The client MAY ignore both counts (2.2.16.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Seconds between heartbeats while the connection is otherwise idle.
    ///
    /// `0` is treated as `1`.
    pub period_secs: u8,
    /// Missed heartbeats that SHOULD trigger a client-side warning.
    pub warning_count: u8,
    /// Missed heartbeats after the warning that SHOULD trigger a client-side
    /// reconnect attempt.
    pub reconnect_count: u8,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            period_secs: 5,
            warning_count: 3,
            reconnect_count: 5,
        }
    }
}
