//! Owns the per-session channel table and its two invariants: a channel id
//! maps to a client-facing [`ServerChannelId`] and back through *one* place,
//! and a channel only becomes writable ([`ChannelState::Open`]) through
//! [`ChannelRegistry::confirm`], which hands back the events deferred while
//! the open was in flight. The backing map is private to this module, so
//! session code cannot create half-registered channels.

use std::collections::HashMap;

use uuid::Uuid;
use warpgate_core::recordings::ConnectionRecorder;

use crate::RCEvent;
use crate::channel_audit::ChannelAudit;
use crate::common::{PtyRequest, ServerChannelId};

/// How far a channel has got through its lifecycle. A channel that is gone is
/// absent from the registry entirely, so there is no "closed" state to go
/// stale.
enum ChannelState {
    /// Open not yet confirmed to the client. Target-side events for the channel
    /// land in `deferred` — there is nowhere else for them to go — so nothing
    /// can be written to the client before `CHANNEL_OPEN_CONFIRMATION` (#2328).
    /// Server-initiated channels (forwarded-tcpip, forwarded-streamlocal) also
    /// accumulate resources here while the client's confirmation is in flight.
    Opening { deferred: Vec<RCEvent> },
    /// Confirmed open on both sides. `pty` marks channels that had a PTY
    /// allocated — those receive service output and drive the interactive
    /// target-selection menu.
    Open { pty: bool },
}

impl Default for ChannelState {
    fn default() -> Self {
        Self::Opening { deferred: vec![] }
    }
}

/// All per-channel resources. Living in one struct per channel (rather than
/// parallel per-resource maps) means they can't fall out of sync as channels
/// come and go, and a new per-channel resource only needs a field here.
pub struct Channel {
    /// The client-facing russh channel id. `None` exactly while a
    /// server-initiated open awaits the client's confirmation — the id is
    /// assigned by the confirmation that resolves the open.
    server_id: Option<ServerChannelId>,
    state: ChannelState,
    pub audit: ChannelAudit,
    pub pty_size: Option<PtyRequest>,
    pub traffic_recorder: Option<ConnectionRecorder>,
}

impl Channel {
    fn new(id: Uuid, server_id: Option<ServerChannelId>) -> Self {
        Self {
            server_id,
            state: ChannelState::default(),
            audit: ChannelAudit::new(id),
            pty_size: None,
            traffic_recorder: None,
        }
    }

    pub const fn server_id(&self) -> Option<ServerChannelId> {
        self.server_id
    }

    pub const fn has_pty(&self) -> bool {
        matches!(self.state, ChannelState::Open { pty: true })
    }

    pub const fn is_open(&self) -> bool {
        matches!(self.state, ChannelState::Open { .. })
    }

    const fn is_opening(&self) -> bool {
        matches!(self.state, ChannelState::Opening { .. })
    }

    /// Queue `event` until the open is confirmed, or hand it back if the
    /// channel is already open and the event should be handled normally.
    pub fn try_defer(&mut self, event: RCEvent) -> Result<(), RCEvent> {
        match &mut self.state {
            ChannelState::Opening { deferred } => {
                deferred.push(event);
                Ok(())
            }
            ChannelState::Open { .. } => Err(event),
        }
    }

    /// Record that the client allocated a PTY. A channel whose open is still
    /// unconfirmed is left alone — the flag would be dropped by the transition
    /// anyway, and the caller re-checks after the target round-trip.
    pub const fn mark_pty(&mut self) {
        if let ChannelState::Open { pty } = &mut self.state {
            *pty = true;
        }
    }

    fn confirm_open(&mut self) -> Vec<RCEvent> {
        match &mut self.state {
            ChannelState::Opening { deferred } => {
                let deferred = std::mem::take(deferred);
                self.state = ChannelState::Open { pty: false };
                deferred
            }
            ChannelState::Open { .. } => vec![],
        }
    }
}

#[derive(Default)]
pub struct ChannelRegistry {
    channels: HashMap<Uuid, Channel>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a client-initiated open (session, direct-tcpip, streamlocal):
    /// the client id is known upfront, the target-side id is minted here.
    pub fn begin_client_open(&mut self, server_id: ServerChannelId) -> Uuid {
        let uuid = Uuid::new_v4();
        self.channels
            .insert(uuid, Channel::new(uuid, Some(server_id)));
        uuid
    }

    /// Register a server-initiated open (forwarded-tcpip, X11, agent): the
    /// target side already named the channel, the client id arrives with the
    /// confirmation ([`Self::assign_server_id`]).
    pub fn begin_server_open(&mut self, id: Uuid) {
        self.channels
            .entry(id)
            .or_insert_with(|| Channel::new(id, None));
    }

    /// Attach the client id the confirmation resolved to. `false` means the
    /// channel was closed while the open was in flight — the caller must not
    /// treat it as open.
    #[must_use]
    pub fn assign_server_id(&mut self, id: Uuid, server_id: ServerChannelId) -> bool {
        match self.channels.get_mut(&id) {
            Some(channel) => {
                channel.server_id = Some(server_id);
                true
            }
            None => false,
        }
    }

    /// The only transition into [`ChannelState::Open`]: hands back the events
    /// held while the open was in flight, so confirming a channel without
    /// replaying them is a visible lint at the call site. A channel closed
    /// while the open was in flight is left absent — inserting here would
    /// resurrect a zombie entry with no client mapping.
    #[must_use]
    pub fn confirm(&mut self, id: Uuid) -> Option<Vec<RCEvent>> {
        self.channels.get_mut(&id).map(Channel::confirm_open)
    }

    /// Tear down a closed channel: dropping its [`Channel`] finalizes the
    /// recorders (their background writers flush on drop, as they do at session
    /// end) and discards any still-deferred events, whose open will never
    /// resolve. Idempotent — the SSH close handshake reaches here from both the
    /// client and the target side.
    pub fn close(&mut self, id: Uuid) {
        self.channels.remove(&id);
    }

    pub fn get(&self, id: &Uuid) -> Option<&Channel> {
        self.channels.get(id)
    }

    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut Channel> {
        self.channels.get_mut(id)
    }

    /// Channels per session number in the handfuls, so a scan beats
    /// maintaining a second, invariant-bearing index.
    pub fn uuid_for(&self, server_id: ServerChannelId) -> Option<Uuid> {
        self.channels
            .iter()
            .find(|(_, c)| c.server_id == Some(server_id))
            .map(|(id, _)| *id)
    }

    pub fn values(&self) -> impl Iterator<Item = &Channel> {
        self.channels.values()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Uuid, &Channel)> {
        self.channels.iter()
    }

    pub fn has_opening(&self) -> bool {
        self.channels.values().any(Channel::is_opening)
    }
}
