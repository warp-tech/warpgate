//! Owns the per-session channel table and its invariants. A channel id maps
//! to a client-facing [`ServerChannelId`] and back through *one* place. A
//! channel only becomes writable ([`ChannelState::Open`]) through
//! [`ChannelRegistry::accept_client_open`] or
//! [`ChannelRegistry::confirm_server_open`], which return the events deferred
//! while the open was in flight. The backing map and the client's open handle
//! are private to this module, so session code cannot create half-registered
//! channels or confirm an open to the client without making the channel
//! writable

use std::collections::HashMap;

use russh::ChannelOpenFailure;
use russh::server::ChannelOpenHandle;
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;
use warpgate_core::recordings::ConnectionRecorder;

use super::session::TrafficRecording;
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
    ///
    /// Each event keeps its outbound slot. The client controls when the open
    /// resolves and the target controls how much it sends until then, so the
    /// slots are the only bound on this queue
    Opening {
        deferred: Vec<DeferredEvent>,
        open: PendingOpen,
    },
    /// Confirmed open on both sides. `pty` marks channels that had a PTY
    /// allocated — those receive service output and drive the interactive
    /// target-selection menu.
    Open { pty: bool },
}

enum PendingOpen {
    /// The client asked for the channel. The target has not answered
    Client(Box<ClientOpen>),
    /// The target asked for the channel. The client has not answered
    Server,
}

impl PendingOpen {
    fn client(self) -> Result<Box<ClientOpen>, Self> {
        match self {
            Self::Client(open) => Ok(open),
            Self::Server => Err(self),
        }
    }

    fn server(self) -> Result<(), Self> {
        match self {
            Self::Server => Ok(()),
            Self::Client(_) => Err(self),
        }
    }
}

struct ClientOpen {
    /// Dropping the handle refuses the open, so removing the channel is
    /// enough to refuse the client
    handle: ChannelOpenHandle,
    /// Set for port forwards. The recording starts when the target accepts
    recording: Option<TrafficRecording>,
}

/// A deferred target-side event and its outbound slot
pub type DeferredEvent = (RCEvent, Option<OwnedSemaphorePermit>);

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
    /// A session channel holds the target's EOF back until the exit status:
    /// an OpenSSH ControlMaster closes on EOF and would miss it (#2872).
    awaits_exit: bool,
    held_eof: bool,
}

impl Channel {
    const fn new(
        id: Uuid,
        server_id: Option<ServerChannelId>,
        awaits_exit: bool,
        open: PendingOpen,
    ) -> Self {
        Self {
            server_id,
            state: ChannelState::Opening {
                deferred: vec![],
                open,
            },
            audit: ChannelAudit::new(id),
            pty_size: None,
            traffic_recorder: None,
            awaits_exit,
            held_eof: false,
        }
    }

    pub async fn record_input(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.audit.on_input(data).await?;
        if let Some(recorder) = self.traffic_recorder.as_mut() {
            recorder.write_tx(data).await?;
        }
        Ok(())
    }

    pub async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.audit.on_output(data).await?;
        if let Some(recorder) = self.traffic_recorder.as_mut() {
            recorder.write_rx(data).await?;
        }
        Ok(())
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

    const fn awaits_client(&self) -> bool {
        matches!(
            self.state,
            ChannelState::Opening {
                open: PendingOpen::Server,
                ..
            }
        )
    }

    /// Queue `event` until the open is confirmed, or hand it back if the
    /// channel is already open and the event should be handled normally.
    /// `slot` is not called if the event is handed back.
    pub fn try_defer(
        &mut self,
        event: RCEvent,
        slot: impl FnOnce() -> Option<OwnedSemaphorePermit>,
    ) -> Result<(), RCEvent> {
        match &mut self.state {
            ChannelState::Opening { deferred, .. } => {
                deferred.push((event, slot()));
                Ok(())
            }
            ChannelState::Open { .. } => Err(event),
        }
    }

    /// Record that the client allocated a PTY. A channel whose open is still
    /// unconfirmed is left alone — the flag would be dropped by the transition
    /// anyway.
    pub const fn mark_pty(&mut self) {
        if let ChannelState::Open { pty } = &mut self.state {
            *pty = true;
        }
    }

    /// Whether the target's EOF has to wait for the exit status.
    pub const fn hold_eof(&mut self) -> bool {
        self.held_eof = self.awaits_exit;
        self.held_eof
    }

    /// Whether an EOF held by [`Self::hold_eof`] is due now that the exit
    /// status or the close has been sent on.
    pub const fn release_eof(&mut self) -> bool {
        self.awaits_exit = false;
        std::mem::replace(&mut self.held_eof, false)
    }

    /// Move the channel to [`ChannelState::Open`] if `resolves` accepts its
    /// pending open, and return the events deferred on it. Otherwise the
    /// state is unchanged
    fn open<T>(
        &mut self,
        resolves: impl FnOnce(PendingOpen) -> Result<T, PendingOpen>,
    ) -> Option<(T, Vec<DeferredEvent>)> {
        match std::mem::replace(&mut self.state, ChannelState::Open { pty: false }) {
            ChannelState::Opening { deferred, open } => match resolves(open) {
                Ok(resolved) => Some((resolved, deferred)),
                Err(open) => {
                    self.state = ChannelState::Opening { deferred, open };
                    None
                }
            },
            state @ ChannelState::Open { .. } => {
                self.state = state;
                None
            }
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
    /// the client id is known upfront, the target-side id is minted here. The
    /// client's open is answered by [`Self::accept_client_open`],
    /// [`Self::reject_client_open`] or [`Self::close`]
    pub fn begin_client_open(
        &mut self,
        server_id: ServerChannelId,
        session: bool,
        handle: ChannelOpenHandle,
        recording: Option<TrafficRecording>,
    ) -> Uuid {
        let uuid = Uuid::new_v4();
        let open = PendingOpen::Client(Box::new(ClientOpen { handle, recording }));
        self.channels
            .insert(uuid, Channel::new(uuid, Some(server_id), session, open));
        uuid
    }

    /// Register a server-initiated open (forwarded-tcpip, X11, agent): the
    /// target side already named the channel, the client id arrives with the
    /// confirmation ([`Self::confirm_server_open`]).
    pub fn begin_server_open(&mut self, id: Uuid) {
        self.channels
            .entry(id)
            .or_insert_with(|| Channel::new(id, None, false, PendingOpen::Server));
    }

    pub fn take_pending_recording(&mut self, id: Uuid) -> Option<TrafficRecording> {
        match &mut self.channels.get_mut(&id)?.state {
            ChannelState::Opening {
                open: PendingOpen::Client(open),
                ..
            } => open.recording.take(),
            _ => None,
        }
    }

    /// Confirm the open to the client and return the target events deferred
    /// on the channel. The confirmation is queued before this returns, so
    /// the replayed events cannot reach the client ahead of it (#2328).
    ///
    /// `None` means the client got no confirmation. Either the channel was
    /// closed while the open was in flight, or its recording was never taken.
    /// The open is then refused, so a forward cannot run unrecorded
    #[must_use]
    pub async fn accept_client_open(
        &mut self,
        id: Uuid,
        traffic_recorder: Option<ConnectionRecorder>,
    ) -> Option<Vec<DeferredEvent>> {
        let channel = self.channels.get_mut(&id)?;
        let (open, deferred) = channel.open(PendingOpen::client)?;
        if open.recording.is_some() {
            // `open` is dropped on return, which refuses the client
            self.channels.remove(&id);
            return None;
        }
        open.handle.accept().await;
        channel.traffic_recorder = traffic_recorder;
        Some(deferred)
    }

    /// Does nothing unless the channel is waiting for the target's answer
    pub async fn reject_client_open(&mut self, id: Uuid, reason: ChannelOpenFailure) {
        let Some((open, _)) = self
            .channels
            .get_mut(&id)
            .and_then(|channel| channel.open(PendingOpen::client))
        else {
            return;
        };
        self.channels.remove(&id);
        open.handle.reject(reason).await;
    }

    /// The client accepted the target's open as channel `server_id`. Returns
    /// the events deferred while the open was in flight. `#[must_use]` makes
    /// confirming without replaying them a lint at the call site.
    ///
    /// `None` means the channel was closed while the open was in flight, or
    /// was not waiting for the client. Nothing is inserted, because that
    /// would resurrect a closed channel
    #[must_use]
    pub fn confirm_server_open(
        &mut self,
        id: Uuid,
        server_id: ServerChannelId,
    ) -> Option<Vec<DeferredEvent>> {
        let channel = self.channels.get_mut(&id)?;
        let ((), deferred) = channel.open(PendingOpen::server)?;
        channel.server_id = Some(server_id);
        Some(deferred)
    }

    /// Tear down a closed channel: dropping its [`Channel`] finalizes the
    /// recorders (their background writers flush on drop, as they do at session
    /// end), discards any still-deferred events, whose open will never
    /// resolve, and refuses a client open still waiting for the target.
    /// Idempotent — the SSH close handshake reaches here from both the client
    /// and the target side.
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

    /// Number of target-initiated opens the client has not answered
    pub fn pending_server_opens(&self) -> usize {
        self.channels.values().filter(|c| c.awaits_client()).count()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use russh::ChannelId;
    use russh::keys::ssh_encoding::Decode;
    use tokio::sync::Semaphore;

    use super::*;

    fn client_id(number: u8) -> ServerChannelId {
        ServerChannelId(ChannelId::decode(&mut &[0, 0, 0, number][..]).unwrap())
    }

    #[test]
    fn deferred_events_hold_their_slots_until_the_open_resolves() {
        let slots = Arc::new(Semaphore::new(2));
        let take = || slots.clone().try_acquire_owned().ok();
        let mut channels = ChannelRegistry::new();

        // Confirming returns the slots with the events
        let id = Uuid::new_v4();
        channels.begin_server_open(id);
        let channel = channels.get_mut(&id).unwrap();
        assert!(channel.try_defer(RCEvent::Eof(id), take).is_ok());
        assert!(channel.try_defer(RCEvent::Eof(id), take).is_ok());
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(channels.pending_server_opens(), 1);
        let deferred = channels.confirm_server_open(id, client_id(1)).unwrap();
        assert!(deferred.iter().all(|(_, slot)| slot.is_some()));
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(channels.pending_server_opens(), 0);
        assert_eq!(channels.uuid_for(client_id(1)), Some(id));
        drop(deferred);

        // A second confirmation changes nothing
        assert!(channels.confirm_server_open(id, client_id(2)).is_none());
        assert_eq!(channels.uuid_for(client_id(1)), Some(id));

        // An open channel takes no slot
        let channel = channels.get_mut(&id).unwrap();
        assert!(channel.try_defer(RCEvent::Eof(id), take).is_err());
        assert_eq!(slots.available_permits(), 2);

        // Closing an unconfirmed channel frees its slots
        let id = Uuid::new_v4();
        channels.begin_server_open(id);
        let channel = channels.get_mut(&id).unwrap();
        assert!(channel.try_defer(RCEvent::Eof(id), take).is_ok());
        assert_eq!(slots.available_permits(), 1);
        channels.close(id);
        assert_eq!(slots.available_permits(), 2);
    }
}
