mod channel_direct_tcpip;
mod channel_session;
mod error;
mod handler;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use channel_direct_tcpip::DirectTCPIPChannel;
use channel_session::SessionChannel;
pub use error::{SshClientError, client_error_message};
use futures::{FutureExt, pin_mut};
use handler::ClientHandler;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Algorithm, Certificate, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{MethodKind, Preferred, Sig, kex, mac};
use serde::Serialize;
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tracing::*;
use uuid::Uuid;
use warpgate_aws::AwsError;
use warpgate_common::helpers::rng::get_crypto_rng;
use warpgate_common::{
    MAX_CERTIFICATE_LIFETIME, SSHTargetAuth, SessionId, SshCertificateCriticalOption,
    TargetOptions, TargetSSHOptions, WarpgateError,
};
use warpgate_common_http::auth::TOKEN_ATTRIBUTIONS;
use warpgate_core::{ConfigProvider, Services};

use self::handler::ClientHandlerEvent;
use super::{ChannelOperation, DirectTCPIPParams};
use crate::client::handler::ClientHandlerError;
use crate::{ForwardedStreamlocalParams, ForwardedTcpIpParams, load_client_keys};

/// What a hop in the chain is to the caller.
///
/// Every hop presents a host key, so "the host key" is ambiguous the moment a
/// jump host is involved — and the answer the caller wants is the one from the
/// hop they named, which is always the last.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HopRole {
    /// An ordinary connection: every hop's key is reported, because the user
    /// may be prompted to trust any of them.
    Connecting,
    /// On the way to the hop being asked about. Its key is verified against
    /// known hosts as usual, but not reported as an answer.
    TraversedWhileChecking,
    /// The hop the caller asked about. Report its key and go no further.
    CheckedHost,
}

/// Which role a hop plays, given which target was asked about.
///
/// By identity, not by position. It used to take "is this the last hop", which
/// is the same answer for every chain built today and a different question: the
/// resolver knows which target was named and threw that away, leaving
/// correctness resting on the chain always happening to terminate there.
fn role(check_target: Option<Uuid>, hop_id: Uuid) -> HopRole {
    match check_target {
        None => HopRole::Connecting,
        Some(asked_about) if asked_about == hop_id => HopRole::CheckedHost,
        Some(_) => HopRole::TraversedWhileChecking,
    }
}

impl HopRole {
    const fn reports_host_key(self) -> bool {
        matches!(self, Self::Connecting | Self::CheckedHost)
    }

    const fn stops_after_host_key(self) -> bool {
        matches!(self, Self::CheckedHost)
    }
}

/// How long a target may take to finish the SSH handshake. Generous for any
/// real server on any real link, and the only thing standing between a target
/// that accepts a connection and then goes quiet and a gateway task held for as
/// long as it likes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How far out the handshake bound is pushed while a host-key question is
/// outstanding.
///
/// Not disarmed — pushed out — so that nothing has to remember to arm it again.
/// A year is "not while a person is reading a fingerprint" expressed as a
/// number.
const fn while_a_host_key_answer_is_outstanding() -> Duration {
    Duration::from_secs(365 * 24 * 60 * 60)
}

/// And what it comes back to once the answer arrives: the remaining handshake
/// is the target's again, so it gets the target's bound.
///
/// A separate function from the constant because this is the thing that can be
/// got wrong. The first version of this pause never ended — the deadline was
/// pushed out and nothing brought it back — and a target that answered with a
/// host key and then went quiet held the session, the ephemeral key and a live
/// certificate until russh's inactivity timeout.
const fn once_the_host_key_is_answered() -> Duration {
    HANDSHAKE_TIMEOUT
}

/// How long authentication may take, when nothing else decides.
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);

/// The worst case a certificate authentication can spend on Vault, counted in
/// operations the client bounds rather than in HTTP requests: a token, a sign,
/// then — on a `403` — a second token and a second sign. Four, with one for
/// margin.
///
/// A metadata fetch does not add to this. It happens inside `login_body()`,
/// which `token()` wraps in a single `config.timeout` together with the login
/// itself, so a method fetching twice still spends one bounded operation
/// getting a token. Counting requests instead of bounds is what made this
/// constant look wrong when it was not.
const VAULT_CALLS_PER_AUTHENTICATION: u32 = 5;

/// How long authentication may take, as distinct from the transport handshake.
///
/// The two shared `HANDSHAKE_TIMEOUT` until now: different phases, different
/// causes, one constant by accident. A certificate target's authentication is
/// dominated by the issuer, and five calls at the default 10s `vault.timeout`
/// is fifty seconds against a thirty-second bound — so a Vault that was slow
/// but working produced a timeout naming the target, which is not the party
/// that was slow.
fn authentication_budget(auth: &SSHTargetAuth, vault_timeout: Option<Duration>) -> Duration {
    match (auth, vault_timeout) {
        (SSHTargetAuth::Certificate(_), Some(per_call)) => AUTHENTICATION_TIMEOUT
            .max(per_call * VAULT_CALLS_PER_AUTHENTICATION + Duration::from_secs(5)),
        _ => AUTHENTICATION_TIMEOUT,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Host key mismatch")]
    HostKeyMismatch {
        received_key_type: russh::keys::Algorithm,
        received_key_base64: String,
        known_key_type: String,
        known_key_base64: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] russh::keys::Error),

    #[error(transparent)]
    Ssh(#[from] russh::Error),

    #[error("AWS: {0}")]
    Aws(#[from] AwsError),

    #[error("Vault: {0}")]
    Vault(#[from] warpgate_vault::VaultError),

    #[error("Could not resolve address")]
    Resolve,

    #[error("Internal error")]
    Internal,

    #[error("Aborted")]
    Aborted,

    /// The peer accepted the connection and then did not finish the handshake.
    /// Distinct from a refusal, because nothing was refused — and distinct from
    /// an ordinary timeout, because it names the stage.
    #[error("The SSH target did not complete the handshake in time")]
    HandshakeTimeout,

    /// Carries why, because the target's own reason is the only thing that
    /// distinguishes a wrong credential from a clock that disagrees — and a
    /// message that reaches only the server log is not much use to whoever is
    /// staring at a closed session.
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Warpgate refused the credential before offering it, so the target never
    /// saw anything — saying it was "rejected by the target" would name the
    /// wrong party and send the operator to the wrong logs.
    #[error("Certificate refused by Warpgate: {0}")]
    CertificateRefused(String),

    #[error("Jump host target not found")]
    JumpHostTargetNotFound,

    /// Only reachable while checking a target's host key: the chain leading to
    /// it goes through a host that is not trusted yet.
    #[error("A jump host on the way to this target has an untrusted host key")]
    UntrustedJumpHost,

    /// Authentication did not finish in time.
    ///
    /// Its own variant rather than `HandshakeTimeout`, and its own budget:
    /// for a certificate target this phase is dominated by the issuer, not by
    /// the target, and naming the target sends whoever is debugging to the
    /// wrong logs.
    #[error("Authentication to the SSH target did not complete in time")]
    AuthenticationTimeout,

    /// A jump host connected, authenticated, and then did not answer the
    /// request to open a tunnel to the next hop.
    ///
    /// Its own variant rather than `HandshakeTimeout`, which names the target —
    /// and the target is not the party that went quiet here. Sending an
    /// operator to the wrong machine's logs is the mistake `CertificateRefused`
    /// was added to stop.
    #[error("A jump host did not open the tunnel to the next hop in time")]
    TunnelOpenTimeout { host: String },

    #[error(transparent)]
    Warpgate(#[from] WarpgateError),
}

impl ConnectionError {
    pub fn client_message(&self) -> String {
        match self {
            ConnectionError::Vault(e) => e.client_message().to_string(),
            ConnectionError::Aws(e) => e.client_message().to_string(),
            ConnectionError::Authentication(reason) => {
                format!("SSH target rejected Warpgate's authentication request: {reason}")
            }
            ConnectionError::CertificateRefused(reason) => {
                format!("Warpgate refused the certificate issued for this session: {reason}")
            }
            ConnectionError::HostKeyMismatch { .. } => "Host key mismatch".to_string(),
            ConnectionError::Resolve => "Could not resolve target address".to_string(),
            ConnectionError::Aborted => "Connection aborted".to_string(),
            ConnectionError::HandshakeTimeout => {
                "The SSH target accepted the connection but never completed the handshake"
                    .to_string()
            }
            ConnectionError::Internal => "Internal connection error".to_string(),
            ConnectionError::JumpHostTargetNotFound => "Jump host target not found".to_string(),
            ConnectionError::UntrustedJumpHost => {
                "A jump host on the way to this target has an untrusted host key; check that host first"
                    .to_string()
            }
            ConnectionError::AuthenticationTimeout => {
                "Authentication did not complete in time — the target or, for a certificate target, the issuer"
                    .to_string()
            }
            ConnectionError::TunnelOpenTimeout { host } => {
                // `{:?}`, as the other arms that carry a configured string do.
                // The host comes from a target's configuration, so it reaches a
                // terminal belonging to whoever connects rather than to whoever
                // set it — the same class as the target names already fixed, and
                // missed here because this variant was added by a later fix.
                format!("The jump host {host:?} did not open the tunnel to the next hop in time")
            }
            ConnectionError::Io(_) | ConnectionError::Key(_) | ConnectionError::Ssh(_) => {
                "SSH protocol error".to_string()
            }
            // Not `to_string()`. This is the sanitiser, and that arm passed
            // `WarpgateError`'s `Display` through verbatim to a PTY and a
            // browser — reachable from inside `authenticate_session`, where a
            // database failure renders as `database error: {DbErr}` carrying SQL
            // text, and an encryption-key mismatch names the configured key
            // fingerprints. The one arm of the function that did not do the job
            // the function exists for.
            ConnectionError::Warpgate(_) => "Internal connection error".to_string(),
        }
    }
}

/// Vault is a second gate, not a trusted party, so what comes back is checked
/// against what was asked for before it is offered to the target.
///
/// The type and key checks are belt-and-braces — neither could authenticate
/// anything — but the last two are load-bearing. The target's sshd enforces
/// whatever critical options arrive, so a `force-command` planted on a role
/// replaces what the user asked to run while keeping their principal and key ID
/// on it: the target's own log then attributes the attacker's command to them.
/// Writing a role is a lower bar than signing with it, so this is the only place
/// the check can land.
/// How much longer than the requested TTL a certificate may be valid for
/// before it is refused.
///
/// The window is measured from now, and the certificate was signed a moment
/// earlier, so an honest issuer always comes back at or under what was asked
/// for. The slack is for the clocks disagreeing, not for the issuer being
/// generous.
const CERTIFICATE_TTL_SLACK: Duration = Duration::from_secs(60);

/// Stands in the username field when the session has no user info recorded.
///
/// `key_id_field` rejects a colon, so no real username can collide with this
/// one, and the field count stays at three whatever happened.
const UNATTRIBUTED: &str = "unattributed";

/// A username as it may appear in a key ID field.
///
/// The key ID is `warpgate:<username>:<session>`, three fields split on a
/// colon, and the target's own sshd log carries it verbatim — a name with a
/// colon in it shifts every field, so whatever reads that log names the wrong
/// person. The admin API refuses one now; a name arriving from an IdP never
/// passes through the admin API, so the structure is held here too.
///
/// A name equal to an attribution is held here for the same reason and by the
/// same argument. `attribution()` puts `admin-token` in this field when the
/// admin API token drives a session, so a user of that name reads in the
/// target's log exactly as the token does. The admin API refuses it — and is
/// one of six paths that create a user. SSO auto-provisioning inserts the
/// IdP's `preferred_username` directly, and the two CLI commands insert what
/// the operator typed, so the refusal is not on the path that matters.
///
/// Substituted rather than refused: a name from a directory is not something
/// the connecting user can fix mid-session.
fn key_id_field(name: &str) -> String {
    name.replace(':', "_")
}

/// A name that came from a person, as it may appear in a key ID field.
///
/// Everything `key_id_field` does, and one thing more: a name equal to an
/// attribution is moved aside, because `attribution()` puts those in this very
/// field when a token drives a session. A user of that name would otherwise be
/// indistinguishable from the gateway in the target's sshd log and in Vault's.
///
/// Only for names that came from a person. The gateway's own attribution goes
/// through `key_id_field` untouched — substituting it renames the thing it
/// identifies, which is exactly what the first version of this did: two guards
/// failed their baseline because `admin-token` had become `admin-token_`.
fn user_key_id_field(name: &str) -> String {
    let field = key_id_field(name);
    if TOKEN_ATTRIBUTIONS.contains(&field.as_str()) {
        return format!("{field}_");
    }
    field
}

/// Whether a host-key check can be answered by this chain at all.
///
/// The walk decides each hop's role by identity, so a `check_target` naming no
/// hop leaves every one of them `TraversedWhileChecking`: none reports its key,
/// none stops the walk, and the caller is handed a live session and no answer.
/// Checked before the first connection rather than after the last, because a
/// question this chain cannot answer is not worth opening a socket for.
///
/// Unreachable while the chain is built from the target being asked about,
/// which is exactly the assumption deciding roles by identity exists to stop
/// depending on.
fn chain_can_answer(check_target: Option<Uuid>, hops: &[Uuid]) -> bool {
    check_target.is_none_or(|asked_about| hops.contains(&asked_about))
}

/// Whether the certificate was signed by the CA the operator pinned.
///
/// Separate from `certificate_mismatch` because it asks a different question.
/// Every check there compares the response against the request — is this the
/// key ID we asked for, the principal, the window. This one asks who signed it,
/// which the request cannot answer.
///
/// A pinned key that will not parse is a refusal, not a warning skipped over: a
/// typo in the config would otherwise turn the check off silently, which is the
/// failure mode a pin exists to prevent.
fn certificate_signer_mismatch(certificate: &Certificate, pinned: Option<&str>) -> Option<String> {
    let pinned = pinned?;
    let Ok(expected) = PublicKey::from_openssh(pinned) else {
        return Some(
            "The pinned Vault CA public key in the configuration could not be parsed".to_owned(),
        );
    };
    if certificate.signature_key() == expected.key_data() {
        return None;
    }
    Some("Vault issued a certificate signed by a CA other than the pinned one".to_owned())
}

fn certificate_mismatch(
    certificate: &Certificate,
    key: &PublicKey,
    principal: &str,
    key_id: &str,
    allowed_options: &[SshCertificateCriticalOption],
    allowed_extensions: &[String],
    requested_ttl: Option<Duration>,
) -> Option<String> {
    // The target's sshd logs this verbatim, and a session being attributable to
    // a person from the target side alone is the whole claim this feature
    // makes. An issuer that returns a different one — or a very long one —
    // breaks the attribution and floods the target's log with it.
    if certificate.key_id() != key_id {
        return Some(
            "Vault issued a certificate under a key ID other than the one requested".to_owned(),
        );
    }
    if certificate.cert_type() != CertType::User {
        return Some("Vault returned a host certificate rather than a user certificate".to_owned());
    }
    if certificate.public_key() != key.key_data() {
        return Some("Vault signed a key other than the one generated for this session".to_owned());
    }
    // Vault returns the requested set verbatim — trimmed, deduped and sorted —
    // or refuses outright, so anything other than exactly the account that was
    // asked for means the answer did not come from this request.
    //
    // Exactly, rather than merely containing it. An extra principal is another
    // account the target will accept this certificate for, chosen by whoever
    // answered rather than by the operator, and where sshd maps principals
    // through `AuthorizedPrincipalsFile` it need not resemble a username at all.
    // It is also the shape of CVE-2026-35414, where a comma inside a principal
    // splits one name into two for one of sshd's checks and not the other.
    let principals = certificate.valid_principals();
    if principals.len() != 1 || principals.first().is_none_or(|only| only != principal) {
        return Some(format!(
            "Vault issued a certificate naming {:?} rather than only the target account {principal}",
            principals
        ));
    }

    // The window is the feature's whole premise: a credential too short-lived
    // to be worth stealing. Nothing checked it, so a role with a `max_ttl` of
    // years — or one quietly edited to have one — produced a certificate good
    // for years, and every layer downstream accepted it.
    // Every way this can be wrong, because the first version handled only the
    // ordinary one and let the other three past.
    //
    // `u64::MAX` is OpenSSH's "never expires" sentinel (PROTOCOL.certkeys), and
    // it is what `ssh-keygen -V always:forever` and a Vault role with no TTL
    // both write. It is checked on the raw field rather than through
    // `valid_before_time()`, which reports the sentinel as a real instant
    // capped at `i64::MAX` — refused either way, but as "valid for
    // 2562047787518949 hours", which names the wrong problem.
    //
    // `valid_before_time()` returns `None` only for a value above `i64::MAX`
    // that is *not* the sentinel. No tool produces one; an issuer that wants
    // this certificate not to expire can write one by hand.
    if certificate.valid_before() == u64::MAX {
        return Some(
            "Vault issued a certificate that never expires, which is not a session credential"
                .to_owned(),
        );
    }
    match certificate
        .valid_before_time()
        .map(|at| at.duration_since(std::time::SystemTime::now()))
    {
        None => {
            return Some(
                "Vault issued a certificate with an unrepresentable expiry time".to_owned(),
            );
        }
        Some(Err(_)) => {
            return Some(
                "Vault issued a certificate that has already expired; check the clock on this host"
                    .to_owned(),
            );
        }
        Some(Ok(lifetime)) if lifetime > MAX_CERTIFICATE_LIFETIME => {
            return Some(format!(
                "Vault issued a certificate valid for {} hours, far longer than a session credential should be",
                lifetime.as_secs() / 3600
            ));
        }
        // The ceiling is a backstop against a misconfigured role. This is the
        // operator's own number, and it was sent and then never looked at
        // again: a target configured for ninety seconds accepted a certificate
        // good for twenty-three hours, because that is still under the ceiling.
        // Asking is not getting, and every other field Vault returns is checked
        // against what was asked for.
        Some(Ok(lifetime))
            if requested_ttl.is_some_and(|ttl| lifetime > ttl + CERTIFICATE_TTL_SLACK) =>
        {
            return Some(format!(
                "Vault issued a certificate valid for {}s, longer than the {}s this target asked for",
                lifetime.as_secs(),
                requested_ttl.map_or(0, |ttl| ttl.as_secs())
            ));
        }
        Some(Ok(_)) => {}
    }

    // Both directions, and pinning a value is what decides which.
    //
    // The list is an allow-list: an option that is not on it is refused. That
    // was built against someone with write access to a Vault role but no right
    // to sign with it, adding an option nobody asked for. Approached from the
    // other side they *remove* one instead — a target whose whole point is a
    // pinned `force-command` accepting a certificate carrying none at all is a
    // full shell rather than the one command, and checking only what arrived
    // can never see that.
    //
    // So a pinned entry is also mandatory. Pinning a value is the act of saying
    // what the option must be, which is not something a certificate can satisfy
    // by leaving it out. A bare name only permits: it is how a role that
    // *sometimes* sets an option is expressed, which an all-mandatory list
    // could not express at all — list the option and certificates without it
    // fail, omit it and certificates with it fail.
    for expected in allowed_options {
        if expected.value.is_some() && !certificate.critical_options().contains_key(&expected.name)
        {
            return Some(format!(
                "Vault issued a certificate without the critical option {:?}, which this target pins to a specific value",
                expected.name
            ));
        }
    }

    // Extensions, which until now were logged and nothing else.
    //
    // The argument for checking critical options — writing a Vault role is a
    // lower bar than signing with it, so this is the only place it can be
    // caught — applies to extensions unchanged. They are a separate
    // authorization mechanism, and the one that decides whether a session can
    // forward ports or reach the connecting user's agent. A `force-command`
    // covers the shell and exec channels; `direct-tcpip` and agent forwarding
    // are judged by OpenSSH purely on what the certificate carries.
    //
    // No second direction here, unlike critical options: an extension that is
    // absent grants nothing, so there is nothing to remove that would widen
    // access.
    for name in certificate.extensions().keys() {
        if !allowed_extensions.iter().any(|allowed| allowed == name) {
            return Some(format!(
                "Vault issued a certificate carrying the extension {name:?}, which this target does not allow"
            ));
        }
    }

    for (name, value) in certificate.critical_options().iter() {
        // The *strictest* matching entry, not the first one.
        //
        // `.find()` returned whichever the operator happened to type first. A
        // config naming `force-command` twice — once bare, once pinned to a
        // value — passed the mandatory-presence loop above on the pinned entry
        // and then matched the bare one here, so any command at all was
        // accepted while the admin UI showed a pin. Fails open, silently, and
        // an operator with two rows on screen has no way to see which one is
        // deciding.
        //
        // Duplicates are a configuration mistake rather than a feature, and
        // every pin is enforced rather than one of them being picked. That also
        // settles two pins that disagree: no value satisfies both, so the
        // certificate is refused instead of one entry winning by position.
        let mut named = allowed_options
            .iter()
            .filter(|option| &option.name == name)
            .peekable();
        if named.peek().is_none() {
            // Quoted with `{:?}`, which escapes control characters: this string
            // comes out of the certificate and ends up on the connecting user's
            // terminal, where a raw escape sequence would be executed rather
            // than shown.
            return Some(format!(
                "Vault issued a certificate carrying the critical option {name:?}, which this target does not allow"
            ));
        }
        for option in named {
            if let Some(expected) = &option.value
                && expected != value
            {
                return Some(format!(
                    "Vault issued a certificate whose critical option {name:?} does not match the value configured for this target"
                ));
            }
        }
    }

    None
}

#[derive(Clone, Debug)]
pub struct ResolvedSshChainHost {
    /// Which target this hop is.
    ///
    /// Carried past resolution because the connection code needs to know which
    /// hop was asked about, and used to infer it from position: the last one.
    /// That is true of every chain built today and is an assumption rather than
    /// a fact — the identity exists here and was thrown away one line later.
    pub id: Uuid,
    pub name: String,
    pub ssh_options: TargetSSHOptions,
}

/// A jump host that names a deleted or non-SSH target: a broken configuration
/// that must fail the connection rather than silently shorten the chain, which
/// would dial the target more directly than the operator intended.
fn unresolvable_jump_host(id: Uuid) -> WarpgateError {
    WarpgateError::InconsistentState(format!(
        "SSH jump host {id} does not resolve to an SSH target"
    ))
}

/// Follow `jump_host` links from `start`, returning the ordered target ids of
/// the chain (the target itself first, then each successive jump host).
///
/// `lookup` resolves a target id: `Some(Some(jump))` — an SSH target that jumps
/// through `jump`; `Some(None)` — an SSH target with no jump host, ending the
/// chain; `None` — the id does not resolve to an SSH target. An unresolvable id,
/// or one that repeats (a cycle), fails resolution.
fn resolve_chain_ids(
    start: Uuid,
    lookup: impl Fn(Uuid) -> Option<Option<Uuid>>,
) -> Result<Vec<Uuid>, WarpgateError> {
    let mut ids = vec![];
    let mut visited = HashSet::new();
    let mut current = Some(start);
    while let Some(id) = current {
        if !visited.insert(id) {
            return Err(WarpgateError::InconsistentState(format!(
                "SSH jump host chain contains a cycle at target {id}"
            )));
        }
        let Some(jump_host) = lookup(id) else {
            return Err(unresolvable_jump_host(id));
        };
        ids.push(id);
        current = jump_host;
    }
    Ok(ids)
}

/// Resolve the full ordered SSH jump chain for a target
/// `logged_in_username` is used to substitute empty dynamic usernames
/// in targets' configs
pub async fn resolve_ssh_chain(
    services: &Services,
    target_id: Uuid,
    logged_in_username: Option<&String>,
) -> Result<Vec<ResolvedSshChainHost>, WarpgateError> {
    let targets = services.config_provider.list_targets().await?;

    let chain_ids = resolve_chain_ids(target_id, |id| {
        targets
            .iter()
            .find(|t| t.id == id)
            .and_then(|t| match &t.options {
                TargetOptions::Ssh(opts) => Some(opts.jump_host),
                _ => None,
            })
    })?;

    let mut jumps = vec![];
    for id in chain_ids {
        let Some(t) = targets.iter().find(|t| t.id == id) else {
            return Err(unresolvable_jump_host(id));
        };
        let TargetOptions::Ssh(opts) = &t.options else {
            return Err(unresolvable_jump_host(id));
        };
        let mut opts = opts.clone();

        // Forward username from the authenticated user to the target, if target has no username
        if let Some(logged_in_username) = logged_in_username
            && opts.username.is_empty()
        {
            opts.username = logged_in_username.clone();
        }

        jumps.push(ResolvedSshChainHost {
            id: t.id,
            name: t.name.clone(),
            ssh_options: opts,
        });
    }
    jumps.reverse();
    Ok(jumps)
}

#[derive(Debug)]
pub enum RCEvent {
    State(RCState),
    Output(Uuid, Bytes),
    Success(Uuid),
    ChannelFailure(Uuid),
    Eof(Uuid),
    Close(Uuid),
    Error(anyhow::Error),
    ExitStatus(Uuid, u32),
    ExitSignal {
        channel: Uuid,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    ExtendedData {
        channel: Uuid,
        data: Bytes,
        ext: u32,
    },
    ConnectionError(ConnectionError),
    HopConnected,
    // ForwardedTCPIP(Uuid, DirectTCPIPParams),
    Done,
    HostKeyReceived(PublicKey),
    HostKeyUnknown(PublicKey, String, u16, oneshot::Sender<bool>),
    ForwardedTcpIp(Uuid, ForwardedTcpIpParams),
    ForwardedStreamlocal(Uuid, ForwardedStreamlocalParams),
    ForwardedAgent(Uuid),
    X11(Uuid, String, u32),
}

impl RCEvent {
    /// The already-open channel this event refers to, if any.
    ///
    /// Deliberately a total match: event deferral during pending channel
    /// opens keys off this (#1459), so a new variant must explicitly decide
    /// whether it names a channel rather than silently defaulting to "no".
    pub(crate) const fn channel(&self) -> Option<Uuid> {
        match self {
            Self::Output(channel, _)
            | Self::Success(channel)
            | Self::ChannelFailure(channel)
            | Self::Eof(channel)
            | Self::Close(channel)
            | Self::ExitStatus(channel, _)
            | Self::ExitSignal { channel, .. }
            | Self::ExtendedData { channel, .. } => Some(*channel),
            // The Forwarded*/X11 variants carry a channel id but *establish*
            // the channel — they must not wait for their own open to resolve.
            Self::State(_)
            | Self::Error(_)
            | Self::ConnectionError(_)
            | Self::HopConnected
            | Self::Done
            | Self::HostKeyReceived(_)
            | Self::HostKeyUnknown(..)
            | Self::ForwardedTcpIp(..)
            | Self::ForwardedStreamlocal(..)
            | Self::ForwardedAgent(_)
            | Self::X11(..) => None,
        }
    }
}

pub type RCCommandReply = oneshot::Sender<Result<(), SshClientError>>;

/// Who asked, when no session user can be named.
///
/// Two kinds of name arrive here and they are indistinguishable as strings,
/// which is the whole of the defect this exists to close. Carried as data
/// instead of guessed from the text.
#[derive(Clone, Debug)]
pub enum IdentityHint {
    /// The gateway's own attribution — `admin-token`, `cluster-token`. Kept
    /// verbatim: it is the string a reader trusts to mean that no person did
    /// this.
    Gateway(String),
    /// A person, named by whatever authenticated them. Sanitised like any
    /// other name a person chose.
    Person(String),
}

#[derive(Clone, Debug)]
pub enum RCCommand {
    Connect(Vec<ResolvedSshChainHost>),
    /// Connect only as far as the target's host key, then stop. Carries who
    /// asked, because any jump host on the way is still authenticated and the
    /// certificate that authenticates it has to name a person.
    ///
    /// A separate command rather than the caller dropping its handle once it has
    /// what it wants: the connection otherwise runs on into authentication, and
    /// for a certificate target that means a real certificate issued and a real
    /// session opened for nobody. Cancelling on a dropped handle is a race the
    /// caller loses about half the time; refusing to start is not.
    CheckHostKey {
        chain: Vec<ResolvedSshChainHost>,
        /// The hop the caller asked about, by identity rather than by position.
        target_id: Uuid,
        requested_by: IdentityHint,
    },
    Channel(Uuid, ChannelOperation),
    ForwardTCPIP(String, u32),
    CancelTCPIPForward(String, u32),
    StreamlocalForward(String),
    CancelStreamlocalForward(String),
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Debug)]
enum InnerEvent {
    RCCommand(RCCommand, Option<RCCommandReply>),
    ClientHandlerEvent(ClientHandlerEvent),
}

pub struct RemoteClient {
    id: SessionId,
    tx: Sender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_pipes: Arc<Mutex<HashMap<Uuid, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(Uuid, ChannelOperation)>,
    pending_forwards: Vec<(String, u32)>,
    pending_streamlocal_forwards: Vec<String>,
    state: RCState,
    abort_rx: UnboundedReceiver<()>,
    inner_event_rx: UnboundedReceiver<InnerEvent>,
    inner_event_tx: UnboundedSender<InnerEvent>,
    child_tasks: Vec<JoinHandle<Result<(), SshClientError>>>,
    services: Services,
    /// Who to name in a certificate when there is no session to look up.
    ///
    /// The admin host-key check has no session — it is a button press, not a
    /// login — but reaching a target behind a jump host still authenticates
    /// that hop, and a certificate is minted for it. Without this the key ID
    /// falls back to naming the random UUID that stood in for a session, so the
    /// jump host's sshd log and Vault's issuance log both record a certificate
    /// that resolves to nobody. That is the attribution failure the whole
    /// feature exists to prevent, in the one caller that has no user to look up.
    identity_hint: Option<IdentityHint>,
}

pub struct RemoteClientHandles {
    pub event_rx: Receiver<RCEvent>,
    pub command_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    pub abort_tx: UnboundedSender<()>,
}

impl RemoteClient {
    pub fn create(id: SessionId, services: Services) -> io::Result<RemoteClientHandles> {
        let (event_tx, event_rx) = channel(1024);
        let (command_tx, mut command_rx) = unbounded_channel();
        let (abort_tx, abort_rx) = unbounded_channel();

        let (inner_event_tx, inner_event_rx) = unbounded_channel();

        let this = Self {
            id,
            tx: event_tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            pending_ops: vec![],
            pending_forwards: vec![],
            pending_streamlocal_forwards: vec![],
            state: RCState::NotInitialized,
            inner_event_rx,
            inner_event_tx: inner_event_tx.clone(),
            child_tasks: vec![],
            services,
            identity_hint: None,
            abort_rx,
        };

        tokio::spawn(
            {
                async move {
                    while let Some((e, response)) = command_rx.recv().await {
                        inner_event_tx.send(InnerEvent::RCCommand(e, response))?;
                    }
                    Ok::<(), anyhow::Error>(())
                }
            }
            .instrument(Span::current()),
        );

        this.start()?;

        Ok(RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx,
        })
    }

    async fn set_disconnected(&mut self) {
        self.session = None;
        for (id, op) in self.pending_ops.drain(..) {
            if matches!(op, ChannelOperation::OpenShell) {
                let _ = self.tx.try_send(RCEvent::Close(id));
            }
            if let ChannelOperation::OpenDirectTCPIP { .. } = op {
                let _ = self.tx.try_send(RCEvent::Close(id));
            }
        }
        let _ = self.set_state(RCState::Disconnected).await;
        let _ = self.tx.send(RCEvent::Done).await;
    }

    async fn set_state(&mut self, state: RCState) -> Result<(), SshClientError> {
        self.state = state.clone();
        self.tx
            .send(RCEvent::State(state))
            .await
            .map_err(|_| SshClientError::MpscError)?;
        Ok(())
    }

    // fn map_channel(&self, ch: &ChannelId) -> Result<Uuid> {
    //     self.channel_map
    //         .get_by_left(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    // fn map_channel_reverse(&self, ch: &Uuid) -> Result<ChannelId> {
    //     self.channel_map
    //         .get_by_right(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    async fn apply_channel_op(
        &mut self,
        channel_id: Uuid,
        op: ChannelOperation,
    ) -> Result<(), SshClientError> {
        if self.state != RCState::Connected {
            self.pending_ops.push((channel_id, op));
            return Ok(());
        }

        match op {
            ChannelOperation::OpenShell => {
                self.open_shell(channel_id).await?;
            }
            ChannelOperation::OpenDirectTCPIP(params) => {
                self.open_direct_tcpip(channel_id, params).await?;
            }
            ChannelOperation::OpenDirectStreamlocal(path) => {
                self.open_direct_streamlocal(channel_id, path).await?;
            }
            op => {
                let mut channel_pipes = self.channel_pipes.lock().await;
                if let Some(tx) = channel_pipes.get(&channel_id) {
                    if tx.send(op).is_err() {
                        channel_pipes.remove(&channel_id);
                    }
                } else {
                    debug!(channel=%channel_id, "operation for unknown channel");
                }
            }
        }
        Ok(())
    }

    pub fn start(mut self) -> io::Result<JoinHandle<anyhow::Result<()>>> {
        let name = format!("SSH {} client commands", self.id);
        tokio::task::Builder::new().name(&name).spawn(
            async move {
                async {
                    loop {
                        tokio::select! {
                            Some(event) = self.inner_event_rx.recv() => {
                                debug!(event=?event, "event");
                                if self.handle_event(event).await? {
                                    break
                                }
                            }
                            Some(()) = self.abort_rx.recv() => {
                                debug!("Abort requested");
                                self.disconnect().await;
                                break
                            }
                        };
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await
                .map_err(|error| {
                    error!(?error, "error in command loop");
                    let err = anyhow::anyhow!("Error in command loop: {error}");
                    let _ = self.tx.try_send(RCEvent::Error(error));
                    err
                })?;
                info!("Client session closed");
                Ok::<(), anyhow::Error>(())
            }
            .instrument(Span::current()),
        )
    }

    async fn handle_event(&mut self, event: InnerEvent) -> Result<bool> {
        match event {
            InnerEvent::RCCommand(cmd, reply) => {
                let result = self.handle_command(cmd).await;
                let brk = matches!(result, Ok(true));
                if let Some(reply) = reply {
                    let _ = reply.send(result.map(|_| ()));
                }
                return Ok(brk);
            }
            InnerEvent::ClientHandlerEvent(client_event) => {
                debug!("Client handler event: {:?}", client_event);
                match client_event {
                    ClientHandlerEvent::Disconnect => {
                        self._on_disconnect().await;
                    }
                    ClientHandlerEvent::ForwardedTcpIp(channel, params) => {
                        info!("New forwarded connection: {params:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self.tx.send(RCEvent::ForwardedTcpIp(id, params)).await;
                    }
                    ClientHandlerEvent::ForwardedStreamlocal(channel, params) => {
                        info!("New forwarded socket connection: {params:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self
                            .tx
                            .send(RCEvent::ForwardedStreamlocal(id, params))
                            .await;
                    }
                    ClientHandlerEvent::ForwardedAgent(channel) => {
                        info!("New forwarded agent connection");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self.tx.send(RCEvent::ForwardedAgent(id)).await;
                    }
                    ClientHandlerEvent::X11(channel, originator_address, originator_port) => {
                        info!("New X11 connection from {originator_address}:{originator_port:?}");
                        let id = self.setup_server_initiated_channel(channel).await?;
                        let _ = self
                            .tx
                            .send(RCEvent::X11(id, originator_address, originator_port))
                            .await;
                    }
                    event => {
                        error!(?event, "Unhandled client handler event");
                    }
                }
            }
        }
        Ok(false)
    }

    async fn setup_server_initiated_channel(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();

        let (tx, rx) = unbounded_channel();
        self.channel_pipes.lock().await.insert(id, tx);

        let session_channel = SessionChannel::new(channel, id, rx, self.tx.clone(), self.id);

        self.child_tasks.push(
            tokio::task::Builder::new()
                .name(&format!("SSH {} {:?} ops", self.id, id))
                .spawn(session_channel.run())?,
        );

        Ok(id)
    }

    async fn handle_command(&mut self, cmd: RCCommand) -> Result<bool, SshClientError> {
        match cmd {
            RCCommand::Connect(options) => match self.connect(options).await {
                Ok(()) => {
                    self.set_state(RCState::Connected)
                        .await
                        .map_err(SshClientError::other)?;
                    let ops = std::mem::take(&mut self.pending_ops);
                    for (id, op) in ops {
                        self.apply_channel_op(id, op).await?;
                    }

                    let forwards = std::mem::take(&mut self.pending_forwards);
                    for (address, port) in forwards {
                        self.tcpip_forward(address, port).await?;
                    }

                    let forwards = std::mem::take(&mut self.pending_streamlocal_forwards);
                    for socket_path in forwards {
                        self.streamlocal_forward(socket_path).await?;
                    }
                }
                Err(e) => {
                    debug!("Connect error: {}", e);
                    let _ = self.tx.send(RCEvent::ConnectionError(e)).await;
                    self.set_disconnected().await;

                    return Ok(true);
                }
            },
            RCCommand::CheckHostKey {
                chain,
                target_id,
                requested_by,
            } => {
                self.identity_hint = Some(requested_by);
                if let Err(e) = self.check_host_key(chain, target_id).await {
                    debug!("Host key check error: {}", e);
                    let _ = self.tx.send(RCEvent::ConnectionError(e)).await;
                }
                self.set_disconnected().await;
                return Ok(true);
            }
            RCCommand::Channel(ch, op) => {
                self.apply_channel_op(ch, op).await?;
            }
            RCCommand::ForwardTCPIP(address, port) => {
                self.tcpip_forward(address, port).await?;
            }
            RCCommand::CancelTCPIPForward(address, port) => {
                self.cancel_tcpip_forward(address, port).await?;
            }
            RCCommand::StreamlocalForward(socket_path) => {
                self.streamlocal_forward(socket_path).await?;
            }
            RCCommand::CancelStreamlocalForward(socket_path) => {
                self.cancel_streamlocal_forward(socket_path).await?;
            }
            RCCommand::Disconnect => {
                self.disconnect().await;
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn build_ssh_config(&self, ssh_options: &TargetSSHOptions) -> Arc<russh::client::Config> {
        let algos = if ssh_options.allow_insecure_algos.unwrap_or(false) {
            Preferred {
                kex: Cow::Borrowed(&[
                    kex::MLKEM768X25519_SHA256,
                    kex::CURVE25519,
                    kex::CURVE25519_PRE_RFC_8731,
                    kex::ECDH_SHA2_NISTP256,
                    kex::ECDH_SHA2_NISTP384,
                    kex::ECDH_SHA2_NISTP521,
                    kex::DH_G16_SHA512,
                    kex::DH_G14_SHA256,
                    kex::DH_GEX_SHA256,
                    kex::DH_G1_SHA1,
                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                    kex::EXTENSION_SUPPORT_AS_SERVER,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]),
                key: Cow::Borrowed(&[
                    russh::keys::Algorithm::Ed25519,
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP256,
                    },
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP384,
                    },
                    russh::keys::Algorithm::Ecdsa {
                        curve: russh::keys::EcdsaCurve::NistP521,
                    },
                    russh::keys::Algorithm::Rsa {
                        hash: Some(russh::keys::HashAlg::Sha256),
                    },
                    russh::keys::Algorithm::Rsa {
                        hash: Some(russh::keys::HashAlg::Sha512),
                    },
                    russh::keys::Algorithm::Rsa { hash: None },
                ]),
                cipher: Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    russh::cipher::AES_256_GCM,
                    russh::cipher::AES_256_CTR,
                    russh::cipher::AES_256_CBC,
                    russh::cipher::AES_192_CTR,
                    russh::cipher::AES_192_CBC,
                    russh::cipher::AES_128_CTR,
                    russh::cipher::AES_128_CBC,
                    russh::cipher::TRIPLE_DES_CBC,
                ]),
                // The secure defaults exclude SHA-1 MACs; append them here for
                // legacy devices (e.g. older network switches that only offer
                // hmac-sha1). https://github.com/warp-tech/warpgate/issues/2066
                mac: Cow::Borrowed(&[
                    mac::HMAC_SHA512_ETM,
                    mac::HMAC_SHA256_ETM,
                    mac::HMAC_SHA512,
                    mac::HMAC_SHA256,
                    mac::HMAC_SHA1_ETM,
                    mac::HMAC_SHA1,
                ]),
                ..<_>::default()
            }
        } else {
            Preferred::default()
        };

        let ssh_config = { self.services.config.lock().await.store.ssh.clone() };
        let mut config = russh::client::Config {
            preferred: algos,
            nodelay: true,
            // Extra time for the "closing due to inactivity" message to be sent
            inactivity_timeout: Some(ssh_config.inactivity_timeout + Duration::from_secs(10)),
            keepalive_interval: ssh_config.keepalive_interval,
            ..Default::default()
        };
        if ssh_options.allow_insecure_algos.unwrap_or(false)
            && let Ok(gex) = russh::client::GexParams::new(2048, 2048, 8192)
        {
            config.gex = gex;
        }
        Arc::new(config)
    }

    /// Connect through a pre-resolved chain of SSH hops, each tunnelled through the previous.
    /// `chain` must be non-empty; the first entry is connected directly, subsequent ones via
    /// `channel_open_direct_tcpip` through the previous session.
    /// `checking_host_key` names the last hop as the one being asked about: the
    /// intermediate ones must still authenticate, or there is no tunnel to carry
    /// the last one, and their keys are not the answer to the question.
    /// Returns `None` when it stopped at that hop's host key as asked.
    async fn connect_chain(
        &mut self,
        chain: Vec<ResolvedSshChainHost>,
        // `check_target`: the hop being asked about, when this is a host-key
        // check, by identity. Deciding it by position asserts that the chain
        // always ends at the target that was named — true of every chain built
        // today, and an assumption rather than something checked.
        check_target: Option<Uuid>,
    ) -> Result<
        Option<(Handle<ClientHandler>, UnboundedReceiver<ClientHandlerEvent>)>,
        ConnectionError,
    > {
        if !chain_can_answer(
            check_target,
            &chain.iter().map(|hop| hop.id).collect::<Vec<_>>(),
        ) {
            error!(
                ?check_target,
                "The chain does not contain the host that was asked about"
            );
            return Err(ConnectionError::Resolve);
        }

        let mut iter = chain.into_iter();
        let first_hop = iter.next().ok_or(ConnectionError::Resolve)?;
        let first_id = first_hop.id;
        let first = first_hop.ssh_options;

        let config = self.build_ssh_config(&first).await;
        let address_str = format!("{}:{}", first.host, first.port);
        let address = address_str
            .to_socket_addrs()
            .map_err(ConnectionError::Io)
            .and_then(|mut x| x.next().ok_or(ConnectionError::Resolve))
            .inspect_err(|e| error!(?e, address=%address_str, "Cannot resolve address"))?;
        info!(?address, username = %first.username, "Connecting");
        let (event_tx, event_rx) = unbounded_channel();
        let handler = ClientHandler {
            ssh_options: first.clone(),
            event_tx,
            services: self.services.clone(),
            session_id: self.id,
        };
        let fut = russh::client::connect(config, address, handler);
        let Some((mut session, mut active_rx)) = self
            .wait_for_connection(&first, fut, event_rx, role(check_target, first_id))
            .boxed()
            .await?
        else {
            return Ok(None);
        };

        for hop in iter {
            let hop_id = hop.id;
            let ssh_options = hop.ssh_options;
            let _ = self.tx.send(RCEvent::HopConnected).await;
            info!(
                host = %ssh_options.host,
                port = ssh_options.port,
                "Opening direct-tcpip channel through jump host"
            );
            // Bounded, because nothing else bounds it.
            //
            // Each hop's own handshake deadline is armed inside
            // `wait_for_connection`, which runs *after* this — so the step that
            // asks a jump host to open the tunnel had no limit at all. A jump
            // host that accepts the request and never replies stalls here for as
            // long as the previous hop's inactivity timeout allows, which is
            // five minutes by default and hours wherever an operator has raised
            // it. Reachable from the admin host-key check too, which adds no
            // timeout of its own.
            let channel = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                session.channel_open_direct_tcpip(
                    ssh_options.host.clone(),
                    u32::from(ssh_options.port),
                    "localhost".to_string(),
                    0,
                ),
            )
            .await
            .map_err(|_| {
                error!(host = %ssh_options.host, "Jump host did not open the tunnel in time");
                ConnectionError::TunnelOpenTimeout {
                    host: ssh_options.host.clone(),
                }
            })?
            .map_err(ConnectionError::Ssh)?;
            let stream = channel.into_stream();
            let config = self.build_ssh_config(&ssh_options).await;
            let (event_tx, event_rx) = unbounded_channel();
            let handler = ClientHandler {
                ssh_options: ssh_options.clone(),
                event_tx,
                services: self.services.clone(),
                session_id: self.id,
            };
            let fut = russh::client::connect_stream(config, stream, handler);
            let Some((new_session, new_rx)) = self
                .wait_for_connection(&ssh_options, fut, event_rx, role(check_target, hop_id))
                .boxed()
                .await?
            else {
                return Ok(None);
            };
            session = new_session;
            active_rx = new_rx;
        }

        Ok(Some((session, active_rx)))
    }

    /// Connects as far as the target's host key and stops, for the admin-side
    /// check. Nothing is authenticated, so nothing is issued.
    async fn check_host_key(
        &mut self,
        chain: Vec<ResolvedSshChainHost>,
        target_id: Uuid,
    ) -> Result<(), ConnectionError> {
        if let Some((session, _)) = self.connect_chain(chain, Some(target_id)).boxed().await? {
            // Only reachable if the connection came up without the handler ever
            // reporting a host key, which should not happen — but an open
            // session left behind would be exactly the leak this command exists
            // to close.
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
        }
        Ok(())
    }

    async fn connect(&mut self, chain: Vec<ResolvedSshChainHost>) -> Result<(), ConnectionError> {
        let Some((session, mut event_rx)) = self.connect_chain(chain, None).boxed().await? else {
            return Err(ConnectionError::Internal);
        };

        self.session = Some(Arc::new(Mutex::new(session)));

        info!("Connected");

        tokio::spawn(
            {
                let inner_event_tx = self.inner_event_tx.clone();
                async move {
                    while let Some(e) = event_rx.recv().await {
                        info!("{:?}", e);
                        inner_event_tx.send(InnerEvent::ClientHandlerEvent(e))?;
                    }
                    Ok::<(), anyhow::Error>(())
                }
            }
            .instrument(Span::current()),
        );

        Ok(())
    }

    async fn wait_for_connection<Fut>(
        &mut self,
        ssh_options: &TargetSSHOptions,
        fut_connect: Fut,
        mut event_rx: UnboundedReceiver<ClientHandlerEvent>,
        hop: HopRole,
    ) -> Result<
        Option<(Handle<ClientHandler>, UnboundedReceiver<ClientHandlerEvent>)>,
        ConnectionError,
    >
    where
        Fut: Future<Output = Result<Handle<ClientHandler>, ClientHandlerError>>,
    {
        pin_mut!(fut_connect);

        // Nothing else bounds this. russh limits how long an identification
        // string may be, but not how long a peer may take to send the rest of
        // the handshake, and the inactivity timeout only starts once the
        // session loop is running. A target that completes the TCP connection
        // and then goes quiet therefore held the session — and its task, and
        // its slot — for as long as it liked. Reachable by anyone who can start
        // a session to a target that has been compromised, or merely wedged.
        //
        // Its own bound, rather than the inactivity timeout. Measured: with
        // that timeout at 45s a stalled handshake was held for 55s, so it was
        // being bounded by the *inbound* session's patience — which governs how
        // long an idle interactive session may live and is legitimately raised
        // to hours. Borrowing it here would extend this hold to match.
        let handshake_deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);
        pin_mut!(handshake_deadline);

        // The deadline pauses while a host key is outstanding and resumes the
        // moment it is answered, which requires seeing the answer. The reply
        // channel goes to the session, so it is intercepted: the session is
        // handed a substitute sender, and the real one is held here until the
        // answer arrives on `host_key_answers`.
        //
        // The first version disarmed the deadline unconditionally and never
        // re-armed it, on the reasoning that "from here the wait is a person's".
        // That reasoning is not available at this point in the code: the
        // verification mode is read in `handle_unknown_host_key`, which answers
        // instantly under `AutoAccept` and `AutoReject`. A target could present
        // an unknown host key under auto-accept, cancel the deadline for good,
        // and then go silent — the exact hold this bound exists to catch,
        // reintroduced by the fix for a different problem.
        let (host_key_answer_tx, mut host_key_answers) = tokio::sync::mpsc::channel::<bool>(1);
        let mut outstanding_host_key: Option<oneshot::Sender<bool>> = None;

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    match event {
                        ClientHandlerEvent::HostKeyReceived(key) => {
                            // Every hop presents a key, and the caller asked
                            // about one of them. Reporting an intermediate hop's
                            // key answers a question nobody asked — and the
                            // admin endpoint, which takes the first key it sees,
                            // then shows the jump host's key as the target's.
                            if hop.reports_host_key() {
                                self.tx.send(RCEvent::HostKeyReceived(key)).await.map_err(|_| ConnectionError::Internal)?;
                            }
                            if hop.stops_after_host_key() {
                                return Ok(None);
                            }
                        }
                        ClientHandlerEvent::HostKeyUnknown(key, reply) => {
                            if hop.reports_host_key() {
                                // Paused, not disarmed, and only for as long as
                                // the answer is outstanding.
                                //
                                // `Prompt` is the default verification mode, so
                                // on a stock install the first connection to any
                                // target — and any target that has rotated its
                                // key — reaches this line. Leaving the deadline
                                // armed gave whoever is comparing a base64
                                // fingerprint under thirty seconds to do it, and
                                // then failed the connection with "the target
                                // never completed the handshake", naming the
                                // target for a delay that was the user's.
                                //
                                // It also could not converge: `known_hosts.trust()`
                                // runs in `check_server_key` *after* the reply,
                                // so a fired deadline drops the connection future,
                                // the reply channel dies, and the key is never
                                // stored — the next attempt asks again.
                                //
                                // Under the automatic modes the answer comes back
                                // in microseconds and the pause is not observable,
                                // which is the point: this arm no longer needs to
                                // know which mode is configured to stay bounded.
                                handshake_deadline.as_mut().reset(
                                    tokio::time::Instant::now()
                                        + while_a_host_key_answer_is_outstanding(),
                                );
                                let (intercept_tx, intercept_rx) = oneshot::channel();
                                outstanding_host_key = Some(reply);
                                let answer_tx = host_key_answer_tx.clone();
                                tokio::spawn(async move {
                                    if let Ok(answer) = intercept_rx.await {
                                        let _ = answer_tx.send(answer).await;
                                    }
                                });
                                self.tx.send(RCEvent::HostKeyUnknown(key, ssh_options.host.clone(), ssh_options.port, intercept_tx)).await.map_err(|_| ConnectionError::Internal)?;
                            } else {
                                // Nobody is listening for an answer on this hop,
                                // and the handler is waiting for one. Refusing is
                                // the honest reply: a jump host whose key is not
                                // yet trusted has its own check to pass first,
                                // and silently accepting it here would trust it
                                // on the strength of a question about something
                                // else.
                                let _ = reply.send(false);
                                return Err(ConnectionError::UntrustedJumpHost);
                            }
                            if hop.stops_after_host_key() {
                                return Ok(None);
                            }
                        }
                        _ => {}
                    }
                }
                // The answer to a host key question, on its way back to
                // `check_server_key`. The remaining handshake is the target's
                // again from here, so the bound comes back with it.
                Some(answer) = host_key_answers.recv() => {
                    handshake_deadline.as_mut().reset(
                        tokio::time::Instant::now() + once_the_host_key_is_answered(),
                    );
                    if let Some(reply) = outstanding_host_key.take() {
                        // A closed receiver means the connection future is
                        // already gone; there is nothing left to answer.
                        let _ = reply.send(answer);
                    }
                }
                () = &mut handshake_deadline => {
                    error!(host = %ssh_options.host, "Target did not finish the SSH handshake in time");
                    // No `set_disconnected()` here: `handle_command` calls it
                    // immediately after sending the error, so doing it first
                    // only reorders `Done` ahead of the reason. A review argued
                    // that ordering discards the message, since both session
                    // loops treat `Done` as terminal — I could not reproduce
                    // that, the reason arrives either way, so this is tidiness
                    // rather than a fix. The test below pins the message
                    // regardless of which explanation is right.
                    return Err(ConnectionError::HandshakeTimeout);
                }
                // `None` means every sender is gone, so the owner has dropped
                // without disconnecting. `ServerSession::drop` signals first, so
                // a live session never arrives here still wanting the
                // connection — anything else that does is abandoning it.
                _ = self.abort_rx.recv() => {
                    info!("Abort requested");
                    self.set_disconnected().await;
                    return Err(ConnectionError::Aborted)
                }
                session = &mut fut_connect => {
                    let mut session = match session {
                        Ok(session) => session,
                        Err(error) => {
                            let connection_error = match error {
                                ClientHandlerError::ConnectionError(e) => e,
                                ClientHandlerError::Ssh(e) => ConnectionError::Ssh(e),
                                ClientHandlerError::Internal => ConnectionError::Internal,
                            };
                            error!(error=?connection_error, "Connection error");
                            return Err(connection_error);
                        }
                    };

                    // Under the same deadline.
                    //
                    // `tokio::select!` stops polling its other branches once it
                    // commits to one, so awaiting authentication inside this arm
                    // put it outside the deadline entirely — and authentication
                    // is where the Vault round trip happens and where a
                    // certificate is minted. A target that finished the
                    // transport handshake and then never answered
                    // `SSH_MSG_USERAUTH_REQUEST` held the task, the session slot,
                    // the ephemeral key and a live certificate until russh's
                    // inactivity timeout — five minutes by default and hours
                    // wherever an operator has raised it for interactive use.
                    // That is the exact hold this deadline was added to bound,
                    // one stage further along than the stage it was bounding.
                    //
                    // Abort is not polled across this window: `abort_rx` needs
                    // `&mut self` and `authenticate_session` takes `&self`. It
                    // was not polled here before either, and the window it
                    // covers is now bounded, so the cost is up to
                    // `HANDSHAKE_TIMEOUT` of delay in tearing down a connection
                    // whose owner has already gone.
                    // Its own budget, not the transport handshake's.
                    let budget = authentication_budget(
                        &ssh_options.auth,
                        self.services.vault.get().map(|v| v.timeout()),
                    );
                    let authentication_deadline = tokio::time::sleep(budget);
                    pin_mut!(authentication_deadline);

                    tokio::select! {
                        () = &mut authentication_deadline => {
                            error!(
                                host = %ssh_options.host,
                                budget = ?budget,
                                "Authentication did not finish in time"
                            );
                            return Err(ConnectionError::AuthenticationTimeout);
                        }
                        result = self.authenticate_session(
                            &mut session,
                            &ssh_options.host,
                            &ssh_options.username,
                            &ssh_options.auth,
                            ssh_options.allow_insecure_algos.unwrap_or(false)
                        ) => result?,
                    }

                    return Ok(Some((session, event_rx)));
                }
            }
        }
    }

    /// Identifies the Warpgate session in the certificate's key ID. The target's
    /// own sshd logs it verbatim, which is what lets a proxied session be traced
    /// to a person from the target side alone.
    async fn certificate_key_id(&self) -> String {
        let session = self
            .services
            .state
            .lock()
            .await
            .sessions
            .get(&self.id)
            .cloned();

        let username = match session {
            Some(session) => session
                .lock()
                .await
                .user_info
                .as_ref()
                .map(|user| user.username.clone()),
            None => None,
        };

        let username = match username {
            Some(name) => Some(user_key_id_field(&name)),
            None => self.identity_hint.as_ref().map(|hint| match hint {
                IdentityHint::Gateway(name) => key_id_field(name),
                IdentityHint::Person(name) => user_key_id_field(name),
            }),
        };
        // Three fields either way. Dropping the middle one shifted the session
        // UUID into the position a reader takes for the username — so a log
        // line naming nobody was indistinguishable from one naming a user
        // called `0e5f…`, and the field this whole feature exists to fill was
        // silently wrong rather than visibly absent. Reachable whenever the
        // session's user info has not been recorded, e.g. a transient database
        // failure in `set_user_info`.
        username.map_or_else(
            || format!("warpgate:{}:{}", UNATTRIBUTED, self.id),
            |username| format!("warpgate:{username}:{}", self.id),
        )
    }

    async fn authenticate_session(
        &self,
        session: &mut Handle<ClientHandler>,
        host: &str,
        username: &str,
        auth: &SSHTargetAuth,
        allow_insecure_algos: bool,
    ) -> Result<(), ConnectionError> {
        let mut auth_result = false;
        let mut auth_error_msg: Option<String> = None;
        match auth {
            SSHTargetAuth::Password(auth) => {
                let password = auth.password.reveal().map_err(WarpgateError::from)?;
                let response = session
                    .authenticate_password(username.to_string(), password.expose_secret())
                    .await?;
                auth_result = self
                    ._handle_auth_result(session, username.to_string(), response)
                    .await
                    .unwrap_or(false);
                if auth_result {
                    debug!(username = username, "Authenticated with password");
                } else {
                    auth_error_msg =
                        Some("Password authentication was rejected by the SSH target".to_string());
                }
            }
            SSHTargetAuth::PublicKey(auth) => {
                let best_hash = session.best_supported_rsa_hash().await?.flatten();
                let keys = load_client_keys(&self.services.db, auth.key_id).await?;
                if keys.is_empty() {
                    auth_error_msg = Some("No SSH client keys are configured".into());
                }
                for key in keys {
                    let key = Arc::new(key);
                    if key.key_data().is_rsa() && best_hash.is_none() && !allow_insecure_algos {
                        info!(
                            "Skipping ssh-rsa (SHA1) key authentication since insecure SSH algos are not allowed for this target"
                        );
                        continue;
                    }
                    let key_str = key.public_key().to_openssh().map_err(russh::Error::from)?;
                    let mut response = session
                        .authenticate_publickey(
                            username.to_string(),
                            PrivateKeyWithHashAlg::new(key.clone(), best_hash),
                        )
                        .await?;

                    auth_result = self
                        ._handle_auth_result(session, username.to_string(), response)
                        .await
                        .unwrap_or(false);

                    if !auth_result
                        && key.key_data().is_rsa()
                        && best_hash.is_some()
                        && allow_insecure_algos
                    {
                        response = session
                            .authenticate_publickey(
                                username.to_string(),
                                PrivateKeyWithHashAlg::new(key.clone(), None),
                            )
                            .await?;

                        auth_result = self
                            ._handle_auth_result(session, username.to_string(), response)
                            .await
                            .unwrap_or(false);
                    }

                    if auth_result {
                        debug!(username=username, key=%key_str, "Authenticated with key");
                        break;
                    }
                    auth_error_msg =
                        Some("Public key authentication was rejected by the SSH target".into());
                }
            }
            SSHTargetAuth::Certificate(auth) => {
                if let Some(vault) = self.services.vault.get() {
                    // The key exists only for this authentication attempt — nothing
                    // the target will ever trust again outlives this scope.
                    let key = Arc::new(
                        PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                            .map_err(russh::keys::Error::from)?,
                    );
                    let public_key = key
                        .public_key()
                        .to_openssh()
                        .map_err(russh::keys::Error::from)?;
                    let key_id = self.certificate_key_id().await;
                    let role = auth.role.as_deref().unwrap_or_else(|| vault.default_role());

                    let signed_key = vault
                        .sign_ssh_key(role, &public_key, username, &key_id)
                        .await?;
                    let certificate =
                        Certificate::from_openssh(&signed_key).map_err(russh::keys::Error::from)?;

                    // Extensions do not change what runs, but an unexpected one
                    // still says the role is not what the operator thinks.
                    if !certificate.extensions().is_empty() {
                        debug!(
                            extensions = ?certificate.extensions().keys().collect::<Vec<_>>(),
                            key_id,
                            "Certificate carries extensions"
                        );
                    }

                    // Captured before the certificate is handed to russh, which
                    // takes ownership of it.
                    // `None` for the sentinel values meaning "no bound", which
                    // a certificate this feature issues never carries.
                    let describe_time = |at: Option<std::time::SystemTime>| {
                        at.map_or_else(
                            || "unbounded".to_owned(),
                            |at| humantime::format_rfc3339_seconds(at).to_string(),
                        )
                    };
                    let validity = (
                        describe_time(certificate.valid_after_time()),
                        describe_time(certificate.valid_before_time()),
                    );

                    if let Some(reason) =
                        certificate_signer_mismatch(&certificate, vault.pinned_ca_public_key())
                            .or_else(|| {
                                certificate_mismatch(
                                    &certificate,
                                    key.public_key(),
                                    username,
                                    &key_id,
                                    &auth.allowed_critical_options,
                                    &auth.allowed_extensions,
                                    vault.certificate_ttl(),
                                )
                            })
                    {
                        // Surfaced to the user, not only to the log: a session
                        // that dies with "the target rejected you" sends whoever
                        // is debugging it to the wrong machine entirely.
                        warn!(key_id, reason, "Refusing the issued certificate");
                        return Err(ConnectionError::CertificateRefused(reason));
                    } else {
                        let response = session
                            .authenticate_openssh_cert(username.to_string(), key, certificate)
                            .await?;

                        // No `_handle_auth_result` here, deliberately.
                        //
                        // That helper falls through to keyboard-interactive and
                        // answers every prompt with an empty string. On a target
                        // whose `TrustedUserCAKeys` was never set, sshd refuses
                        // the certificate, offers keyboard-interactive, and a
                        // permissive PAM stack — `pam_permit`, `nullok`, the
                        // minimal stack in a lot of appliance images — accepts
                        // it. The session then proceeds, the log says
                        // "Authenticated with certificate", and the target's own
                        // sshd log carries no key ID at all: the attribution
                        // this feature exists to produce is silently absent, and
                        // the evidence says the opposite.
                        //
                        // A certificate target has one credential by design. If
                        // it is refused, that is the answer.
                        auth_result = matches!(response, AuthResult::Success);

                        if auth_result {
                            debug!(
                                username = username,
                                key_id, "Authenticated with certificate"
                            );
                        } else {
                            // The window is named because the most common cause
                            // of a target refusing an otherwise good certificate
                            // is its own clock: these live minutes, and a target
                            // that lags rejects them as not yet valid without
                            // saying so anywhere the operator can see.
                            auth_error_msg = Some(format!(
                                "Certificate authentication was rejected by the SSH target \
                                 (the certificate was valid from {} to {}; check the target's clock)",
                                validity.0, validity.1
                            ));
                        }
                    }
                } else {
                    // `CertificateRefused`, not `Authentication`: nothing was
                    // ever offered to the target, and the other variant renders
                    // as "SSH target rejected Warpgate's authentication
                    // request", which sends whoever is debugging this to the
                    // target's logs to look for a refusal that is not there.
                    // Reachable whenever a certificate target outlives the
                    // `vault:` section, or is reached from a node that has none.
                    return Err(ConnectionError::CertificateRefused(
                        "no Vault server is configured on this node".to_owned(),
                    ));
                }
            }
            SSHTargetAuth::IamRole(_) => {
                let instance_info = warpgate_aws::find_instance_by_ip(host).await?;

                let key = load_client_keys(&self.services.db, None)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        WarpgateError::InconsistentState("No SSH client keys are configured".into())
                    })?;

                let pub_key_str = key.public_key().to_openssh().map_err(russh::Error::from)?;

                // Push the public key via EC2 Instance Connect
                warpgate_aws::send_ssh_public_key(
                    &instance_info.instance_id,
                    &instance_info.availability_zone,
                    &instance_info.region,
                    username,
                    &pub_key_str,
                )
                .await?;

                // Now authenticate with this key (key is valid for 60 seconds)
                let key = Arc::new(key.clone());
                let best_hash = session.best_supported_rsa_hash().await?.flatten();
                let response = session
                    .authenticate_publickey(
                        username.to_string(),
                        PrivateKeyWithHashAlg::new(key.clone(), best_hash),
                    )
                    .await?;

                auth_result = self
                    ._handle_auth_result(session, username.to_string(), response)
                    .await
                    .unwrap_or(false);

                if auth_result {
                    debug!(
                        username = username,
                        "Authenticated via EC2 Instance Connect"
                    );
                }

                if !auth_result {
                    auth_error_msg = Some(
                        "EC2 Instance Connect authentication was rejected by the SSH target".into(),
                    );
                }
            }
        }

        if !auth_result {
            let reason = auth_error_msg
                .unwrap_or_else(|| "Authentication was rejected by the SSH target".to_string());
            error!(%reason, "Warpgate could not authenticate with SSH target");
            let reason = reason.clone();
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            return Err(ConnectionError::Authentication(reason));
        }

        Ok(())
    }
    /// If presented with an additional keyboard-interactive challenge it will respond with empty
    /// strings. This ensures optional 2fa is respected, where this extra challenge always happens.
    ///
    /// TODO: Optionally implement forwarding the challenges to the user
    ///
    /// # Arguments
    ///
    /// * `session`: the session for which the initial result is
    /// * `username`: username of the authenticating user
    /// * `result`: the initial result received via the configured auth method
    async fn _handle_auth_result(
        &self,
        session: &mut Handle<ClientHandler>,
        username: String,
        result: AuthResult,
    ) -> Result<bool> {
        debug!("Handling AuthResult");
        match result {
            AuthResult::Success => {
                debug!("AuthResult is already success, no further handling needed");
                return Ok(true);
            }
            AuthResult::Failure {
                remaining_methods: methods,
                ..
            } => {
                debug!("Initial auth failed, checking remaining methods");
                for method in methods.iter() {
                    if matches!(method, MethodKind::KeyboardInteractive) {
                        debug!("Found keyboard-interactive challenge");
                        let mut kb_result = session
                            .authenticate_keyboard_interactive_start(username.clone(), None)
                            .await?;

                        while let KeyboardInteractiveAuthResponse::InfoRequest {
                            name: _name,
                            instructions: _instructions,
                            prompts,
                        } = kb_result
                        {
                            for prompt in prompts.iter().clone() {
                                debug!(
                                    prompt = prompt.prompt,
                                    echo = prompt.echo,
                                    "Prompt received for keyboard-interactive"
                                );
                            }
                            debug!("Responding with empty responses");
                            kb_result = session
                                .authenticate_keyboard_interactive_respond(vec![
                                    String::new();
                                    prompts.len()
                                ])
                                .await?;
                        }

                        match kb_result {
                            KeyboardInteractiveAuthResponse::Success => {
                                debug!("keyboard-interactive challenge successful");
                                return Ok(true);
                            }
                            KeyboardInteractiveAuthResponse::Failure {
                                remaining_methods: _remaining_methods,
                                ..
                            } => {
                                debug!("keyboard-interactive challenge failed");
                                return Ok(false);
                            }
                            KeyboardInteractiveAuthResponse::InfoRequest { .. } => {}
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    async fn open_shell(&mut self, channel_id: Uuid) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session.channel_open_session().await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel = SessionChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn open_direct_tcpip(
        &mut self,
        channel_id: Uuid,
        params: DirectTCPIPParams,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session
                .channel_open_direct_tcpip(
                    params.host_to_connect,
                    params.port_to_connect,
                    params.originator_address,
                    params.originator_port,
                )
                .await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel =
                DirectTCPIPChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn open_direct_streamlocal(
        &mut self,
        channel_id: Uuid,
        path: String,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            let channel = session.channel_open_direct_streamlocal(path).await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel =
                DirectTCPIPChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run())
                    .map_err(|e| SshClientError::Other(Box::new(e)))?,
            );
        }
        Ok(())
    }

    async fn tcpip_forward(&mut self, address: String, port: u32) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.tcpip_forward(address, port).await?;
        } else {
            self.pending_forwards.push((address, port));
        }
        Ok(())
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: String,
        port: u32,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.cancel_tcpip_forward(address, port).await?;
        } else {
            self.pending_forwards
                .retain(|x| x.0 != address || x.1 != port);
        }
        Ok(())
    }

    async fn streamlocal_forward(&mut self, socket_path: String) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.streamlocal_forward(socket_path).await?;
        } else {
            self.pending_streamlocal_forwards.push(socket_path);
        }
        Ok(())
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        socket_path: String,
    ) -> Result<(), SshClientError> {
        if let Some(session) = &self.session {
            let session = session.lock().await;
            session.cancel_streamlocal_forward(socket_path).await?;
        } else {
            self.pending_streamlocal_forwards
                .retain(|x| x != &socket_path);
        }
        Ok(())
    }

    async fn disconnect(&mut self) {
        if let Some(session) = &mut self.session {
            let _ = session
                .lock()
                .await
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            self.set_disconnected().await;
        }
    }

    async fn _on_disconnect(&mut self) {
        self.set_disconnected().await;
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        for task in self.child_tasks.drain(..) {
            task.abort();
        }
        info!("Closed connection");
        debug!("Dropped");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use super::{HopRole, resolve_chain_ids, role};

    /// A host key check must go no further than the hop it was asked about.
    ///
    /// Moved here from the integration suite on §8's terms, and the terms were
    /// met rather than assumed: the guard was pinned by
    /// `test_the_host_key_check_reports_the_target_and_not_the_jump_host`,
    /// which asks *whose key is reported* — a different question — and the
    /// verifier measured that it passes with the guard disabled. An
    /// end-to-end run cannot separate "stopped after the key" from "carried on
    /// and the target refused us anyway", because a real sshd refuses on its
    /// own. Here there is no target to do the refusing.
    ///
    /// What the guard prevents is a *check* becoming a session: the admin
    /// endpoint asks for a host key, and answering it must not leave Warpgate
    /// authenticated to the target.
    #[test]
    fn a_host_key_check_stops_at_the_hop_it_asked_about() {
        assert!(HopRole::CheckedHost.stops_after_host_key());

        // Everything else carries on. A hop merely traversed on the way has
        // more chain behind it, and an ordinary connection is not a check at
        // all.
        assert!(!HopRole::TraversedWhileChecking.stops_after_host_key());
        assert!(!HopRole::Connecting.stops_after_host_key());
    }

    /// The role is decided by identity, and the two predicates follow from it.
    ///
    /// Pinned together because they are one decision read two ways: the hop the
    /// caller named reports its key and stops; a hop on the way reports
    /// nothing and continues; a plain connection reports every key and never
    /// stops.
    #[test]
    fn each_role_reports_and_stops_as_its_name_says() {
        let (asked_about, other) = (Uuid::new_v4(), Uuid::new_v4());

        let checked = role(Some(asked_about), asked_about);
        assert_eq!(checked, HopRole::CheckedHost);
        assert!(checked.reports_host_key() && checked.stops_after_host_key());

        let traversed = role(Some(asked_about), other);
        assert_eq!(traversed, HopRole::TraversedWhileChecking);
        assert!(!traversed.reports_host_key() && !traversed.stops_after_host_key());

        let connecting = role(None, other);
        assert_eq!(connecting, HopRole::Connecting);
        assert!(connecting.reports_host_key() && !connecting.stops_after_host_key());
    }

    #[test]
    fn resolve_chain_ids_returns_ordered_chain() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let jumps: HashMap<Uuid, Option<Uuid>> =
            HashMap::from([(a, Some(b)), (b, Some(c)), (c, None)]);
        let ids = resolve_chain_ids(a, |id| jumps.get(&id).copied()).unwrap();
        assert_eq!(ids, vec![a, b, c]);
    }

    #[test]
    fn resolve_chain_ids_detects_cycle() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let jumps: HashMap<Uuid, Option<Uuid>> = HashMap::from([(a, Some(b)), (b, Some(a))]);
        assert!(resolve_chain_ids(a, |id| jumps.get(&id).copied()).is_err());
    }

    #[test]
    fn resolve_chain_ids_rejects_unresolvable_jump_host() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        // `a` jumps through `b`, but `b` resolves to no SSH target.
        let jumps: HashMap<Uuid, Option<Uuid>> = HashMap::from([(a, Some(b))]);
        assert!(resolve_chain_ids(a, |id| jumps.get(&id).copied()).is_err());
    }

    mod certificate_lifetime {
        //! The validity window, at the level where every case can be reached.
        //!
        //! The integration test for a never-expiring certificate is skipped —
        //! that input holds the session open for a reason not yet isolated — and
        //! for two rounds the guard therefore had no coverage anywhere, while
        //! the mutation matrix reported it covered because its anchor had gone
        //! stale. Two independent instruments agreeing on an answer neither one
        //! had measured. These do not need a session at all.

        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        use russh::keys::ssh_key::certificate::{Builder, CertType};
        use russh::keys::{Algorithm, PrivateKey, PublicKey};
        use warpgate_common::helpers::rng::get_crypto_rng;

        use crate::client::{MAX_CERTIFICATE_LIFETIME, certificate_mismatch};

        const PRINCIPAL: &str = "root";
        const KEY_ID: &str = "warpgate:alice:0e6d1f4c";

        fn now() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is before the epoch")
                .as_secs()
        }

        /// A certificate over a freshly generated key, signed by a throwaway CA.
        fn issued(
            valid_after: u64,
            valid_before: u64,
        ) -> (russh::keys::ssh_key::Certificate, PublicKey) {
            let ca = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a CA key");
            let subject = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a subject key");
            let mut builder = Builder::new_with_random_nonce(
                &mut get_crypto_rng(),
                subject.public_key(),
                valid_after,
                valid_before,
            )
            .expect("building the certificate");
            builder.cert_type(CertType::User).expect("cert type");
            builder.key_id(KEY_ID).expect("key id");
            builder.valid_principal(PRINCIPAL).expect("principal");
            let certificate = builder.sign(&ca).expect("signing");
            (certificate, subject.public_key().clone())
        }

        fn verdict(valid_after: u64, valid_before: u64) -> Option<String> {
            let (certificate, key) = issued(valid_after, valid_before);
            certificate_mismatch(&certificate, &key, PRINCIPAL, KEY_ID, &[], &[], None)
        }

        /// The one response-side property with no check at all until now: every
        /// other asks whether the certificate matches the request, and none
        /// asked who signed it. The CA here is generated per call, so a pin
        /// naming any other key must refuse — and an unparseable pin must refuse
        /// too, rather than quietly checking nothing.
        #[test]
        fn a_certificate_from_an_unpinned_ca_is_refused() {
            let ca = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a CA key");
            let subject = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a subject key");
            let mut builder = Builder::new_with_random_nonce(
                &mut get_crypto_rng(),
                subject.public_key(),
                now() - 60,
                now() + 600,
            )
            .expect("building the certificate");
            builder.cert_type(CertType::User).expect("cert type");
            builder.key_id(KEY_ID).expect("key id");
            builder.valid_principal(PRINCIPAL).expect("principal");
            let certificate = builder.sign(&ca).expect("signing");

            let signer = ca
                .public_key()
                .to_openssh()
                .expect("serialising the signing CA");
            let elsewhere = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating another CA key")
                .public_key()
                .to_openssh()
                .expect("serialising the other CA key");

            assert!(
                crate::client::certificate_signer_mismatch(&certificate, None).is_none(),
                "no pin was configured, so nothing should have been refused"
            );
            // Both directions. A check that refuses everything passes the
            // negative case alone, and would break every session.
            assert!(
                crate::client::certificate_signer_mismatch(&certificate, Some(&signer)).is_none(),
                "the certificate's own signing CA was refused as unpinned"
            );
            assert!(
                crate::client::certificate_signer_mismatch(&certificate, Some(&elsewhere))
                    .is_some(),
                "a certificate signed by a CA other than the pinned one was accepted"
            );
            assert!(
                crate::client::certificate_signer_mismatch(&certificate, Some("not-a-key"))
                    .is_some(),
                "an unparseable pin silently checked nothing"
            );
        }

        fn verdict_against(valid_before: u64, requested: Option<Duration>) -> Option<String> {
            let (certificate, key) = issued(now() - 60, valid_before);
            certificate_mismatch(&certificate, &key, PRINCIPAL, KEY_ID, &[], &[], requested)
        }

        /// The operator's own number, which was sent and then never looked at.
        /// Twenty-three hours is under the ceiling, so nothing refused it.
        #[test]
        fn a_certificate_longer_than_the_requested_ttl_is_refused() {
            let reason = verdict_against(now() + 23 * 3600, Some(Duration::from_secs(90)))
                .expect("a certificate far longer than requested");
            assert!(
                reason.contains("longer than the 90s this target asked for"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn a_certificate_matching_the_requested_ttl_is_accepted() {
            assert_eq!(
                verdict_against(now() + 180, Some(Duration::from_secs(180))),
                None
            );
        }

        /// Clocks disagree; the issuer being generous is a different thing.
        #[test]
        fn a_certificate_within_the_skew_allowance_is_accepted() {
            assert_eq!(
                verdict_against(now() + 180 + 30, Some(Duration::from_secs(180))),
                None
            );
        }

        #[test]
        fn a_certificate_past_the_skew_allowance_is_refused() {
            assert!(
                verdict_against(now() + 180 + 120, Some(Duration::from_secs(180))).is_some(),
                "two minutes over a three-minute request should be refused"
            );
        }

        /// With no TTL configured the role's own decides, and there is nothing
        /// to compare against — only the ceiling applies.
        #[test]
        fn without_a_requested_ttl_only_the_ceiling_applies() {
            assert_eq!(verdict_against(now() + 23 * 3600, None), None);
        }

        #[test]
        fn a_short_lived_certificate_is_accepted() {
            assert_eq!(verdict(now() - 60, now() + 300), None);
        }

        /// `u64::MAX` is OpenSSH's "never expires" sentinel — what
        /// `ssh-keygen -V always:forever` and a Vault role with no TTL write.
        ///
        /// Writing this test is what established that the comment beside the
        /// check was wrong: it claimed the sentinel makes `valid_before_time()`
        /// return `None`. It does not — `ssh-key` reports it as a real instant
        /// capped at `i64::MAX`, so the certificate was refused by the
        /// maximum-lifetime arm, under the message "valid for 2562047787518949
        /// hours". Refused either way, but naming the wrong problem to whoever
        /// has to act on it.
        #[test]
        fn a_never_expiring_certificate_is_refused() {
            let reason = verdict(now() - 60, u64::MAX).expect("a never-expiring certificate");
            assert!(
                reason.contains("never expires"),
                "refused for the wrong reason: {reason}"
            );
        }

        /// Above `i64::MAX` but not the sentinel: no tool writes this, an
        /// issuer that wants the certificate not to expire can. This is the
        /// only input that actually reaches the `None` arm.
        #[test]
        fn an_unrepresentable_expiry_is_refused() {
            let reason = verdict(now() - 60, u64::MAX - 1).expect("an unrepresentable expiry");
            assert!(
                reason.contains("unrepresentable"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn an_already_expired_certificate_is_refused() {
            let reason = verdict(now() - 600, now() - 300).expect("an expired certificate");
            assert!(
                reason.contains("already expired"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn a_certificate_outliving_the_bound_is_refused() {
            let over = MAX_CERTIFICATE_LIFETIME + Duration::from_secs(3600);
            let reason =
                verdict(now() - 60, now() + over.as_secs()).expect("an overlong certificate");
            assert!(
                reason.contains("far longer"),
                "refused for the wrong reason: {reason}"
            );
        }

        /// The boundary itself, so that tightening the bound cannot silently
        /// start refusing what it is documented to allow.
        #[test]
        fn a_certificate_at_the_bound_is_accepted() {
            assert_eq!(
                verdict(now() - 60, now() + MAX_CERTIFICATE_LIFETIME.as_secs() - 60),
                None
            );
        }
    }

    mod critical_options {
        //! Pinning a value is what makes an option mandatory.
        //!
        //! Every case is here rather than end to end because the target's own
        //! sshd refuses options it does not recognise, so an integration test
        //! that watches for a failed connection cannot tell our refusal from
        //! the target's. At this level the target is not in the picture at all.

        use std::time::{SystemTime, UNIX_EPOCH};

        use russh::keys::ssh_key::certificate::{Builder, CertType};
        use russh::keys::{Algorithm, PrivateKey, PublicKey};
        use warpgate_common::SshCertificateCriticalOption;
        use warpgate_common::helpers::rng::get_crypto_rng;

        use crate::client::certificate_mismatch;

        const PRINCIPAL: &str = "root";
        const KEY_ID: &str = "warpgate:alice:0e6d1f4c";

        fn carrying(options: &[(&str, &str)]) -> (russh::keys::ssh_key::Certificate, PublicKey) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is before the epoch")
                .as_secs();
            let ca = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a CA key");
            let subject = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a subject key");
            let mut builder = Builder::new_with_random_nonce(
                &mut get_crypto_rng(),
                subject.public_key(),
                now - 60,
                now + 300,
            )
            .expect("building the certificate");
            builder.cert_type(CertType::User).expect("cert type");
            builder.key_id(KEY_ID).expect("key id");
            builder.valid_principal(PRINCIPAL).expect("principal");
            for (name, value) in options {
                builder
                    .critical_option(*name, *value)
                    .expect("critical option");
            }
            let certificate = builder.sign(&ca).expect("signing");
            (certificate, subject.public_key().clone())
        }

        fn carrying_extensions(
            extensions: &[(&str, &str)],
        ) -> (russh::keys::ssh_key::Certificate, PublicKey) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is before the epoch")
                .as_secs();
            let ca = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a CA key");
            let subject = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519)
                .expect("generating a subject key");
            let mut builder = Builder::new_with_random_nonce(
                &mut get_crypto_rng(),
                subject.public_key(),
                now - 60,
                now + 300,
            )
            .expect("building the certificate");
            builder.cert_type(CertType::User).expect("cert type");
            builder.key_id(KEY_ID).expect("key id");
            builder.valid_principal(PRINCIPAL).expect("principal");
            for (name, value) in extensions {
                builder.extension(*name, *value).expect("extension");
            }
            let certificate = builder.sign(&ca).expect("signing");
            (certificate, subject.public_key().clone())
        }

        fn pinned(name: &str, value: Option<&str>) -> SshCertificateCriticalOption {
            SshCertificateCriticalOption {
                name: name.to_owned(),
                value: value.map(str::to_owned),
            }
        }

        fn verdict(
            carried: &[(&str, &str)],
            configured: &[SshCertificateCriticalOption],
        ) -> Option<String> {
            let (certificate, key) = carrying(carried);
            certificate_mismatch(&certificate, &key, PRINCIPAL, KEY_ID, configured, &[], None)
        }

        /// A duplicate name must not disable the pin.
        ///
        /// `.find()` took whichever entry the operator typed first, so a config
        /// naming an option twice — once bare, once pinned — passed the
        /// mandatory-presence check on the pinned entry and then matched the
        /// bare one, accepting any value at all while the admin UI showed a
        /// pin. The order of the two rows decided whether the target was
        /// confined, and nothing on screen said so.
        #[test]
        fn a_bare_duplicate_does_not_cancel_a_pinned_value() {
            for configured in [
                vec![
                    pinned("force-command", None),
                    pinned("force-command", Some("/usr/bin/backup")),
                ],
                // Both orders, because the defect was entirely about order.
                vec![
                    pinned("force-command", Some("/usr/bin/backup")),
                    pinned("force-command", None),
                ],
            ] {
                let reason = verdict(&[("force-command", "/bin/sh")], &configured)
                    .expect("a certificate whose command is not the pinned one");
                assert!(
                    reason.contains("does not match the value"),
                    "refused for the wrong reason: {reason}"
                );
            }
        }

        /// Two pins that disagree cannot both be satisfied, so nothing may be.
        #[test]
        fn conflicting_pins_refuse_everything_rather_than_picking_one() {
            let configured = [
                pinned("force-command", Some("/usr/bin/backup")),
                pinned("force-command", Some("/usr/bin/restore")),
            ];
            for offered in ["/usr/bin/backup", "/usr/bin/restore", "/bin/sh"] {
                assert!(
                    verdict(&[("force-command", offered)], &configured).is_some(),
                    "{offered} satisfied a pair of pins that disagree"
                );
            }
        }

        /// The removal attack. Someone with role-write but no right to sign does
        /// not have to add anything — taking the pinned `force-command` out
        /// turns a target locked to one command into a shell.
        #[test]
        fn a_pinned_option_missing_from_the_certificate_is_refused() {
            let reason = verdict(&[], &[pinned("force-command", Some("/usr/bin/backup"))])
                .expect("a certificate without the pinned option");
            assert!(
                reason.contains("without the critical option") && reason.contains("force-command"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn a_pinned_option_with_the_wrong_value_is_refused() {
            let reason = verdict(
                &[("force-command", "/bin/sh")],
                &[pinned("force-command", Some("/usr/bin/backup"))],
            )
            .expect("a certificate with the wrong value");
            assert!(
                reason.contains("does not match the value"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn a_pinned_option_with_the_configured_value_is_accepted() {
            assert_eq!(
                verdict(
                    &[("force-command", "/usr/bin/backup")],
                    &[pinned("force-command", Some("/usr/bin/backup"))]
                ),
                None
            );
        }

        /// A bare name permits without requiring — the configuration an
        /// all-mandatory list could not express, for a role that sets an option
        /// only sometimes.
        #[test]
        fn an_option_permitted_by_name_may_be_absent() {
            assert_eq!(verdict(&[], &[pinned("source-address", None)]), None);
        }

        #[test]
        fn an_option_permitted_by_name_accepts_any_value() {
            assert_eq!(
                verdict(
                    &[("source-address", "10.0.0.0/8")],
                    &[pinned("source-address", None)]
                ),
                None
            );
        }

        /// The key ID is three colon-separated fields, so a colon in the
        /// username shifts every one of them — and what reads that log then
        /// names the wrong person, which is the single claim this feature
        /// makes. The admin API refuses one now; a name from an IdP never
        /// passes through it, so the structure is held where it is built.
        #[test]
        fn a_username_carrying_a_colon_cannot_shift_the_key_id_fields() {
            // Through the shipped function, not a copy of it written here.
            let key_id = format!(
                "warpgate:{}:0e6d1f4c-0000-0000-0000-000000000000",
                crate::client::key_id_field("root:admin")
            );
            let fields: Vec<&str> = key_id.split(':').collect();
            assert_eq!(
                fields.len(),
                3,
                "the key ID split into {} fields",
                fields.len()
            );
            assert_eq!(fields[1], "root_admin");
        }

        #[test]
        fn an_ordinary_username_is_left_alone() {
            assert_eq!(crate::client::key_id_field("alice"), "alice");
        }

        /// `attribution()` puts `admin-token` in this field when the admin API
        /// token drives a session. A user of that name produced the same three
        /// fields, in the target's sshd log and in Vault's audit log — the two
        /// records this feature exists to make trustworthy. The admin API
        /// refuses the name; SSO auto-provisioning inserts the IdP's claim
        /// without asking it.
        #[test]
        fn a_username_cannot_impersonate_the_gateways_own_attribution() {
            for reserved in warpgate_common_http::auth::TOKEN_ATTRIBUTIONS {
                assert_ne!(
                    crate::client::user_key_id_field(reserved),
                    reserved,
                    "a user named {reserved} produces the attribution's own key ID"
                );
            }
        }

        /// And the other direction, which the first version of this fix did not
        /// have. The gateway's own attribution must pass through unchanged:
        /// substituting it renames the thing it identifies, and two guards
        /// caught that by failing their baseline — the key ID had become
        /// `warpgate:admin-token_:<session>`.
        #[test]
        fn the_gateways_own_attribution_is_left_alone() {
            for reserved in warpgate_common_http::auth::TOKEN_ATTRIBUTIONS {
                assert_eq!(
                    crate::client::key_id_field(reserved),
                    reserved,
                    "the gateway's own attribution was renamed on its way to the key ID"
                );
            }
        }

        /// A chain that does not contain the host being asked about cannot
        /// answer the question, and used to be walked to the end anyway —
        /// every hop traversed, no key reported, a live session handed back.
        /// The property the integration test was believed to hold and does
        /// not: measured twice, the stalling fixture never reaches this code.
        /// It delivers the host key on the wire, but russh does not call
        /// `check_server_key` until the key exchange completes, and the fixture
        /// mutes before `NEWKEYS`. Letting `NEWKEYS` through instead trips
        /// strict-kex and the client disconnects in three seconds. So what that
        /// test measures is the plain handshake bound, which has its own guard.
        ///
        /// What is left to state is the property itself: whatever the pause is,
        /// the answer has to bring the bound back to the target's own, and not
        /// to something a stalled target can sit inside. Pushing the resume out
        /// instead of back is the exact regression this exists to catch, and it
        /// is what the previous version of this fix did.
        #[test]
        fn answering_a_host_key_question_puts_the_targets_own_bound_back() {
            assert_eq!(
                crate::client::once_the_host_key_is_answered(),
                super::super::HANDSHAKE_TIMEOUT,
                "the answer left the connection on a bound other than the target's"
            );
            assert!(
                crate::client::once_the_host_key_is_answered()
                    < crate::client::while_a_host_key_answer_is_outstanding(),
                "the bound after the answer is no shorter than the pause, so the \
                 pause is never lifted in any way a stalled target would notice"
            );
        }

        #[test]
        fn a_chain_without_the_host_asked_about_cannot_answer() {
            let asked_about = uuid::Uuid::new_v4();
            let other = uuid::Uuid::new_v4();

            assert!(crate::client::chain_can_answer(None, &[other]));
            assert!(crate::client::chain_can_answer(
                Some(asked_about),
                &[other, asked_about]
            ));
            assert!(
                !crate::client::chain_can_answer(Some(asked_about), &[other]),
                "a chain missing the host asked about reported that it could answer"
            );
        }

        /// The budget for authentication is not the budget for the transport
        /// handshake, and used to be.
        ///
        /// Five calls at the default 10s `vault.timeout` is fifty seconds
        /// against a thirty-second bound, so a Vault that was slow but working
        /// timed out and the message named the target.
        #[test]
        fn a_certificate_target_gets_a_budget_that_fits_its_vault_calls() {
            use std::time::Duration;

            use warpgate_common::{SSHTargetAuth, SshTargetCertificateAuth, SshTargetPasswordAuth};

            use crate::client::{AUTHENTICATION_TIMEOUT, authentication_budget};

            let certificate = SSHTargetAuth::Certificate(SshTargetCertificateAuth::default());

            // The default: five 10s calls do not fit in 30s, so the budget grows.
            let budget = authentication_budget(&certificate, Some(Duration::from_secs(10)));
            assert!(
                budget >= Duration::from_secs(50),
                "five 10s calls do not fit in {budget:?}"
            );

            // A fast Vault does not shrink it below the floor.
            assert_eq!(
                authentication_budget(&certificate, Some(Duration::from_secs(1))),
                AUTHENTICATION_TIMEOUT
            );

            // Nothing to budget for when the target does not use an issuer.
            let password = SSHTargetAuth::Password(SshTargetPasswordAuth {
                password: String::new().into(),
            });
            assert_eq!(
                authentication_budget(&password, Some(Duration::from_secs(10))),
                AUTHENTICATION_TIMEOUT
            );
            assert_eq!(
                authentication_budget(&certificate, None),
                AUTHENTICATION_TIMEOUT
            );
        }

        /// Extensions decide what a session can *do*, and were logged and
        /// nothing else. `force-command` governs the shell and exec channels;
        /// OpenSSH opens `direct-tcpip` and reaches the user's agent on the
        /// strength of the certificate alone.
        #[test]
        fn an_extension_the_target_did_not_name_is_refused() {
            let (certificate, key) = carrying_extensions(&[("permit-port-forwarding", "")]);
            let reason = certificate_mismatch(
                &certificate,
                &key,
                PRINCIPAL,
                KEY_ID,
                &[],
                &["permit-pty".to_owned()],
                None,
            )
            .expect("an unexpected extension");
            assert!(
                reason.contains("permit-port-forwarding") && reason.contains("does not allow"),
                "refused for the wrong reason: {reason}"
            );
        }

        #[test]
        fn a_named_extension_is_accepted() {
            let (certificate, key) = carrying_extensions(&[("permit-pty", "")]);
            assert_eq!(
                certificate_mismatch(
                    &certificate,
                    &key,
                    PRINCIPAL,
                    KEY_ID,
                    &[],
                    &["permit-pty".to_owned()],
                    None,
                ),
                None
            );
        }

        /// An absent extension grants nothing, so unlike a pinned critical
        /// option there is nothing to remove that would widen access.
        #[test]
        fn a_named_extension_may_be_absent() {
            let (certificate, key) = carrying_extensions(&[]);
            assert_eq!(
                certificate_mismatch(
                    &certificate,
                    &key,
                    PRINCIPAL,
                    KEY_ID,
                    &[],
                    &[
                        "permit-pty".to_owned(),
                        "permit-agent-forwarding".to_owned()
                    ],
                    None,
                ),
                None
            );
        }

        /// The other direction, unchanged: nothing unlisted gets through.
        #[test]
        fn an_option_the_target_did_not_name_is_refused() {
            let reason = verdict(&[("force-command", "/bin/sh")], &[])
                .expect("an unexpected critical option");
            assert!(
                reason.contains("does not allow"),
                "refused for the wrong reason: {reason}"
            );
        }
    }
}
