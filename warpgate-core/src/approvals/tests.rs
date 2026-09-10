use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{Database, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::{
    ApprovalKind, ApprovalScope, AuthStateUserInfo, RememberApprovalBy, StoredCredential,
    StoredCredentialFingerprint, StoredCredentialKind, WebApprovalMatchKey,
};
use warpgate_common::{NodeId, Protocol, UserSessionId};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
use warpgate_db_entities::SessionApprovalRequest::{
    self, Advertised, ApprovalActor, close_request, mark_consumed, upsert_request,
};
use warpgate_db_migrations::migrate_database;

use super::*;

async fn migrated_db() -> DatabaseConnection {
    set_config_migration_values(ConfigMigrationValues::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate_database(&db).await.unwrap();
    db
}

async fn advertise_row(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    subject: &ApprovalSubject,
) {
    advertise_row_on(db, NodeId(Uuid::new_v4()), session_id, subject).await;
}

/// [`advertise_row`], on a named node — for tests of delivery, which is
/// node-scoped: a row is only delivered (or declared undeliverable) by the
/// node it names.
async fn advertise_row_on(
    db: &DatabaseConnection,
    node_id: NodeId,
    session_id: UserSessionId,
    subject: &ApprovalSubject,
) {
    // The administrator half goes through the real advertiser, so the reuse
    // policy under test is the one production passes.
    if matches!(subject.kind, ApprovalKind::Admin) {
        let mut subject = subject.clone();
        subject.session_id = session_id;
        super::wait::advertise_admin_request(db, node_id, &subject)
            .await
            .unwrap();
        return;
    }
    // Only the user half reaches here, and a user question carries a code and
    // no ticket — which is now the only shape one can be built in.
    upsert_request(
        db,
        SessionApprovalRequest::NewRequest {
            session_id,
            target: subject.target_name.clone(),
            node_id,
            protocol: subject.protocol.to_string(),
            username: subject.user_info.username.clone(),
            user_id: subject.user_info.id,
            remote_address: subject.remote_ip.map(|ip| ip.to_string()),
            match_digest: subject.match_digest(),
            started: OffsetDateTime::now_utc(),
            about: SessionApprovalRequest::RequestAsk::User {
                identification_string: "TEST".to_owned(),
            },
        },
    )
    .await
    .unwrap();
}

fn plain_subject(target: &str) -> ApprovalSubject {
    ApprovalSubject {
        kind: ApprovalKind::Admin,
        session_id: UserSessionId(Uuid::new_v4()),
        user_info: AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "someone".into(),
        },
        protocol: Protocol::Ssh,
        target_name: target.into(),
        remote_ip: None,
        remember_by: RememberApprovalBy::Nothing,
        ticket_id: None,
    }
}

async fn pending_row(db: &DatabaseConnection, session_id: UserSessionId, target: &str) {
    advertise_row(db, session_id, &plain_subject(target)).await;
}

fn admin_actor() -> ApprovalActor {
    ApprovalActor {
        username: Some("admin".into()),
        user_id: Uuid::nil(),
    }
}

async fn find_question(
    db: &DatabaseConnection,
    which: SessionApprovalRequest::Key,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find()
        .filter(which.into_condition())
        .one(db)
        .await?)
}

async fn approve(db: &DatabaseConnection, session_id: UserSessionId, target: &str) -> bool {
    approve_with_scope(db, session_id, target, ApprovalScope::Once).await
}

async fn approve_with_scope(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    target: &str,
    scope: ApprovalScope,
) -> bool {
    record_decision(
        db,
        session_id,
        ApprovalKind::Admin,
        target,
        ApprovalDecision::Approved(scope),
        admin_actor(),
    )
    .await
    .unwrap()
}

async fn status_of(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    target: &str,
) -> SessionApprovalRequest::ApprovalRequestStatus {
    let which = SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, target);

    SessionApprovalRequest::Entity::find()
        .filter(which.into_condition())
        .one(db)
        .await
        .unwrap()
        .expect("the request should still exist")
        .status
}

/// Every request of one kind on a session, across its targets.
fn one_request(session_id: UserSessionId, kind: ApprovalKind) -> Condition {
    SessionApprovalRequest::Column::SessionId
        .eq(session_id)
        .and(SessionApprovalRequest::Column::Kind.eq(kind))
        .into_condition()
}

/// Moves a request's start time into the past, so the reaper sees it as
/// older than the window anything could still be waiting for.
async fn backdate_request(db: &DatabaseConnection, session_id: UserSessionId, by: Duration) {
    SessionApprovalRequest::Entity::update_many()
        .col_expr(
            SessionApprovalRequest::Column::Started,
            (OffsetDateTime::now_utc() - time::Duration::seconds(by.as_secs() as i64)).into(),
        )
        .filter(one_request(session_id, ApprovalKind::Admin))
        .exec(db)
        .await
        .unwrap();
}

/// The request of one kind on a session, where only one can exist: a login has
/// a single target name fixed when its auth state is built, so its own approval
/// is unambiguous. Administrator gates name their target — see
/// [`find_question`].
async fn find_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
) -> Result<Option<SessionApprovalRequest::Model>, WarpgateError> {
    Ok(SessionApprovalRequest::Entity::find()
        .filter(one_request(session_id, kind))
        .one(db)
        .await?)
}

/// Nothing else ends a request whose owning node died mid-hold: the guard's
/// `Drop` never ran, and no waiter is left to time out. Without the reaper
/// the row sits in the inbox forever, offering an administrator a session
/// that no longer exists.
#[tokio::test]
async fn reaping_ends_requests_nobody_can_still_be_waiting_on() {
    use SessionApprovalRequest::ApprovalRequestStatus as Status;

    let db = migrated_db().await;
    let stale = UserSessionId(Uuid::new_v4());
    let recent = UserSessionId(Uuid::new_v4());
    pending_row(&db, stale, "a-target").await;
    pending_row(&db, recent, "a-target").await;
    // Past any window: the lifetime is the approval timeout, never shorter
    // than the auth-state timeout.
    backdate_request(&db, stale, Duration::from_secs(24 * 3600)).await;

    reap_stale(&db).await.unwrap();

    assert_eq!(status_of(&db, stale, "a-target").await, Status::Abandoned);
    assert_eq!(
        status_of(&db, recent, "a-target").await,
        Status::Pending,
        "a request still inside its window is still a live question",
    );
}

/// Audit retention is configured independently of the approval window, so a
/// short retention meets rows that are still live. Deleting one a held
/// connection is polling reads to that connection as "no longer a live
/// question" — it would deny a session no administrator decided against, and
/// erase the record of the request in the same stroke.
#[tokio::test]
async fn pruning_leaves_anything_still_being_waited_on() {
    let db = migrated_db().await;
    let asking = UserSessionId(Uuid::new_v4());
    let answered = UserSessionId(Uuid::new_v4());
    let delivered = UserSessionId(Uuid::new_v4());
    let gave_up = UserSessionId(Uuid::new_v4());

    for session in [asking, answered, delivered, gave_up] {
        pending_row(&db, session, "a-target").await;
    }
    // Answered, but the owning node has yet to read it back.
    assert!(approve(&db, answered, "a-target").await);
    // Answered and picked up.
    assert!(approve(&db, delivered, "a-target").await);
    mark_consumed(
        &db,
        SessionApprovalRequest::Key::new(delivered, ApprovalKind::Admin, "a-target"),
    )
    .await
    .unwrap();
    // Ended without an answer.
    close_request(
        &db,
        gave_up,
        ApprovalKind::Admin,
        "a-target",
        SessionApprovalRequest::UndecidedApprovalRequestStatus::Abandoned,
    )
    .await
    .unwrap();

    // Every row is older than the retention.
    SessionApprovalRequest::delete_all_before(&db, OffsetDateTime::now_utc())
        .await
        .unwrap();

    let survives = async |session| {
        find_question(
            &db,
            SessionApprovalRequest::Key::new(session, ApprovalKind::Admin, "a-target"),
        )
        .await
        .unwrap()
        .is_some()
    };
    assert!(survives(asking).await, "a question still being asked");
    assert!(
        survives(answered).await,
        "an answer the owning node has yet to read back",
    );
    assert!(
        !survives(delivered).await,
        "a delivered decision is history"
    );
    assert!(!survives(gave_up).await, "an abandoned request is history");
}

/// The reaper runs on a timer against every row in the table, so it meets
/// answered ones too. An answer outranks the reaper: the owning node may
/// not have picked it up yet, and overwriting it would deny a session an
/// administrator approved.
#[tokio::test]
async fn reaping_never_erases_an_answer() {
    use SessionApprovalRequest::ApprovalRequestStatus as Status;

    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;
    assert!(approve(&db, session_id, "a-target").await);
    backdate_request(&db, session_id, Duration::from_secs(24 * 3600)).await;

    reap_stale(&db).await.unwrap();

    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        Status::Approved
    );
}

/// A request/response protocol re-enters its gate on every request, so the
/// same session re-advertises constantly. If that overwrote the decision
/// columns it would erase an administrator's answer, and the session would
/// wait forever while the inbox kept offering it again.
#[tokio::test]
async fn re_advertising_keeps_a_recorded_decision() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;
    assert!(approve(&db, session_id, "a-target").await);

    pending_row(&db, session_id, "a-target").await;

    let row = find_request(&db, session_id, ApprovalKind::Admin)
        .await
        .unwrap()
        .expect("the request should still exist");
    assert!(
        matches!(row_state(&row).unwrap(), RowState::Decided(..)),
        "re-advertising must not erase the recorded decision",
    );
}

/// The identity columns are what an approver decided about — and what the
/// grace-period bypass later matches a connection against. Re-advertising
/// while an answer stands must therefore leave them exactly as they were:
/// rewriting them would re-key a standing grant to credentials and an
/// address nobody approved, and corrupt the record of what was asked.
#[tokio::test]
async fn re_advertising_does_not_rewrite_what_was_approved() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());

    let mut asked = plain_subject("a-target");
    asked.session_id = session_id;
    asked.remote_ip = Some("10.0.0.1".parse().unwrap());
    advertise_row(&db, session_id, &asked).await;
    assert!(approve(&db, session_id, "a-target").await);

    let approved = find_question(
        &db,
        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target"),
    )
    .await
    .unwrap()
    .expect("the request should still exist");

    // The same question asked again, by a connection presenting different
    // credentials from a different address, before the owner picks the
    // answer up.
    let mut asked_again = asked.clone();
    asked_again.remote_ip = Some("10.0.0.2".parse().unwrap());
    asked_again.remember_by = password_credentials([7; 32]);
    advertise_row(&db, session_id, &asked_again).await;

    let after = find_question(
        &db,
        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target"),
    )
    .await
    .unwrap()
    .expect("the request should still exist");
    assert_eq!(
        after.remote_address, approved.remote_address,
        "an answered request must keep the address it was approved for",
    );
    assert_eq!(
        after.match_digest, approved.match_digest,
        "an answered request must keep the credentials it was approved for",
    );
    assert_eq!(after.node_id, approved.node_id);
    assert_eq!(after.started, approved.started);
}

/// Rows outlive their gate now, so a session that gates again — a new
/// target, or a retry after a timeout — would otherwise read the previous
/// gate's answer as this one's and walk straight through.
#[tokio::test]
async fn re_advertising_reopens_a_finished_request() {
    let db = migrated_db().await;

    for finished in [
        SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut,
        SessionApprovalRequest::UndecidedApprovalRequestStatus::Abandoned,
    ] {
        let session_id = UserSessionId(Uuid::new_v4());
        pending_row(&db, session_id, "a-target").await;
        close_request(&db, session_id, ApprovalKind::Admin, "a-target", finished)
            .await
            .unwrap();

        pending_row(&db, session_id, "a-target").await;

        let row = find_question(
            &db,
            SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target"),
        )
        .await
        .unwrap()
        .expect("the request should still exist");
        assert_eq!(
            row.status,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
            "a request left {finished:?} must be reopened, not reused",
        );
        // Closing stamps `resolved_at`, so a reopening that left it behind
        // would read as a question that had already been answered.
        assert!(
            row.resolved_at.is_none(),
            "reopening must leave nothing of how the previous asking ended",
        );
        assert!(row.consumed_at.is_none());
        assert!(row.scope.is_none());
        assert!(row.resolved_by_username.is_none());
    }
}

/// A delivered decision stands, whatever asks next. No protocol can put a second
/// question under one key anyway — `(user_session_id, target_id)` is unique and
/// a target session only ends with its parent, so an admitted session keeps its
/// access row and never reaches the gate again; and every protocol that can be
/// self-approved takes a fresh session id per attempt. Were one to, the answer
/// already on the row is the right one: rewriting it would put a settled
/// question to an approver again and destroy the record of the first answer.
#[tokio::test]
async fn re_advertising_reuses_a_consumed_decision() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;
    assert!(approve_with_scope(&db, session_id, "a-target", ApprovalScope::Target).await);
    mark_consumed(
        &db,
        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target".into()),
    )
    .await
    .unwrap();

    pending_row(&db, session_id, "a-target").await;

    let row = find_request(&db, session_id, ApprovalKind::Admin)
        .await
        .unwrap()
        .expect("the request should still exist");
    assert_eq!(
        row.status,
        SessionApprovalRequest::ApprovalRequestStatus::Approved,
        "the decision must stand, to be reused rather than re-asked",
    );
    assert_eq!(row.scope, Some(ApprovalScope::Target));
    assert_eq!(row.resolved_by_username.as_deref(), Some("admin"));
    assert!(
        row.consumed_at.is_some(),
        "and the record of it having been delivered",
    );
}

/// A decision names the question it answers. A request reopened for a
/// different target between the approver's screen and their click is a
/// question they were never shown, and their answer must not land on it.
#[tokio::test]
async fn a_decision_names_its_question() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;

    assert!(
        !approve(&db, session_id, "another-target").await,
        "a decision about a different target must not be recorded",
    );
    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Pending,
    );
}

/// Gating for a second target asks a second question. It gets its own row,
/// and the answer already given about the first stays exactly as the
/// administrator left it — the record of who approved what is the table,
/// and a session reaching two targets must not cost it one of them.
#[tokio::test]
async fn a_second_target_asks_alongside_the_first() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;
    assert!(approve_with_scope(&db, session_id, "a-target", ApprovalScope::Target).await);

    pending_row(&db, session_id, "b-target").await;

    let first = find_question(
        &db,
        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target"),
    )
    .await
    .unwrap()
    .expect("the answered question must still be on record");
    assert_eq!(
        first.status,
        SessionApprovalRequest::ApprovalRequestStatus::Approved,
    );
    assert_eq!(
        first.scope,
        Some(ApprovalScope::Target),
        "the grant the administrator gave must survive the next question",
    );
    assert_eq!(first.resolved_by_username.as_deref(), Some("admin"));

    let second = find_question(
        &db,
        SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "b-target"),
    )
    .await
    .unwrap()
    .expect("the new question should exist");
    assert_eq!(
        second.status,
        SessionApprovalRequest::ApprovalRequestStatus::Pending,
    );
    assert!(second.scope.is_none());
    assert!(second.resolved_by_username.is_none());
}

/// A session's questions are answered one at a time and in any order, so a
/// waiter must read only its own row: admitting a connection on the
/// strength of an approval given for a different target would let one
/// decision open two doors.
#[tokio::test]
async fn a_waiter_only_sees_answers_to_its_own_question() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;
    pending_row(&db, session_id, "b-target").await;
    assert!(approve(&db, session_id, "b-target").await);

    let outcome = await_row_decision(
        &db,
        session_id,
        ApprovalKind::Admin,
        "a-target",
        Duration::from_millis(1500),
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome, DecisionWaitOutcome::TimedOut),
        "a wait must not adopt an answer given about another target",
    );
}

/// Closing is what replaces deleting: a waiter that gives up must leave the
/// row behind as the record, must not overwrite an answer that landed
/// while it was giving up, and must not touch the session's other
/// questions.
#[tokio::test]
async fn closing_keeps_the_row_and_never_overwrites_an_answer() {
    let db = migrated_db().await;

    let abandoned = UserSessionId(Uuid::new_v4());
    pending_row(&db, abandoned, "a-target").await;
    SessionApprovalRequest::abandon_requests_for_session(&db, abandoned)
        .await
        .unwrap();
    assert_eq!(
        status_of(&db, abandoned, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
    );

    let answered = UserSessionId(Uuid::new_v4());
    pending_row(&db, answered, "a-target").await;
    assert!(approve(&db, answered, "a-target").await);
    close_request(
        &db,
        answered,
        ApprovalKind::Admin,
        "a-target",
        SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut,
    )
    .await
    .unwrap();
    assert_eq!(
        status_of(&db, answered, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Approved,
    );

    let two_targets = UserSessionId(Uuid::new_v4());
    pending_row(&db, two_targets, "a-target").await;
    pending_row(&db, two_targets, "b-target").await;
    close_request(
        &db,
        two_targets,
        ApprovalKind::Admin,
        "a-target",
        SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut,
    )
    .await
    .unwrap();
    assert_eq!(
        status_of(&db, two_targets, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
    );
    assert_eq!(
        status_of(&db, two_targets, "b-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Pending,
        "closing one question must not end the session's others",
    );
}

/// The waiting side has to notice a decision written by *another* task —
/// that hand-off is the whole substrate, and a wait that only ever reads the
/// row once would hold the session open forever.
#[tokio::test]
async fn a_decision_written_later_is_picked_up() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    pending_row(&db, session_id, "a-target").await;

    let writer = {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            record_decision(
                &db,
                session_id,
                ApprovalKind::Admin,
                "a-target",
                ApprovalDecision::Approved(ApprovalScope::Once),
                ApprovalActor {
                    username: Some("admin".into()),
                    user_id: Uuid::nil(),
                },
            )
            .await
            .unwrap()
        })
    };

    let outcome = await_row_decision(
        &db,
        session_id,
        ApprovalKind::Admin,
        "a-target",
        Duration::from_secs(20),
    )
    .await
    .unwrap();

    assert!(
        writer.await.unwrap(),
        "the decision should have been recorded"
    );
    assert!(
        matches!(
            outcome,
            DecisionWaitOutcome::Decided(ApprovalDecision::Approved(ApprovalScope::Once))
        ),
        "the wait should have seen the recorded decision",
    );
}

fn password_credentials(hash: [u8; 32]) -> RememberApprovalBy {
    RememberApprovalBy::from_credentials(vec![StoredCredential::new(
        StoredCredentialKind::Password,
        Uuid::from_u128(u128::from(hash[0])),
        StoredCredentialFingerprint::of_stored_verifier(hash.as_slice()),
    )])
}

fn remembered_subject(target: &str, hash: [u8; 32]) -> ApprovalSubject {
    ApprovalSubject {
        remote_ip: Some("10.0.0.5".parse().unwrap()),
        remember_by: password_credentials(hash),
        ..plain_subject(target)
    }
}

fn lookup_key(target: &str, hash: [u8; 32]) -> WebApprovalMatchKey {
    WebApprovalMatchKey::build(
        ApprovalKind::Admin,
        "10.0.0.5".parse().unwrap(),
        Protocol::Ssh,
        // Case differs from the stored row's "someone" on purpose:
        // usernames compare case-insensitively across the auth stack.
        "Someone",
        target,
        &password_credentials(hash),
    )
    .expect("a subject with an origin and credentials is keyable")
}

async fn remembered_approval(
    db: &DatabaseConnection,
    target: &str,
    hash: [u8; 32],
    scope: ApprovalScope,
) -> UserSessionId {
    let session_id = UserSessionId(Uuid::new_v4());
    advertise_row(db, session_id, &remembered_subject(target, hash)).await;
    assert!(approve_with_scope(db, session_id, target, scope).await);
    session_id
}

const GRACE: Duration = Duration::from_secs(3600);

/// The bypass answers from the stored rows, so it must demand the full
/// match: the kind, the target, the credentials, and a fresh resolution.
#[tokio::test]
async fn a_remembered_approval_requires_a_full_match() {
    let db = migrated_db().await;
    remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::Target).await;

    assert!(
        approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
    // Another target is not covered.
    assert!(
        !approval_is_remembered(&db, &lookup_key("staging", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
    // Different credentials are not covered.
    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [9u8; 32]), GRACE)
            .await
            .unwrap()
    );
    // A zero grace is never fresh, so approval is required again.
    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), Duration::ZERO,)
            .await
            .unwrap()
    );

    // The other approval kind is a different question entirely.
    let existing = lookup_key("prod", [7u8; 32]);

    let other_kind = WebApprovalMatchKey::build(
        ApprovalKind::User,
        existing.identity().remote_ip(),
        existing.identity().protocol(),
        existing.identity().username(),
        "prod",
        &RememberApprovalBy::Credentials(existing.identity().other_credentials().clone()),
    )
    .unwrap();

    assert!(
        !approval_is_remembered(&db, &other_kind, GRACE)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_all_targets_grant_covers_every_target() {
    let db = migrated_db().await;
    remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::AllTargets).await;

    assert!(
        approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
    assert!(
        approval_is_remembered(&db, &lookup_key("staging", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
    // Approving every target is strictly broader than approving a portal
    // sign-in, so it subsumes an untargeted ask too.
    assert!(
        approval_is_remembered(&db, &lookup_key("", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
}

/// An HTTP sign-in / SSH menu login carries no target. A grant given to
/// one must not stand in for approval of an actual target, nor a target's
/// grant for it.
#[tokio::test]
async fn an_untargeted_grant_is_its_own_bucket() {
    let db = migrated_db().await;
    remembered_approval(&db, "", [7u8; 32], ApprovalScope::Target).await;

    assert!(
        approval_is_remembered(&db, &lookup_key("", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_once_approval_is_not_remembered() {
    let db = migrated_db().await;
    remembered_approval(&db, "prod", [7u8; 32], ApprovalScope::Once).await;

    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
}

/// Only an approval grants; a question still open, or one answered with a
/// refusal, remembers nothing.
#[tokio::test]
async fn only_an_approval_is_remembered() {
    let db = migrated_db().await;

    let pending = UserSessionId(Uuid::new_v4());
    advertise_row(&db, pending, &remembered_subject("prod", [7u8; 32])).await;
    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );

    assert!(
        record_decision(
            &db,
            pending,
            ApprovalKind::Admin,
            "prod",
            ApprovalDecision::Rejected,
            admin_actor(),
        )
        .await
        .unwrap()
    );
    assert!(
        !approval_is_remembered(&db, &lookup_key("prod", [7u8; 32]), GRACE)
            .await
            .unwrap()
    );
}

async fn ticket_with_uses(db: &DatabaseConnection, uses: i16) -> Uuid {
    use warpgate_db_entities::Target::TargetKind;
    use warpgate_db_entities::{Target, Ticket, User};

    let user_id = Uuid::new_v4();
    User::Entity::insert(User::ActiveModel {
        id: Set(user_id),
        username: Set(format!("user-{user_id}")),
        credential_policy: Set(serde_json::Value::Null),
        description: Set(String::new()),
        rate_limit_bytes_per_second: Set(None),
        ldap_server_id: Set(None),
        ldap_object_uuid: Set(None),
        allowed_ip_ranges: Set(serde_json::Value::Null),
    })
    .exec(db)
    .await
    .unwrap();

    let target_id = Uuid::new_v4();
    Target::Entity::insert(Target::ActiveModel {
        id: Set(target_id),
        name: Set(format!("target-{target_id}")),
        description: Set(String::new()),
        kind: Set(TargetKind::Ssh),
        options: Set(serde_json::Value::Null),
        rate_limit_bytes_per_second: Set(None),
        group_id: Set(None),
        ticket_max_duration_seconds: Set(None),
        ticket_requests_disabled: Set(false),
        ticket_require_approval: Set(false),
        ticket_max_uses: Set(None),
        require_approval: Set(true),
    })
    .exec(db)
    .await
    .unwrap();

    let id = Uuid::new_v4();
    Ticket::Entity::insert(Ticket::ActiveModel {
        id: Set(id),
        secret_hash: Set("hash".into()),
        user_id: Set(user_id),
        description: Set(String::new()),
        target_id: Set(target_id),
        uses_left: Set(Some(uses)),
        self_service: Set(false),
        expiry: Set(None),
        created: Set(OffsetDateTime::now_utc()),
    })
    .exec(db)
    .await
    .unwrap();
    id
}

async fn uses_left(db: &DatabaseConnection, id: Uuid) -> Option<i16> {
    use warpgate_db_entities::Ticket;

    Ticket::Entity::find_by_id(id)
        .one(db)
        .await
        .unwrap()
        .expect("the ticket should exist")
        .uses_left
}

/// The use a question holds was spent when the session authenticated; an
/// approval leaves that spend standing — it transfers to the admitted session
/// — and touches the ticket in no other way, however many gates across the
/// cluster watch the row.
#[tokio::test]
async fn an_approval_keeps_the_spend_and_takes_nothing_more() {
    let db = migrated_db().await;
    // The session's own use is already spent — that is what "the question
    // holds a use" means — leaving none over.
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    // A decision about a different target moves nothing and settles nothing.
    assert!(!approve(&db, session_id, "another-target").await);
    assert_eq!(uses_left(&db, ticket_id).await, Some(0));

    assert!(approve(&db, session_id, "a-target").await);
    assert_eq!(uses_left(&db, ticket_id).await, Some(0));

    // A second decision finds the question already answered.
    assert!(!approve(&db, session_id, "a-target").await);
    assert_eq!(uses_left(&db, ticket_id).await, Some(0));
}

/// A question that ends unanswered gives its use back, and asking the same
/// question again takes a use of its own — the refund is not a free pass to
/// re-ask forever on one spend.
#[tokio::test]
async fn asking_again_re_spends_the_use_a_timeout_gave_back() {
    use SessionApprovalRequest::UndecidedApprovalRequestStatus;

    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    assert!(
        SessionApprovalRequest::close_request(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            UndecidedApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        uses_left(&db, ticket_id).await,
        Some(1),
        "a question that ended unanswered gives the use back",
    );

    advertise_row(&db, session_id, &subject).await;
    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Pending,
    );
    assert_eq!(
        uses_left(&db, ticket_id).await,
        Some(0),
        "asking again holds a use of its own",
    );
}

/// When the refunded use has since gone elsewhere, the re-ask is refused
/// rather than opened unpaid — and refused typed, so the gate turns the
/// session away instead of parking it on a question nobody opened.
#[tokio::test]
async fn an_exhausted_ticket_cannot_ask_again() {
    use SessionApprovalRequest::{Advertised, UndecidedApprovalRequestStatus};

    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    assert!(
        SessionApprovalRequest::close_request(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            UndecidedApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap()
    );
    // The refunded use goes to someone else before the re-ask.
    warpgate_db_entities::Ticket::spend_use(&db, ticket_id)
        .await
        .unwrap();

    let advertised = super::wait::advertise_admin_request(&db, NodeId(Uuid::new_v4()), &{
        let mut again = subject.clone();
        again.session_id = session_id;
        again
    })
    .await
    .unwrap();
    assert_eq!(advertised, Advertised::TicketExhausted);
    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::TimedOut,
        "no question was opened",
    );
    assert_eq!(uses_left(&db, ticket_id).await, Some(0));
}

/// A settle aimed at one asking must not land on its successor: the write is
/// pinned to the asking that was read, and a reopened question is a different
/// asking holding a different use. An unpinned close here would refund a
/// live, paid-for question — and refund again when it later closes.
#[tokio::test]
async fn a_decision_aimed_at_an_earlier_asking_settles_nothing() {
    use SessionApprovalRequest::UndecidedApprovalRequestStatus;

    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    // The first asking, as some slow decision-maker read it.
    let stale = SessionApprovalRequest::Entity::find()
        .filter(
            SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "a-target")
                .into_condition(),
        )
        .one(&db)
        .await
        .unwrap()
        .unwrap();

    // The asking times out (refunding) and is asked afresh (re-spending) —
    // with a renewed `started`, which is what tells the askings apart.
    assert!(
        SessionApprovalRequest::close_request(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            UndecidedApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap()
    );
    advertise_row(&db, session_id, &subject).await;
    assert_eq!(uses_left(&db, ticket_id).await, Some(0));

    let landed = SessionApprovalRequest::settle_request(
        &db,
        &stale,
        SessionApprovalRequest::ApprovalRequestStatus::Rejected,
        None,
        &ApprovalActor {
            username: Some("admin".into()),
            user_id: Uuid::nil(),
        },
    )
    .await
    .unwrap();
    assert!(!landed, "a decision about the earlier asking must not land");
    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Pending,
        "the new asking still stands",
    );
    assert_eq!(
        uses_left(&db, ticket_id).await,
        Some(0),
        "and keeps the use it holds",
    );
}

/// A node that dies mid-hold closes nothing itself; the reaper closes for it,
/// and a close gives the use back — so a crash costs the user nothing once
/// the row ages out.
#[tokio::test]
async fn reaping_refunds_what_dead_askings_held() {
    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;
    backdate_request(&db, session_id, Duration::from_secs(24 * 3600)).await;

    reap_stale(&db).await.unwrap();

    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
    );
    assert_eq!(uses_left(&db, ticket_id).await, Some(1));
}

/// Ending a session abandons what it was still asking, one asking at a time,
/// so each gives back the use it held.
#[tokio::test]
async fn session_teardown_gives_held_uses_back() {
    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    SessionApprovalRequest::abandon_requests_for_session(&db, session_id)
        .await
        .unwrap();

    assert_eq!(
        status_of(&db, session_id, "a-target").await,
        SessionApprovalRequest::ApprovalRequestStatus::Abandoned,
    );
    assert_eq!(uses_left(&db, ticket_id).await, Some(1));
}

/// Every audit event this test binary emits, so an assertion can pick out
/// its own by session id.
///
/// Installed once and globally rather than per-test with `set_default`:
/// `tracing` caches a callsite first reached with no subscriber listening
/// as never-interested for the whole process, so a thread-local subscriber
/// set afterwards sees nothing whenever another test thread got there
/// first — which passes alone and fails in the suite.
fn audit_events() -> &'static Mutex<Vec<HashMap<&'static str, String>>> {
    use tracing_subscriber::layer::SubscriberExt;

    use crate::logging::layer::ValuesLogLayer;

    static EVENTS: OnceLock<Mutex<Vec<HashMap<&'static str, String>>>> = OnceLock::new();
    let events = EVENTS.get_or_init(|| Mutex::new(Vec::new()));
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let subscriber =
            tracing_subscriber::registry().with(ValuesLogLayer::new(|values, _target| {
                if let Ok(mut events) = events.lock() {
                    events.push(values.into_values());
                }
            }));
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
    events
}

/// The audit events of one `_type` recorded for one session.
fn audited_for(session_id: UserSessionId, event_type: &str) -> Vec<HashMap<&'static str, String>> {
    let session = session_id.0.to_string();
    audit_events()
        .lock()
        .unwrap()
        .iter()
        .filter(|values| {
            values.get("session") == Some(&session)
                && values.get("_type").map(String::as_str) == Some(event_type)
        })
        .cloned()
        .collect()
}

/// The administrator acted, so the audit trail must say so regardless of
/// who was listening — a session that gave up, or an owning node that died
/// mid-wait, would otherwise erase an approval from the record entirely.
/// Captured through the same layer the audit sink uses, since an event
/// without a parseable `session` is dropped there and never reaches the
/// session log.
#[tokio::test]
async fn a_decision_is_audited_with_nobody_waiting() {
    let db = migrated_db().await;
    let session_id = UserSessionId(Uuid::new_v4());
    audit_events();
    pending_row(&db, session_id, "a-target").await;

    assert!(approve(&db, session_id, "a-target").await);
    // Answering a question that is already over is not this call's to
    // audit, so a straggling second click must not log a second time.
    assert!(!approve(&db, session_id, "a-target").await);

    let resolved = audited_for(session_id, "SessionApprovalResolved1");

    assert_eq!(
        resolved.len(),
        1,
        "the decision must be audited exactly once, with nobody waiting on it",
    );
    let event = &resolved[0];
    assert_eq!(event.get("approved").map(String::as_str), Some("true"));
    assert_eq!(event.get("resolved_by").map(String::as_str), Some("admin"));
    assert_eq!(event.get("target").map(String::as_str), Some("a-target"));
}

/// A refusal is not the user's doing, so the use the question held goes back
/// to the ticket.
#[tokio::test]
async fn a_rejection_gives_the_use_back() {
    let db = migrated_db().await;
    let ticket_id = ticket_with_uses(&db, 0).await;

    let session_id = UserSessionId(Uuid::new_v4());
    let mut subject = plain_subject("a-target");
    subject.ticket_id = Some(ticket_id);
    advertise_row(&db, session_id, &subject).await;

    assert!(
        record_decision(
            &db,
            session_id,
            ApprovalKind::Admin,
            "a-target",
            ApprovalDecision::Rejected,
            admin_actor(),
        )
        .await
        .unwrap()
    );
    assert_eq!(uses_left(&db, ticket_id).await, Some(1));
}

/// Delivering recorded self-approval decisions to the auth state they were
/// asked for. Needs a real `Services` because delivery spans the store and the
/// rows; everything heavy in it just wraps the same in-memory database.
mod delivery {
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::sync::{Mutex, broadcast};
    use warpgate_common::auth::{
        AuthResult, CredentialKind, CredentialPolicy, CredentialPolicyResponse,
    };
    use warpgate_common::{GlobalParams, Secret, User, WarpgateConfig, WarpgateConfigStore};

    use super::*;
    use crate::cluster::Cluster;
    use crate::login_protection::LoginProtectionService;
    use crate::rate_limiting::RateLimiterRegistry;
    use crate::recordings::SessionRecordings;
    use crate::{AuthStateStore, DatabaseConfigProvider, Services, State};

    struct RequireWebApproval;

    impl CredentialPolicy for RequireWebApproval {
        fn is_sufficient(
            &self,
            _protocol: Protocol,
            valid_credentials: &HashSet<CredentialKind>,
        ) -> CredentialPolicyResponse {
            if valid_credentials.contains(&CredentialKind::WebUserApproval) {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need(
                    [CredentialKind::WebUserApproval].into_iter().collect(),
                )
            }
        }
    }

    pub(super) async fn test_services(db: &DatabaseConnection) -> Services {
        let params = GlobalParams::new(PathBuf::from("/warpgate.yaml"), false).unwrap();
        let rate_limiter_registry = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let cluster = Arc::new(Cluster::new(db.clone(), 0).await.unwrap());
        Services {
            db: db.clone(),
            recordings: Arc::new(SessionRecordings::new(db.clone(), &params)),
            config: Arc::new(Mutex::new(WarpgateConfig {
                store: WarpgateConfigStore::default(),
            })),
            state: State::new(db, &rate_limiter_registry, cluster.node_id),
            cluster,
            rate_limiter_registry,
            config_provider: Arc::new(DatabaseConfigProvider::new(db).into()),
            auth_state_store: Arc::new(Mutex::new(AuthStateStore::without_request_recording())),
            admin_token: Arc::new(None),
            cluster_token: Arc::new(Secret::new("test".into())),
            login_protection: Arc::new(LoginProtectionService::new(db.clone()).await.unwrap()),
            global_params: Arc::new(params),
            listener_status: Default::default(),
            admin_approval_request_tx: broadcast::channel(8).0,
        }
    }

    fn user_subject(session_id: UserSessionId, user: &User, target: &str) -> ApprovalSubject {
        let mut subject = plain_subject(target);
        subject.kind = ApprovalKind::User;
        subject.session_id = session_id;
        subject.user_info = AuthStateUserInfo {
            id: user.id,
            username: user.username.clone(),
        };
        subject
    }

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "someone".into(),
            description: String::new(),
            credential_policy: None,
            rate_limit_bytes_per_second: None,
            ldap_server_id: None,
            allowed_ip_ranges: None,
        }
    }

    async fn decide(db: &DatabaseConnection, session_id: UserSessionId, target: &str) -> bool {
        record_decision(
            db,
            session_id,
            ApprovalKind::User,
            target,
            ApprovalDecision::Approved(ApprovalScope::Once),
            admin_actor(),
        )
        .await
        .unwrap()
    }

    async fn user_row(
        db: &DatabaseConnection,
        session_id: UserSessionId,
        target: &str,
    ) -> SessionApprovalRequest::Model {
        let which = SessionApprovalRequest::Key::new(session_id, ApprovalKind::User, target);
        SessionApprovalRequest::Entity::find()
            .filter(which.into_condition())
            .one(db)
            .await
            .unwrap()
            .expect("the request should still exist")
    }

    /// An auth state answers for one target at a time while its session's rows
    /// keep one question per target. An answer given to a question the state
    /// has moved on from must not satisfy the question it is asking now, and
    /// must not take the live question's row with it when it is put away.
    #[tokio::test]
    async fn an_answer_to_a_superseded_question_is_not_delivered_to_the_current_one() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let user = test_user();

        // The question the state has since moved on from, and the current one.
        let node = services.cluster.node_id;
        advertise_row_on(
            &db,
            node,
            session_id,
            &user_subject(session_id, &user, "alpha"),
        )
        .await;
        advertise_row_on(
            &db,
            node,
            session_id,
            &user_subject(session_id, &user, "beta"),
        )
        .await;

        let state_arc = services.auth_state_store.lock().await.create(
            &session_id,
            &user,
            Protocol::Ssh,
            "beta",
            Box::new(RequireWebApproval),
            None,
        );

        assert!(decide(&db, session_id, "alpha").await);
        services
            .apply_recorded_user_decision(&session_id)
            .await
            .unwrap();

        // Alpha's answer satisfies nothing...
        assert!(matches!(
            state_arc.lock().await.verify(),
            AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
        ));
        // ...its row is stamped as picked up so it stops being re-offered...
        assert!(
            user_row(&db, session_id, "alpha")
                .await
                .consumed_at
                .is_some()
        );
        // ...and the live question is untouched: still pending, still deliverable.
        let beta = user_row(&db, session_id, "beta").await;
        assert_eq!(
            beta.status,
            SessionApprovalRequest::ApprovalRequestStatus::Pending
        );
        assert!(beta.consumed_at.is_none());

        // The current question's own answer still gets through.
        assert!(decide(&db, session_id, "beta").await);
        services
            .apply_recorded_user_decision(&session_id)
            .await
            .unwrap();
        assert!(matches!(
            state_arc.lock().await.verify(),
            AuthResult::Accepted { .. }
        ));
        assert!(
            user_row(&db, session_id, "beta")
                .await
                .consumed_at
                .is_some()
        );
    }

    /// A fresh attempt on the same connection can take the session's state
    /// over for a different user. An answer given about the previous user's
    /// login must not satisfy the new user's — same session, same target,
    /// different question.
    #[tokio::test]
    async fn an_answer_about_one_user_is_not_delivered_to_another() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let asked_about = test_user();

        advertise_row_on(
            &db,
            services.cluster.node_id,
            session_id,
            &user_subject(session_id, &asked_about, "a-target"),
        )
        .await;

        // The state was since rebuilt for a different user.
        let state_arc = services.auth_state_store.lock().await.create(
            &session_id,
            &test_user(),
            Protocol::Ssh,
            "a-target",
            Box::new(RequireWebApproval),
            None,
        );

        assert!(decide(&db, session_id, "a-target").await);
        services
            .apply_recorded_user_decision(&session_id)
            .await
            .unwrap();

        assert!(matches!(
            state_arc.lock().await.verify(),
            AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval)
        ));
        assert!(
            user_row(&db, session_id, "a-target")
                .await
                .consumed_at
                .is_some()
        );
    }
}

// --- The polled gate: one row read per request -------------------------------

mod polled_gate {
    use warpgate_common::{Target, TargetHTTPOptions, TargetOptions, Tls};

    use super::delivery::test_services;
    use super::*;
    use crate::Services;

    fn gated_target(name: &str) -> Target {
        Target {
            id: Uuid::new_v4(),
            name: name.into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(TargetHTTPOptions {
                url: "http://target".into(),
                tls: Tls::default(),
                headers: Default::default(),
                external_host: None,
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: true,
            ticket_max_uses: None,
        }
    }

    fn someone() -> AuthStateUserInfo {
        AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "someone".into(),
        }
    }

    async fn poll(
        services: &Services,
        session_id: UserSessionId,
        user_info: &AuthStateUserInfo,
        target: &str,
    ) -> PolledGate {
        services
            .poll_admin_approval(
                crate::TargetAuthorization::for_test(
                    user_info.clone(),
                    gated_target(target),
                    Protocol::Http,
                ),
                session_id,
                GatedConnection {
                    remote_ip: None,
                    credentials: RememberApprovalBy::Nothing,
                },
            )
            .await
            .unwrap()
    }

    /// An ungated target admits without a question, and the use spent at
    /// authentication simply stands — there is no guard left to mis-drop it
    /// back, which is what once made a one-use ticket to an ungated target
    /// effectively unlimited.
    #[tokio::test]
    async fn an_ungated_admission_keeps_the_tickets_spend() {
        let db = migrated_db().await;
        audit_events();
        let services = test_services(&db).await;
        // Spent at authentication: the fixture's 0 is the post-spend state.
        let ticket_id = ticket_with_uses(&db, 0).await;

        let mut target = gated_target("open");
        target.require_approval = false;
        let gate = services
            .poll_admin_approval(
                crate::TargetAuthorization::for_ticket_session(
                    someone(),
                    target,
                    Some(ticket_id),
                    Protocol::Http,
                )
                .unwrap(),
                UserSessionId(Uuid::new_v4()),
                GatedConnection {
                    remote_ip: None,
                    credentials: RememberApprovalBy::Nothing,
                },
            )
            .await
            .unwrap();

        assert!(matches!(gate, PolledGate::Approved(_)));
        assert_eq!(uses_left(&db, ticket_id).await, Some(0));
    }

    /// A poll whose re-ask cannot be paid for is a denial, not an eternal
    /// "waiting": the client is turned away the moment the ticket runs dry,
    /// instead of polling a question nobody opened.
    #[tokio::test]
    async fn a_poll_on_an_exhausted_ticket_is_denied() {
        use SessionApprovalRequest::UndecidedApprovalRequestStatus;

        let db = migrated_db().await;
        audit_events();
        let services = test_services(&db).await;
        let ticket_id = ticket_with_uses(&db, 0).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let user_info = someone();

        let authorization = || {
            crate::TargetAuthorization::for_ticket_session(
                user_info.clone(),
                gated_target("prod"),
                Some(ticket_id),
                Protocol::Http,
            )
            .unwrap()
        };
        let connection = || GatedConnection {
            remote_ip: None,
            credentials: RememberApprovalBy::Nothing,
        };

        // First ask: paid for by the authentication-time spend.
        assert!(matches!(
            services
                .poll_admin_approval(authorization(), session_id, connection())
                .await
                .unwrap(),
            PolledGate::Pending
        ));
        // The question times out (refunding), and the refunded use goes
        // elsewhere before the next poll.
        assert!(
            SessionApprovalRequest::close_request(
                &db,
                session_id,
                ApprovalKind::Admin,
                "prod",
                UndecidedApprovalRequestStatus::TimedOut,
            )
            .await
            .unwrap()
        );
        warpgate_db_entities::Ticket::spend_use(&db, ticket_id)
            .await
            .unwrap();

        assert!(matches!(
            services
                .poll_admin_approval(authorization(), session_id, connection())
                .await
                .unwrap(),
            PolledGate::Refused
        ));
    }

    /// The client's retry cadence is the poll, so the same session returns
    /// every few seconds for the whole window. Only the first arrival asks:
    /// a repeat must neither announce again nor touch `started` — that is the
    /// reap clock and the timeout anchor, and refreshing it would let a
    /// polite client extend its own approval window forever.
    #[tokio::test]
    async fn a_poll_asks_once_and_repeats_leave_the_question_alone() {
        let db = migrated_db().await;
        audit_events();
        let services = test_services(&db).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let user_info = someone();

        assert!(matches!(
            poll(&services, session_id, &user_info, "prod").await,
            PolledGate::Pending
        ));
        let asked = find_question(
            &db,
            SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "prod"),
        )
        .await
        .unwrap()
        .expect("the first poll should have asked");

        for _ in 0..3 {
            assert!(matches!(
                poll(&services, session_id, &user_info, "prod").await,
                PolledGate::Pending
            ));
        }

        let after = find_question(
            &db,
            SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "prod"),
        )
        .await
        .unwrap()
        .expect("the question should still stand");
        assert_eq!(
            after.started, asked.started,
            "a repeat poll must not reset the question's clock",
        );
        assert_eq!(
            audited_for(session_id, "SessionApprovalRequested1").len(),
            1,
            "one asking, one announcement",
        );
    }

    /// The row carries the answer, so the poll that finds one delivers it —
    /// and keeps delivering it, in both directions.
    #[tokio::test]
    async fn a_poll_delivers_the_recorded_decision_durably() {
        let db = migrated_db().await;
        let services = test_services(&db).await;
        let user_info = someone();

        let approved_session = UserSessionId(Uuid::new_v4());
        assert!(matches!(
            poll(&services, approved_session, &user_info, "prod").await,
            PolledGate::Pending
        ));
        assert!(approve(&db, approved_session, "prod").await);
        assert!(matches!(
            poll(&services, approved_session, &user_info, "prod").await,
            PolledGate::Approved(_)
        ));
        assert!(
            find_question(
                &db,
                SessionApprovalRequest::Key::new(approved_session, ApprovalKind::Admin, "prod"),
            )
            .await
            .unwrap()
            .expect("the answered row is the record")
            .consumed_at
            .is_some(),
            "delivering the answer stamps it picked up",
        );
        assert!(matches!(
            poll(&services, approved_session, &user_info, "prod").await,
            PolledGate::Approved(_)
        ));

        let denied_session = UserSessionId(Uuid::new_v4());
        assert!(matches!(
            poll(&services, denied_session, &user_info, "prod").await,
            PolledGate::Pending
        ));
        assert!(
            record_decision(
                &db,
                denied_session,
                ApprovalKind::Admin,
                "prod",
                ApprovalDecision::Rejected,
                admin_actor(),
            )
            .await
            .unwrap()
        );
        for _ in 0..2 {
            assert!(matches!(
                poll(&services, denied_session, &user_info, "prod").await,
                PolledGate::Refused
            ));
        }
    }

    /// Expiry needs no waiter: the poll that finds the window run out closes
    /// the question as timed out — auditing what a blocking wait's deadline
    /// would have — and asks afresh, so an administrator who missed the first
    /// window gets a live question rather than a stale one.
    #[tokio::test]
    async fn a_poll_times_out_an_expired_question_and_asks_afresh() {
        let db = migrated_db().await;
        audit_events();
        let services = test_services(&db).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let user_info = someone();

        assert!(matches!(
            poll(&services, session_id, &user_info, "prod").await,
            PolledGate::Pending
        ));
        // Far past any window: the default timeout is the auth-state TTL.
        backdate_request(&db, session_id, Duration::from_secs(24 * 3600)).await;

        assert!(matches!(
            poll(&services, session_id, &user_info, "prod").await,
            PolledGate::Pending
        ));

        assert_eq!(
            status_of(&db, session_id, "prod").await,
            SessionApprovalRequest::ApprovalRequestStatus::Pending,
            "the expired question must have been asked afresh",
        );
        assert_eq!(
            audited_for(session_id, "SessionApprovalTimedOut1").len(),
            1,
            "the expiry itself must reach the audit trail",
        );
        assert_eq!(
            audited_for(session_id, "SessionApprovalRequested1").len(),
            2,
            "two askings, two announcements",
        );
    }

    /// A standing decision is reused, not re-asked — and *announcing* nothing
    /// is part of that: a gate that finds the answer already on the row must
    /// not put a `SessionApprovalRequested1` in the audit trail or ping the
    /// inbox for a question nobody is being asked.
    #[tokio::test]
    async fn a_standing_decision_is_reused_without_announcing() {
        let db = migrated_db().await;
        audit_events();
        let services = test_services(&db).await;
        let session_id = UserSessionId(Uuid::new_v4());
        let user_info = someone();

        assert!(matches!(
            poll(&services, session_id, &user_info, "prod").await,
            PolledGate::Pending
        ));
        assert!(approve(&db, session_id, "prod").await);

        // The blocking shape re-entering the same question: announce finds the
        // decision standing, and the wait reads it straight back.
        let outcome: GateOutcome = services
            .require_admin_approval(
                crate::TargetAuthorization::for_test(
                    user_info.clone(),
                    gated_target("prod"),
                    Protocol::Http,
                ),
                session_id,
                GatedConnection {
                    remote_ip: None,
                    credentials: RememberApprovalBy::Nothing,
                },
                || async { Ok::<_, WarpgateError>(()) },
            )
            .await
            .unwrap();
        assert!(matches!(outcome, GateOutcome::Approved(_)));

        assert_eq!(
            audited_for(session_id, "SessionApprovalRequested1").len(),
            1,
            "only the original asking may announce",
        );
    }

    /// What the advertiser reports is what the announcement decision rides on.
    #[tokio::test]
    async fn advertising_reports_what_it_did() {
        let db = migrated_db().await;
        let session_id = UserSessionId(Uuid::new_v4());
        let mut subject = plain_subject("prod");
        subject.session_id = session_id;
        let node = NodeId(Uuid::new_v4());

        let advertise = || super::super::wait::advertise_admin_request(&db, node, &subject);
        let started = || async {
            find_question(
                &db,
                SessionApprovalRequest::Key::new(session_id, ApprovalKind::Admin, "prod"),
            )
            .await
            .unwrap()
            .expect("the question should exist")
            .started
        };

        assert_eq!(advertise().await.unwrap(), Advertised::Asked);
        let asked_at = started().await;
        assert_eq!(advertise().await.unwrap(), Advertised::AlreadyAdvertised);
        assert_eq!(
            started().await,
            asked_at,
            "refreshing a live question must not reset its clock — that is the \
             reap anchor and the timeout anchor, and a re-advertise every few \
             seconds would push the window out forever",
        );

        close_request(
            &db,
            session_id,
            ApprovalKind::Admin,
            "prod",
            SessionApprovalRequest::UndecidedApprovalRequestStatus::TimedOut,
        )
        .await
        .unwrap();
        assert_eq!(
            advertise().await.unwrap(),
            Advertised::Asked,
            "a question that ended unanswered is asked afresh",
        );

        assert!(approve(&db, session_id, "prod").await);
        assert_eq!(
            advertise().await.unwrap(),
            Advertised::AlreadyAdvertised,
            "an answer on the row is not overwritten by asking again",
        );
    }
}
