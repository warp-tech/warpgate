//! Keep each user's Oracle O5LOGON verifier in sync with their Warpgate password.
//!
//! Oracle thin login (O5LOGON) is a *mutual* challenge/response: the gateway can
//! only complete a client's login if it holds a verifier derived from the
//! password. Unlike SSH or HTTP, the password never crosses the wire in
//! cleartext, so Warpgate's one-way Argon2 password hash cannot be used to prove
//! it to the database. To let users reach Oracle targets with their ordinary
//! Warpgate password, every place that sets a user's password also calls
//! [`sync_oracle_verifier_from_password`], which derives the 12c verifier from
//! that same plaintext. The Oracle login still checks the password it recovers
//! against the user's Argon2 password credential; the verifier only exists to
//! make the O5LOGON exchange possible.
//!
//! The trade-off: the verifier is a password-equivalent PBKDF2-SHA512 hash with
//! 4096 iterations, far cheaper to brute-force than the Argon2 hash. It is
//! therefore stored only while the Oracle listener is enabled
//! (`store.oracle.enable`). Users whose password was set before Oracle was
//! enabled have no verifier and need their password set again before they can
//! log in over Oracle. Disabling the listener does not purge stored verifiers;
//! each one is dropped the next time that user's password is set or deleted
//! (see [`delete_oracle_verifier`]). The plaintext is never persisted.

use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{Secret, WarpgateError};
use warpgate_db_entities::OracleCredential;
use warpgate_oracle_tns::o5logon::Verifier12c;

/// Standard Oracle 12c PBKDF2 iteration counts: `AUTH_PBKDF2_VGEN_COUNT` for the
/// password-key stretch and `AUTH_PBKDF2_SDER_COUNT` for the combo-key step.
const VGEN_COUNT: u32 = 4096;
const SDER_COUNT: u32 = 3;

/// Replace the user's Oracle verifier after their Warpgate password was set.
///
/// The previous verifier is always deleted. A new one is derived from
/// `password` and stored only when `oracle_enabled` (the Oracle listener is
/// on), so no password-equivalent PBKDF2 hash is kept where Oracle is unused.
/// Fresh random salts are generated per call and the plaintext is used only to
/// derive the verifier — never stored or logged.
pub async fn sync_oracle_verifier_from_password<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    password: &Secret<String>,
    oracle_enabled: bool,
) -> Result<(), WarpgateError> {
    // One verifier per user: the Oracle session resolves it with a single-row
    // lookup, and a verifier for an old password must not outlive it.
    delete_oracle_verifier(db, user_id).await?;

    if !oracle_enabled {
        return Ok(());
    }

    let vfr_data: [u8; 16] = std::array::from_fn(|_| rand::random());
    let csk_salt: [u8; 16] = std::array::from_fn(|_| rand::random());
    let verifier = Verifier12c::from_password(
        password.expose_secret().as_bytes(),
        vfr_data,
        VGEN_COUNT,
        csk_salt,
        SDER_COUNT,
    );

    OracleCredential::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        vfr_data: Set(hex::encode(verifier.vfr_data)),
        vgen_count: Set(verifier.vgen_count as i32),
        csk_salt: Set(hex::encode(verifier.csk_salt)),
        sder_count: Set(verifier.sder_count as i32),
        password_key: Set(hex::encode(verifier.password_key)),
    }
    .insert(db)
    .await
    .map_err(WarpgateError::from)?;

    Ok(())
}

/// Delete the user's Oracle verifier. Call this wherever a password credential
/// is deleted so the verifier never outlives the password it was derived from.
pub async fn delete_oracle_verifier<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
) -> Result<(), WarpgateError> {
    OracleCredential::Entity::delete_many()
        .filter(OracleCredential::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(WarpgateError::from)?;
    Ok(())
}
