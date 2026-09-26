use tracing::debug;

use crate::SecurityStatus;
use crate::auth_identity::AuthIdentityBuffers;
use crate::crypto::{HASH_SIZE, Rc4};
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::{CLIENT_SEAL_MAGIC, CLIENT_SIGN_MAGIC, SERVER_SEAL_MAGIC, SERVER_SIGN_MAGIC};
use crate::ntlm::{MESSAGE_INTEGRITY_CHECK_SIZE, Mic, NegotiateFlags, Ntlm, NtlmState, SESSION_KEY_SIZE};

pub(crate) fn complete_authenticate(context: &mut Ntlm) -> crate::Result<SecurityStatus> {
    if context.state == NtlmState::Final {
        return Ok(SecurityStatus::Ok);
    }

    if context.state != NtlmState::Completion {
        return Err(crate::Error::new(
            crate::ErrorKind::OutOfSequence,
            String::from("Complete authenticate was fired but the state is not a Completion"),
        ));
    }

    let negotiate_message = context
        .negotiate_message
        .as_ref()
        .expect("negotiate message must be set on negotiate phase");
    let challenge_message = context
        .challenge_message
        .as_ref()
        .expect("challenge message must be set on challenge phase");
    let authenticate_message = context
        .authenticate_message
        .as_ref()
        .expect("authenticate message must be set on authenticate phase");

    let candidates = context.allowed_identities.as_ref().ok_or_else(|| {
        crate::Error::new(
            crate::ErrorKind::LogonDenied,
            String::from("no identity available for authentication"),
        )
    })?;

    // The NTLMv2 hash must use the client's wire user/domain (from the
    // authenticate message), not the candidate's. The client computed its
    // hash with its own user/domain encoding (e.g. full UPN as user with
    // empty domain), so the server must match that exactly.
    let wire_identity = context
        .identity
        .as_ref()
        .expect("identity must be set before complete_authenticate");

    for (i, identity) in candidates.iter().enumerate() {
        let candidate = AuthIdentityBuffers {
            user: wire_identity.user.clone(),
            domain: wire_identity.domain.clone(),
            password: identity.password.clone(),
        };
        let ntlm_v2_hash = match compute_ntlm_v2_hash(&candidate) {
            Ok(hash) => hash,
            Err(e) => {
                debug!(?e, "candidate skipped: compute_ntlm_v2_hash failed");
                continue;
            }
        };
        let (_, key_exchange_key) = match compute_ntlm_v2_response(
            authenticate_message.client_challenge.as_ref(),
            challenge_message.server_challenge.as_ref(),
            authenticate_message.target_info.as_ref(),
            ntlm_v2_hash.as_ref(),
            challenge_message.timestamp,
        ) {
            Ok(result) => result,
            Err(e) => {
                debug!(?e, "candidate skipped: compute_ntlm_v2_response failed");
                continue;
            }
        };
        let session_key = match authenticate_message.encrypted_random_session_key.map_or(
            Ok(key_exchange_key),
            |encrypted_random_session_key| {
                get_session_key(key_exchange_key, &encrypted_random_session_key, context.flags)
            },
        ) {
            Ok(key) => key,
            Err(e) => {
                debug!(?e, "candidate skipped: get_session_key failed");
                continue;
            }
        };

        if check_mic_correctness(
            negotiate_message.message.as_ref(),
            challenge_message.message.as_ref(),
            authenticate_message.message.as_ref(),
            &authenticate_message.mic,
            session_key.as_ref(),
        )
        .is_ok()
        {
            context.send_signing_key = generate_signing_key(session_key.as_ref(), SERVER_SIGN_MAGIC);
            context.recv_signing_key = generate_signing_key(session_key.as_ref(), CLIENT_SIGN_MAGIC);
            context.send_sealing_key = Some(Rc4::new(
                generate_signing_key(session_key.as_ref(), SERVER_SEAL_MAGIC).as_ref(),
            ));
            context.recv_sealing_key = Some(Rc4::new(
                generate_signing_key(session_key.as_ref(), CLIENT_SEAL_MAGIC).as_ref(),
            ));

            // Replace identity with the matched candidate (wire user/domain
            // + matched password). This overwrites the original wire-only
            // identity so downstream consumers get the authenticated result.
            debug!(candidate_index = i, "credential candidate matched");
            context.identity = Some(candidate);
            context.session_key = Some(session_key);
            context.state = NtlmState::Final;

            return Ok(SecurityStatus::Ok);
        }
    }

    Err(crate::Error::new(
        crate::ErrorKind::LogonDenied,
        String::from("no candidate credential matched"),
    ))
}

fn check_mic_correctness(
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
    mic: &Option<Mic>,
    exported_session_key: &[u8],
) -> crate::Result<()> {
    if mic.is_some() {
        // Client calculates the MIC with the authenticate message
        // without the MIC ([0x00;16] instead of data),
        // so for check correctness of the MIC,
        // we need empty the MIC part of auth. message and then will come back the MIC.
        let mic = mic.as_ref().unwrap();
        let mut authenticate_message = authenticate_message.to_vec();
        authenticate_message[mic.offset as usize..mic.offset as usize + MESSAGE_INTEGRITY_CHECK_SIZE]
            .clone_from_slice(&[0x00; MESSAGE_INTEGRITY_CHECK_SIZE]);
        let calculated_mic = compute_message_integrity_check(
            negotiate_message,
            challenge_message,
            authenticate_message.as_ref(),
            exported_session_key,
        )?;

        if mic.value != calculated_mic {
            return Err(crate::Error::new(
                crate::ErrorKind::MessageAltered,
                String::from("Message Integrity Check (MIC) verification failed!"),
            ));
        }
    }

    Ok(())
}

fn get_session_key(
    key_exchange_key: [u8; HASH_SIZE],
    encrypted_random_session_key: &[u8],
    flags: NegotiateFlags,
) -> crate::Result<[u8; SESSION_KEY_SIZE]> {
    let session_key = if flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH) {
        let mut session_key = [0x00; SESSION_KEY_SIZE];
        session_key.clone_from_slice(
            Rc4::new(key_exchange_key.as_ref())
                .process(encrypted_random_session_key)
                .as_slice(),
        );

        session_key
    } else {
        key_exchange_key
    };

    Ok(session_key)
}
