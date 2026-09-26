use super::*;
use crate::Utf16StringExt;
use crate::ntlm::messages::test::*;
use crate::ntlm::*;

#[test]
fn write_negotiate_writes_correct_signature() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(NTLM_SIGNATURE, buff[SIGNATURE_START..MESSAGE_TYPE_START]);
}

#[test]
fn write_negotiate_writes_correct_message_type() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(NEGOTIATE_MESSAGE_TYPE, buff[MESSAGE_TYPE_START..NEGOTIATE_FLAGS_START]);
}

#[test]
fn write_negotiate_writes_flags() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_FLAGS.to_le_bytes(),
        buff[NEGOTIATE_FLAGS_START..NEGOTIATE_DOMAIN_NAME_START]
    );
    assert_eq!(NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap(), context.flags);
}

#[test]
fn write_negotiate_writes_domain_name() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_DOMAIN,
        buff[NEGOTIATE_DOMAIN_NAME_START..NEGOTIATE_WORKSTATION_START]
    );
}

#[test]
fn write_negotiate_writes_workstation() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_WORKSTATION,
        buff[NEGOTIATE_WORKSTATION_START..NEGOTIATE_VERSION_START]
    );
}

#[test]
fn write_negotiate_writes_version() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_VERSION,
        buff[NEGOTIATE_VERSION_START..NEGOTIATE_VERSION_START + NTLM_VERSION_SIZE]
    );
}

#[test]
fn write_negotiate_writes_buffer_to_context() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!((*LOCAL_NEGOTIATE_MESSAGE).as_ref(), buff.as_slice());
}

#[test]
fn write_negotiate_changes_context_state_on_success() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let expected_state = NtlmState::Challenge;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(expected_state, context.state);
}

#[test]
fn write_negotiate_failed_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;

    let mut buff = Vec::new();
    assert!(write_negotiate(&mut context, &mut buff).is_err());
}

#[test]
fn read_challenge_does_not_fail_with_correct_header() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();
}

#[test]
fn read_challenge_fails_with_incorrect_signature() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let mut buff = LOCAL_CHALLENGE_MESSAGE.to_vec();
    buff[1] += 1;
    assert!(read_challenge(&mut context, buff.as_slice()).is_err());
}

#[test]
fn read_challenge_fails_with_incorrect_message_type() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let mut buff = LOCAL_CHALLENGE_MESSAGE.to_vec();
    buff[8] = 3;
    assert!(read_challenge(&mut context, buff.as_slice()).is_err());
}

#[test]
fn read_challenge_reads_correct_flags() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_FLAGS.to_le_bytes(),
        buff[CHALLENGE_FLAGS_START..CHALLENGE_SERVER_CHALLENGE_START]
    );
    assert_eq!(NegotiateFlags::from_bits(LOCAL_CHALLENGE_FLAGS).unwrap(), context.flags);
}

#[test]
fn read_challenge_reads_correct_target_info() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_TARGET_INFO_BUFFER.as_ref(),
        context.challenge_message.unwrap().target_info.as_slice()
    );
}

#[test]
fn read_challenge_reads_correct_server_challenge() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_SERVER_CHALLENGE,
        context.challenge_message.unwrap().server_challenge
    );
}

#[test]
fn read_challenge_reads_correct_timestamp() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(LOCAL_CHALLENGE_TIMESTAMP, context.challenge_message.unwrap().timestamp);
}

#[test]
fn read_challenge_writes_buffer_to_context() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        (*LOCAL_CHALLENGE_MESSAGE).as_ref(),
        context.challenge_message.unwrap().message.as_slice()
    );
}

#[test]
fn read_challenge_fails_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    assert!(read_challenge(&mut context, buff.as_ref()).is_err());
}

#[test]
fn write_authenticate_writes_correct_header() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));
    let mut buff = Vec::new();
    let expected = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00];

    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[SIGNATURE_START..AUTHENTICATE_LM_CHALLENGE_RESPONSE_START],
        expected
    );
}

#[test]
fn write_authenticate_changes_context_state_on_success() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    let mut buff = Vec::new();
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));
    context.state = NtlmState::Authenticate;
    let expected_state = NtlmState::Final;

    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(context.state, expected_state);
}

#[test]
fn write_authenticate_correct_writes_domain_name() {
    let expected = [0x0c, 0x00, 0x0c, 0x00, 0x58, 0x00, 0x00, 0x00];
    let expected_buffer = [0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00];

    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[AUTHENTICATE_DOMAIN_NAME_START..AUTHENTICATE_USER_NAME_START],
        expected
    );
    assert_eq!(
        buff[AUTHENTICATE_OFFSET_WITH_MIC..AUTHENTICATE_OFFSET_WITH_MIC + TEST_CREDENTIALS.domain.as_bytes_le().len()],
        expected_buffer[..]
    );
}

#[test]
fn write_authenticate_correct_writes_user_name() {
    let expected = [0x08, 0x00, 0x08, 0x00, 0x64, 0x00, 0x00, 0x00];
    let expected_buffer = [0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00];

    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[AUTHENTICATE_USER_NAME_START..AUTHENTICATE_WORKSTATION_START],
        expected
    );
    let offset = AUTHENTICATE_OFFSET_WITH_MIC + TEST_CREDENTIALS.domain.as_bytes_le().len();
    assert_eq!(
        buff[offset..offset + TEST_CREDENTIALS.user.as_bytes_le().len()],
        expected_buffer[..]
    );
}

#[test]
fn write_authenticate_fails_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Final;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    assert!(write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).is_err());
}
