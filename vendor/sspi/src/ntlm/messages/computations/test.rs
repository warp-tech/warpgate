use time::{Date, Month, OffsetDateTime};

use crate::ntlm::messages::av_pair::*;
use crate::ntlm::messages::computations::*;
use crate::ntlm::messages::test::*;
use crate::{AuthIdentity, Username};

#[test]
fn get_system_time_as_file_time_test_one_second_diff() {
    let expected = 1000 * 1000 * 10;
    let end_date = Date::from_calendar_date(1601, Month::January, 1)
        .unwrap()
        .with_hms(0, 1, 2)
        .unwrap()
        .assume_utc();
    assert_eq!(convert_to_file_time(end_date).unwrap(), expected);
}

#[test]
fn get_system_time_as_file_time_test_start_date_is_bigger_than_end_date() {
    let end_date = Date::from_calendar_date(1601, Month::January, 1)
        .unwrap()
        .midnight()
        .assume_utc();
    assert!(convert_to_file_time(end_date).is_err());
}

#[test]
fn get_system_time_as_file_time_test_returns_value_in_correct_case() {
    let end_date = OffsetDateTime::now_utc();
    convert_to_file_time(end_date).unwrap();
}

#[test]
fn get_challenge_target_info_correct_writes_needed_values_with_timestamp() {
    let challenge_target_info_buffer = get_challenge_target_info(TIMESTAMP).unwrap();
    let mut av_pairs = AvPair::buffer_to_av_pairs(&challenge_target_info_buffer).unwrap();

    // check that does not have duplicates
    let len = av_pairs.len();
    av_pairs.dedup_by(|a, b| {
        let a: u16 = a.as_u16();
        let b: u16 = b.as_u16();
        a == b
    });
    assert_eq!(len, av_pairs.len());

    for av_pair in av_pairs.iter() {
        match av_pair {
            AvPair::Timestamp(value) => assert_eq!(*value, TIMESTAMP),
            AvPair::EOL => (),
            AvPair::NbDomainName(_value) => (),
            AvPair::NbComputerName(_value) => (),
            AvPair::DnsDomainName(_value) => (),
            AvPair::DnsComputerName(_value) => (),
            _ => unreachable!(),
        };
    }
}

#[test]
fn get_challenge_target_info_correct_writes_needed_values_with_empty_timestamp() {
    let challenge_target_info_buffer = get_challenge_target_info(TIMESTAMP).unwrap();
    let mut av_pairs = AvPair::buffer_to_av_pairs(&challenge_target_info_buffer).unwrap();

    // check that does not have duplicates
    let len = av_pairs.len();
    av_pairs.dedup_by(|a, b| {
        let a: u16 = a.as_u16();
        let b: u16 = b.as_u16();
        a == b
    });
    assert_eq!(len, av_pairs.len());

    for av_pair in av_pairs.iter() {
        match av_pair {
            AvPair::Timestamp(value) => assert_eq!(*value, TIMESTAMP),
            AvPair::EOL => (),
            AvPair::NbDomainName(_value) => (),
            AvPair::NbComputerName(_value) => (),
            AvPair::DnsDomainName(_value) => (),
            AvPair::DnsComputerName(_value) => (),
            _ => unreachable!(),
        };
    }
}

#[test]
fn get_authenticate_target_info_correct_returns_with_use_mic() {
    let send_single_host_data = false;
    let target_info = get_challenge_target_info(TIMESTAMP).unwrap();

    let mut authenticate_target_info =
        get_authenticate_target_info(target_info.as_ref(), None, send_single_host_data).unwrap();

    assert_eq!(
        authenticate_target_info[authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE..],
        [0x00; AUTHENTICATE_TARGET_INFO_PADDING_SIZE]
    );
    authenticate_target_info.resize(
        authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE,
        0x00,
    );
    let mut av_pairs = AvPair::buffer_to_av_pairs(&authenticate_target_info).unwrap();

    // check that does not have duplicates
    let len = av_pairs.len();
    av_pairs.dedup_by(|a, b| {
        let a: u16 = a.as_u16();
        let b: u16 = b.as_u16();
        a == b
    });
    assert_eq!(len, av_pairs.len());

    for av_pair in av_pairs.iter() {
        match av_pair {
            AvPair::Timestamp(value) => assert_eq!(*value, TIMESTAMP),
            AvPair::Flags(value) => assert_eq!(*value, MsvAvFlags::MESSAGE_INTEGRITY_CHECK.bits()),
            AvPair::EOL => (),
            AvPair::NbDomainName(_value) => (),
            AvPair::NbComputerName(_value) => (),
            AvPair::DnsDomainName(_value) => (),
            AvPair::DnsComputerName(_value) => (),
            _ => unreachable!(),
        };
    }
}

#[test]
fn get_authenticate_target_info_correct_returns_with_send_single_host_data() {
    let send_single_host_data = true;
    let target_info = get_challenge_target_info(TIMESTAMP).unwrap();

    let mut authenticate_target_info =
        get_authenticate_target_info(target_info.as_ref(), None, send_single_host_data).unwrap();

    assert_eq!(
        authenticate_target_info[authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE..],
        [0x00; AUTHENTICATE_TARGET_INFO_PADDING_SIZE]
    );
    authenticate_target_info.resize(
        authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE,
        0x00,
    );
    let mut av_pairs = AvPair::buffer_to_av_pairs(&authenticate_target_info).unwrap();

    // check that does not have duplicates
    let len = av_pairs.len();
    av_pairs.dedup_by(|a, b| {
        let a: u16 = a.as_u16();
        let b: u16 = b.as_u16();
        a == b
    });
    assert_eq!(len, av_pairs.len());

    for av_pair in av_pairs.iter() {
        match av_pair {
            AvPair::Timestamp(value) => assert_eq!(*value, TIMESTAMP),
            AvPair::SingleHost(value) => assert_eq!(value[..], SINGLE_HOST_DATA[..]),
            AvPair::EOL => (),
            AvPair::Flags(value) => assert_eq!(*value, MsvAvFlags::MESSAGE_INTEGRITY_CHECK.bits()),
            AvPair::NbDomainName(_value) => (),
            AvPair::NbComputerName(_value) => (),
            AvPair::DnsDomainName(_value) => (),
            AvPair::DnsComputerName(_value) => (),
            _ => unreachable!(),
        };
    }
}

#[test]
fn get_authenticate_target_info_returns_without_principal_name() {
    let send_single_host_data = false;
    let target_info = get_challenge_target_info(TIMESTAMP).unwrap();

    let mut authenticate_target_info =
        get_authenticate_target_info(target_info.as_ref(), None, send_single_host_data).unwrap();

    assert_eq!(
        authenticate_target_info[authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE..],
        [0x00; AUTHENTICATE_TARGET_INFO_PADDING_SIZE]
    );
    authenticate_target_info.resize(
        authenticate_target_info.len() - AUTHENTICATE_TARGET_INFO_PADDING_SIZE,
        0x00,
    );
    let mut av_pairs = AvPair::buffer_to_av_pairs(&authenticate_target_info).unwrap();

    // check that does not have duplicates
    let len = av_pairs.len();
    av_pairs.dedup_by(|a, b| {
        let a: u16 = a.as_u16();
        let b: u16 = b.as_u16();
        a == b
    });
    assert_eq!(len, av_pairs.len());

    for av_pair in av_pairs.iter() {
        match av_pair {
            AvPair::Timestamp(value) => assert_eq!(*value, TIMESTAMP),
            AvPair::EOL => (),
            AvPair::Flags(value) => assert_eq!(*value, MsvAvFlags::MESSAGE_INTEGRITY_CHECK.bits()),
            AvPair::NbDomainName(_value) => (),
            AvPair::NbComputerName(_value) => (),
            AvPair::DnsDomainName(_value) => (),
            AvPair::DnsComputerName(_value) => (),
            _ => unreachable!(),
        };
    }
}

#[test]
fn compute_ntlmv2_hash_password_is_less_than_hash_len_offset() {
    let expected = [
        0xc, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x0, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f,
    ];

    assert_eq!(compute_ntlm_v2_hash(&TEST_CREDENTIALS).unwrap(), expected);
}

#[test]
fn compute_ntlmv2_hash_password_local_logon() {
    let identity = AuthIdentity {
        username: Username::new("username", Some("win7")).unwrap(),
        password: String::from("password").into(),
    }
    .into();

    let expected = [
        0xef, 0xc2, 0xc0, 0x9f, 0x06, 0x11, 0x3d, 0x71, 0x08, 0xd0, 0xd2, 0x29, 0xfa, 0x4d, 0xe6, 0x98,
    ];

    assert_eq!(compute_ntlm_v2_hash(&identity).unwrap(), expected);
}

#[test]
fn compute_ntlmv2_hash_password_domain_logon() {
    let identity = AuthIdentity {
        username: Username::new("Administrator", Some("AWAKECODING")).unwrap(),
        password: String::from("Password123!").into(),
    }
    .into();

    let expected = [
        0xf7, 0x46, 0x48, 0xaa, 0x78, 0x78, 0x2e, 0x92, 0x0f, 0x92, 0x9a, 0xed, 0x7f, 0x1d, 0xd5, 0x23,
    ];

    assert_eq!(compute_ntlm_v2_hash(&identity).unwrap(), expected);
}

#[test]
fn compute_ntlmv2_hash_works_on_empty_password() {
    let identity = AuthIdentity {
        username: Username::new("Administrator", Some("AWAKECODING")).unwrap(),
        password: String::new().into(),
    }
    .into();

    let expected = [
        0xa0, 0x84, 0x29, 0x48, 0xa6, 0xb9, 0xac, 0xa7, 0x6c, 0xf5, 0x54, 0xdb, 0x5e, 0xc3, 0x17, 0x76,
    ];

    assert_eq!(compute_ntlm_v2_hash(&identity).unwrap(), expected);
}

#[test]
#[should_panic]
fn compute_ntlmv2_hash_fails_on_empty_identity() {
    assert!(compute_ntlm_v2_hash(&TEST_CREDENTIALS).is_err());
}

#[test]
fn compute_lm_v2_repsonse_correct_computes_response() {
    let ntlm_v2_hash = compute_ntlm_v2_hash(&TEST_CREDENTIALS).unwrap();
    let client_challenge = CLIENT_CHALLENGE.as_ref();
    let server_challenge = SERVER_CHALLENGE.as_ref();

    let mut expected = vec![
        0x5e, 0xc3, 0xc5, 0x2e, 0xe7, 0x5a, 0x23, 0x45, 0x73, 0x72, 0xd8, 0x2b, 0x43, 0xea, 0xc4, 0x26,
    ];
    expected.extend(client_challenge);

    assert_eq!(
        compute_lm_v2_response(client_challenge, server_challenge, ntlm_v2_hash.as_ref()).unwrap(),
        expected.as_slice()
    );
}

#[test]
fn compute_ntlm_v2_repsonse_correct_computes_challenge_response() {
    let server_challenge = SERVER_CHALLENGE;
    let client_challenge = CLIENT_CHALLENGE;
    let target_info = Vec::new();
    let ntlm_v2_hash = compute_ntlm_v2_hash(&TEST_CREDENTIALS).unwrap();
    let timestamp = TIMESTAMP;

    let expected = [
        0xa8, 0x38, 0x98, 0x9e, 0xdc, 0xbe, 0xcf, 0x8d, 0xb7, 0x5c, 0x14, 0x85, 0x26, 0xa0, 0x2a, 0xf9, 0x1, 0x1, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7, 0x8b, 0xcf, 0x1, 0x20, 0xc0, 0x2b, 0x3d, 0xc0, 0x61,
        0xa7, 0x73, 0x0, 0x0, 0x0, 0x0,
    ];

    let (nt_challenge_response, _) = compute_ntlm_v2_response(
        client_challenge.as_ref(),
        server_challenge.as_ref(),
        target_info.as_ref(),
        ntlm_v2_hash.as_ref(),
        timestamp,
    )
    .unwrap();
    assert_eq!(nt_challenge_response[..], expected[..]);
}

#[test]
fn compute_ntlm_v2_repsonse_correct_computes_key_exchange_key() {
    let server_challenge = SERVER_CHALLENGE;
    let client_challenge = CLIENT_CHALLENGE;
    let target_info = Vec::new();
    let ntlm_v2_hash = compute_ntlm_v2_hash(&TEST_CREDENTIALS).unwrap();
    let timestamp = TIMESTAMP;

    let expected = [
        0x72, 0xe5, 0x3e, 0x4b, 0x89, 0x18, 0xc9, 0x8f, 0xda, 0xfb, 0xa0, 0x74, 0x6, 0x61, 0xbc, 0x9f,
    ];

    let (_, key_exchange_key) = compute_ntlm_v2_response(
        client_challenge.as_ref(),
        server_challenge.as_ref(),
        target_info.as_ref(),
        ntlm_v2_hash.as_ref(),
        timestamp,
    )
    .unwrap();

    assert_eq!(key_exchange_key, expected);
}

#[test]
fn get_av_flags_from_response_returns_empty_flags_if_flags_are_absent() {
    let input_flags = vec![AvPair::Timestamp(0), AvPair::EOL];

    let expected_flags = MsvAvFlags::empty();

    let buffer = AvPair::list_to_buffer(input_flags.as_ref()).unwrap();
    let av_pairs = AvPair::buffer_to_av_pairs(&buffer).unwrap();

    let flags = get_av_flags_from_response(&av_pairs).unwrap();

    assert_eq!(expected_flags, flags);
}

#[test]
fn av_pair_list_to_buffer_with_all_possible_pairs() {
    let expected_buffer = [
        0x1, 0x0, 0xe, 0x0, 0x4e, 0x62, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x2,
        0x0, 0xc, 0x0, 0x4e, 0x62, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x3, 0x0, 0xf, 0x0,
        0x44, 0x6e, 0x73, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x4, 0x0, 0xd, 0x0,
        0x44, 0x6e, 0x73, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x5, 0x0, 0xb, 0x0, 0x44, 0x6e,
        0x73, 0x54, 0x72, 0x65, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x6, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x8,
        0x0, 0xd2, 0x2, 0x96, 0x49, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x30, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0x9, 0x0, 0xa, 0x0, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0xa, 0x0,
        0x10, 0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0,
        0x0, 0x0, 0x0,
    ];

    let nb_computer_name = b"NbComputerName".to_vec();
    let nb_domain_name = b"NbDomainName".to_vec();
    let dns_computer_name = b"DnsComputerName".to_vec();
    let dns_domain_name = b"DnsDomainName".to_vec();
    let dns_tree_name = b"DnsTreeName".to_vec();
    let flags = 0;
    let timestamp = 1_234_567_890;
    let single_host_data = *SINGLE_HOST_DATA;
    let target_name = b"TargetName".to_vec();
    let channel_bindings = [0xff; HASH_SIZE];

    let av_pairs = vec![
        AvPair::NbComputerName(nb_computer_name),
        AvPair::NbDomainName(nb_domain_name),
        AvPair::DnsComputerName(dns_computer_name),
        AvPair::DnsDomainName(dns_domain_name),
        AvPair::DnsTreeName(dns_tree_name),
        AvPair::Flags(flags),
        AvPair::Timestamp(timestamp),
        AvPair::SingleHost(single_host_data),
        AvPair::TargetName(target_name),
        AvPair::ChannelBindings(channel_bindings),
        AvPair::EOL,
    ];

    let av_pairs_buffer = AvPair::list_to_buffer(av_pairs.as_ref()).unwrap();

    assert_eq!(expected_buffer.as_ref(), av_pairs_buffer.as_slice());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_flags_size() {
    let buffer = [0x6, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_timestamp_size() {
    let buffer = [0x7, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_eol_size() {
    let buffer = [0x0, 0x0, 0x1, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_single_host_data_size() {
    let buffer = [0x8, 0x0, 0x1, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_channel_bindings_size() {
    let buffer = [0xa0, 0x0, 0x1, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}

#[test]
fn av_pair_from_buffer_fails_on_invalid_av_type() {
    let buffer = [0xa1, 0x0, 0x1, 0x0, 0x0];
    assert!(AvPair::from_buffer(buffer.as_ref()).is_err());
}
