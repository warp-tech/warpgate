#![allow(clippy::result_large_err)]

mod context_validator;
pub(super) mod kdc;
pub(super) mod network_client;

use std::collections::{HashMap, HashSet};
use std::panic;

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::MechTypeList;
use sspi::credssp::SspiContext;
use sspi::kerberos::ServerProperties;
use sspi::network_client::NetworkClient;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, Credentials, CredentialsBuffers, DataRepresentation, Kerberos,
    KerberosConfig, KerberosServerConfig, Negotiate, NegotiateConfig, NegotiatedProtocol, SecurityBuffer,
    SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};
use url::Url;

use crate::client_server::kerberos::context_validator::{
    EmptySspiContextValidator, SpnegoKerberosContextValidator, SpnegoKerberosNtlmFallbackValidator,
    SpnegoServerNtlmFallbackValidator, SspiContextValidator,
};
use crate::client_server::kerberos::kdc::{
    CLIENT_COMPUTER_NAME, KDC_URL, KdcMock, MAX_TIME_SKEW, PasswordCreds, SERVER_COMPUTER_NAME, UserName, Validators,
};
use crate::client_server::kerberos::network_client::{FailedNetworkClientMock, NetworkClientMock};
use crate::client_server::{test_encryption, test_rpc_request_encryption, test_stream_buffer_encryption};

/// Represents a Kerberos environment:
/// * user and services keys;
/// * user logon credentials;
/// * realm and target application service name;
///
/// It is used for simplifying tests environment preparation.
pub(super) struct KrbEnvironment {
    pub keys: HashMap<UserName, Vec<u8>>,
    pub users: HashMap<UserName, PasswordCreds>,
    pub credentials: Credentials,
    pub realm: String,
    pub target_name: String,
    pub target_service_name: PrincipalName,
}

/// Initializes a Kerberos environment. It includes:
/// * User logon credentials (password-based).
/// * Kerberos services keys.
/// * Target machine name.
pub(super) fn init_krb_environment() -> KrbEnvironment {
    let username = "pw13";
    let user_password = "qweQWE123!@#";
    let domain = "EXAMPLE";
    let realm = "EXAMPLE.COM";
    let mut salt = realm.to_string();
    salt.push_str(username);
    let krbtgt = "krbtgt";
    let termsrv = "TERMSRV";
    let target_machine_name = "DESKTOP-8F33RFH.example.com";
    let mut target_name = termsrv.to_string();
    target_name.push('/');
    target_name.push_str(target_machine_name);

    let tgt_service_key = vec![
        199, 133, 201, 239, 57, 139, 61, 128, 71, 236, 217, 130, 250, 148, 117, 193, 197, 86, 155, 11, 92, 124, 232,
        146, 3, 14, 158, 220, 113, 63, 110, 230,
    ];
    let application_service_key = vec![
        168, 29, 77, 196, 211, 88, 148, 180, 123, 188, 196, 182, 173, 30, 249, 191, 89, 35, 44, 56, 20, 217, 132, 131,
        89, 144, 33, 79, 16, 91, 126, 72,
    ];
    let keys = [
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(krbtgt.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(domain.into()).unwrap()),
                ])),
            }),
            tgt_service_key.clone(),
        ),
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(krbtgt.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(realm.to_string()).unwrap()),
                ])),
            }),
            tgt_service_key,
        ),
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(termsrv.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(target_machine_name.into()).unwrap()),
                ])),
            }),
            application_service_key,
        ),
    ]
    .into_iter()
    .collect();
    let users = [(
        UserName(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string(username.into()).unwrap(),
            )])),
        }),
        PasswordCreds {
            password: user_password.as_bytes().to_vec(),
            salt,
        },
    )]
    .into_iter()
    .collect();

    let credentials = Credentials::AuthIdentity(AuthIdentity {
        username: Username::new_down_level_logon_name(username, domain).unwrap(),
        password: user_password.to_owned().into(),
    });

    KrbEnvironment {
        keys,
        users,
        realm: realm.to_string(),
        credentials,
        target_name,
        target_service_name: PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string("TERMSRV".into()).unwrap()),
                KerberosStringAsn1::from(IA5String::from_string("DESKTOP-8F33RFH.example.com".into()).unwrap()),
            ])),
        },
    }
}

/// Does all preparations and calls the [initialize_security_context_impl] function
/// on the provided Kerberos context.
pub(super) fn initialize_security_context(
    client: &mut SspiContext,
    credentials_handle: &mut Option<CredentialsBuffers>,
    flags: ClientRequestFlags,
    target_name: &str,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> (SecurityStatus, Vec<u8>) {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let mut builder = client
        .initialize_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(target_name)
        .with_input(&mut input_token)
        .with_output(&mut output_token);
    let result = client
        .initialize_security_context_impl(&mut builder)
        .expect("Kerberos initialize_security_context should not fail")
        .resolve_with_client(network_client)
        .expect("Kerberos initialize_security_context should not fail");

    (result.status, output_token.remove(0).buffer)
}

/// Does all preparations and calls the [accept_security_context] function
/// on the provided Kerberos context.
pub(super) fn accept_security_context(
    server: &mut SspiContext,
    credentials_handle: &mut Option<CredentialsBuffers>,
    flags: ServerRequestFlags,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> (SecurityStatus, Vec<u8>) {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let builder = server
        .accept_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input_token)
        .with_output(&mut output_token);
    let result = server
        .accept_security_context_impl(builder)
        .expect("Kerberos accept_security_context should not fail")
        .resolve_with_client(network_client)
        .expect("Kerberos accept_security_context should not fail");

    (result.status, output_token.remove(0).buffer)
}

#[expect(clippy::too_many_arguments, reason = "many arguments are acceptable in test helpers")]
fn run_kerberos(
    client: &mut SspiContext,
    client_credentials_handle: &mut Option<CredentialsBuffers>,
    client_flags: ClientRequestFlags,
    target_name: &str,

    server: &mut SspiContext,
    server_credentials_handle: &mut Option<CredentialsBuffers>,
    server_flags: ServerRequestFlags,

    network_client: &mut dyn NetworkClient,
    steps: usize,
    mut context_validator: impl SspiContextValidator,
) {
    let mut client_in_token = Vec::new();

    for step in 0..steps {
        let (client_status, token) = initialize_security_context(
            client,
            client_credentials_handle,
            client_flags,
            target_name,
            client_in_token,
            network_client,
        );

        context_validator.validate_client(step, client);

        if client_status == SecurityStatus::Ok {
            if !token.is_empty() {
                accept_security_context(server, server_credentials_handle, server_flags, token, network_client);
            }

            test_encryption(client, server);
            test_stream_buffer_encryption(client, server);
            test_rpc_request_encryption(client, server);
            return;
        }

        let (_, token) =
            accept_security_context(server, server_credentials_handle, server_flags, token, network_client);
        client_in_token = token;
    }

    panic!("Kerberos authentication should not exceed {steps} steps");
}

#[test]
fn kerberos_auth() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|tgs_req| {
                // Here, we should check that the Kerberos client does not negotiated Kerberos U2U auth and not enabled any unneeded flags.

                let kdc_options = tgs_req.0.req_body.kdc_options.0.0.as_bytes();
                // enc-tkt-in-skey must be disabled.
                assert_eq!(kdc_options[4], 0x00, "some unneeded KDC options are enabled");

                let additional_tickets = tgs_req
                    .0
                    .req_body
                    .0
                    .additional_tickets
                    .0
                    .as_ref()
                    .map(|additional_tickets| additional_tickets.0.0.as_slice());
                assert!(
                    matches!(additional_tickets, None | Some(&[])),
                    "TgsReq should not contain any additional tickets"
                );
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let kerberos_client = Kerberos::new_client_from_config(client_config).unwrap();

    let server_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: None,
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server = Kerberos::new_server_from_config(server_config, server_properties).unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Kerberos(kerberos_client),
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut SspiContext::Kerberos(kerberos_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        2,
        EmptySspiContextValidator,
    );
}

#[test]
fn spnego_kerberos_u2u() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|_tgs_req| {
                // Nothing to validate in TgsReq.
                //
                // Previously, we were able to validate the presence of the additional ticket and enc-tkt-in-skey flag.
                // But since we use a preflight Kerberos exchange to check if the Kerberos is possible,
                // we can no longer do that.
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let spnego_client = Negotiate::new_client(NegotiateConfig::new(
        Box::new(client_config.clone()),
        Some(String::from("kerberos,!ntlm")),
        CLIENT_COMPUTER_NAME.into(),
    ))
    .unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();

    let server_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: Some(credentials.clone()),
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let spnego_server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(kerberos_server_config),
            Some(String::from("kerberos,!ntlm")),
            SERVER_COMPUTER_NAME.into(),
        ),
        vec![identity_1, identity_2],
    )
    .unwrap();

    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_SESSION_KEY // Kerberos U2U auth
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_SESSION_KEY // Kerberos U2U auth
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Negotiate(spnego_client),
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut SspiContext::Negotiate(spnego_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        3,
        SpnegoKerberosContextValidator,
    );
}

fn run_spnego(
    client_flags: ClientRequestFlags,
    server_flags: ServerRequestFlags,
    steps: usize,
    get_network_client: impl Fn(KdcMock) -> Box<dyn NetworkClient>,
    client_package_list: Option<String>,
    server_package_list: Option<String>,
    context_validator: impl SspiContextValidator,
) -> (SspiContext, SspiContext) {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|_tgs_req| {
                // Nothing to validate in TgsReq.
            }),
        },
    );
    let mut network_client = get_network_client(kdc);

    let client_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let mut spnego_client = SspiContext::Negotiate(
        Negotiate::new_client(NegotiateConfig::new(
            Box::new(client_config.clone()),
            client_package_list.clone(),
            CLIENT_COMPUTER_NAME.into(),
        ))
        .unwrap(),
    );

    let server_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: None,
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let mut spnego_server = SspiContext::Negotiate(
        Negotiate::new_server(
            NegotiateConfig::new(
                Box::new(kerberos_server_config),
                server_package_list.clone(),
                SERVER_COMPUTER_NAME.into(),
            ),
            vec![identity_1, identity_2],
        )
        .unwrap(),
    );

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    run_kerberos(
        &mut spnego_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut spnego_server,
        &mut server_credentials_handle,
        server_flags,
        &mut *network_client,
        steps,
        context_validator,
    );

    (spnego_client, spnego_server)
}

#[test]
fn spnego_kerberos_1() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        3,
        |kdc| Box::new(NetworkClientMock { kdc }),
        package_list.clone(),
        package_list,
        SpnegoKerberosContextValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Kerberos(_)),);
}

#[test]
fn spnego_kerberos_dce_style() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_DCE_STYLE
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_DCE_STYLE
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        4,
        |kdc| Box::new(NetworkClientMock { kdc }),
        package_list.clone(),
        package_list,
        SpnegoKerberosContextValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Kerberos(_)),);
}

#[test]
fn spnego_kerberos_ntlm_fallback() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    for kind in sspi::FALLBACK_ERROR_KINDS {
        let (client, _server) = run_spnego(
            client_flags,
            server_flags,
            4,
            |_| Box::new(FailedNetworkClientMock { kind }),
            package_list.clone(),
            package_list.clone(),
            SpnegoKerberosNtlmFallbackValidator,
        );

        let SspiContext::Negotiate(negotiate) = client else {
            panic!("client must be a Negotiate context");
        };
        let negotiated_protocol = negotiate.negotiated_protocol();

        assert!(
            matches!(negotiated_protocol, NegotiatedProtocol::Ntlm(_)),
            "Client should fallback to NTLM if Kerberos fails with {kind:?} error"
        );
    }
}

#[test]
fn spnego_kerberos_server_ntlm_fallback() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let client_package_list = Some(String::from("kerberos,ntlm"));
    let server_package_list = Some(String::from("!kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        4,
        |kdc| Box::new(NetworkClientMock { kdc }),
        client_package_list,
        server_package_list,
        SpnegoServerNtlmFallbackValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Ntlm(_)),);
}

// This test ensures that the client falls back to NTLM when the SPN is an IP address, which is not supported by Kerberos.
#[test]
fn spnego_kerberos_ntlm_fallback_spn_ip_address() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name: _,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                panic!("AS_REQ should not be sent when the SPN is an IP address");
            }),
            tgs_req: Box::new(|_tgs_req| {
                panic!("TGS_REQ should not be sent when the SPN is an IP address");
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let spnego_client = Negotiate::new_client(NegotiateConfig::new(
        Box::new(client_config.clone()),
        Some(String::from("kerberos,ntlm")),
        CLIENT_COMPUTER_NAME.into(),
    ))
    .unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();

    let server_config = KerberosConfig {
        kdc_url: Some(Url::parse(KDC_URL).unwrap()),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: Some(credentials.clone()),
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let spnego_server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(kerberos_server_config),
            Some(String::from("kerberos,ntlm")),
            SERVER_COMPUTER_NAME.into(),
        ),
        vec![identity_1, identity_2],
    )
    .unwrap();

    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_SESSION_KEY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_SESSION_KEY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Negotiate(spnego_client),
        &mut client_credentials_handle,
        client_flags,
        // The client must fallback to NTLM when the SPN is an IP address.
        "TERMSRV/192.168.1.104",
        &mut SspiContext::Negotiate(spnego_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        3,
        SpnegoKerberosNtlmFallbackValidator,
    );
}
