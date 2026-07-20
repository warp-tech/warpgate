use std::str::FromStr;

use bitflags;
use md5::{Digest, Md5};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ExplicitContextTag9, ExplicitContextTag11, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::AUTHENTICATOR_CHECKSUM_TYPE;
use picky_krb::constants::key_usages::{
    AP_REP_ENC, AP_REQ_AUTHENTICATOR, KRB_PRIV_ENC_PART, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::constants::types::{
    AD_AUTH_DATA_AP_OPTION_TYPE, AP_REP_MSG_TYPE, AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, KERB_AP_OPTIONS_CBT, KRB_PRIV,
    NET_BIOS_ADDR_TYPE, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE,
    PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE, TGT_REQ_MSG_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncApRepPart,
    EncApRepPartInner, EncKrbPrivPart, EncKrbPrivPartInner, EncryptedData, EncryptionKey, HostAddress,
    KerbPaPacRequest, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions, PrincipalName,
    Realm, Ticket,
};
use picky_krb::gss_api::{MechType, MechTypeList};
use picky_krb::messages::{
    ApMessage, ApRep, ApRepInner, ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, KrbPriv, KrbPrivInner,
    KrbPrivMessage, TgsReq, TgtReq,
};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use time::{Duration, OffsetDateTime};

use crate::channel_bindings::ChannelBindings;
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::flags::{ApOptions as ApOptionsFlags, KdcOptions};
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams, KERBEROS_VERSION};
use crate::utils::parse_target_name;
use crate::{ClientRequestFlags, Error, ErrorKind, Result, Secret};

/// Moved to [`super::principal::get_client_principal_name_type`].
#[allow(
    clippy::deprecated_semver,
    reason = "`<next-version>` placeholder filled in at release time"
)]
#[deprecated(
    since = "<next-version>",
    note = "moved to the `kerberos::client::principal` module — see https://github.com/Devolutions/sspi-rs/issues/708"
)]
pub fn get_client_principal_name_type(username: &str, domain: &str) -> u8 {
    super::principal::get_client_principal_name_type(username, domain)
}

/// Moved to [`super::principal::get_client_principal_realm`].
#[allow(
    clippy::deprecated_semver,
    reason = "`<next-version>` placeholder filled in at release time"
)]
#[deprecated(
    since = "<next-version>",
    note = "moved to the `kerberos::client::principal` module — see https://github.com/Devolutions/sspi-rs/issues/708"
)]
pub fn get_client_principal_realm(username: &str, domain: &str) -> String {
    super::principal::get_client_principal_realm(username, domain)
}

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
/// [Microseconds](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4).
/// The maximum microseconds value.
///
/// ```not_rust
/// Microseconds    ::= INTEGER (0..999999)
/// ```
pub const MAX_MICROSECONDS: u32 = 999_999;
const MD5_CHECKSUM_TYPE: [u8; 1] = [0x07];

// Renewable, Canonicalize, and Renewable-ok are on by default
// https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
pub const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x00, 0x81, 0x00, 0x10];

// Renewable, Canonicalize.
// https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x00, 0x81, 0x00, 0x00];

const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

/// [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
///
/// **Important**: the last 4 bytes are [Checksum Flags Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1).
/// This value should be set separately based on provided [CLientRequestFlags] or [GssFlags].
pub const AUTHENTICATOR_DEFAULT_CHECKSUM: [u8; 24] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
];

pub(super) fn generate_tgt_req(sname: &[&str]) -> Result<TgtReq> {
    let sname = sname
        .iter()
        .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string(sname.to_string())?)))
        .collect::<Result<Vec<_>>>()?;

    Ok(TgtReq {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REQ_MSG_TYPE])),
        server_name: ExplicitContextTag2::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(sname)),
        }),
    })
}

/// Parameters for generating pa-datas for [AsReq] message.
#[derive(Debug)]
pub struct GenerateAsPaDataOptions<'a> {
    pub password: &'a str,
    /// Salt for deriving the encryption key.
    ///
    /// The salt value should be extracted from the [KrbError] message.
    pub salt: Vec<u8>,
    pub enc_params: EncryptionParams,
    /// Flag that indicates whether to generate pa-datas.
    pub with_pre_auth: bool,
}

/// Build the PA-ENC-TIMESTAMP pre-auth value, encrypting the current time with
/// an already-derived long-term `key` of type `encryption_type`.
fn encode_enc_timestamp_pa_data(key: &[u8], encryption_type: &CipherSuite) -> Result<PaData> {
    let cipher = encryption_type.cipher();

    let current_date = OffsetDateTime::now_utc();
    let microseconds = current_date.microsecond().min(MAX_MICROSECONDS);

    let timestamp = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        pausec: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(
            microseconds.to_be_bytes().to_vec(),
        )))),
    };
    let timestamp_bytes = picky_asn1_der::to_vec(&timestamp)?;

    trace!(?encryption_type, "AS timestamp encryption params",);

    let encrypted_timestamp = cipher.encrypt(key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes)?;

    trace!(
        ?current_date,
        ?microseconds,
        ?timestamp_bytes,
        ?encrypted_timestamp,
        "Encrypted timestamp params",
    );

    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_timestamp)),
        })?)),
    })
}

/// Build the PA-PAC-REQUEST pre-auth value (always requests a PAC).
fn encode_pac_request_pa_data() -> Result<PaData> {
    Ok(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
            include_pac: ExplicitContextTag0::from(true),
        })?)),
    })
}

#[instrument(level = "trace", ret, skip_all, fields(options.salt, options.enc_params, options.with_pre_auth))]
pub fn generate_pa_datas_for_as_req(options: &GenerateAsPaDataOptions<'_>) -> Result<Vec<PaData>> {
    let GenerateAsPaDataOptions {
        password,
        salt,
        enc_params,
        with_pre_auth,
    } = options;

    let mut pa_datas = Vec::new();

    if *with_pre_auth {
        let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
        let key = encryption_type
            .cipher()
            .generate_key_from_password(password.as_bytes(), salt)?;
        pa_datas.push(encode_enc_timestamp_pa_data(&key, encryption_type)?);
    }

    pa_datas.push(encode_pac_request_pa_data()?);

    Ok(pa_datas)
}

/// Parameters for generating pa-datas for an [AsReq] using a pre-derived
/// long-term key (keytab-based client authentication).
#[derive(Debug)]
pub struct GenerateKeytabPaDataOptions {
    /// Raw long-term key bytes.
    pub key: Secret<Vec<u8>>,
    /// Kerberos encryption type of `key` (e.g. aes256-cts-hmac-sha1-96).
    pub key_enctype: CipherSuite,
    /// Flag that indicates whether to generate the PA-ENC-TIMESTAMP pa-data.
    pub with_pre_auth: bool,
}

#[instrument(level = "trace", ret, skip_all, fields(options.key_enctype, options.with_pre_auth))]
pub fn generate_pa_datas_for_as_req_with_key(options: &GenerateKeytabPaDataOptions) -> Result<Vec<PaData>> {
    let mut pa_datas = Vec::new();

    if options.with_pre_auth {
        pa_datas.push(encode_enc_timestamp_pa_data(
            options.key.as_ref(),
            &options.key_enctype,
        )?);
    }

    pa_datas.push(encode_pac_request_pa_data()?);

    Ok(pa_datas)
}

/// Parameters for generating [AsReq].
#[derive(Debug)]
pub struct GenerateAsReqOptions<'a> {
    pub realm: &'a str,
    pub username: &'a str,
    pub cname_type: u8,
    pub snames: &'a [&'a str],
    pub nonce: &'a [u8],
    pub hostname: &'a str,
    pub context_requirements: ClientRequestFlags,
}

#[instrument(level = "trace", ret)]
pub fn generate_as_req_kdc_body(options: &GenerateAsReqOptions<'_>) -> Result<KdcReqBody> {
    let GenerateAsReqOptions {
        realm,
        username,
        cname_type,
        snames,
        nonce,
        hostname: address,
        context_requirements,
    } = options;

    let expiration_date = OffsetDateTime::now_utc()
        .checked_add(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let host_address = HostAddress {
        addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
        address: ExplicitContextTag1::from(OctetStringAsn1::from(address.as_bytes().to_vec())),
    };

    let address = Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![host_address])));

    let mut service_names = Vec::with_capacity(snames.len());
    for sname in *snames {
        service_names.push(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?));
    }

    let mut as_req_options = KdcOptions::from_bits(u32::from_be_bytes(DEFAULT_AS_REQ_OPTIONS)).unwrap();
    if context_requirements.contains(ClientRequestFlags::DELEGATE) {
        as_req_options |= KdcOptions::FORWARDABLE;
    }

    Ok(KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            as_req_options.bits().to_be_bytes().to_vec(),
        ))),
        cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![*cname_type])),
            // A Kerberos principal name is a sequence of `/`-separated
            // components (RFC 1964 §2.1.1). Service principals such as
            // `kafka/host` carry two components; user principals carry one.
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                username
                    .split('/')
                    .map(|c| Ok(KerberosStringAsn1::from(IA5String::from_string(c.to_owned())?)))
                    .collect::<Result<Vec<_>>>()?,
            )),
        }))),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string((*realm).into())?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
            GeneralizedTime::from(expiration_date),
        )))),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(nonce.to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
        ])),
        addresses: Optional::from(address),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    })
}

#[instrument(level = "debug", ret, skip_all)]
pub fn generate_as_req(pa_datas: Vec<PaData>, kdc_req_body: KdcReqBody) -> AsReq {
    AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(pa_datas)))),
        req_body: ExplicitContextTag4::from(kdc_req_body),
    })
}

/// Parameters for generating [TgsReq].
#[derive(Debug)]
pub struct GenerateTgsReqOptions<'a> {
    pub realm: &'a str,
    pub service_principal: &'a str,
    pub session_key: &'a Secret<Vec<u8>>,
    /// [Ticket] extracted from the [AsRep] message.
    pub ticket: Ticket,
    /// [Authenticator] to be included in [TgsReq] pa-data.
    pub authenticator: &'a mut Authenticator,
    /// If the Kerberos U2U auth is negotiated, then this parameter must have one ticket: TGT ticket of the application service.
    /// Otherwise, set it to `None`.
    pub additional_tickets: Option<Vec<Ticket>>,
    pub enc_params: &'a EncryptionParams,
    pub context_requirements: ClientRequestFlags,
}

#[instrument(level = "debug", ret)]
pub fn generate_tgs_req(options: GenerateTgsReqOptions<'_>) -> Result<TgsReq> {
    let GenerateTgsReqOptions {
        realm,
        service_principal,
        session_key,
        ticket,
        authenticator,
        additional_tickets,
        enc_params,
        context_requirements,
    } = options;

    let (service_name, service_principal_name) = parse_target_name(service_principal)?;

    let expiration_date = OffsetDateTime::now_utc()
        .checked_add(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let mut tgs_req_options = KdcOptions::from_bits(u32::from_be_bytes(DEFAULT_TGS_REQ_OPTIONS)).unwrap();
    if context_requirements.contains(ClientRequestFlags::DELEGATE) {
        tgs_req_options |= KdcOptions::FORWARDABLE;
    }
    if context_requirements.contains(ClientRequestFlags::USE_SESSION_KEY) {
        tgs_req_options |= KdcOptions::ENC_TKT_IN_SKEY;
    }

    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let mut nonce = [0; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let req_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            tgs_req_options.bits().to_be_bytes().to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_str(realm)?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string(service_name.into())?),
                KerberosStringAsn1::from(IA5String::from_string(service_principal_name.into())?),
            ])),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(nonce.to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(
            additional_tickets.map(|tickets| ExplicitContextTag11::from(Asn1SequenceOf::from(tickets))),
        ),
    };

    let mut md5 = Md5::new();
    md5.update(&picky_asn1_der::to_vec(&req_body)?);
    let checksum = md5.finalize();

    authenticator.0.cksum = Optional::from(Some(ExplicitContextTag3::from(Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(MD5_CHECKSUM_TYPE.to_vec())),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum.to_vec())),
    })));

    let pa_tgs_req =
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &generate_tgs_ap_req(ticket, session_key, authenticator, enc_params)?,
            )?)),
        };

    let pa_pac_options = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_OPTIONS_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&PaPacOptions {
            flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_PA_PAC_OPTIONS.to_vec(),
            ))),
        })?)),
    };

    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs_req,
            pa_pac_options,
        ])))),
        req_body: ExplicitContextTag4::from(req_body),
    }))
}

#[derive(Debug)]
pub struct ChecksumOptions {
    pub checksum_type: Vec<u8>,
    pub checksum_value: ChecksumValues,
}

#[derive(Debug)]
pub struct ChecksumValues {
    inner: Vec<u8>, // use named fields for future extensibility, this is a temporary solution
}

impl Default for ChecksumValues {
    fn default() -> Self {
        Self {
            inner: AUTHENTICATOR_DEFAULT_CHECKSUM.to_vec(),
        }
    }
}

impl From<ChecksumValues> for Vec<u8> {
    fn from(val: ChecksumValues) -> Self {
        val.inner
    }
}

impl From<[u8; 24]> for ChecksumValues {
    fn from(bytes: [u8; 24]) -> Self {
        ChecksumValues {
            inner: Vec::from(bytes),
        }
    }
}

impl ChecksumValues {
    pub(crate) fn set_flags(&mut self, flags: GssFlags) {
        let flag_bits = flags.bits();
        let flag_bytes = flag_bits.to_le_bytes();
        self.inner[20..24].copy_from_slice(&flag_bytes);
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.inner
    }
}

bitflags::bitflags! {
    /// The checksum "Flags" field is used to convey service options or extension negotiation information.
    /// More info:
    /// * https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1
    #[derive(Debug,Clone,Copy)]
    pub(crate) struct GssFlags: u32 {
        // [Checksum Flags Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1).
        const GSS_C_DELEG_FLAG      = 1;
        const GSS_C_MUTUAL_FLAG     = 2;
        const GSS_C_REPLAY_FLAG     = 4;
        const GSS_C_SEQUENCE_FLAG   = 8;
        const GSS_C_CONF_FLAG       = 16;
        const GSS_C_INTEG_FLAG      = 32;

        const GSS_C_ANON_FLAG       = 64;
        const GSS_C_PROT_READY_FLAG = 128;
        const GSS_C_TRANS_FLAG      = 256;
        const GSS_C_DELEG_POLICY_FLAG = 32768;

        // Additional GSS flags from MS-KILE specification:
        // * [3.2.5.2 Authenticator Checksum Flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/387806fc-ed78-445e-afd8-c5639fe4a90a)

        // [Mechanism Specific Changes](https://www.rfc-editor.org/rfc/rfc4757.html#section-7.1):
        // Setting this flag indicates that the client wants to be informed of extended error information. In
        // particular, Windows 2000 status codes may be returned in the data field of a Kerberos error message.
        // This allows the client to understand a server failure more precisely.
        const GSS_C_EXTENDED_ERROR_FLAG = 0x4000;
        // This flag allows the client to indicate to the server that it should only allow the server application to identify
        // the client by name and ID, but not to impersonate the client.
        const GSS_C_IDENTIFY_FLAG = 0x2000;
        // This flag was added for use with Microsoft's implementation of Distributed Computing Environment Remote Procedure
        // Call (DCE RPC), which initially expected three legs of authentication.
        const GSS_C_DCE_STYLE = 0x1000;
    }
}

impl From<ClientRequestFlags> for GssFlags {
    /*
       the semantics of some of the flags of SSPI are I believe one to one mapped to the GSS flags
    */
    fn from(value: ClientRequestFlags) -> Self {
        let mut flags = GssFlags::empty();

        if value.contains(ClientRequestFlags::DELEGATE) {
            flags |= GssFlags::GSS_C_DELEG_FLAG;
        }

        if value.contains(ClientRequestFlags::MUTUAL_AUTH) {
            flags |= GssFlags::GSS_C_MUTUAL_FLAG;
        }

        if value.contains(ClientRequestFlags::REPLAY_DETECT) {
            flags |= GssFlags::GSS_C_REPLAY_FLAG;
        }

        if value.contains(ClientRequestFlags::SEQUENCE_DETECT) {
            flags |= GssFlags::GSS_C_SEQUENCE_FLAG;
        }

        if value.contains(ClientRequestFlags::CONFIDENTIALITY) {
            flags |= GssFlags::GSS_C_CONF_FLAG;
        }

        if value.contains(ClientRequestFlags::INTEGRITY) {
            flags |= GssFlags::GSS_C_INTEG_FLAG;
        }

        if value.contains(ClientRequestFlags::NO_INTEGRITY) {
            flags &= !GssFlags::GSS_C_INTEG_FLAG;
        }

        if value.contains(ClientRequestFlags::USE_DCE_STYLE) {
            flags |= GssFlags::GSS_C_DCE_STYLE;
        }

        flags
    }
}

#[derive(Debug)]
pub struct AuthenticatorChecksumExtension {
    pub extension_type: u32,
    pub extension_value: Vec<u8>,
}

/// Encryption key.
#[derive(Debug)]
pub struct EncKey {
    /// Encryption type.
    pub key_type: CipherSuite,
    /// Encryption key value.
    pub key_value: Vec<u8>,
}

/// Input parameters for generating ApReq Authenticator.
#[derive(Debug)]
pub struct GenerateAuthenticatorOptions<'a> {
    /// [KdcRep] from previous interaction with KDC.
    pub kdc_rep: &'a KdcRep,
    /// Sequence number.
    pub seq_num: Option<u32>,
    /// Sub-session encryption key.
    pub sub_key: Option<EncKey>,
    /// Authenticator checksum options.
    pub checksum: Option<ChecksumOptions>,
    /// Channel bindings.
    pub channel_bindings: Option<&'a ChannelBindings>,
    /// Possible authenticator extensions.
    pub extensions: Vec<AuthenticatorChecksumExtension>,
}

/// Generated ApReq Authenticator.
#[instrument(level = "trace", ret)]
pub fn generate_authenticator(options: GenerateAuthenticatorOptions<'_>) -> Result<Authenticator> {
    let GenerateAuthenticatorOptions {
        kdc_rep,
        seq_num,
        sub_key,
        checksum,
        channel_bindings,
        ..
    } = options;

    let current_date = OffsetDateTime::now_utc();
    let mut microseconds = current_date.microsecond();
    if microseconds > MAX_MICROSECONDS {
        microseconds = MAX_MICROSECONDS;
    }

    let authorization_data = Optional::from(channel_bindings.as_ref().map(|_| {
        ExplicitContextTag8::from(AuthorizationData::from(vec![AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(IntegerAsn1::from(AD_AUTH_DATA_AP_OPTION_TYPE.to_vec())),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(KERB_AP_OPTIONS_CBT.to_vec())),
        }]))
    }));

    let cksum = if let Some(ChecksumOptions {
        checksum_type,
        checksum_value,
    }) = checksum
    {
        let mut checksum_value = checksum_value.into_inner();
        if checksum_type == AUTHENTICATOR_CHECKSUM_TYPE
            && let Some(channel_bindings) = channel_bindings
        {
            if checksum_value.len() < 20 {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Invalid authenticator checksum length: expected >= 20 but got {}. ",
                        checksum_value.len()
                    ),
                ));
            }
            // [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
            // 4..19 - Channel binding information (19 inclusive).
            checksum_value[4..20].copy_from_slice(&compute_md5_channel_bindings_hash(channel_bindings));
        }
        Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum_value)),
        })))
    } else {
        Optional::from(None)
    };

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum,
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(sub_key.map(|EncKey { key_type, key_value }| {
            ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![key_type.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key_value)),
            })
        })),
        seq_number: Optional::from(seq_num.map(|seq_num| {
            ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(seq_num.to_be_bytes().to_vec()))
        })),
        authorization_data,
    }))
}

#[instrument(level = "trace", skip_all, ret)]
pub fn generate_ap_rep(
    session_key: &Secret<Vec<u8>>,
    seq_number: Vec<u8>,
    enc_params: &EncryptionParams,
) -> Result<ApRep> {
    let current_date = OffsetDateTime::now_utc();
    let microseconds = current_date.microsecond().min(MAX_MICROSECONDS);

    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);

    let enc_ap_rep_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        cusec: ExplicitContextTag1::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        subkey: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(seq_number)))),
    });

    let cipher = encryption_type.cipher();

    let encoded_enc_ap_rep_part = picky_asn1_der::to_vec(&enc_ap_rep_part)?;
    let encrypted_enc_ap_rep_part = cipher.encrypt(session_key.as_ref(), AP_REP_ENC, &encoded_enc_ap_rep_part)?;

    Ok(ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REP_MSG_TYPE])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_enc_ap_rep_part)),
        }),
    }))
}

pub fn generate_tgs_ap_req(
    ticket: Ticket,
    session_key: &Secret<Vec<u8>>,
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encoded_authenticator = picky_asn1_der::to_vec(&authenticator)?;
    let encrypted_authenticator = cipher.encrypt(
        session_key.as_ref(),
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &encoded_authenticator,
    )?;

    trace!(
        ?session_key,
        ?encryption_type,
        "TGS AP_REQ authenticator encryption params",
    );
    trace!(
        plain = ?encoded_authenticator,
        encrypted = ?encrypted_authenticator,
        "TGS AP_REQ authenticator",
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            // do not need any options when ap_req uses in tgs_req pa_data
            0x00, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

#[instrument(level = "trace", ret)]
pub fn generate_ap_req(
    ticket: Ticket,
    session_key: &Secret<Vec<u8>>,
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    options: ApOptionsFlags,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encoded_authenticator = picky_asn1_der::to_vec(&authenticator)?;
    let encrypted_authenticator = cipher.encrypt(session_key.as_ref(), AP_REQ_AUTHENTICATOR, &encoded_authenticator)?;

    trace!(
        plain = ?encoded_authenticator,
        encrypted = ?encrypted_authenticator,
        "AP_REQ authenticator",
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(
            options.bits().to_be_bytes().to_vec(),
        ))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

/// Returns supported authentication types.
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![MechType::from(oids::ms_krb5()), MechType::from(oids::krb5())])
}

#[instrument(level = "trace", ret)]
pub fn generate_krb_priv_request(
    ticket: Ticket,
    session_key: &Secret<Vec<u8>>,
    new_password: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    seq_num: u32,
    address: &str,
) -> Result<KrbPrivMessage> {
    let ap_req = generate_ap_req(ticket, session_key, authenticator, enc_params, ApOptionsFlags::empty())?;

    let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
        user_data: ExplicitContextTag0::from(OctetStringAsn1::from(new_password.to_vec())),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from_bytes_be_unsigned(
            seq_num.to_be_bytes().to_vec(),
        )))),
        s_address: ExplicitContextTag4::from(HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(address.as_bytes().to_vec())),
        }),
        r_address: Optional::from(None),
    });

    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encryption_key = &authenticator.0.subkey.0.as_ref().unwrap().key_value.0;
    let encoded_krb_priv = picky_asn1_der::to_vec(&enc_part)?;

    let enc_part = cipher.encrypt(encryption_key, KRB_PRIV_ENC_PART, &encoded_krb_priv)?;

    trace!(?encryption_key, ?encryption_type, "KRB_PRIV encryption params",);
    trace!(
        plain = ?encoded_krb_priv,
        encrypted = ?enc_part,
        "KRB_PRIV encrypted part",
    );

    let krb_priv = KrbPriv::from(KrbPrivInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_PRIV])),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_part)),
        }),
    });

    Ok(KrbPrivMessage {
        ap_message: ApMessage::ApReq(ap_req),
        krb_priv,
    })
}

#[cfg(test)]
mod tests {
    use picky_krb::constants::types::NT_PRINCIPAL;

    use super::*;

    #[test]
    fn test_set_flags() {
        let mut checksum_values = ChecksumValues::default();
        let flags = GssFlags::GSS_C_MUTUAL_FLAG | GssFlags::GSS_C_REPLAY_FLAG;
        checksum_values.set_flags(flags);
        let expected_bytes = flags.bits().to_le_bytes();
        assert_eq!(checksum_values.inner[20..24], expected_bytes);
    }

    #[test]
    fn test_default() {
        // ensure backwards compatibility
        let checksum_values = ChecksumValues::default();
        assert_eq!(checksum_values.into_inner(), AUTHENTICATOR_DEFAULT_CHECKSUM);
    }

    #[test]
    fn test_flag_for_sign_and_seal() {
        let mut checksum_values = ChecksumValues::default();
        let flags = GssFlags::GSS_C_MUTUAL_FLAG
            | GssFlags::GSS_C_REPLAY_FLAG
            | GssFlags::GSS_C_SEQUENCE_FLAG
            | GssFlags::GSS_C_CONF_FLAG
            | GssFlags::GSS_C_INTEG_FLAG;
        checksum_values.set_flags(flags);
        let expected_bytes = [0x3E, 0x00, 0x00, 0x00];
        assert_eq!(checksum_values.inner[20..24], expected_bytes);
    }

    fn cname_components(username: &str) -> Vec<String> {
        let body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "CRABKA.TEST",
            username,
            cname_type: NT_PRINCIPAL,
            snames: &["krbtgt", "CRABKA.TEST"],
            nonce: &[0, 0, 0, 1],
            hostname: "host",
            context_requirements: ClientRequestFlags::empty(),
        })
        .expect("generate as-req body");

        body.cname
            .0
            .expect("cname present")
            .0
            .name_string
            .0
            .0
            .iter()
            .map(|s| s.0.to_string())
            .collect()
    }

    #[test]
    fn single_component_cname() {
        assert_eq!(cname_components("alice"), vec!["alice".to_string()]);
    }

    #[test]
    fn service_principal_cname_is_split_on_slash() {
        // A `kafka/host` service principal must be encoded as two name-string
        // components, or MIT KDC rejects the principal as unknown.
        assert_eq!(
            cname_components("kafka/host"),
            vec!["kafka".to_string(), "host".to_string()]
        );
    }

    #[test]
    fn keytab_pa_datas_without_pre_auth_is_just_pac_request() {
        let pa_datas = generate_pa_datas_for_as_req_with_key(&GenerateKeytabPaDataOptions {
            key: vec![0u8; 32].into(),
            key_enctype: CipherSuite::Aes256CtsHmacSha196,
            with_pre_auth: false,
        })
        .expect("generate keytab pa-datas");
        // No pre-auth requested: only the PA-PAC-REQUEST is emitted.
        assert_eq!(pa_datas.len(), 1);
    }

    #[test]
    fn keytab_pa_datas_with_pre_auth_includes_enc_timestamp() {
        let pa_datas = generate_pa_datas_for_as_req_with_key(&GenerateKeytabPaDataOptions {
            key: vec![0u8; 32].into(),
            key_enctype: CipherSuite::Aes256CtsHmacSha196,
            with_pre_auth: true,
        })
        .expect("generate keytab pa-datas");
        // PA-ENC-TIMESTAMP plus PA-PAC-REQUEST.
        assert_eq!(pa_datas.len(), 2);
    }
}
