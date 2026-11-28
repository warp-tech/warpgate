use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use crypto_bigint::BoxedUint;
use iso7816::{Aid, Command, Instruction};
use iso7816_tlv::ber::{Tag, Tlv, Value};
use picky::key::PrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::Sha1;
use uuid::Uuid;

use crate::card_capability_container::build_ccc;
use crate::chuid::{CHUID_LENGTH, build_chuid};
use crate::piv_cert::build_auth_cert;
use crate::winscard::{AttributeId, ControlCode, Protocol, ReaderAction, ShareMode, TransmitOutData, WinScard};
use crate::{Error, ErrorKind, Response, Status, WinScardResult, tlv_tags, winscard};

/// [NIST.SP.800-73-4, part 1, section 2.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=16).
pub const PIV_AID: Aid = Aid::new_truncatable(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00], 9);
/// The max amount of data one APDU response can transmit.
pub const CHUNK_SIZE: usize = 256;
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const CARD_AUTH_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x01];
// NIST.SP.800-73-4, part 1, section 4.3, Table 3
const CHUID_TAG: &[u8] = &[0x5F, 0xC1, 0x02];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const PIV_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x05];
// NIST.SP.800-73-4, part 1, section 4.3, Table 3
const CARD_CAPABILITY_CONTAINER_TAG: &[u8] = &[0x5F, 0xC1, 0x07];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const DIGITAL_SIGNATURE_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x0A];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const KEY_MANAGEMENT_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x0B];
// NIST.SP.800-73-4 part 2, section 2.4.3
const PIN_LENGTH_RANGE_LOW_BOUND: usize = 6;
// NIST.SP.800-73-4 part 2, section 2.4.3
const PIN_LENGTH_RANGE_HIGH_BOUND: usize = 8;
/// Supported connection protocol in emulated smart cards.
///
/// We are always using the T1 protocol as the original Windows TPM smart card does
pub const SUPPORTED_CONNECTION_PROTOCOL: Protocol = Protocol::T1;
// Only one supported control code.
// `#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)`
// Request features described in the *PC/SC 2.0 Specification Part 10*
const IO_CTL: u32 = 0x00313520;

/// The original winscard ATR is not suitable because it contains AID bytes.
/// So we need to construct our own. Read more about our constructed ATR string:
/// <https://smartcard-atr.apdu.fr/parse?ATR=3B+8D+01+80+FB+A0+00+00+03+08+00+00+10+00+01+00+4D>
#[rustfmt::skip]
pub const ATR: [u8; 17] = [
    // TS. Direct Convention
    0x3b,
    // T0. Y(1): b1000, K: 13 (historical bytes)
    0x8d,
    // TD. Y(i+1) = b0000, Protocol T=1
    0x01,
    // Historical bytes
    0x80,
    // Tag: 15, Len: 11.
    0xfb,
    // PIV AID
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    // TCK (Checksum)
    0x4d,
];

/// Emulated smart card.
///
/// Currently, we support one key container per smart card.
#[derive(Debug, Clone)]
pub struct SmartCard<'a> {
    reader_name: Cow<'a, str>,
    chuid: [u8; CHUID_LENGTH],
    ccc: Vec<u8>,
    pin: Vec<u8>,
    auth_cert: Vec<u8>,
    auth_pk: PrivateKey,
    state: SCardState,
    // We don't need to track actual transactions for the emulated smart card.
    // We are using this flag to track incorrect smart card usage.
    transaction: bool,
    pending_command: Option<Command<1024>>,
    pending_response: Option<Vec<u8>>,
    // We keep it just for compatibility reasons with WinSCard API.
    // Usually, the mstsc.exe doesn't use scard attributes for connection establishing.
    attributes: BTreeMap<AttributeId, Cow<'a, [u8]>>,
}

impl SmartCard<'_> {
    /// Creates a smart card instance based on the provided data.
    pub fn new(
        reader_name: Cow<'_, str>,
        card_id: Uuid,
        pin: Vec<u8>,
        auth_cert_der: Vec<u8>,
        auth_pk: PrivateKey,
    ) -> WinScardResult<SmartCard<'_>> {
        let chuid = build_chuid(card_id)?;
        let auth_cert = build_auth_cert(auth_cert_der)?;

        Ok(SmartCard {
            reader_name,
            chuid,
            ccc: build_ccc(),
            pin: SmartCard::validate_and_pad_pin(pin)?,
            auth_cert,
            auth_pk,
            state: SCardState::Ready,
            transaction: false,
            pending_command: None,
            pending_response: None,
            attributes: BTreeMap::new(),
        })
    }

    fn validate_and_pad_pin(pin: Vec<u8>) -> WinScardResult<Vec<u8>> {
        // All PIN requirements can be found here: NIST.SP.800-73-4 part 2, section 2.4.3
        if !(PIN_LENGTH_RANGE_LOW_BOUND..=PIN_LENGTH_RANGE_HIGH_BOUND).contains(&pin.len()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should be no shorter than 6 bytes and no longer than 8",
            ));
        }
        if pin.iter().any(|byte| !byte.is_ascii_digit()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should consist only of ASCII values representing decimal digits (0-9)",
            ));
        };

        Ok(Self::pad_pin(pin))
    }

    fn pad_pin(mut pin: Vec<u8>) -> Vec<u8> {
        if pin.len() < PIN_LENGTH_RANGE_HIGH_BOUND {
            // NIST.SP.800-73-4 part 2, section 2.4.3
            const PIN_PAD_VALUE: u8 = 0xFF;
            pin.resize(PIN_LENGTH_RANGE_HIGH_BOUND, PIN_PAD_VALUE);
        }

        pin
    }

    /// This functions handles one APDU command.
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    pub fn handle_command(&mut self, data: &[u8]) -> WinScardResult<Response> {
        let cmd = Command::<1024>::try_from(data).map_err(|error| {
            error!(?error, "APDU command parsing error");
            Error::new(
                ErrorKind::InternalError,
                format!("error: an error happened while parsing an APDU command: {error:?}"),
            )
        })?;
        let cmd = if let Some(mut chained) = self.pending_command.take() {
            chained.extend_from_command(&cmd).map_err(|_| {
                Error::new(
                    ErrorKind::InternalError,
                    "error: an error happened while trying to build a chained APDU command",
                )
            })?;
            chained
        } else {
            cmd
        };

        if cmd.class().chain().not_the_last() {
            self.pending_command = Some(cmd);
            return Ok(Status::OK.into());
        }
        if self.state == SCardState::Ready && cmd.instruction() != Instruction::Select {
            // if the application wasn't selected, only the SELECT command can be used
            return Ok(Status::NotFound.into());
        } else if self.state == SCardState::PivAppSelected && cmd.instruction() == Instruction::GeneralAuthenticate {
            // GENERAL AUTHENTICATE can only be used if the smart card has already been unlocked using the PIN code
            return Ok(Status::SecurityStatusNotSatisfied.into());
        }
        match cmd.instruction() {
            Instruction::Select => self.select(cmd),
            Instruction::GetData => self.get_data(cmd),
            Instruction::Verify => self.verify(cmd),
            Instruction::GeneralAuthenticate => self.general_authenticate(cmd),
            Instruction::GetResponse => self.get_response(),
            _ => {
                error!(instruction = ?cmd.instruction(), "unimplemented instruction");
                Ok(Status::InstructionNotSupported.into())
            }
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn select(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.1.1
        // PIV SELECT command
        //      CLA - 0x00
        //      INS - 0xA4
        //      P1  - 0x04
        //      P2  - 0x00

        // ISO/IEC 7816-4, Section 7.1.1, Table 39
        const APPLICATION_IDENTIFIER: u8 = 0x04;
        // ISO/IEC 7816-4, Section 7.1.1, Table 40
        const FIRST_OR_ONLY_OCCURRENCE: u8 = 0x00;

        if cmd.p1 != APPLICATION_IDENTIFIER || cmd.p2 != FIRST_OR_ONLY_OCCURRENCE || !PIV_AID.matches(cmd.data()) {
            return Ok(Status::NotFound.into());
        }
        let data = Tlv::new(
            Tag::try_from(tlv_tags::APPLICATION_PROPERTY_TEMPLATE)?,
            Value::Constructed(vec![
                Tlv::new(
                    Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                    // application portion + version portion of the PIV AID
                    // NIST.SP.800-73-4 Part 1, section 2.2
                    Value::Primitive(vec![0x00, 0x00, 0x10, 0x00, 0x01, 0x00]),
                )?,
                Tlv::new(
                    Tag::try_from(tlv_tags::COEXISTING_TAG_ALLOCATION_AUTHORITY)?,
                    Value::Constructed(vec![Tlv::new(
                        Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                        Value::Primitive(PIV_AID.to_vec()),
                    )?]),
                )?,
            ]),
        )?;
        self.state = SCardState::PivAppSelected;
        Ok(Response::new(Status::OK, Some(data.to_vec())))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn verify(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.2.1
        // PIV VERIFY command
        //      CLA  - 0x00
        //      INS  - 0x20
        //      P1   - 0x00 | 0xFF
        //      P2   - 0x80
        //      Data - PIN
        //
        // If P1 is 0xFF, the Data field should be empty

        // ISO/IEC 7816-4, Section 7.5.1
        const NO_IDENTIFIER: u8 = 0x00;
        // NIST.SP.800-73-4, Part 2, Section 3.2.1
        const RESET_SECURITY_STATUS: u8 = 0xFF;
        // ISO/IEC 7816-4, Section 7.5.1, Table 65
        const SPECIFIC_REFERENCE_DATA: u8 = 0x80;

        if cmd.p1 == RESET_SECURITY_STATUS && !cmd.data().is_empty() {
            return Ok(Status::IncorrectP1orP2.into());
        }
        if cmd.p2 != SPECIFIC_REFERENCE_DATA {
            return Ok(Status::KeyReferenceNotFound.into());
        }
        match cmd.p1 {
            NO_IDENTIFIER => {
                // PIN was already verified -> return OK
                if self.state != SCardState::PinVerified {
                    if !cmd.data().is_empty()
                        && !(PIN_LENGTH_RANGE_LOW_BOUND..=PIN_LENGTH_RANGE_HIGH_BOUND).contains(&cmd.data().len())
                    {
                        // Incorrect PIN length -> do not proceed and return an error
                        return Ok(Status::IncorrectDataField.into());
                    }
                    // Retrieve the number of further allowed retries if the data field is absent
                    // Otherwise just compare the provided PIN with the stored one
                    if cmd.data().is_empty() || cmd.data() != self.pin.as_slice() {
                        return Ok(Status::VerificationFailedWithRetries.into());
                    } else {
                        // data field is present and the provided PIN is correct -> change state and return OK
                        self.state = SCardState::PinVerified;
                    }
                }
            }
            RESET_SECURITY_STATUS => {
                // p1 is 0xFF and the data field is absent -> reset the security status and return OK
                self.state = SCardState::PivAppSelected;
            }
            _ => return Ok(Status::IncorrectP1orP2.into()),
        };
        Ok(Status::OK.into())
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn get_data(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.1.2
        // PIV GET DATA command
        //      CLA  - 0x00
        //      INS  - 0xCB
        //      P1   - 0x3F
        //      P2   - 0xFF
        //      Data - a single BER-TLV tag of the data object to be retrieved
        //
        // Our PIV smart card only supports:
        //      5FC102 - Card Holder Unique Identifier
        //      5FC105 - X.509 Certificate for PIV Authentication

        // ISO/IEC 7816-4, Section 7.4.1
        const FIRST_BYTE_OF_CURRENT_DF: u8 = 0x3F;
        const SECOND_BYTE_OF_CURRENT_DF: u8 = 0xFF;

        if cmd.p1 != FIRST_BYTE_OF_CURRENT_DF || cmd.p2 != SECOND_BYTE_OF_CURRENT_DF {
            return Ok(Status::IncorrectP1orP2.into());
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::TAG_LIST)? {
            return Ok(Status::NotFound.into());
        }

        match request.value() {
            Value::Primitive(tag) => match tag.as_slice() {
                CHUID_TAG => Ok(Response::new(Status::OK, Some(self.chuid.to_vec()))),
                [a, b, c]
                    if matches!(
                        [*a, *b, *c],
                        PIV_CERT_TAG | CARD_AUTH_CERT_TAG | KEY_MANAGEMENT_CERT_TAG | DIGITAL_SIGNATURE_CERT_TAG
                    ) =>
                {
                    // certificate is almost certainly longer than 256 bytes, so we can just set a pending response and call the GET RESPONSE handler
                    self.pending_response = Some(self.auth_cert.clone());
                    self.get_response()
                }
                CARD_CAPABILITY_CONTAINER_TAG => Ok(Response::new(Status::OK, Some(self.ccc.clone()))),
                _ => Ok(Status::NotFound.into()),
            },
            Value::Constructed(_) => Ok(Status::NotFound.into()),
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn get_response(&mut self) -> WinScardResult<Response> {
        // ISO/IEC 7816-4, Section 7.6.1
        // The smart card uses the standard (short) APDU response form, so the maximum amount of data transferred in one response is 256 bytes
        match self.get_next_response_chunk() {
            Some((chunk, bytes_left)) => {
                let status = if bytes_left == 0 {
                    self.pending_response = None;
                    Status::OK
                } else if bytes_left < CHUNK_SIZE {
                    // conversion is safe as we know that bytes_left isn't bigger than 256
                    Status::MoreAvailable(bytes_left.try_into().unwrap())
                } else {
                    // 0 indicates that we have 256 or more bytes left to be read
                    Status::MoreAvailable(0)
                };
                Ok(Response::new(status, Some(chunk)))
            }
            None => Ok(Status::NotFound.into()),
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn general_authenticate(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.2.4
        // PIV GENERAL AUTHENTICATE command
        //      CLA  - 0x00 | 0x10 (command chaining)
        //      INS  - 0x87
        //      P1   - 0x07 - RSA
        //      P2   - 0x9A - PIV Authentication Key or PIV Digital Signature Key
        //      Data - Dynamic Authentication Template with Challenge inside
        //
        // There are many possible P1 and P2 values in this command, but our smart card only supports the RSA algorithm
        // and data signing using the PIV Authentication Key or PIV Digital Signature Key.

        // NIST.SP.800-73-4, Part 1, Table 5
        const RSA_ALGORITHM: u8 = 0x07;
        // NIST.SP.800-73-4, Part 1, Table 4b
        const PIV_AUTHENTICATION_KEY: u8 = 0x9A;
        const PIV_DIGITAL_SIGNATURE_KEY: u8 = 0x9C;

        // We accept two types of key references: PIV Authentication Key and Digital Signature Key.
        if cmd.p1 != RSA_ALGORITHM || (cmd.p2 != PIV_DIGITAL_SIGNATURE_KEY && cmd.p2 != PIV_AUTHENTICATION_KEY) {
            return Err(Error::new(
                ErrorKind::UnsupportedFeature,
                format!(
                    "provided algorithm or key reference isn't supported: got algorithm {:x}, expected 0x07; got key reference {:x}, expected 0x9a or 0x9c",
                    cmd.p1, cmd.p2
                ),
            ));
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?
            || !request.value().is_constructed()
        {
            // wrong TLV request structure
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: wrong top-level tag structure".to_string(),
            ));
        }
        let inner_tlv = match request.value() {
            // we already know that the value is constructed at this point
            Value::Primitive(_) => unreachable!(),
            Value::Constructed(tlv_vec) => tlv_vec,
        };
        // to avoid constructing the tag on each iteration
        let challenge_tag = Tag::try_from(tlv_tags::DAT_CHALLENGE)?;
        let challenge = inner_tlv
            .iter()
            .find(|&tlv| tlv.tag() == &challenge_tag)
            .ok_or(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: no challenge field is present in the request".to_string(),
            ))?;
        // Signature creation is described in NIST.SP.800-73-4, Part 2, Appendix A, Sections A.1-3 and Section A.4.1
        let challenge = match challenge.value() {
            Value::Primitive(challenge) => challenge,
            Value::Constructed(_) => {
                // this tag must contain a primitive value
                return Err(Error::new(
                    ErrorKind::InvalidValue,
                    "TLV structure is invalid: challenge field contains constructed value".to_string(),
                ));
            }
        };
        let signed_challenge = self.sign_padded(challenge)?;
        let response = Tlv::new(
            Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?,
            Value::Constructed(vec![Tlv::new(
                Tag::try_from(tlv_tags::DAT_RESPONSE)?,
                Value::Primitive(signed_challenge),
            )?]),
        )?
        .to_vec();
        self.pending_response = Some(response);
        self.get_response()
    }

    fn sign_padded(&self, data: impl AsRef<[u8]>) -> WinScardResult<Vec<u8>> {
        let rsa_private_key = RsaPrivateKey::try_from(&self.auth_pk)?;
        // According to the specification, the PIV smart card accepts already padded digest.
        // So, it's safe to use the `rsa_decrypt_and_check` function here.
        let signature = rsa::hazmat::rsa_decrypt_and_check(
            &rsa_private_key,
            None::<&mut crate::dummy_rng::Dummy>,
            &BoxedUint::from_be_slice_vartime(data.as_ref()),
        )?;

        let mut signature = signature.to_be_bytes_trimmed_vartime().into_vec();

        while signature.len() < rsa_private_key.size() {
            signature.insert(0, 0);
        }

        Ok(signature)
    }

    /// Signs the provided data using the smart card private key.
    /// *Warning 1*. The input data should be a *SHA1* hash of the actually you want to sign.
    pub fn sign_hashed(&self, data: impl AsRef<[u8]>) -> WinScardResult<Vec<u8>> {
        let rsa_private_key = RsaPrivateKey::try_from(&self.auth_pk)?;
        let signature = rsa_private_key.sign(Pkcs1v15Sign::new::<Sha1>(), data.as_ref())?;

        Ok(signature)
    }

    /// Verifies the PIN code. This method alters the scard state.
    pub fn verify_pin(&mut self, pin: &[u8]) -> WinScardResult<()> {
        if self.pin != Self::pad_pin(pin.into()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN verification error: Invalid PIN",
            ));
        }

        self.state = SCardState::PinVerified;

        Ok(())
    }

    fn get_next_response_chunk(&mut self) -> Option<(Vec<u8>, usize)> {
        let vec = self.pending_response.as_mut()?;
        if vec.is_empty() {
            return None;
        }
        let next_chunk_length = CHUNK_SIZE.min(vec.len());
        let chunk = vec.drain(0..next_chunk_length).collect::<Vec<u8>>();
        Some((chunk, vec.len()))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
}

impl WinScard for SmartCard<'_> {
    fn status(&self) -> WinScardResult<winscard::Status<'_>> {
        Ok(winscard::Status {
            readers: vec![self.reader_name.clone()],
            // The original winscard always returns SCARD_SPECIFIC for a working inserted card
            state: winscard::State::Specific,
            // We are always using the T1 protocol as the original Windows TPM smart card does
            protocol: SUPPORTED_CONNECTION_PROTOCOL,
            atr: ATR.into(),
        })
    }

    fn control(&mut self, code: ControlCode, _input: &[u8]) -> WinScardResult<()> {
        if code != IO_CTL {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                format!("unsupported control code: {code:?}"),
            ));
        }

        Ok(())
    }

    fn control_with_output(&mut self, code: ControlCode, input: &[u8], _output: &mut [u8]) -> WinScardResult<usize> {
        self.control(code, input)?;

        Ok(0)
    }

    fn transmit(&mut self, input_apdu: &[u8]) -> WinScardResult<TransmitOutData> {
        let Response { status, data } = self.handle_command(input_apdu)?;

        let mut output_apdu = data.unwrap_or_default();
        let status_data: [u8; 2] = status.into();
        output_apdu.extend_from_slice(&status_data);

        Ok(TransmitOutData {
            output_apdu,
            receive_pci: None,
        })
    }

    fn begin_transaction(&mut self) -> WinScardResult<()> {
        if self.transaction {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the transaction already in progress",
            ));
        }
        self.transaction = true;
        Ok(())
    }

    fn end_transaction(&mut self, _disposition: ReaderAction) -> WinScardResult<()> {
        if !self.transaction {
            return Err(Error::new(ErrorKind::NotTransacted, "the transaction is not started"));
        }
        self.transaction = false;
        Ok(())
    }

    fn reconnect(&mut self, _: ShareMode, _: Option<Protocol>, _: ReaderAction) -> WinScardResult<Protocol> {
        // Because it's an emulated smart card, we do nothing and return success.
        Ok(SUPPORTED_CONNECTION_PROTOCOL)
    }

    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<Cow<'_, [u8]>> {
        let data = self.attributes.get(&attribute_id).map(AsRef::as_ref).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("The {attribute_id:?} attribute id is not present"),
            )
        })?;

        Ok(Cow::Borrowed(data))
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        self.attributes
            .insert(attribute_id, Cow::Owned(attribute_data.to_vec()));

        Ok(())
    }

    fn disconnect(&mut self, _disposition: ReaderAction) -> WinScardResult<()> {
        // We don't need any actions during the disconnection in emulated smart cards.
        // It's enough just to drop the card object.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
    use crypto_bigint::{Odd, Resize};
    use picky::hash::HashAlgorithm;
    use picky::signature::SignatureAlgorithm;
    use proptest::prelude::*;
    use proptest::{collection, option, prop_compose};
    use rand::RngExt as _;
    use rand::distr::Uniform;
    use rsa::BoxedUint;
    use rsa::traits::PublicKeyParts;

    use super::*;
    use crate::ber_tlv::ber_tlv_length_encoding;

    fn arb_status() -> impl Strategy<Value = Status> {
        prop_oneof![
            Just(Status::NotFound),
            Just(Status::OK),
            Just(Status::VerificationFailedWithRetries),
            any::<u8>().prop_map(Status::MoreAvailable),
            Just(Status::KeyReferenceNotFound),
            Just(Status::SecurityStatusNotSatisfied),
            Just(Status::IncorrectP1orP2),
            Just(Status::IncorrectDataField),
            Just(Status::InstructionNotSupported)
        ]
    }

    prop_compose! {
        fn arb_response()(status in arb_status(), data in option::of(collection::vec(any::<u8>(), 0..256))) -> Response {
            Response::new(status, data)
        }
    }

    proptest! {
        #[test]
        fn response_is_encoded_correctly(arb_response in arb_response()) {
            let data = arb_response.data.clone();
            let status: [u8; 2] = arb_response.status.clone().into();
            let expected_result = if let Some(mut bytes) = data {
                bytes.extend(status);
                bytes
            } else {
                Vec::from(status)
            };
            assert_eq!(expected_result, Vec::from(arb_response));
        }
    }

    fn new_scard() -> SmartCard<'static> {
        let rsa_2048_private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiJ/d1/2d1CQYlJfZ02TOH7F/5U53a6IZc8QwTQEsBQbVGfQO
RN/+b09NzJJZmtyuLdBAXLzP8lEzKcfgn4JNl5G7DuKOxRreE5tq8uA+j2SQCw7m
Sm6todEOvkWG5Dov3Q9QnlPbvqp871pfbRsfKwOo2RxJIjbjpM5FQnlqOd+3gu2I
TF8dt+/PY+wl1w6kPTUZg/mzElY95WSnOE9bFlHcVL//Sl3caW85AB0lLUbd96b/
7PMO6IWJQyvS0ssG0emcyQYllvvSCFSpVWA/e1EGzKrwbtG1Xn9je5L4mIKiSw/p
gbjnYE9g+pibLJNobBBLkzGdo/KzyCQbMWirkQIDAQABAoIBAEbAm28mXNymkMAq
31g1BPWuwy/p8bggqxOjjuvh5nz369XT6KvMYAQeyohdZd/n1p/ND/e2o+22FUvW
wcF5Bluu0XNE6nCymD0JKFp8vIkfp+TCI4p6RJrfG8Z3VQLOC0lsi/BiNxNHUQnX
AEINYJey/nboygrY6AzJ8V4aaGNtbtnz7tfyALJHUK0qRa+AmyLCzaZR5RSbDgB5
srCX9J5OCxH2s5tVSfqg48Z0RIiBcDFPYbJDakZWLRNLD8ByW3e0jEFDA1vQPsaj
CsyY4E6UZwYNZemC60zW0e8BYJYnOAhcmwaYnaxvL5xy0aW5pUGr+FgnO4NrNr33
pKT2eFECgYEA2LJdjjFGdTsuW8esbTn+9hGyNnUR9gxYGdNhcINhPHMhoR8GkakC
5sLOlpgCDpdzHDduW2GjhIAUnXt50yZNpkXQuSWdjucbYGc2G5ySc8eHaP+5tHAr
svyZBchE+Kf4p2nNoXoQxsgxY2Qgz/ctUgCR7SnbgRW0cHDH7HIXlJ0CgYEAoWeY
rt2q8PFW3sEWy1RK0dxD+7UnuN76x5rd0IUxi2HS5F4tyfiDy3LgVs0XJqF9IN6K
IQ7pX/0C1g91NbUl8pAnu+k7R/CiynqGAmQumkMscIRO4VoR+v3+Hta9NV6sy/0U
fDfQSK9AnrFXGCpHPLC+YrmgbVnKqJ526vBxboUCgYEAvx4pJ0TMWI62p1nm+HrD
JLGc1SzRh4mBll15PeuRsef1DA66E3PVzEKaQ/WTMt1eN8+ntE7cEfuIsxB49MJ+
j5xZp0HGwYeQ/Khq71VbUWP0SKXqWnrn/7eLGq90LT6wLq9BHh7zdu6PqJJh4iml
vgIkseBN6X6EIvtFSIOjyn0CgYBRvEiRpSd/xHedbmLArPsGs2ip+t8Wu7R7iG1z
vz+Lugo2I4tEkFkNmisJSerDYVwgXRHOE+MS/OmGxWUxwX5qC55ThpTCpZWKu+lJ
JLqE3CeRAy9+50HbvOwHae9/K2aOFqddEFaluDodIulcD2zrywVesWoQdjwuj7Dg
4MpQkQKBgA4vlTf+n8kpOJWls2YMyZaauY48xcNzDdhpBGFCjVm+aiKX5dyIjAQK
9LX8/iVau8ZRM+qSLpuEP+o8qGR11TbGZrLH/wITc7r9cWnaGDsozmPAnxMcu1zz
9IRTY9zr9QWzxGiSqr834q5IZIQ/5uDBW/857MP0bpMl6cTdxzg0
-----END RSA PRIVATE KEY-----";
        let auth_pk = PrivateKey::from_pem_str(rsa_2048_private_key).unwrap();
        let certificate_stub = vec![0xff; 1024];
        let pin = vec![0x39; 6];
        SmartCard::new(
            Cow::Borrowed("Reader 0"),
            // The tests do not care about the card identifier, so any fixed value suits them.
            Uuid::from_u128(1),
            pin,
            certificate_stub,
            auth_pk,
        )
        .unwrap()
    }

    // Helper function that calls the GET RESPONSE handler until there is no more data to read
    fn get_all_available_data(mut response: Response, scard: &mut SmartCard<'_>) -> Vec<u8> {
        let mut complete_response = vec![];
        while let Status::MoreAvailable(bytes_left) = response.status {
            complete_response.extend_from_slice(&response.data.expect("Data should be present"));
            let apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];
            response = scard
                .handle_command(&apdu_get_response)
                .expect("Can't retrieve all available data");
        }
        assert_eq!(response.status, Status::OK);
        complete_response.extend_from_slice(&response.data.expect("The last chunk of data isn't present"));
        complete_response
    }

    #[test]
    fn invalid_apdu_command() {
        // Verify that smart card correctly handles invalid APDU commands
        let mut scard = new_scard();

        let bad_apdu_command = vec![0x00; 2048];
        let response = scard.handle_command(&bad_apdu_command);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::InternalError));
    }

    #[test]
    fn wrong_command_order() {
        // Verify that the smart card prohibits using any commands besides SELECT when no app was selected
        let mut scard = new_scard();

        let mut apdu_verify_cmd = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        // add pin
        apdu_verify_cmd.extend_from_slice(&[0xA9; 8]);
        let response = scard.handle_command(&apdu_verify_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn invalid_select_command() {
        // Verify that the SELECT handler correctly responds if called with an invalid AID
        let mut scard = new_scard();

        let bad_aid = vec![0xff; 11];

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&bad_aid);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn select_command() {
        // Verify that the SELECT command works as expected and returns expected output
        let mut scard = new_scard();

        let mut expected_response = vec![
            0x61, 0x17, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x0D, 0x4F, 0x0B,
        ];
        expected_response.extend_from_slice(&PIV_AID);

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&PIV_AID);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(
            |resp| resp.status == Status::OK && resp.data.expect("Data should be present") == expected_response
        ));
    }

    #[test]
    fn unsupported_command() {
        // Verify that smart card correctly handles unsupported commands
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // RESET RETRY COUNTER APDU command
        let apdu_reset_retry_cmd = vec![0x00, 0x2C, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_reset_retry_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::InstructionNotSupported));
    }

    #[test]
    fn invalid_verify_commands() {
        // Verify that the VERIFY command handler correctly handles badly structured or malformed requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 can only be 0x00 or 0xFF
        let apdu_verify_bad_p1 = vec![0x00, 0x20, 0xAA, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_bad_p1);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // if p1 is 0xFF, the data field should be empty
        let apdu_verify_bad_p1_data = vec![0x00, 0x20, 0xFF, 0x80, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p1_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // p2 should always be 0x80
        let apdu_verify_bad_p2 = vec![0x00, 0x20, 0x00, 0x81, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::KeyReferenceNotFound));

        // PIN should be no shorter than six bytes and no longer than 8
        let apdu_verify_bad_pin = vec![0x00, 0x20, 0x00, 0x80, 0x02, 0xAA, 0xAA];
        let response = scard.handle_command(&apdu_verify_bad_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectDataField));
    }

    #[test]
    fn verify_command() {
        // Verify that the VERIFY command handler correctly handles all supported types of requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // retrieve number of allowed retries by omitting the data field
        let apdu_verify_no_data = vec![0x00, 0x20, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_no_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the wrong PIN code
        let mut apdu_verify_wrong_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_wrong_pin.extend_from_slice(&[0xCC; 8]);
        let response = scard.handle_command(&apdu_verify_wrong_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the correct PIN code
        let mut apdu_verify_correct_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_correct_pin.extend_from_slice(&[0x39; 6]);
        // 0xFF padding
        apdu_verify_correct_pin.extend_from_slice(&[0xFF; 2]);
        let response = scard.handle_command(&apdu_verify_correct_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PinVerified);

        // Reset the security status
        let apdu_verify_reset = vec![0x00, 0x20, 0xFF, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_reset);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PivAppSelected);
    }

    #[test]
    fn get_response_command() {
        // Verify that the GET RESPONSE handler correctly sends the data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;
        let mut rng = rand::rng();

        // get a random Vec<u8> of length 513
        let uniform = Uniform::new(0, 255).unwrap();
        let data: Vec<u8> = (0..513).map(|_| rng.sample(uniform)).collect();
        // we will have to make 3 calls to get this data
        scard.pending_response = Some(data.clone());

        let mut received_result = vec![];
        // 0 means any valid number in range 0..=256
        // We set this to 0 on the first call so that the smart card returns whatever it got
        let bytes_left = 0;
        let mut apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];

        let response = scard.handle_command(&apdu_get_response);
        assert!(
            response
                .as_ref()
                .is_ok_and(|resp| resp.status == Status::MoreAvailable(0)
                    && resp.data.is_some()
                    && resp.data.as_ref().unwrap() == &data[0..256])
        );
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        let response = scard.handle_command(&apdu_get_response);
        assert!(
            response
                .as_ref()
                .is_ok_and(|resp| resp.status == Status::MoreAvailable(1)
                    && resp.data.is_some()
                    && resp.data.as_ref().unwrap() == &data[256..512])
        );
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        // set the Le field to 1 so that we get the last remaining byte
        apdu_get_response[4] = 1;
        let response = scard.handle_command(&apdu_get_response);
        assert!(response.as_ref().is_ok_and(|resp| resp.status == Status::OK
            && resp.data.is_some()
            && resp.data.as_ref().unwrap() == &data[512..]));
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        assert_eq!(received_result, data);
    }

    #[test]
    fn invalid_get_data_command() {
        // Verify that the GET DATA handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 should always be 0x3F; p2 should always be 0xFF
        let apdu_get_data_bad_p1_p2 = vec![0x00, 0xCB, 0x10, 0x21, 0x00];
        let response = scard.handle_command(&apdu_get_data_bad_p1_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // bad object tag in the data field
        let apdu_get_data_bad_tag = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x08];
        let response = scard.handle_command(&apdu_get_data_bad_tag);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn get_data_command() {
        // Verify that the GET DATA handler correctly handles all supported requests and returns correct data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // get CHUID
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let response = scard.handle_command(&apdu_get_data_chuid);
        assert!(
            response.is_ok_and(|resp| resp.status == Status::OK && resp.data.expect("Expected CHUID") == scard.chuid)
        );

        // get PIV authentication certificate
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        let response = scard.handle_command(&apdu_get_data_chuid);
        // verify the contents
        assert!(response.is_ok_and(|resp| {
            // as the certificate is larger than 256 bytes, we have to call the GET RESPONSE function a few times
            let complete_response = get_all_available_data(resp, &mut scard);
            complete_response == scard.auth_cert
        }));
    }

    #[test]
    fn general_authenticate_no_pin() {
        // Verify that the GENERAL AUTHENTICATE handler can't be used without unlocking the smart card first
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        let apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::SecurityStatusNotSatisfied));
    }

    #[test]
    fn invalid_general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        // p1 should always be 0x07; p2 should always be 0x9A
        let apdu_general_authenticate = vec![0x00, 0x87, 0xFF, 0xCC, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::UnsupportedFeature));
    }

    #[test]
    fn general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly encrypts the provided data
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        let data = "My message".as_bytes();

        let rsa_pk = RsaPrivateKey::try_from(&scard.auth_pk).expect("Can't convert the private key");
        // sign the data using the PKCS1-v1.5 padding scheme
        let signature_algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_512);
        let signed_data = signature_algorithm
            .sign(data, &scard.auth_pk)
            .expect("Error while signing the data");
        // extract the padded hash by decrypting the signature using the public key
        // we need to extract the padded hash to calculate the signature ourselves
        let padded_hash = modpow(
            &BoxedUint::from_be_slice_vartime(&signed_data),
            rsa_pk.e(),
            Odd::new(rsa_pk.n().clone().get()).into_option().unwrap(),
        );
        let padded_hash = padded_hash.to_be_bytes_trimmed_vartime().into_vec();

        // the hash is bigger than 127, so we have to use BER-TLV encoding
        let encoded_hash_length = ber_tlv_length_encoding(padded_hash.len());
        // encoded_hash_length + tag + hash
        let dat_tag_data_length = ber_tlv_length_encoding(1 + encoded_hash_length.len() + padded_hash.len());

        // use command chaining to send the data that is bigger than 255 bytes
        let mut apdu_general_authenticate = vec![0x10, 0x87, 0x07, 0x9A, 0xFF, 0x7C];
        apdu_general_authenticate.extend_from_slice(&dat_tag_data_length);
        apdu_general_authenticate.extend_from_slice(&[0x81]);
        apdu_general_authenticate.extend_from_slice(&encoded_hash_length);
        apdu_general_authenticate.extend_from_slice(&padded_hash[..248]);

        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));

        // send the remaining data and end command chaining by setting the CLA byte to 0x00
        let mut apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x07];
        apdu_general_authenticate.extend_from_slice(&padded_hash[248..]);
        // Le
        apdu_general_authenticate.extend_from_slice(&[0x00]);

        let response = scard
            .handle_command(&apdu_general_authenticate)
            .expect("Shouldn't have failed");

        let complete_response = get_all_available_data(response, &mut scard);
        let parsed_response =
            Tlv::from_bytes(&complete_response).expect("Couldn't parse a TLV object sent from the smart card");

        // verify the structure of the response and extract the signed hash
        assert_eq!(
            parsed_response.tag(),
            &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE).expect("Couldn't construct a TLV tag")
        );
        let response_tag = match parsed_response.value() {
            Value::Constructed(data) => data
                .iter()
                .find(|tlv_object| {
                    tlv_object.tag() == &Tag::try_from(tlv_tags::DAT_RESPONSE).expect("Couldn't construct a TLV tag")
                })
                .expect("The inner TLV object should contain a Response tag"),
            Value::Primitive(_) => panic!("Dynamic Authentication Template should contain constructed value"),
        };
        let signed_hash = match response_tag.value() {
            Value::Constructed(_) => panic!("Response tag should contain a primitive value"),
            Value::Primitive(signed_hash) => signed_hash,
        };
        // verify that the returned signature can be verified using the corresponding public key
        assert!(
            signature_algorithm
                .verify(
                    &scard
                        .auth_pk
                        .to_public_key()
                        .expect("Error while creating public key from a private key"),
                    data,
                    signed_hash
                )
                .is_ok()
        );
    }

    fn modpow(public_key: &BoxedUint, private_key: &BoxedUint, p: Odd<BoxedUint>) -> BoxedUint {
        let p = BoxedMontyParams::new_vartime(p);
        pow_mod_params(public_key, private_key, &p)
    }

    // Copied from `rsa` crate: https://github.com/RustCrypto/RSA/blob/eb1cca7b7ea42445dc874c1c1ce38873e4adade7/src/algorithms/rsa.rs#L232-L241
    fn pow_mod_params(base: &BoxedUint, exp: &BoxedUint, n_params: &BoxedMontyParams) -> BoxedUint {
        let base = reduce_vartime(base, n_params);
        base.pow(exp).retrieve()
    }

    fn reduce_vartime(n: &BoxedUint, p: &BoxedMontyParams) -> BoxedMontyForm {
        let modulus = p.modulus().as_nz_ref().clone();
        let n_reduced = n.rem_vartime(&modulus).resize_unchecked(p.bits_precision());
        BoxedMontyForm::new(n_reduced, p)
    }
}
