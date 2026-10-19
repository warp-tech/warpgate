use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_size, invalid_field_err,
    other_err,
};

use super::{ClientGccBlocks, ServerGccBlocks};
use crate::{mcs, per};

const CONFERENCE_REQUEST_OBJECT_ID: [u8; 6] = [0, 0, 20, 124, 0, 1];
const CONFERENCE_REQUEST_CLIENT_TO_SERVER_H221_NON_STANDARD: &[u8; 4] = b"Duca";
const CONFERENCE_REQUEST_SERVER_TO_CLIENT_H221_NON_STANDARD: &[u8; 4] = b"McDn";
const CONFERENCE_REQUEST_U16_MIN: u16 = 1001;

const CONFERENCE_REQUEST_CONNECT_PDU_SIZE: usize = 12;
const CONFERENCE_RESPONSE_CONNECT_PDU_SIZE: usize = 13;
const OBJECT_IDENTIFIER_KEY: u8 = 0;
const CONNECT_GCC_PDU_CONFERENCE_REQUEST_CHOICE: u8 = 0;
const CONNECT_GCC_PDU_CONFERENCE_RESPONSE_CHOICE: u8 = 0x14;
const CONFERENCE_REQUEST_USER_DATA_SELECTION: u8 = 8;
const USER_DATA_NUMBER_OF_SETS: u8 = 1;
const USER_DATA_H221_NON_STANDARD_CHOICE: u8 = 0xc0;
const CONFERENCE_RESPONSE_TAG: u32 = 1;
const CONFERENCE_RESPONSE_RESULT: u8 = 0;
const H221_NON_STANDARD_MIN_LENGTH: usize = 4;
const CONFERENCE_NAME: &[u8] = b"1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConferenceCreateRequest {
    /// INVARIANT: `gcc_blocks.size() <= u16::MAX - CONFERENCE_REQUEST_CONNECT_PDU_SIZE`
    gcc_blocks: ClientGccBlocks,
}

// Hand-rolled because the gcc_blocks size invariant cannot be expressed via
// `derive(Arbitrary)`. Without it, encode() panics via u16::try_from on
// overflowing gcc_blocks under fuzz.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ConferenceCreateRequest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let gcc_blocks = ClientGccBlocks::arbitrary(u)?;
        Self::new(gcc_blocks).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl ConferenceCreateRequest {
    const NAME: &'static str = "ConferenceCreateRequest";

    pub fn new(gcc_blocks: ClientGccBlocks) -> DecodeResult<Self> {
        // Ensure the invariant on gcc_blocks.size() is respected.
        check_invariant(gcc_blocks.size() <= usize::from(u16::MAX) - CONFERENCE_REQUEST_CONNECT_PDU_SIZE).ok_or_else(
            || {
                invalid_field_err!(
                    "gcc_blocks",
                    "gcc_blocks.size() + CONFERENCE_REQUEST_CONNECT_PDU_SIZE > u16::MAX"
                )
            },
        )?;

        Ok(Self { gcc_blocks })
    }

    pub fn gcc_blocks(&self) -> &ClientGccBlocks {
        &self.gcc_blocks
    }

    pub fn into_gcc_blocks(self) -> ClientGccBlocks {
        self.gcc_blocks
    }
}

impl Encode for ConferenceCreateRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in:dst, size: self.size());

        let gcc_blocks_buffer_length = self.gcc_blocks.size();

        // ConnectData::Key: select type OBJECT_IDENTIFIER
        per::write_choice(dst, OBJECT_IDENTIFIER_KEY);
        // ConnectData::Key: value
        per::write_object_id(dst, CONFERENCE_REQUEST_OBJECT_ID);

        // ConnectData::connectPDU: length
        per::write_length(
            dst,
            cast_length!(
                "gccBlocksLen",
                gcc_blocks_buffer_length + CONFERENCE_REQUEST_CONNECT_PDU_SIZE
            )?,
        );
        // ConnectGCCPDU (CHOICE): Select conferenceCreateRequest (0) of type ConferenceCreateRequest
        per::write_choice(dst, CONNECT_GCC_PDU_CONFERENCE_REQUEST_CHOICE);
        // ConferenceCreateRequest::Selection: select optional userData from ConferenceCreateRequest
        per::write_selection(dst, CONFERENCE_REQUEST_USER_DATA_SELECTION);
        // ConferenceCreateRequest::ConferenceName
        per::write_numeric_string(dst, CONFERENCE_NAME, 1).map_err(|e| other_err!("confName", source: e))?;
        per::write_padding(dst, 1);
        // UserData (SET OF SEQUENCE)
        // one set of UserData
        per::write_number_of_sets(dst, USER_DATA_NUMBER_OF_SETS);
        // select h221NonStandard
        per::write_choice(dst, USER_DATA_H221_NON_STANDARD_CHOICE);
        // h221NonStandard: client-to-server H.221 key, "Duca"
        per::write_octet_string(
            dst,
            CONFERENCE_REQUEST_CLIENT_TO_SERVER_H221_NON_STANDARD,
            H221_NON_STANDARD_MIN_LENGTH,
        )
        .map_err(|e| other_err!("client-to-server", source: e))?;
        // H221NonStandardIdentifier (octet string)
        per::write_length(dst, cast_length!("gccBlocksLen", gcc_blocks_buffer_length)?);
        self.gcc_blocks.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let gcc_blocks_buffer_length = self.gcc_blocks.size();
        let req_length = u16::try_from(CONFERENCE_REQUEST_CONNECT_PDU_SIZE + gcc_blocks_buffer_length)
            .expect("per the invariant on self.gcc_blocks, this cast is infallible");
        let length = u16::try_from(gcc_blocks_buffer_length)
            .expect("per the invariant on self.gcc_blocks, this cast is infallible");

        per::CHOICE_SIZE
            + CONFERENCE_REQUEST_OBJECT_ID.len()
            + per::sizeof_length(usize::from(req_length))
            + CONFERENCE_REQUEST_CONNECT_PDU_SIZE
            + per::sizeof_length(usize::from(length))
            + gcc_blocks_buffer_length
    }
}

impl<'de> Decode<'de> for ConferenceCreateRequest {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // ConnectData

        // ConnectData::Key: select object (0) of type OBJECT_IDENTIFIER
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != OBJECT_IDENTIFIER_KEY {
            return Err(invalid_field_err!("ConnectData::Key", "Got unexpected ConnectData key"));
        }
        // ConnectData::Key: value (OBJECT_IDENTIFIER)
        if per::read_object_id(src).map_err(|e| other_err!("value", source: e))? != CONFERENCE_REQUEST_OBJECT_ID {
            return Err(invalid_field_err!(
                "ConnectData::Key",
                "Got unexpected ConnectData key value"
            ));
        }

        // ConnectData::connectPDU: length
        let _length = per::read_length(src).map_err(|e| other_err!("len", source: e))?;
        // ConnectGCCPDU (CHOICE): Select conferenceCreateRequest (0) of type ConferenceCreateRequest
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != CONNECT_GCC_PDU_CONFERENCE_REQUEST_CHOICE {
            return Err(invalid_field_err!(
                "ConnectData::connectPdu",
                "Got invalid ConnectGCCPDU choice (expected ConferenceCreateRequest)"
            ));
        }
        // ConferenceCreateRequest::Selection: select optional userData from ConferenceCreateRequest
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_selection(src) != CONFERENCE_REQUEST_USER_DATA_SELECTION {
            return Err(invalid_field_err!(
                "ConferenceCreateRequest::Selection",
                "Got invalid ConferenceCreateRequest selection (expected UserData)",
            ));
        }
        // ConferenceCreateRequest::ConferenceName
        per::read_numeric_string(src, 1).map_err(|e| other_err!("confName", source: e))?;
        // padding
        per::read_padding(src, 1);

        // UserData (SET OF SEQUENCE)
        // one set of UserData
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_number_of_sets(src) != USER_DATA_NUMBER_OF_SETS {
            return Err(invalid_field_err!(
                "ConferenceCreateRequest",
                "Got invalid ConferenceCreateRequest number of sets (expected 1)",
            ));
        }
        // select h221NonStandard
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != USER_DATA_H221_NON_STANDARD_CHOICE {
            return Err(invalid_field_err!(
                "ConferenceCreateRequest",
                "Expected UserData H221NonStandard choice",
            ));
        }
        // h221NonStandard: client-to-server H.221 key, "Duca"
        if per::read_octet_string(src, H221_NON_STANDARD_MIN_LENGTH)
            .map_err(|e| other_err!("client-to-server", source: e))?
            != CONFERENCE_REQUEST_CLIENT_TO_SERVER_H221_NON_STANDARD
        {
            return Err(invalid_field_err!(
                "ConferenceCreateRequest",
                "Got invalid H221NonStandard client-to-server key",
            ));
        }
        // H221NonStandardIdentifier (octet string)
        let (_gcc_blocks_buffer_length, _) = per::read_length(src).map_err(|e| other_err!("len", source: e))?;
        let gcc_blocks = ClientGccBlocks::decode(src)?;

        Self::new(gcc_blocks)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConferenceCreateResponse {
    user_id: u16,
    /// INVARIANT: `gcc_blocks.size() <= u16::MAX - CONFERENCE_RESPONSE_CONNECT_PDU_SIZE`
    gcc_blocks: ServerGccBlocks,
}

// Hand-rolled for the same reason as `ConferenceCreateRequest` above: the
// gcc_blocks size invariant cannot be expressed via `derive(Arbitrary)`.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ConferenceCreateResponse {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let user_id = u16::arbitrary(u)?;
        let gcc_blocks = ServerGccBlocks::arbitrary(u)?;
        Self::new(user_id, gcc_blocks).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl ConferenceCreateResponse {
    const NAME: &'static str = "ConferenceCreateResponse";

    pub fn new(user_id: u16, gcc_blocks: ServerGccBlocks) -> DecodeResult<Self> {
        // Ensure the invariant on gcc_blocks.size() is respected.
        check_invariant(gcc_blocks.size() <= usize::from(u16::MAX) - CONFERENCE_RESPONSE_CONNECT_PDU_SIZE).ok_or_else(
            || {
                invalid_field_err!(
                    "gcc_blocks",
                    "gcc_blocks.size() + CONFERENCE_REQUEST_CONNECT_PDU_SIZE > u16::MAX"
                )
            },
        )?;

        Ok(Self { user_id, gcc_blocks })
    }

    pub fn gcc_blocks(&self) -> &ServerGccBlocks {
        &self.gcc_blocks
    }

    pub fn into_gcc_blocks(self) -> ServerGccBlocks {
        self.gcc_blocks
    }
}

impl Encode for ConferenceCreateResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let gcc_blocks_buffer_length = self.gcc_blocks.size();

        // ConnectData::Key: select type OBJECT_IDENTIFIER
        per::write_choice(dst, OBJECT_IDENTIFIER_KEY);
        // ConnectData::Key: value
        per::write_object_id(dst, CONFERENCE_REQUEST_OBJECT_ID);

        // ConnectData::connectPDU: length (MUST be ignored by the client according to [MS-RDPBCGR])
        per::write_length(
            dst,
            cast_length!(
                "gccBlocksLen",
                // FIXME: It seems that the addition of 1 here is a bug.
                // The fuzzing is not failing because this length is ignored.
                gcc_blocks_buffer_length + CONFERENCE_RESPONSE_CONNECT_PDU_SIZE + 1
            )?,
        );
        // ConnectGCCPDU (CHOICE): Select conferenceCreateResponse (1) of type ConferenceCreateResponse
        per::write_choice(dst, CONNECT_GCC_PDU_CONFERENCE_RESPONSE_CHOICE);
        // ConferenceCreateResponse::nodeID (UserID)
        per::write_u16(dst, self.user_id, CONFERENCE_REQUEST_U16_MIN).map_err(|e| other_err!("userId", source: e))?;
        // ConferenceCreateResponse::tag (INTEGER)
        per::write_u32(dst, CONFERENCE_RESPONSE_TAG);
        // ConferenceCreateResponse::result (ENUMERATED)
        per::write_enum(dst, CONFERENCE_RESPONSE_RESULT);
        per::write_number_of_sets(dst, USER_DATA_NUMBER_OF_SETS);
        // select h221NonStandard
        per::write_choice(dst, USER_DATA_H221_NON_STANDARD_CHOICE);
        // h221NonStandard, server-to-client H.221 key, "McDn"
        per::write_octet_string(
            dst,
            CONFERENCE_REQUEST_SERVER_TO_CLIENT_H221_NON_STANDARD,
            H221_NON_STANDARD_MIN_LENGTH,
        )
        .map_err(|e| other_err!("server-to-client", source: e))?;
        // H221NonStandardIdentifier (octet string)
        per::write_length(dst, cast_length!("gccBlocksLen", gcc_blocks_buffer_length)?);
        self.gcc_blocks.encode(dst)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let gcc_blocks_buffer_length = self.gcc_blocks.size();
        let req_length = u16::try_from(CONFERENCE_RESPONSE_CONNECT_PDU_SIZE + gcc_blocks_buffer_length)
            .expect("per the invariant on self.gcc_blocks, this cast is infallible");
        let length = u16::try_from(gcc_blocks_buffer_length)
            .expect("per the invariant on self.gcc_blocks, this cast is infallible");

        per::CHOICE_SIZE
            + CONFERENCE_REQUEST_OBJECT_ID.len()
            + per::sizeof_length(usize::from(req_length))
            + CONFERENCE_RESPONSE_CONNECT_PDU_SIZE
            + per::sizeof_length(usize::from(length))
            + gcc_blocks_buffer_length
    }
}

impl<'de> Decode<'de> for ConferenceCreateResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        // ConnectData::Key: select type OBJECT_IDENTIFIER
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != OBJECT_IDENTIFIER_KEY {
            return Err(invalid_field_err!("ConnectData::Key", "Got unexpected ConnectData key"));
        }
        // ConnectData::Key: value
        if per::read_object_id(src).map_err(|e| other_err!("value", source: e))? != CONFERENCE_REQUEST_OBJECT_ID {
            return Err(invalid_field_err!(
                "ConnectData::Key",
                "Got unexpected ConnectData key value"
            ));
        };
        // ConnectData::connectPDU: length (MUST be ignored by the client according to [MS-RDPBCGR])
        let _length = per::read_length(src).map_err(|e| other_err!("len", source: e))?;
        // ConnectGCCPDU (CHOICE): Select conferenceCreateResponse (1) of type ConferenceCreateResponse
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != CONNECT_GCC_PDU_CONFERENCE_RESPONSE_CHOICE {
            return Err(invalid_field_err!(
                "ConnectData::connectPdu",
                "Got invalid ConnectGCCPDU choice (expected ConferenceCreateResponse)"
            ));
        }
        // ConferenceCreateResponse::nodeID (UserID)
        let user_id = per::read_u16(src, CONFERENCE_REQUEST_U16_MIN).map_err(|e| other_err!("userId", source: e))?;
        // ConferenceCreateResponse::tag (INTEGER)
        if per::read_u32(src).map_err(|e| other_err!("tag", source: e))? != CONFERENCE_RESPONSE_TAG {
            return Err(invalid_field_err!(
                "ConferenceCreateResponse::tag",
                "Got unexpected ConferenceCreateResponse tag",
            ));
        }
        // ConferenceCreateResponse::result (ENUMERATED)
        if per::read_enum(src, mcs::RESULT_ENUM_LENGTH).map_err(|e| other_err!("result", source: e))?
            != CONFERENCE_RESPONSE_RESULT
        {
            return Err(invalid_field_err!(
                "ConferenceCreateResponse::result",
                "Got invalid ConferenceCreateResponse result",
            ));
        }
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_number_of_sets(src) != USER_DATA_NUMBER_OF_SETS {
            return Err(invalid_field_err!(
                "ConferenceCreateResponse",
                "Got invalid ConferenceCreateResponse number of sets (expected 1)",
            ));
        }
        // select h221NonStandard
        ensure_size!(in: src, size: per::CHOICE_SIZE);
        if per::read_choice(src) != USER_DATA_H221_NON_STANDARD_CHOICE {
            return Err(invalid_field_err!(
                "ConferenceCreateResponse",
                "Expected UserData H221NonStandard choice",
            ));
        }
        // h221NonStandard, server-to-client H.221 key, "McDn"
        if per::read_octet_string(src, H221_NON_STANDARD_MIN_LENGTH)
            .map_err(|e| other_err!("server-to-client", source: e))?
            != CONFERENCE_REQUEST_SERVER_TO_CLIENT_H221_NON_STANDARD
        {
            return Err(invalid_field_err!(
                "ConferenceCreateResponse",
                "Got invalid H221NonStandard server-to-client key",
            ));
        }
        let (_gcc_blocks_buffer_length, _) = per::read_length(src).map_err(|e| other_err!("len", source: e))?;
        let gcc_blocks = ServerGccBlocks::decode(src)?;

        Self::new(user_id, gcc_blocks)
    }
}

/// Use this when establishing invariants.
#[inline]
#[must_use]
fn check_invariant(condition: bool) -> Option<()> {
    condition.then_some(())
}
