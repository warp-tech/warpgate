use std::borrow::Cow;

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, IntoOwned, ReadCursor, WriteCursor, cast_length, ensure_size,
    invalid_field_err,
};

use crate::tpdu::{TpduCode, TpduHeader};
use crate::tpkt::TpktHeader;
use crate::{Pdu, impl_x224_pdu_borrowing};

pub trait X224Pdu<'de>: Sized {
    const X224_NAME: &'static str;

    const TPDU_CODE: TpduCode;

    fn x224_body_encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()>;

    fn x224_body_decode(src: &mut ReadCursor<'de>, tpkt: &TpktHeader, tpdu: &TpduHeader) -> DecodeResult<Self>;

    fn tpdu_header_variable_part_size(&self) -> usize;

    fn tpdu_user_data_size(&self) -> usize;
}

impl<'de, T> Pdu for T
where
    T: X224Pdu<'de>,
{
    const NAME: &'static str = T::X224_NAME;
}

#[derive(Debug, Eq, PartialEq)]
pub struct X224<T>(pub T);

impl<'de, T> Encode for X224<T>
where
    T: X224Pdu<'de>,
{
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let packet_length = self.size();

        ensure_size!(in: dst, size: packet_length);

        TpktHeader {
            packet_length: cast_length!("packet length", packet_length)?,
        }
        .write(dst)?;

        let li = cast_length!(
            "length indicator",
            (T::TPDU_CODE.header_fixed_part_size() + self.0.tpdu_header_variable_part_size() - 1)
        )?;

        TpduHeader { li, code: T::TPDU_CODE }.write(dst)?;

        self.0.x224_body_encode(dst)
    }

    fn name(&self) -> &'static str {
        T::X224_NAME
    }

    fn size(&self) -> usize {
        TpktHeader::SIZE
            + T::TPDU_CODE.header_fixed_part_size()
            + self.0.tpdu_header_variable_part_size()
            + self.0.tpdu_user_data_size()
    }
}

impl<'de, T> Decode<'de> for X224<T>
where
    T: X224Pdu<'de>,
{
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let tpkt = TpktHeader::read(src)?;

        ensure_size!(in: src, size: tpkt.packet_length().saturating_sub(TpktHeader::SIZE));

        let tpdu = TpduHeader::read(src, &tpkt)?;
        tpdu.code.check_expected(T::TPDU_CODE)?;

        if tpdu.size() < tpdu.fixed_part_size() {
            return Err(invalid_field_err(
                "TpduHeader",
                "li",
                "fixed part bigger than total header size",
            ));
        }

        T::x224_body_decode(src, &tpkt, &tpdu).map(X224)
    }
}

pub struct X224Data<'a> {
    pub data: Cow<'a, [u8]>,
}

impl_x224_pdu_borrowing!(X224Data<'_>, OwnedX224Data);

impl IntoOwned for X224Data<'_> {
    type Owned = OwnedX224Data;

    fn into_owned(self) -> Self::Owned {
        X224Data {
            data: Cow::Owned(self.data.into_owned()),
        }
    }
}

impl<'de> X224Pdu<'de> for X224Data<'de> {
    const X224_NAME: &'static str = "X.224 Data";

    const TPDU_CODE: TpduCode = TpduCode::DATA;

    fn x224_body_encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.data.len());
        dst.write_slice(&self.data);

        Ok(())
    }

    fn x224_body_decode(src: &mut ReadCursor<'de>, tpkt: &TpktHeader, tpdu: &TpduHeader) -> DecodeResult<Self> {
        let user_data_size = user_data_size(tpkt, tpdu);

        ensure_size!(in: src, size: user_data_size);
        let data = src.read_slice(user_data_size);

        Ok(Self {
            data: Cow::Borrowed(data),
        })
    }

    fn tpdu_header_variable_part_size(&self) -> usize {
        0
    }

    fn tpdu_user_data_size(&self) -> usize {
        self.data.len()
    }
}

pub fn user_data_size(tpkt: &TpktHeader, tpdu: &TpduHeader) -> usize {
    tpkt.packet_length() - TpktHeader::SIZE - tpdu.size()
}
