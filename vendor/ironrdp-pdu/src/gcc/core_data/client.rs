use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, ensure_size,
    invalid_field_err, write_padding,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive as _;
use tap::Pipe as _;

use super::{RdpVersion, VERSION_SIZE};
use crate::nego::SecurityProtocol;
use crate::utils;

pub const IME_FILE_NAME_SIZE: usize = 64;

const DESKTOP_WIDTH_SIZE: usize = 2;
const DESKTOP_HEIGHT_SIZE: usize = 2;
const COLOR_DEPTH_SIZE: usize = 2;
const SEC_ACCESS_SEQUENCE_SIZE: usize = 2;
const KEYBOARD_LAYOUT_SIZE: usize = 4;
const CLIENT_BUILD_SIZE: usize = 4;
const CLIENT_NAME_SIZE: usize = 32;
const KEYBOARD_TYPE_SIZE: usize = 4;
const KEYBOARD_SUB_TYPE_SIZE: usize = 4;
const KEYBOARD_FUNCTIONAL_KEYS_COUNT_SIZE: usize = 4;

const POST_BETA_COLOR_DEPTH_SIZE: usize = 2;
const CLIENT_PRODUCT_ID_SIZE: usize = 2;
const SERIAL_NUMBER_SIZE: usize = 4;
const HIGH_COLOR_DEPTH_SIZE: usize = 2;
const SUPPORTED_COLOR_DEPTHS_SIZE: usize = 2;
const EARLY_CAPABILITY_FLAGS_SIZE: usize = 2;
const DIG_PRODUCT_ID_SIZE: usize = 64;
const CONNECTION_TYPE_SIZE: usize = 1;
const PADDING_SIZE: usize = 1;
const SERVER_SELECTED_PROTOCOL_SIZE: usize = 4;
const DESKTOP_PHYSICAL_WIDTH_SIZE: usize = 4;
const DESKTOP_PHYSICAL_HEIGHT_SIZE: usize = 4;
const DESKTOP_ORIENTATION_SIZE: usize = 2;
const DESKTOP_SCALE_FACTOR_SIZE: usize = 4;
const DEVICE_SCALE_FACTOR_SIZE: usize = 4;

/// 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE) (required part)
///
/// [2.2.1.3.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientCoreData {
    pub version: RdpVersion,
    pub desktop_width: u16,
    pub desktop_height: u16,
    /// The requested color depth. Values in this field MUST be ignored if the postBeta2ColorDepth field is present.
    pub color_depth: ColorDepth,
    pub sec_access_sequence: SecureAccessSequence,
    pub keyboard_layout: u32,
    pub client_build: u32,
    pub client_name: String,
    pub keyboard_type: KeyboardType,
    pub keyboard_subtype: u32,
    pub keyboard_functional_keys_count: u32,
    pub ime_file_name: String,
    pub optional_data: ClientCoreOptionalData,
}

impl ClientCoreData {
    const NAME: &'static str = "ClientCoreData";

    const FIXED_PART_SIZE: usize = VERSION_SIZE
        + DESKTOP_WIDTH_SIZE
        + DESKTOP_HEIGHT_SIZE
        + COLOR_DEPTH_SIZE
        + SEC_ACCESS_SEQUENCE_SIZE
        + KEYBOARD_LAYOUT_SIZE
        + CLIENT_BUILD_SIZE
        + CLIENT_NAME_SIZE
        + KEYBOARD_TYPE_SIZE
        + KEYBOARD_SUB_TYPE_SIZE
        + KEYBOARD_FUNCTIONAL_KEYS_COUNT_SIZE
        + IME_FILE_NAME_SIZE;

    pub fn client_color_depth(&self) -> ClientColorDepth {
        if let Some(high_color_depth) = self.optional_data.high_color_depth {
            if let Some(early_capability_flags) = self.optional_data.early_capability_flags {
                if early_capability_flags.contains(ClientEarlyCapabilityFlags::WANT_32_BPP_SESSION) {
                    ClientColorDepth::Bpp32
                } else {
                    From::from(high_color_depth)
                }
            } else {
                From::from(high_color_depth)
            }
        } else if let Some(post_beta_color_depth) = self.optional_data.post_beta2_color_depth {
            From::from(post_beta_color_depth)
        } else {
            From::from(self.color_depth)
        }
    }
}

impl Encode for ClientCoreData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let mut client_name_dst = utils::to_utf16_bytes(self.client_name.as_ref());
        client_name_dst.resize(CLIENT_NAME_SIZE - 2, 0);
        let mut ime_file_name_dst = utils::to_utf16_bytes(self.ime_file_name.as_ref());
        ime_file_name_dst.resize(IME_FILE_NAME_SIZE - 2, 0);

        dst.write_u32(self.version.0);
        dst.write_u16(self.desktop_width);
        dst.write_u16(self.desktop_height);
        dst.write_u16(self.color_depth.as_u16());
        dst.write_u16(self.sec_access_sequence.as_u16());
        dst.write_u32(self.keyboard_layout);
        dst.write_u32(self.client_build);
        dst.write_slice(client_name_dst.as_ref());
        dst.write_u16(0); // client name UTF-16 null terminator
        dst.write_u32(self.keyboard_type.0);
        dst.write_u32(self.keyboard_subtype);
        dst.write_u32(self.keyboard_functional_keys_count);
        dst.write_slice(ime_file_name_dst.as_ref());
        dst.write_u16(0); // ime file name UTF-16 null terminator

        self.optional_data.encode(dst)
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.optional_data.size()
    }
}

impl<'de> Decode<'de> for ClientCoreData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let version = src.read_u32().pipe(RdpVersion);
        let desktop_width = src.read_u16();
        let desktop_height = src.read_u16();
        let color_depth = src
            .read_u16()
            .pipe(ColorDepth::from_u16)
            .ok_or_else(|| invalid_field_err!("colorDepth", "invalid color depth"))?;
        let sec_access_sequence = src
            .read_u16()
            .pipe(SecureAccessSequence::from_u16)
            .ok_or_else(|| invalid_field_err!("secAccessSequence", "invalid secure access sequence"))?;
        let keyboard_layout = src.read_u32();
        let client_build = src.read_u32();

        let client_name_buffer = src.read_slice(CLIENT_NAME_SIZE);
        let client_name = utils::from_utf16_bytes(client_name_buffer)
            .trim_end_matches('\u{0}')
            .into();

        let keyboard_type = src.read_u32().pipe(KeyboardType);
        let keyboard_subtype = src.read_u32();
        let keyboard_functional_keys_count = src.read_u32();

        let ime_file_name_buffer = src.read_slice(IME_FILE_NAME_SIZE);
        let ime_file_name = utils::from_utf16_bytes(ime_file_name_buffer)
            .trim_end_matches('\u{0}')
            .into();

        let optional_data = ClientCoreOptionalData::decode(src)?;

        Ok(Self {
            version,
            desktop_width,
            desktop_height,
            color_depth,
            sec_access_sequence,
            keyboard_layout,
            client_build,
            client_name,
            keyboard_type,
            keyboard_subtype,
            keyboard_functional_keys_count,
            ime_file_name,
            optional_data,
        })
    }
}

/// 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE) (optional part)
///
/// For every field in this structure, the previous fields MUST be present in order to be a valid structure.
/// It is incumbent on the user of this structure to ensure that the structure is valid.
///
/// [2.2.1.3.2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ClientCoreOptionalData {
    /// The requested color depth. Values in this field MUST be ignored if the highColorDepth field is present.
    pub post_beta2_color_depth: Option<ColorDepth>,
    pub client_product_id: Option<u16>,
    pub serial_number: Option<u32>,
    /// The requested color depth.
    pub high_color_depth: Option<HighColorDepth>,
    /// Specifies the high color depths that the client is capable of supporting.
    pub supported_color_depths: Option<SupportedColorDepths>,
    pub early_capability_flags: Option<ClientEarlyCapabilityFlags>,
    pub dig_product_id: Option<String>,
    pub connection_type: Option<ConnectionType>,
    pub server_selected_protocol: Option<SecurityProtocol>,
    pub desktop_physical_width: Option<u32>,
    pub desktop_physical_height: Option<u32>,
    pub desktop_orientation: Option<u16>,
    pub desktop_scale_factor: Option<u32>,
    pub device_scale_factor: Option<u32>,
}

impl ClientCoreOptionalData {
    const NAME: &'static str = "ClientCoreOptionalData";
}

impl Encode for ClientCoreOptionalData {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        if let Some(value) = self.post_beta2_color_depth {
            dst.write_u16(value.as_u16());
        }

        if let Some(value) = self.client_product_id {
            if self.post_beta2_color_depth.is_none() {
                return Err(invalid_field_err!(
                    "postBeta2ColorDepth",
                    "postBeta2ColorDepth must be present"
                ));
            }
            dst.write_u16(value);
        }

        if let Some(value) = self.serial_number {
            if self.client_product_id.is_none() {
                return Err(invalid_field_err!("clientProductId", "clientProductId must be present"));
            }
            dst.write_u32(value);
        }

        if let Some(value) = self.high_color_depth {
            if self.serial_number.is_none() {
                return Err(invalid_field_err!("serialNumber", "serialNumber must be present"));
            }
            dst.write_u16(value.as_u16());
        }

        if let Some(value) = self.supported_color_depths {
            if self.high_color_depth.is_none() {
                return Err(invalid_field_err!("highColorDepth", "highColorDepth must be present"));
            }
            dst.write_u16(value.bits());
        }

        if let Some(value) = self.early_capability_flags {
            if self.supported_color_depths.is_none() {
                return Err(invalid_field_err!(
                    "supportedColorDepths",
                    "supportedColorDepths must be present"
                ));
            }
            dst.write_u16(value.bits());
        }

        if let Some(ref value) = self.dig_product_id {
            if self.early_capability_flags.is_none() {
                return Err(invalid_field_err!(
                    "earlyCapabilityFlags",
                    "earlyCapabilityFlags must be present"
                ));
            }
            let mut dig_product_id_buffer = utils::to_utf16_bytes(value);
            dig_product_id_buffer.resize(DIG_PRODUCT_ID_SIZE - 2, 0);
            dig_product_id_buffer.extend_from_slice([0; 2].as_ref()); // UTF-16 null terminator

            dst.write_slice(dig_product_id_buffer.as_ref())
        }

        if let Some(value) = self.connection_type {
            if self.dig_product_id.is_none() {
                return Err(invalid_field_err!("digProductId", "digProductId must be present"));
            }
            dst.write_u8(value.as_u8());
            write_padding!(dst, 1);
        }

        if let Some(value) = self.server_selected_protocol {
            if self.connection_type.is_none() {
                return Err(invalid_field_err!("connectionType", "connectionType must be present"));
            }
            dst.write_u32(value.bits())
        }

        if let Some(value) = self.desktop_physical_width {
            if self.server_selected_protocol.is_none() {
                return Err(invalid_field_err!(
                    "serverSelectedProtocol",
                    "serverSelectedProtocol must be present"
                ));
            }
            dst.write_u32(value);
        }

        if let Some(value) = self.desktop_physical_height {
            if self.desktop_physical_width.is_none() {
                return Err(invalid_field_err!(
                    "desktopPhysicalWidth",
                    "desktopPhysicalWidth must be present"
                ));
            }
            dst.write_u32(value);
        }

        if let Some(value) = self.desktop_orientation {
            if self.desktop_physical_height.is_none() {
                return Err(invalid_field_err!(
                    "desktopPhysicalHeight",
                    "desktopPhysicalHeight must be present"
                ));
            }
            dst.write_u16(value);
        }

        if let Some(value) = self.desktop_scale_factor {
            if self.desktop_orientation.is_none() {
                return Err(invalid_field_err!(
                    "desktopOrientation",
                    "desktopOrientation must be present"
                ));
            }
            dst.write_u32(value);
        }

        if let Some(value) = self.device_scale_factor {
            if self.desktop_scale_factor.is_none() {
                return Err(invalid_field_err!(
                    "desktopScaleFactor",
                    "desktopScaleFactor must be present"
                ));
            }
            dst.write_u32(value);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let mut size = 0;

        if self.post_beta2_color_depth.is_some() {
            size += POST_BETA_COLOR_DEPTH_SIZE;
        }
        if self.client_product_id.is_some() {
            size += CLIENT_PRODUCT_ID_SIZE;
        }
        if self.serial_number.is_some() {
            size += SERIAL_NUMBER_SIZE;
        }
        if self.high_color_depth.is_some() {
            size += HIGH_COLOR_DEPTH_SIZE;
        }
        if self.supported_color_depths.is_some() {
            size += SUPPORTED_COLOR_DEPTHS_SIZE;
        }
        if self.early_capability_flags.is_some() {
            size += EARLY_CAPABILITY_FLAGS_SIZE;
        }
        if self.dig_product_id.is_some() {
            size += DIG_PRODUCT_ID_SIZE;
        }
        if self.connection_type.is_some() {
            size += CONNECTION_TYPE_SIZE + PADDING_SIZE;
        }
        if self.server_selected_protocol.is_some() {
            size += SERVER_SELECTED_PROTOCOL_SIZE;
        }
        if self.desktop_physical_width.is_some() {
            size += DESKTOP_PHYSICAL_WIDTH_SIZE;
        }
        if self.desktop_physical_height.is_some() {
            size += DESKTOP_PHYSICAL_HEIGHT_SIZE;
        }
        if self.desktop_orientation.is_some() {
            size += DESKTOP_ORIENTATION_SIZE;
        }
        if self.desktop_scale_factor.is_some() {
            size += DESKTOP_SCALE_FACTOR_SIZE;
        }
        if self.device_scale_factor.is_some() {
            size += DEVICE_SCALE_FACTOR_SIZE;
        }

        size
    }
}

macro_rules! try_or_return {
    ($expr:expr, $ret:expr) => {
        match $expr {
            Ok(v) => v,
            Err(_) => return Ok($ret),
        }
    };
}

impl<'de> Decode<'de> for ClientCoreOptionalData {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        let mut optional_data = Self::default();

        optional_data.post_beta2_color_depth = Some(
            ColorDepth::from_u16(try_or_return!(src.try_read_u16(), optional_data))
                .ok_or_else(|| invalid_field_err!("postBeta2ColorDepth", "invalid color depth"))?,
        );

        optional_data.client_product_id = Some(try_or_return!(src.try_read_u16(), optional_data));
        optional_data.serial_number = Some(try_or_return!(src.try_read_u32(), optional_data));

        optional_data.high_color_depth = Some(
            HighColorDepth::from_u16(try_or_return!(src.try_read_u16(), optional_data))
                .ok_or_else(|| invalid_field_err!("highColorDepth", "invalid color depth"))?,
        );

        optional_data.supported_color_depths = Some(
            SupportedColorDepths::from_bits(try_or_return!(src.try_read_u16(), optional_data))
                .ok_or_else(|| invalid_field_err!("supportedColorDepths", "invalid supported color depths"))?,
        );

        optional_data.early_capability_flags = Some(
            ClientEarlyCapabilityFlags::from_bits(try_or_return!(src.try_read_u16(), optional_data))
                .ok_or_else(|| invalid_field_err!("earlyCapabilityFlags", "invalid early capability flags"))?,
        );

        if src.len() < DIG_PRODUCT_ID_SIZE {
            return Ok(optional_data);
        }

        let dig_product_id = src.read_slice(DIG_PRODUCT_ID_SIZE);
        optional_data.dig_product_id = Some(utils::from_utf16_bytes(dig_product_id).trim_end_matches('\u{0}').into());

        optional_data.connection_type = Some(
            ConnectionType::from_u8(try_or_return!(src.try_read_u8(), optional_data))
                .ok_or_else(|| invalid_field_err!("connectionType", "invalid connection type"))?,
        );

        try_or_return!(src.try_read_u8(), optional_data);

        optional_data.server_selected_protocol = Some(
            SecurityProtocol::from_bits(try_or_return!(src.try_read_u32(), optional_data))
                .ok_or_else(|| invalid_field_err!("serverSelectedProtocol", "invalid security protocol"))?,
        );

        optional_data.desktop_physical_width = Some(try_or_return!(src.try_read_u32(), optional_data));
        // physical height must be present, if the physical width is present
        optional_data.desktop_physical_height = Some(src.read_u32());

        optional_data.desktop_orientation = Some(try_or_return!(src.try_read_u16(), optional_data));
        optional_data.desktop_scale_factor = Some(try_or_return!(src.try_read_u32(), optional_data));
        // device scale factor must be present, if the desktop scale factor is present
        optional_data.device_scale_factor = Some(src.read_u32());

        Ok(optional_data)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ClientColorDepth {
    Bpp4,
    Bpp8,
    Rgb555Bpp16,
    Rgb565Bpp16,
    Bpp24,
    Bpp32,
}

impl From<ColorDepth> for ClientColorDepth {
    fn from(color_depth: ColorDepth) -> Self {
        match color_depth {
            ColorDepth::Bpp4 => ClientColorDepth::Bpp4,
            ColorDepth::Bpp8 => ClientColorDepth::Bpp8,
            ColorDepth::Rgb555Bpp16 => ClientColorDepth::Rgb555Bpp16,
            ColorDepth::Rgb565Bpp16 => ClientColorDepth::Rgb565Bpp16,
            ColorDepth::Bpp24 => ClientColorDepth::Bpp24,
        }
    }
}

impl From<HighColorDepth> for ClientColorDepth {
    fn from(color_depth: HighColorDepth) -> Self {
        match color_depth {
            HighColorDepth::Bpp4 => ClientColorDepth::Bpp4,
            HighColorDepth::Bpp8 => ClientColorDepth::Bpp8,
            HighColorDepth::Rgb555Bpp16 => ClientColorDepth::Rgb555Bpp16,
            HighColorDepth::Rgb565Bpp16 => ClientColorDepth::Rgb565Bpp16,
            HighColorDepth::Bpp24 => ClientColorDepth::Bpp24,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ColorDepth {
    Bpp4 = 0xCA00,
    Bpp8 = 0xCA01,
    Rgb555Bpp16 = 0xCA02,
    Rgb565Bpp16 = 0xCA03,
    Bpp24 = 0xCA04,
}

impl ColorDepth {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, FromPrimitive, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum HighColorDepth {
    Bpp4 = 0x0004,
    Bpp8 = 0x0008,
    Rgb555Bpp16 = 0x000F,
    Rgb565Bpp16 = 0x0010,
    Bpp24 = 0x0018,
}

impl HighColorDepth {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum SecureAccessSequence {
    Del = 0xAA03,
}

impl SecureAccessSequence {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u16(self) -> u16 {
        self as u16
    }
}

/// 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE) `keyboardType` field.
///
/// MS-RDPBCGR documents this as a value table that has grown across revisions (the copy in this
/// section already lists `KOREAN`, a value absent from the older copy in 2.2.7.1.6); Windows'
/// `GetKeyboardType` additionally documents `0x51` for generic HID keyboards. Represented
/// permissively rather than as a closed enum so an unrecognized value round-trips instead of
/// failing the whole Client Core Data parse, matching `RdpVersion` immediately above this field
/// in the same structure.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyboardType(pub u32);

impl KeyboardType {
    pub const IBM_PC_XT: Self = Self(1);
    pub const OLIVETTI_ICO: Self = Self(2);
    pub const IBM_PC_AT: Self = Self(3);
    pub const IBM_ENHANCED: Self = Self(4);
    pub const NOKIA_1050: Self = Self(5);
    pub const NOKIA_9140: Self = Self(6);
    pub const JAPANESE: Self = Self(7);
    pub const KOREAN: Self = Self(8);
}

impl From<u32> for KeyboardType {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<KeyboardType> for u32 {
    fn from(keyboard_type: KeyboardType) -> Self {
        keyboard_type.0
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ConnectionType {
    NotUsed = 0, // not used as ClientEarlyCapabilityFlags::VALID_CONNECTION_TYPE not set
    Modem = 1,
    BroadbandLow = 2,
    Satellite = 3,
    BroadbandHigh = 4,
    Wan = 5,
    Lan = 6,
    Autodetect = 7,
}

impl ConnectionType {
    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u8(self) -> u8 {
        self as u8
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct SupportedColorDepths: u16 {
        const BPP24 = 1;
        const BPP16 = 2;
        const BPP15 = 4;
        const BPP32 = 8;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct ClientEarlyCapabilityFlags: u16 {
        const SUPPORT_ERR_INFO_PDU = 0x0001;
        const WANT_32_BPP_SESSION = 0x0002;
        const SUPPORT_STATUS_INFO_PDU = 0x0004;
        const STRONG_ASYMMETRIC_KEYS = 0x0008;
        const RELATIVE_MOUSE_INPUT = 0x0010;
        const VALID_CONNECTION_TYPE = 0x0020;
        const SUPPORT_MONITOR_LAYOUT_PDU = 0x0040;
        const SUPPORT_NET_CHAR_AUTODETECT = 0x0080;
        const SUPPORT_DYN_VC_GFX_PROTOCOL =0x0100;
        const SUPPORT_DYNAMIC_TIME_ZONE = 0x0200;
        const SUPPORT_HEART_BEAT_PDU = 0x0400;
        const SUPPORT_SKIP_CHANNELJOIN = 0x0800;
        // The source may set any bits
        const _ = !0;
    }
}
