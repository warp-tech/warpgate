use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, ensure_fixed_part_size, invalid_field_err,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerSetErrorInfoPdu(pub ErrorInfo);

impl ServerSetErrorInfoPdu {
    const NAME: &'static str = "ServerSetErrorInfoPdu";

    const FIXED_PART_SIZE: usize = 4 /* errorInfo */;
}

impl Encode for ServerSetErrorInfoPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u32(self.0.as_u32());

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for ServerSetErrorInfoPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let error_info = src.read_u32();
        let error_info =
            ErrorInfo::from_u32(error_info).ok_or_else(|| invalid_field_err!("errorInfo", "unexpected info code"))?;

        Ok(Self(error_info))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ErrorInfo {
    ProtocolIndependentCode(ProtocolIndependentCode),
    ProtocolIndependentLicensingCode(ProtocolIndependentLicensingCode),
    ProtocolIndependentConnectionBrokerCode(ProtocolIndependentConnectionBrokerCode),
    RdpSpecificCode(RdpSpecificCode),
}

impl ErrorInfo {
    pub fn description(self) -> String {
        match self {
            Self::ProtocolIndependentCode(c) => {
                format!("[Protocol independent error] {}", c.description())
            }
            Self::ProtocolIndependentLicensingCode(c) => {
                format!("[Protocol independent licensing error] {}", c.description())
            }
            Self::ProtocolIndependentConnectionBrokerCode(c) => {
                format!("[Protocol independent connection broker error] {}", c.description())
            }
            Self::RdpSpecificCode(c) => format!("[RDP specific code]: {}", c.description()),
        }
    }

    fn as_u32(self) -> u32 {
        match self {
            Self::ProtocolIndependentCode(c) => c.as_u32(),
            Self::ProtocolIndependentLicensingCode(c) => c.as_u32(),
            Self::ProtocolIndependentConnectionBrokerCode(c) => c.as_u32(),
            Self::RdpSpecificCode(c) => c.as_u32(),
        }
    }
}

impl FromPrimitive for ErrorInfo {
    fn from_i64(n: i64) -> Option<Self> {
        if let Some(v) = ProtocolIndependentCode::from_i64(n) {
            Some(Self::ProtocolIndependentCode(v))
        } else if let Some(v) = ProtocolIndependentLicensingCode::from_i64(n) {
            Some(Self::ProtocolIndependentLicensingCode(v))
        } else if let Some(v) = ProtocolIndependentConnectionBrokerCode::from_i64(n) {
            Some(Self::ProtocolIndependentConnectionBrokerCode(v))
        } else {
            RdpSpecificCode::from_i64(n).map(Self::RdpSpecificCode)
        }
    }

    fn from_u64(n: u64) -> Option<Self> {
        if let Some(v) = ProtocolIndependentCode::from_u64(n) {
            Some(Self::ProtocolIndependentCode(v))
        } else if let Some(v) = ProtocolIndependentLicensingCode::from_u64(n) {
            Some(Self::ProtocolIndependentLicensingCode(v))
        } else if let Some(v) = ProtocolIndependentConnectionBrokerCode::from_u64(n) {
            Some(Self::ProtocolIndependentConnectionBrokerCode(v))
        } else {
            RdpSpecificCode::from_u64(n).map(Self::RdpSpecificCode)
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ProtocolIndependentCode {
    None = 0x0000_0000,
    RpcInitiatedDisconnect = 0x0000_0001,
    RpcInitiatedLogoff = 0x0000_0002,
    IdleTimeout = 0x0000_0003,
    LogonTimeout = 0x0000_0004,
    DisconnectedByOtherconnection = 0x0000_0005,
    OutOfMemory = 0x0000_0006,
    ServerDeniedConnection = 0x0000_0007,
    ServerInsufficientPrivileges = 0x0000_0009,
    ServerFreshCredentialsRequired = 0x0000_000A,
    RpcInitiatedDisconnectByuser = 0x0000_000B,
    LogoffByUser = 0x0000_000C,
    CloseStackOnDriverNotReady = 0x0000_000F,
    ServerDwmCrash = 0x0000_0010,
    CloseStackOnDriverFailure = 0x0000_0011,
    CloseStackOnDriverIfaceFailure = 0x0000_0012,
    ServerWinlogonCrash = 0x0000_0017,
    ServerCsrssCrash = 0x0000_0018,
}

impl ProtocolIndependentCode {
    pub fn description(&self) -> &str {
        match self {
            Self::None => "No error has occurred",
            Self::RpcInitiatedDisconnect => {
                "The disconnection was initiated by an administrative tool on the server in another session"
            }
            Self::RpcInitiatedLogoff => {
                "The disconnection was due to a forced logoff initiated by an administrative tool on the server in another session"
            }
            Self::IdleTimeout => "The idle session limit timer on the server has elapsed",
            Self::LogonTimeout => "The active session limit timer on the server has elapsed",
            Self::DisconnectedByOtherconnection => {
                "Another user connected to the server, forcing the disconnection of the current connection"
            }
            Self::OutOfMemory => "The server ran out of available memory resources",
            Self::ServerDeniedConnection => "The server denied the connection",
            Self::ServerInsufficientPrivileges => {
                "The user cannot connect to the server due to insufficient access privileges"
            }
            Self::ServerFreshCredentialsRequired => {
                "The server does not accept saved user credentials and requires that the user enter their credentials for each connection"
            }
            Self::RpcInitiatedDisconnectByuser => {
                "The disconnection was initiated by an administrative tool on the server running in the user's session"
            }
            Self::LogoffByUser => {
                "The disconnection was initiated by the user logging off his or her session on the server"
            }
            Self::CloseStackOnDriverNotReady => {
                "The display driver in the remote session did not report any status within the time allotted for startup"
            }
            Self::ServerDwmCrash => "The DWM process running in the remote session terminated unexpectedly",
            Self::CloseStackOnDriverFailure => {
                "The display driver in the remote session was unable to complete all the tasks required for startup"
            }
            Self::CloseStackOnDriverIfaceFailure => {
                "The display driver in the remote session started up successfully, but due to internal failures was not usable by the remoting stack"
            }
            Self::ServerWinlogonCrash => "The Winlogon process running in the remote session terminated unexpectedly",
            Self::ServerCsrssCrash => "The CSRSS process running in the remote session terminated unexpectedly",
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ProtocolIndependentLicensingCode {
    Internal = 0x0000_0100,
    NoLicenseServer = 0x0000_0101,
    NoLicense = 0x0000_0102,
    BadClientMsg = 0x0000_0103,
    HwidDoesntMatchLicense = 0x0000_0104,
    BadClientLicense = 0x0000_0105,
    CantFinishProtocol = 0x0000_0106,
    ClientEndedProtocol = 0x0000_0107,
    BadClientEncryption = 0x0000_0108,
    CantUpgradeLicense = 0x0000_0109,
    NoRemoteConnections = 0x0000_010A,
}

impl ProtocolIndependentLicensingCode {
    pub fn description(&self) -> &str {
        match self {
            Self::Internal => "An internal error has occurred in the Terminal Services licensing component",
            Self::NoLicenseServer => "A Remote Desktop License Server could not be found to provide a license",
            Self::NoLicense => "There are no Client Access Licenses available for the target remote computer",
            Self::BadClientMsg => "The remote computer received an invalid licensing message from the client",
            Self::HwidDoesntMatchLicense => "The Client Access License stored by the client has been modified",
            Self::BadClientLicense => "The Client Access License stored by the client is in an invalid format",
            Self::CantFinishProtocol => "Network problems have caused the licensing protocol to be terminated",
            Self::ClientEndedProtocol => "The client prematurely ended the licensing protocol",
            Self::BadClientEncryption => "A licensing message was incorrectly encrypted",
            Self::CantUpgradeLicense => {
                "The Client Access License stored by the client could not be upgraded or renewed"
            }
            Self::NoRemoteConnections => "The remote computer is not licensed to accept remote connections",
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ProtocolIndependentConnectionBrokerCode {
    DestinationNotFound = 0x0000_0400,
    LoadingDestination = 0x0000_0402,
    RedirectingToDestination = 0x0000_0404,
    SessionOnlineVmWake = 0x0000_0405,
    SessionOnlineVmBoot = 0x0000_0406,
    SessionOnlineVmNoDns = 0x0000_0407,
    DestinationPoolNotFree = 0x0000_0408,
    ConnectionCancelled = 0x0000_0409,
    ConnectionErrorInvalidSettings = 0x0000_0410,
    SessionOnlineVmBootTimeout = 0x0000_0411,
    SessionOnlineVmSessmonFailed = 0x0000_0412,
}

impl ProtocolIndependentConnectionBrokerCode {
    pub fn description(&self) -> &str {
        match self {
            Self::DestinationNotFound => "The target endpoint could not be found",
            Self::LoadingDestination => {
                "The target endpoint to which the client is being redirected is disconnecting from the Connection Broker"
            }
            Self::RedirectingToDestination => {
                "An error occurred while the connection was being redirected to the target endpoint"
            }
            Self::SessionOnlineVmWake => {
                "An error occurred while the target endpoint (a virtual machine) was being awakened"
            }
            Self::SessionOnlineVmBoot => {
                "An error occurred while the target endpoint (a virtual machine) was being started"
            }
            Self::SessionOnlineVmNoDns => {
                "The IP address of the target endpoint (a virtual machine) cannot be determined"
            }
            Self::DestinationPoolNotFree => {
                "There are no available endpoints in the pool managed by the Connection Broker"
            }
            Self::ConnectionCancelled => "Processing of the connection has been canceled",
            Self::ConnectionErrorInvalidSettings => {
                "The settings contained in the routingToken field of the X.224 Connection Request PDU cannot be validated"
            }
            Self::SessionOnlineVmBootTimeout => {
                "A time-out occurred while the target endpoint (a virtual machine) was being started"
            }
            Self::SessionOnlineVmSessmonFailed => {
                "A session monitoring error occurred while the target endpoint (a virtual machine) was being started"
            }
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RdpSpecificCode {
    UnknownPduType2 = 0x0000_10C9,
    UnknownPduType = 0x0000_10CA,
    DataPdusEquence = 0x0000_10CB,
    ControlPduSequence = 0x0000_10CD,
    InvalidControlPduAction = 0x0000_10CE,
    InvalidInputPduType = 0x0000_10CF,
    InvalidInputPduMouse = 0x0000_10D0,
    InvalidRefreshRectPdu = 0x0000_10D1,
    CreateUserDataFailed = 0x0000_10D2,
    ConnectFailed = 0x0000_10D3,
    ConfirmActiveWrongShareId = 0x0000_10D4,
    ConfirmActiveWrongOriginator = 0x0000_10D5,
    PersistentKeyPduBadLength = 0x0000_10DA,
    PersistentKeyPduIllegalFirst = 0x0000_10DB,
    PersistentKeyPduTooManyTotalKeys = 0x0000_10DC,
    PersistentKeyPduTooManyCacheKeys = 0x0000_10DD,
    InputPduBadLength = 0x0000_10DE,
    BitmapCacheErrorPduBadLength = 0x0000_10DF,
    SecurityDataTooShort = 0x0000_10E0,
    VcHannelDataTooShort = 0x0000_10E1,
    ShareDataTooShort = 0x0000_10E2,
    BadSuppressOutputPdu = 0x0000_10E3,
    ConfirmActivePduTooShort = 0x0000_10E5,
    CapabilitySetTooSmall = 0x0000_10E7,
    CapabilitySetTooLarge = 0x0000_10E8,
    NoCursorCache = 0x0000_10E9,
    BadCapabilities = 0x0000_10EA,
    VirtualChannelDecompressionError = 0x0000_10EC,
    InvalidVcCompressionType = 0x0000_10ED,
    InvalidChannelId = 0x0000_10EF,
    VirtualChannelsTooMany = 0x0000_10F0,
    RemoteAppsNotEnabled = 0x0000_10F3,
    CacheCapabilityNotSet = 0x0000_10F4,
    BitmapCacheErrorPduBadLength2 = 0x0000_10F5,
    OffscrCacheErrorPduBadLength = 0x0000_10F6,
    DngCacheErrorPduBadLength = 0x0000_10F7,
    GdiPlusPduBadLength = 0x0000_10F8,
    SecurityDataTooShort2 = 0x0000_1111,
    SecurityDataTooShort3 = 0x0000_1112,
    SecurityDataTooShort4 = 0x0000_1113,
    SecurityDataTooShort5 = 0x0000_1114,
    SecurityDataTooShort6 = 0x0000_1115,
    SecurityDataTooShort7 = 0x0000_1116,
    SecurityDataTooShort8 = 0x0000_1117,
    SecurityDataTooShort9 = 0x0000_1118,
    SecurityDataTooShort10 = 0x0000_1119,
    SecurityDataTooShort11 = 0x0000_111A,
    SecurityDataTooShort12 = 0x0000_111B,
    SecurityDataTooShort13 = 0x0000_111C,
    SecurityDataTooShort14 = 0x0000_111D,
    SecurityDataTooShort15 = 0x0000_111E,
    SecurityDataTooShort16 = 0x0000_111F,
    SecurityDataTooShort17 = 0x0000_1120,
    SecurityDataTooShort18 = 0x0000_1121,
    SecurityDataTooShort19 = 0x0000_1122,
    SecurityDataTooShort20 = 0x0000_1123,
    SecurityDataTooShort21 = 0x0000_1124,
    SecurityDataTooShort22 = 0x0000_1125,
    SecurityDataTooShort23 = 0x0000_1126,
    BadMonitorData = 0x0000_1129,
    VcDecompressedReassembleFailed = 0x0000_112A,
    VcDataTooLong = 0x0000_112B,
    BadFrameAckData = 0x0000_112C,
    GraphicsModeNotSupported = 0x0000_112D,
    GraphicsSubsystemResetFailed = 0x0000_112E,
    GraphicsSubsystemFailed = 0x0000_112F,
    TimezoneKeyNameLengthTooShort = 0x0000_1130,
    TimezoneKeyNameLengthTooLong = 0x0000_1131,
    DynamicDstDisabledFieldMissing = 0x0000_1132,
    VcDecodingError = 0x0000_1133,
    VirtualDesktopTooLarge = 0x0000_1134,
    MonitorGeometryValidationFailed = 0x0000_1135,
    InvalidMonitorCount = 0x0000_1136,
    UpdateSessionKeyFailed = 0x0000_1191,
    DecryptFailed = 0x0000_1192,
    EncryptFailed = 0x0000_1193,
    EncPkgMismatch = 0x0000_1194,
    DecryptFailed2 = 0x0000_1195,
}

impl RdpSpecificCode {
    pub fn description(&self) -> &str {
        match self {
            Self::UnknownPduType2 => "Unknown pduType2 field in a received Share Data Header",
            Self::UnknownPduType => "Unknown pduType field in a received Share Control Header",
            Self::DataPdusEquence => "An out-of-sequence Slow-Path Data PDU has been received",
            Self::ControlPduSequence => "An out-of-sequence Slow-Path Non-Data PDU has been received",
            Self::InvalidControlPduAction => "A Control PDU has been received with an invalid action field",
            Self::InvalidInputPduType => {
                "One of two possible errors: A Slow-Path Input Event has been received with an invalid messageType field; or A Fast-Path Input Event has been received with an invalid eventCode field"
            }
            Self::InvalidInputPduMouse => {
                "One of two possible errors: A Slow-Path Mouse Event or Extended Mouse Event has been received with an invalid pointerFlags field; or A Fast-Path Mouse Event or Fast-Path Extended Mouse Event has been received with an invalid pointerFlags field"
            }
            Self::InvalidRefreshRectPdu => "An invalid Refresh Rect PDU has been received",
            Self::CreateUserDataFailed => "The server failed to construct the GCC Conference Create Response user data",
            Self::ConnectFailed => {
                "Processing during the Channel Connection phase of the RDP Connection Sequence has failed"
            }
            Self::ConfirmActiveWrongShareId => {
                "A Confirm Active PDU was received from the client with an invalid shareID field"
            }
            Self::ConfirmActiveWrongOriginator => {
                "A Confirm Active PDU was received from the client with an invalid originatorID field"
            }
            Self::PersistentKeyPduBadLength => "There is not enough data to process a Persistent Key List PDU",
            Self::PersistentKeyPduIllegalFirst => {
                "A Persistent Key List PDU marked as PERSIST_PDU_FIRST (0x01) was received after the reception of a prior Persistent Key List PDU also marked as PERSIST_PDU_FIRST"
            }
            Self::PersistentKeyPduTooManyTotalKeys => {
                "A Persistent Key List PDU was received which specified a total number of bitmap cache entries larger than 262144"
            }
            Self::PersistentKeyPduTooManyCacheKeys => {
                "A Persistent Key List PDU was received which specified an invalid total number of keys for a bitmap cache (the number of entries that can be stored within each bitmap cache is specified in the Revision 1 or 2 Bitmap Cache Capability Set that is sent from client to server)"
            }
            Self::InputPduBadLength => {
                "There is not enough data to process Input Event PDU Data or a Fast-Path Input Event PDU"
            }
            Self::BitmapCacheErrorPduBadLength => {
                "There is not enough data to process the shareDataHeader, NumInfoBlocks, Pad1, and Pad2 fields of the Bitmap Cache Error PDU Data"
            }
            Self::SecurityDataTooShort => {
                "One of two possible errors: The dataSignature field of the Fast-Path Input Event PDU does not contain enough data; or The fipsInformation and dataSignature fields of the Fast-Path Input Event PDU do not contain enough data"
            }
            Self::VcHannelDataTooShort => {
                "One of two possible errors: There is not enough data in the Client Network Data to read the virtual channel configuration data; or There is not enough data to read a complete Channel PDU Header"
            }
            Self::ShareDataTooShort => {
                "One of four possible errors: There is not enough data to process Control PDU Data; or There is not enough data to read a complete Share Control Header; or There is not enough data to read a complete Share Data Header of a Slow-Path Data PDU; or There is not enough data to process Font List PDU Data"
            }
            Self::BadSuppressOutputPdu => {
                "One of two possible errors: There is not enough data to process Suppress Output PDU Data; or The allowDisplayUpdates field of the Suppress Output PDU Data is invalid"
            }
            Self::ConfirmActivePduTooShort => {
                "One of two possible errors: There is not enough data to read the shareControlHeader, shareID, originatorID, lengthSourceDescriptor, and lengthCombinedCapabilities fields of the Confirm Active PDU Data; or There is not enough data to read the sourceDescriptor, numberCapabilities, pad2Octets, and capabilitySets fields of the Confirm Active PDU Data"
            }
            Self::CapabilitySetTooSmall => {
                "There is not enough data to read the capabilitySetType and the lengthCapability fields in a received Capability Set"
            }
            Self::CapabilitySetTooLarge => {
                "A Capability Set has been received with a lengthCapability field that contains a value greater than the total length of the data received"
            }
            Self::NoCursorCache => {
                "One of two possible errors: Both the colorPointerCacheSize and pointerCacheSize fields in the Pointer Capability Set are set to zero; or The pointerCacheSize field in the Pointer Capability Set is not present, and the colorPointerCacheSize field is set to zero"
            }
            Self::BadCapabilities => {
                "The capabilities received from the client in the Confirm Active PDU were not accepted by the server"
            }
            Self::VirtualChannelDecompressionError => {
                "An error occurred while using the bulk compressor to decompress a Virtual Channel PDU"
            }
            Self::InvalidVcCompressionType => {
                "An invalid bulk compression package was specified in the flags field of the Channel PDU Header"
            }
            Self::InvalidChannelId => {
                "An invalid MCS channel ID was specified in the mcsPdu field of the Virtual Channel PDU)"
            }
            Self::VirtualChannelsTooMany => {
                "The client requested more than the maximum allowed 31 static virtual channels in the Client Network Data"
            }
            Self::RemoteAppsNotEnabled => {
                "The INFO_RAIL flag (0x0000_8000) MUST be set in the flags field of the Info Packet as the session on the remote server can only host remote applications"
            }
            Self::CacheCapabilityNotSet => {
                "The client sent a Persistent Key List PDU without including the prerequisite Revision 2 Bitmap Cache Capability Set in the Confirm Active PDU"
            }
            Self::BitmapCacheErrorPduBadLength2 => {
                "The NumInfoBlocks field in the Bitmap Cache Error PDU Data is inconsistent with the amount of data in the Info field"
            }
            Self::OffscrCacheErrorPduBadLength => {
                "There is not enough data to process an Offscreen Bitmap Cache Error PDU"
            }
            Self::DngCacheErrorPduBadLength => "There is not enough data to process a DrawNineGrid Cache Error PDU",
            Self::GdiPlusPduBadLength => "There is not enough data to process a GDI+ Error PDU",
            Self::SecurityDataTooShort2 => "There is not enough data to read a Basic Security Header",
            Self::SecurityDataTooShort3 => {
                "There is not enough data to read a Non-FIPS Security Header or FIPS Security Header"
            }
            Self::SecurityDataTooShort4 => {
                "There is not enough data to read the basicSecurityHeader and length fields of the Security Exchange PDU Data"
            }
            Self::SecurityDataTooShort5 => {
                "There is not enough data to read the CodePage, flags, cbDomain, cbUserName, cbPassword, cbAlternateShell, cbWorkingDir, Domain, UserName, Password, AlternateShell, and WorkingDir fields in the Info Packet"
            }
            Self::SecurityDataTooShort6 => {
                "There is not enough data to read the CodePage, flags, cbDomain, cbUserName, cbPassword, cbAlternateShell, and cbWorkingDir fields in the Info Packet"
            }
            Self::SecurityDataTooShort7 => {
                "There is not enough data to read the clientAddressFamily and cbClientAddress fields in the Extended Info Packet"
            }
            Self::SecurityDataTooShort8 => {
                "There is not enough data to read the clientAddress field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort9 => {
                "There is not enough data to read the cbClientDir field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort10 => {
                "There is not enough data to read the clientDir field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort11 => {
                "There is not enough data to read the clientTimeZone field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort12 => {
                "There is not enough data to read the clientSessionId field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort13 => {
                "There is not enough data to read the performanceFlags field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort14 => {
                "There is not enough data to read the cbAutoReconnectCookie field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort15 => {
                "There is not enough data to read the autoReconnectCookie field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort16 => {
                "The cbAutoReconnectCookie field in the Extended Info Packet contains a value which is larger than the maximum allowed length of 128 bytes"
            }
            Self::SecurityDataTooShort17 => {
                "There is not enough data to read the clientAddressFamily and cbClientAddress fields in the Extended Info Packet"
            }
            Self::SecurityDataTooShort18 => {
                "There is not enough data to read the clientAddress field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort19 => {
                "There is not enough data to read the cbClientDir field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort20 => {
                "There is not enough data to read the clientDir field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort21 => {
                "There is not enough data to read the clientTimeZone field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort22 => {
                "There is not enough data to read the clientSessionId field in the Extended Info Packet"
            }
            Self::SecurityDataTooShort23 => "There is not enough data to read the Client Info PDU Data",
            Self::BadMonitorData => {
                "The number of TS_MONITOR_DEF structures present in the monitorDefArray field of the Client Monitor Data is less than the value specified in monitorCount field"
            }
            Self::VcDecompressedReassembleFailed => {
                "The server-side decompression buffer is invalid, or the size of the decompressed VC data exceeds the chunking size specified in the Virtual Channel Capability Set"
            }
            Self::VcDataTooLong => {
                "The size of a received Virtual Channel PDU exceeds the chunking size specified in the Virtual Channel Capability Set"
            }
            Self::BadFrameAckData => "There is not enough data to read a TS_FRAME_ACKNOWLEDGE_PDU",
            Self::GraphicsModeNotSupported => {
                "The graphics mode requested by the client is not supported by the server"
            }
            Self::GraphicsSubsystemResetFailed => "The server-side graphics subsystem failed to reset",
            Self::GraphicsSubsystemFailed => {
                "The server-side graphics subsystem is in an error state and unable to continue graphics encoding"
            }
            Self::TimezoneKeyNameLengthTooShort => {
                "There is not enough data to read the cbDynamicDSTTimeZoneKeyName field in the Extended Info Packet"
            }
            Self::TimezoneKeyNameLengthTooLong => {
                "The length reported in the cbDynamicDSTTimeZoneKeyName field of the Extended Info Packet is too long"
            }
            Self::DynamicDstDisabledFieldMissing => {
                "The dynamicDaylightTimeDisabled field is not present in the Extended Info Packet"
            }
            Self::VcDecodingError => "An error occurred when processing dynamic virtual channel data",
            Self::VirtualDesktopTooLarge => {
                "The width or height of the virtual desktop defined by the monitor layout in the Client Monitor Data is larger than the maximum allowed value of 32,766"
            }
            Self::MonitorGeometryValidationFailed => {
                "The monitor geometry defined by the Client Monitor Data is invalid"
            }
            Self::InvalidMonitorCount => "The monitorCount field in the Client Monitor Data is too large",
            Self::UpdateSessionKeyFailed => {
                "An attempt to update the session keys while using Standard RDP Security mechanisms failed"
            }
            Self::DecryptFailed => {
                "One of two possible error conditions: Decryption using Standard RDP Security mechanisms failed; or Session key creation using Standard RDP Security mechanisms failed"
            }
            Self::EncryptFailed => "Encryption using Standard RDP Security mechanisms failed",
            Self::EncPkgMismatch => {
                "Failed to find a usable Encryption Method in the encryptionMethods field of the Client Security Data"
            }
            Self::DecryptFailed2 => {
                "Unencrypted data was encountered in a protocol stream which is meant to be encrypted with Standard RDP Security mechanisms"
            }
        }
    }

    #[expect(
        clippy::as_conversions,
        reason = "guarantees discriminant layout, and as is the only way to cast enum -> primitive"
    )]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    const SERVER_SET_ERROR_INFO_BUFFER: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

    const SERVER_SET_ERROR_INFO: ServerSetErrorInfoPdu = ServerSetErrorInfoPdu(
        ErrorInfo::ProtocolIndependentLicensingCode(ProtocolIndependentLicensingCode::Internal),
    );

    #[test]
    fn from_buffer_correctly_parses_server_set_error_info() {
        assert_eq!(
            SERVER_SET_ERROR_INFO,
            decode(SERVER_SET_ERROR_INFO_BUFFER.as_ref()).unwrap()
        );
    }

    #[test]
    fn to_buffer_correctly_serializes_server_set_error_info() {
        let expected = SERVER_SET_ERROR_INFO_BUFFER.as_ref();

        let buffer = encode_vec(&SERVER_SET_ERROR_INFO).unwrap();
        assert_eq!(expected, buffer.as_slice());
    }

    #[test]
    fn buffer_length_is_correct_for_server_set_error_info() {
        assert_eq!(SERVER_SET_ERROR_INFO_BUFFER.len(), SERVER_SET_ERROR_INFO.size());
    }
}
