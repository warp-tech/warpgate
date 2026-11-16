//! Wire constants for the Oracle TNS/TTC protocol.
//!
//! Values transcribed from the python-oracledb thin implementation
//! (`src/oracledb/impl/thin/constants.pxi`, UPL-1.0/Apache-2.0):
//! <https://github.com/oracle/python-oracledb/blob/main/src/oracledb/impl/thin/constants.pxi>
//! Cross-checked against go-ora (`sijms/go-ora`, `v2/network`).
//!
//! These drive both legs of the proxy, so they must match the drivers exactly.
//! Anything still unverified against a live server is flagged `VALIDATE:`.

/// TNS packet types (byte 4 of the 8-byte packet header).
pub mod packet {
    pub const CONNECT: u8 = 1;
    pub const ACCEPT: u8 = 2;
    pub const ACKNOWLEDGE: u8 = 3;
    pub const REFUSE: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const DATA: u8 = 6;
    pub const NULL: u8 = 7;
    pub const ABORT: u8 = 9;
    pub const RESEND: u8 = 11;
    pub const MARKER: u8 = 12;
    pub const ATTENTION: u8 = 13;
    pub const CONTROL: u8 = 14;
}

/// TTC message types (first byte of a DATA packet payload).
pub mod msg {
    pub const PROTOCOL: u8 = 1;
    pub const DATA_TYPES: u8 = 2;
    pub const FUNCTION: u8 = 3;
    pub const ERROR: u8 = 4;
    pub const PIGGYBACK: u8 = 17;
    pub const END_OF_RESPONSE: u8 = 29; // 23ai, TNS version >= 319
    pub const FAST_AUTH: u8 = 34; // 23ai
}

/// TTC function codes (the `OALL8`/auth family). Carried right after `msg::FUNCTION`.
pub mod func {
    pub const AUTH_PHASE_ONE: u8 = 118;
    pub const AUTH_PHASE_TWO: u8 = 115;
    pub const EXECUTE: u8 = 94; // full "OALL8" execute — carries SQL text on parse
    pub const REEXECUTE: u8 = 4; // re-run a cursor — SQL text NOT resent
    pub const REEXECUTE_AND_FETCH: u8 = 78;
    pub const FETCH: u8 = 5;
    pub const CLOSE_CURSORS: u8 = 105; // usually a piggyback
    pub const COMMIT: u8 = 14;
    pub const ROLLBACK: u8 = 15;
    pub const LOGOFF: u8 = 9;
}

/// Password-verifier format codes (the type tag sent with `AUTH_VFR_DATA`).
pub mod verifier {
    /// 12c SHA-512 PBKDF2 verifier — the only format the MVP synthesises.
    pub const V12C: u16 = 0x4815;
    pub const V11G_1: u16 = 0xb152;
    pub const V11G_2: u16 = 0x1b25;
}

/// Auth-mode bit flags accumulated across the two auth phases.
pub mod auth_mode {
    pub const LOGON: u32 = 0x0000_0001;
    pub const WITH_PASSWORD: u32 = 0x0000_0100;
    pub const CHANGE_PASSWORD: u32 = 0x0000_0002;
}

/// ACCEPT-packet flags (how the proxy, as server, steers the client).
///
/// To keep one simple framing/auth path, the proxy's ACCEPT toward the client
/// must NOT set `FAST_AUTH` (forces the classic Protocol→DataTypes→Auth flow)
/// and must NOT set `CHECK_OOB` (keeps break handling in-band).
pub mod accept_flag {
    pub const CHECK_OOB: u32 = 0x0000_0001;
    pub const FAST_AUTH: u32 = 0x1000_0000; // 23ai single-roundtrip auth
    pub const HAS_END_OF_RESPONSE: u32 = 0x0200_0000; // 23ai
}

/// Global service options (the u16 at offset 12 of CONNECT, 10 of ACCEPT).
pub mod gso {
    /// python-oracledb `TNS_GSO_CAN_RECV_ATTENTION`: the peer can take an
    /// out-of-band (TCP urgent) break.
    pub const CAN_RECV_ATTENTION: u16 = 0x0400;
    /// Every out-of-band bit a client may offer: `CAN_RECV_ATTENTION` plus the
    /// 0x0800 bit Oracle JDBC thin sets next to it. Both are exactly what OJDBC's
    /// own `oracle.net.disableOob=true` clears (0x0c41 -> 0x0041 on the wire).
    pub const OOB_MASK: u16 = 0x0c00;
}

/// CONNECT-packet flags (`connect_flags_2`, the u32 at offset 70 of a CONNECT
/// whose connect-data offset is >= 74).
pub mod connect_flag {
    /// The client asks the server to run the out-of-band break check; the server
    /// echoes it as [`accept_flag::CHECK_OOB`](super::accept_flag::CHECK_OOB).
    pub const CHECK_OOB: u32 = 0x0000_0001;
}

/// Encoding flags a client sends in its DATATYPES message (the byte after the
/// two u16-LE charset ids). Values from python-oracledb `constants.pxi`.
pub mod encoding {
    pub const MULTI_BYTE: u8 = 0x01;
    /// Character (CHR) fields such as the AUTH username are length-prefixed.
    /// python-oracledb and go-ora set it (0x03); Oracle JDBC thin does not
    /// (0x01) and writes the username raw, and the server then expects it raw.
    pub const CONV_LENGTH: u8 = 0x02;
}

/// DATA-packet data-flags (the uint16 directly after the 8-byte header).
pub mod data_flag {
    pub const END_OF_RESPONSE: u16 = 0x2000; // 23ai
}

/// Network Session Image (ANO) flags in CONNECT/ACCEPT.
///
/// The proxy advertises `NA_DISABLED` towards the database and never sets
/// `NA_REQUIRED` towards the client, so native network encryption/checksumming
/// is refused on both legs and the TTC payload (and thus SQL) stays readable.
/// TLS is provided by TCPS instead. Matches python-oracledb thin behaviour.
pub mod nsi {
    pub const SUPPORT_SECURITY_RENEG: u8 = 0x80;
    pub const NA_REQUIRED: u8 = 0x10;
    pub const NA_DISABLED: u8 = 0x04;
}

/// TNS protocol versions and the thresholds that change framing/behaviour.
/// Values from python-oracledb `constants.pxi`.
pub mod version {
    /// Highest version the reference thin client speaks (our server's max).
    pub const DESIRED: u16 = 319;
    /// Lowest version a client will offer.
    pub const MINIMUM: u16 = 300;
    /// Below this the client rejects the server (12.1).
    pub const MIN_ACCEPTED: u16 = 315;
    /// At/above this version the packet length field is a full u32 (large SDU);
    /// below it the length is u16 followed by a u16 of flags.
    pub const MIN_LARGE_SDU: u16 = 315;
    /// At/above this version the client reads the 32-bit `flags2` in ACCEPT and
    /// performs the out-of-band break check.
    pub const MIN_OOB_CHECK: u16 = 318;
    /// At/above this version the server may use the 23ai end-of-response marker.
    pub const MIN_END_OF_RESPONSE: u16 = 319;
}

/// TTC runtime "field version" thresholds (a byte in the negotiated
/// compile-capabilities array). The field version is negotiated per connection;
/// a peer below a given threshold omits the message fields introduced at it, so
/// a parser/writer MUST gate those fields on the negotiated value rather than
/// assume the newest layout. Values from python-oracledb `constants.pxi`.
pub mod field_version {
    /// Byte index of the TTC field version within a compile-capabilities array
    /// (python-oracledb `TNS_CCAP_FIELD_VERSION`).
    pub const CAPS_INDEX: usize = 7;
    /// EXECUTE carries the SQL signature / SQL id fields (`..._12_2`).
    pub const V12_2: u8 = 8;
    /// EXECUTE also carries the chunk-id fields (`..._12_2_EXT1`).
    pub const V12_2_EXT1: u8 = 9;
    /// First field version whose FUNCTION / piggyback preamble carries the
    /// `token_num` ub8 (`TNS_CCAP_FIELD_VERSION_23_1_EXT_1`). 23ai servers
    /// negotiate at or above this (e.g. 27); 19c negotiates below it (12), so a
    /// 19c client omits `token_num` from every AUTH / EXECUTE / piggyback
    /// preamble. See python-oracledb `msgbase.pyx::_write_function_code`.
    pub const TOKEN_NUM_MIN: u8 = 18;
    /// A representative field version for a pre-23ai (19c) target, used as a
    /// coarse fallback when the negotiated value could not be observed.
    pub const PRE_23AI: u8 = 12;
}

/// Packet-header flag: after a TCPS REDIRECT the client renegotiates TLS.
pub const PACKET_FLAG_TLS_RENEG: u8 = 0x08;

/// `EXECUTE` option bits (first u32 of the execute body).
pub mod exec_option {
    pub const PARSE: u32 = 0x0000_0001; // set => SQL text is present in this call
    pub const EXECUTE: u32 = 0x0000_0020;
    pub const FETCH: u32 = 0x0000_0040;
    pub const NO_COMPRESSED_FETCH: u32 = 0x0004_0000;
}

/// 8-byte TNS packet header size.
pub const PACKET_HEADER_SIZE: usize = 8;

/// Key names carried in the O5LOGON key/value lists.
pub mod authkv {
    pub const SESSKEY: &str = "AUTH_SESSKEY";
    pub const VFR_DATA: &str = "AUTH_VFR_DATA";
    pub const PBKDF2_CSK_SALT: &str = "AUTH_PBKDF2_CSK_SALT";
    pub const PBKDF2_VGEN_COUNT: &str = "AUTH_PBKDF2_VGEN_COUNT";
    pub const PBKDF2_SDER_COUNT: &str = "AUTH_PBKDF2_SDER_COUNT";
    pub const PBKDF2_SPEEDY_KEY: &str = "AUTH_PBKDF2_SPEEDY_KEY";
    pub const PASSWORD: &str = "AUTH_PASSWORD";
    pub const SVR_RESPONSE: &str = "AUTH_SVR_RESPONSE";
    pub const SESSION_ID: &str = "AUTH_SESSION_ID";
    pub const SERIAL_NUM: &str = "AUTH_SERIAL_NUM";
    pub const VERSION_NO: &str = "AUTH_VERSION_NO";
}

/// Literal label the client expects to find in the decrypted `AUTH_SVR_RESPONSE`
/// (bytes 16..32) to confirm the server proved knowledge of the verifier.
pub const SERVER_TO_CLIENT: &[u8] = b"SERVER_TO_CLIENT";
