//! What an Oracle client reports about itself at login — the attributes Oracle
//! shows in `v$session` / `v$session_connect_info` — gathered so the gateway can
//! record them with its own session and pass them on to the database in its own
//! login. Everything here is asserted by the client and unverified, exactly as
//! it is for the database.

use crate::ttc::{AuthPair, MAX_SHORT_LENGTH};

/// Appended to the client's machine name the gateway passes on to the database,
/// so the database side can tell the session came through Warpgate.
pub const WARPGATE_MARK: &[u8] = b"_warpgate";

/// The client attributes of one login, `v$session` style. Empty when the client
/// did not report one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    /// OS user on the client machine (`AUTH_SID`, `v$session.osuser`).
    pub os_user: String,
    /// Client host name (`AUTH_MACHINE`).
    pub machine: String,
    /// Client terminal (`AUTH_TERMINAL`).
    pub terminal: String,
    /// Client program (`AUTH_PROGRAM_NM`), e.g. `sqlplus@host (TNS V1-V3)`.
    pub program: String,
    /// Client process id (`AUTH_PID`, `v$session.process`).
    pub process: String,
    /// Driver name (`SESSION_CLIENT_DRIVER_NAME`), e.g. `jdbcthin`, `SQL*PLUS`.
    pub driver: String,
    /// Client library version (`SESSION_CLIENT_VERSION`), as Oracle prints it.
    pub version: String,
}

impl ClientInfo {
    /// Collect the attributes from the pairs of the client's AUTH requests
    /// (phase one, then phase two — the first non-empty value wins) and, for
    /// any the pairs lack, from the `CID` of its CONNECT `descriptor`
    /// (`USER`, `HOST`, `PROGRAM`).
    pub fn from_login(descriptor: &str, auth_pairs: &[AuthPair]) -> Self {
        let text = |key: &str, cid_key: Option<&str>| {
            String::from_utf8_lossy(&attribute(descriptor, auth_pairs, key, cid_key)).into_owned()
        };
        let version = text("SESSION_CLIENT_VERSION", None);
        Self {
            os_user: text("AUTH_SID", Some("USER")),
            machine: text("AUTH_MACHINE", Some("HOST")),
            terminal: text("AUTH_TERMINAL", None),
            program: text("AUTH_PROGRAM_NM", Some("PROGRAM")),
            process: text("AUTH_PID", None),
            driver: text("SESSION_CLIENT_DRIVER_NAME", None),
            version: version.parse().map(decode_version).unwrap_or(version),
        }
    }
}

/// The client attributes the gateway's own login reports to the target
/// database (the AUTH pair values Oracle shows in `v$session` /
/// `v$session_connect_info`): the client's own, as raw bytes, with
/// [`WARPGATE_MARK`] after the machine name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedClient {
    /// `AUTH_SID` (`v$session.osuser`).
    pub os_user: Vec<u8>,
    /// `AUTH_MACHINE` (`v$session.machine`), followed by [`WARPGATE_MARK`].
    pub machine: Vec<u8>,
    /// `AUTH_TERMINAL` (`v$session.terminal`).
    pub terminal: Vec<u8>,
    /// `AUTH_PROGRAM_NM` (`v$session.program`).
    pub program: Vec<u8>,
    /// `AUTH_PID` (`v$session.process`).
    pub process: Vec<u8>,
    /// `SESSION_CLIENT_DRIVER_NAME` (`v$session_connect_info.client_driver`).
    pub driver: Vec<u8>,
    /// `SESSION_CLIENT_VERSION`: the packed version number in decimal.
    pub version: Vec<u8>,
}

impl ReportedClient {
    /// The client's attributes, gathered as in [`ClientInfo::from_login`] and
    /// passed on as they are, except that the machine name carries the mark,
    /// cut so the mark fits the 64-byte `v$session.machine` column. A missing
    /// attribute is reported as `unknown`, a version that is not a number as
    /// `0`. Before the client's phase two its driver and version are not known
    /// yet, but the gateway's phase one does not send them either.
    pub fn from_login(descriptor: &str, auth_pairs: &[AuthPair]) -> Self {
        let raw =
            |key: &str, cid_key: Option<&str>| attribute(descriptor, auth_pairs, key, cid_key);
        // Re-render the number rather than forward the client's digits, which
        // may carry a sign or leading zeros of any length.
        let version = std::str::from_utf8(&raw("SESSION_CLIENT_VERSION", None))
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        Self {
            os_user: as_is(&raw("AUTH_SID", Some("USER"))),
            machine: mark(&raw("AUTH_MACHINE", Some("HOST")), 64),
            terminal: as_is(&raw("AUTH_TERMINAL", None)),
            program: as_is(&raw("AUTH_PROGRAM_NM", Some("PROGRAM"))),
            process: as_is(&raw("AUTH_PID", None)),
            driver: as_is(&raw("SESSION_CLIENT_DRIVER_NAME", None)),
            version: version.to_string().into_bytes(),
        }
    }

    /// What the gateway reports when it logs in with no client behind it (the
    /// admin connection test).
    pub fn gateway() -> Self {
        Self {
            os_user: b"warpgate".to_vec(),
            machine: b"warpgate".to_vec(),
            terminal: b"unknown".to_vec(),
            program: b"warpgate".to_vec(),
            process: b"0".to_vec(),
            driver: b"warpgate".to_vec(),
            version: b"0".to_vec(),
        }
    }
}

/// The client's raw value of one attribute: the first non-empty `key` pair of
/// its AUTH requests (phase one, then phase two), trailing NULs and surrounding
/// whitespace trimmed, else the `cid_key` field of its CONNECT `descriptor`'s
/// `CID`. Empty when the client reported neither.
fn attribute(
    descriptor: &str,
    auth_pairs: &[AuthPair],
    key: &str,
    cid_key: Option<&str>,
) -> Vec<u8> {
    auth_pairs
        .iter()
        .filter(|p| p.key == key)
        .map(|p| {
            let end = p.value.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            p.value.split_at(end).0.trim_ascii()
        })
        .find(|v| !v.is_empty())
        .map(<[u8]>::to_vec)
        .or_else(|| {
            cid_key
                .and_then(|k| cid_field(descriptor, k))
                .map(String::into_bytes)
        })
        .unwrap_or_default()
}

/// `value` (`unknown` if empty), cut to the longest value the thick AUTH
/// framing carries — a CID fallback is not bounded by the client's own AUTH.
fn as_is(value: &[u8]) -> Vec<u8> {
    cut(or_unknown(value), MAX_SHORT_LENGTH).to_vec()
}

/// `value` (`unknown` if empty) followed by [`WARPGATE_MARK`], the value cut so
/// the whole fits `width` bytes. Control bytes become `?`, so a NUL or line
/// break cannot hide the mark.
fn mark(value: &[u8], width: usize) -> Vec<u8> {
    let shown = cut(or_unknown(value), width - WARPGATE_MARK.len())
        .iter()
        .map(|&b| if b.is_ascii_control() { b'?' } else { b });
    shown.chain(WARPGATE_MARK.iter().copied()).collect()
}

const fn or_unknown(value: &[u8]) -> &[u8] {
    if value.is_empty() { b"unknown" } else { value }
}

/// At most `max` bytes of `value`, on a character boundary when it is UTF-8.
fn cut(value: &[u8], max: usize) -> &[u8] {
    let mut keep = value.len().min(max);
    if let Ok(text) = std::str::from_utf8(value) {
        while !text.is_char_boundary(keep) {
            keep -= 1;
        }
    }
    value.split_at(keep).0
}

/// Render Oracle's packed client version number as Oracle prints it. From 18c
/// on it is `major<<24 | release_update<<16 | revision<<12 | increment<<4 |
/// extension` (OCI 19.8 sends 0x13080000); older libraries — and the
/// python-oracledb thin driver — use `major<<24 | minor<<20 | update<<12 |
/// port_release<<8 | port_update` (4.0.2 is 0x04002000).
fn decode_version(v: u32) -> String {
    let major = v >> 24;
    if major >= 18 {
        format!(
            "{}.{}.{}.{}.{}",
            major,
            (v >> 16) & 0xFF,
            (v >> 12) & 0xF,
            (v >> 4) & 0xFF,
            v & 0xF
        )
    } else {
        format!(
            "{}.{}.{}.{}.{}",
            major,
            (v >> 20) & 0xF,
            (v >> 12) & 0xFF,
            (v >> 8) & 0xF,
            v & 0xFF
        )
    }
}

/// A field of the descriptor's `CID` (e.g. `(CID=(PROGRAM=sqlplus)(HOST=h)(USER=u))`),
/// matching the key case-insensitively.
pub(crate) fn cid_field(descriptor: &str, key: &str) -> Option<String> {
    let upper = descriptor.to_ascii_uppercase();
    let cid = upper.find("(CID=")?;
    let needle = format!("({key}=");
    let start = cid + upper[cid..].find(&needle)? + needle.len();
    let end = start + descriptor[start..].find(')')?;
    Some(descriptor[start..end].trim().to_owned()).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiation::parse_auth_request_pairs;

    fn pairs(hexes: &[(&str, u8)]) -> Vec<AuthPair> {
        hexes
            .iter()
            .flat_map(|(h, fv)| {
                parse_auth_request_pairs(&hex::decode(h.trim()).unwrap(), *fv).unwrap()
            })
            .collect()
    }

    #[test]
    fn sqlplus_19_login() {
        let p = pairs(&[(
            include_str!("../tests/fixtures/ttc/thick_auth1_req_19c.hex"),
            0,
        )]);
        let info = ClientInfo::from_login(
            "(CONNECT_DATA=(SERVICE_NAME=orclpdb1)(CID=(PROGRAM=sqlplus)(HOST=06c5fe373663)(USER=root)))",
            &p,
        );
        assert_eq!(info.os_user, "root");
        assert_eq!(info.machine, "06c5fe373663");
        assert_eq!(info.program, "sqlplus@06c5fe373663 (TNS V1-V3)");
        assert_eq!(info.process, "7");
        assert_eq!(info.terminal, "");
    }

    #[test]
    fn oci_phase_two_adds_driver_and_version() {
        let p = pairs(&[
            (include_str!("../tests/fixtures/ttc/thick_auth1_req.hex"), 0),
            (include_str!("../tests/fixtures/ttc/thick_auth2_req.hex"), 0),
        ]);
        let info = ClientInfo::from_login("", &p);
        assert_eq!(info.driver, "SQL*PLUS");
        assert_eq!(info.version, "19.8.0.0.0");
        assert_eq!(info.os_user, "tester");
    }

    #[test]
    fn python_thin_login() {
        let p = pairs(&[
            (include_str!("../tests/fixtures/ttc/auth1_req.hex"), 27),
            (include_str!("../tests/fixtures/ttc/auth2_req.hex"), 27),
        ]);
        let info = ClientInfo::from_login("", &p);
        assert_eq!(info.driver, "python-oracledb thn : 4.0.2");
        assert_eq!(info.version, "4.0.2.0.0");
        assert_eq!(info.terminal, "unknown");
        assert_eq!(info.machine, "client-workstation-1.test");
    }

    #[test]
    fn ojdbc_19c_login() {
        let p = pairs(&[(
            include_str!("../tests/fixtures/ttc/auth1_req_19c_jdbc.hex"),
            12,
        )]);
        let info = ClientInfo::from_login(
            "(CID=(PROGRAM=JDBC Thin Client)(HOST=__jdbc__)(USER=tester))",
            &p,
        );
        assert_eq!(info.program, "JDBC Thin Client");
        assert_eq!(info.os_user, "tester");
    }

    #[test]
    fn falls_back_to_the_descriptor_cid() {
        let info = ClientInfo::from_login(
            "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=x)(cid=(program=toad.exe)(host=WS-12)(user=ivan))))",
            &[],
        );
        assert_eq!(
            (
                info.program.as_str(),
                info.machine.as_str(),
                info.os_user.as_str()
            ),
            ("toad.exe", "WS-12", "ivan")
        );
        assert_eq!(
            ClientInfo::from_login("(CONNECT_DATA=(SERVICE_NAME=x))", &[]),
            ClientInfo::default()
        );
    }

    #[test]
    fn reports_the_client_to_the_database_machine_marked() {
        let p = pairs(&[(
            include_str!("../tests/fixtures/ttc/thick_auth1_req_19c.hex"),
            0,
        )]);
        let r = ReportedClient::from_login(
            "(CONNECT_DATA=(SERVICE_NAME=orclpdb1)(CID=(PROGRAM=sqlplus)(HOST=06c5fe373663)(USER=root)))",
            &p,
        );
        assert_eq!(r.machine, b"06c5fe373663_warpgate");
        assert_eq!(r.os_user, b"root");
        assert_eq!(r.program, b"sqlplus@06c5fe373663 (TNS V1-V3)");
        assert_eq!(r.process, b"7");
        assert_eq!(r.terminal, b"unknown", "SQL*Plus sent no terminal");
        // Phase one carries no driver or version yet.
        assert_eq!(
            (r.driver.as_slice(), r.version.as_slice()),
            (&b"unknown"[..], &b"0"[..])
        );
    }

    #[test]
    fn reports_driver_and_raw_version_from_phase_two() {
        let p = pairs(&[
            (include_str!("../tests/fixtures/ttc/auth1_req.hex"), 27),
            (include_str!("../tests/fixtures/ttc/auth2_req.hex"), 27),
        ]);
        let r = ReportedClient::from_login("", &p);
        assert_eq!(r.driver, b"python-oracledb thn : 4.0.2");
        assert_eq!(
            r.version,
            0x0400_2000u32.to_string().as_bytes(),
            "the packed number"
        );
        assert_eq!(r.machine, b"client-workstation-1.test_warpgate");
    }

    #[test]
    fn mark_fits_the_column_and_keeps_utf8_whole() {
        assert_eq!(mark(b"", 30), b"unknown_warpgate");
        let long = mark("Пользователь-очень-длинное-имя".as_bytes(), 30);
        assert!(long.len() <= 30 && long.ends_with(WARPGATE_MARK));
        // 21 bytes are left for the value: ten 2-byte letters, not ten and a half.
        assert_eq!(std::str::from_utf8(&long).unwrap(), "Пользовате_warpgate");
        // A non-UTF-8 value (a single-byte client charset) is cut by bytes.
        assert_eq!(
            mark(&[0xC8; 40], 24),
            [&[0xC8; 15][..], WARPGATE_MARK].concat()
        );
        assert_eq!(mark(b"a\0b\nc", 30), b"a?b?c_warpgate");
    }

    #[test]
    fn unmarked_values_pass_as_sent_within_the_framing_limit() {
        assert_eq!(as_is(b""), b"unknown");
        assert_eq!(as_is(b"a\0b"), b"a\0b");
        let descriptor = format!("(CID=(PROGRAM={})(HOST=h)(USER=u))", "x".repeat(300));
        let r = ReportedClient::from_login(&descriptor, &[]);
        assert_eq!(r.program.len(), MAX_SHORT_LENGTH);
    }

    #[test]
    fn decodes_both_version_layouts() {
        assert_eq!(decode_version(0x1308_0000), "19.8.0.0.0");
        assert_eq!(decode_version(0x0400_2000), "4.0.2.0.0");
        assert_eq!(decode_version(0x0C20_0100), "12.2.0.1.0");
    }
}
