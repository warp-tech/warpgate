use bitflags::bitflags;

use crate::ClientRequestFlags;

bitflags! {
    /// This flags appears in the KRB_AS_REQ and KRB_TGS_REQ requests to
    /// the KDC and indicates the flags that the client wants set on the tickets.
    ///
    /// [KDCOptions](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct KdcOptions: u32 {
        const FORWARDABLE = 0x40000000;
        const FORWARDED = 0x20000000;
        const PROXIABLE = 0b10000000;
        const PROXY = 0x08000000;
        const ALLOW_POSTDATE = 0x04000000;
        const POSTDATED = 0x02000000;
        const RENEWABLE = 0x00800000;
        const OPT_HARDWARE_AUTH = 0x00100000;
        const CANONICALIZE = 0x00010000;
        const DISABLE_TRANSITED_CHECK = 0x00000020;
        const RENEWABLE_OK = 0x00000010;
        const ENC_TKT_IN_SKEY = 0x00000008;
        const RENEW = 0x00000002;
        const VALIDATE = 0x00000001;
    }
}

bitflags! {
    /// This flags appears in the application request (KRB_AP_REQ) and
    /// affects the way the request is processed.
    ///
    /// [APOptions](https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ApOptions: u32 {
        const USE_SESSION_KEY = 0x40000000;
        const MUTUAL_REQUIRED = 0x20000000;
    }
}

impl From<ClientRequestFlags> for ApOptions {
    fn from(flags: ClientRequestFlags) -> Self {
        let mut ap_options = ApOptions::empty();

        if flags.contains(ClientRequestFlags::MUTUAL_AUTH) {
            ap_options |= ApOptions::MUTUAL_REQUIRED;
        }
        if flags.contains(ClientRequestFlags::USE_SESSION_KEY) {
            ap_options |= ApOptions::USE_SESSION_KEY;
        }

        ap_options
    }
}
