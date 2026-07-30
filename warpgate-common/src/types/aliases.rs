use uuid::Uuid;

pub type SessionId = Uuid;

/// Identity of a Warpgate protocol. Used wherever code branches on the
/// protocol (credential policies, auth states) so that a protocol can't be
/// misspelled or silently unmatched; the wire/DB/audit string form is
/// [`Protocol::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Ssh,
    MySql,
    Postgres,
    Kubernetes,
    Vnc,
    Rdp,
}

impl Protocol {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Ssh => "SSH",
            Self::MySql => "MySQL",
            Self::Postgres => "PostgreSQL",
            Self::Kubernetes => "Kubernetes",
            Self::Vnc => "VNC",
            Self::Rdp => "RDP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
