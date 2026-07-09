use crate::{SessionError, SessionErrorExt as _};

pub(crate) fn map_error(error: ironrdp_connector::ConnectorError) -> SessionError {
    SessionError::custom("connector error", error)
}
