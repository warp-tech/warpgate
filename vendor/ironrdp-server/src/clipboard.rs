use ironrdp_cliprdr::backend::CliprdrBackendFactory;

use crate::ServerEventSender;

pub trait CliprdrServerFactory: CliprdrBackendFactory + ServerEventSender {}
