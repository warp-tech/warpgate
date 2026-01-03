use enum_dispatch::enum_dispatch;
use warpgate_common::ListenEndpoint;
use warpgate_core::{ProtocolServer, TargetTestError};
use warpgate_protocol_http::HTTPProtocolServer;
use warpgate_protocol_mysql::MySQLProtocolServer;
use warpgate_protocol_postgres::PostgresProtocolServer;
use warpgate_protocol_remoterun::RemoteRunProtocolServer;
use warpgate_protocol_ssh::SSHProtocolServer;

#[enum_dispatch(ProtocolServer)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum ProtocolServerEnum {
    SSHProtocolServer,
    HTTPProtocolServer,
    MySQLProtocolServer,
    PostgresProtocolServer,
    RemoteRunProtocolServer,
}

impl ProtocolServer for ProtocolServerEnum {
    async fn run(self, address: ListenEndpoint) -> anyhow::Result<()> {
        match self {
            ProtocolServerEnum::SSHProtocolServer(s) => s.run(address).await,
            ProtocolServerEnum::HTTPProtocolServer(s) => s.run(address).await,
            ProtocolServerEnum::MySQLProtocolServer(s) => s.run(address).await,
            ProtocolServerEnum::PostgresProtocolServer(s) => s.run(address).await,
            ProtocolServerEnum::RemoteRunProtocolServer(s) => s.run(address).await,
        }
    }

    async fn test_target(
        &self,
        target: warpgate_common::Target,
    ) -> anyhow::Result<(), TargetTestError> {
        match self {
            ProtocolServerEnum::SSHProtocolServer(s) => s.test_target(target).await,
            ProtocolServerEnum::HTTPProtocolServer(s) => s.test_target(target).await,
            ProtocolServerEnum::MySQLProtocolServer(s) => s.test_target(target).await,
            ProtocolServerEnum::PostgresProtocolServer(s) => s.test_target(target).await,
            ProtocolServerEnum::RemoteRunProtocolServer(s) => s.test_target(target).await,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ProtocolServerEnum::SSHProtocolServer(x) => x.name(),
            ProtocolServerEnum::HTTPProtocolServer(x) => x.name(),
            ProtocolServerEnum::MySQLProtocolServer(x) => x.name(),
            ProtocolServerEnum::PostgresProtocolServer(x) => x.name(),
            ProtocolServerEnum::RemoteRunProtocolServer(x) => x.name(),
        }
    }
}
