use ironrdp_connector::credssp::{CredsspProcessGenerator, CredsspSequence, KerberosConfig};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError, ConnectorResult, ServerName, State as _,
    general_err,
};
use ironrdp_core::WriteBuf;
use tracing::{debug, info, instrument, trace};

use crate::framed::{Framed, FramedRead, FramedWrite};
use crate::{NetworkClient, single_sequence_step};

#[non_exhaustive]
pub struct ShouldUpgrade;

#[instrument(skip_all)]
pub async fn connect_begin<S>(framed: &mut Framed<S>, connector: &mut ClientConnector) -> ConnectorResult<ShouldUpgrade>
where
    S: Sync + FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();

    info!("Begin connection procedure");

    while !connector.should_perform_security_upgrade() {
        single_sequence_step(framed, connector, &mut buf).await?;
    }

    Ok(ShouldUpgrade)
}

/// # Panics
///
/// Panics if connector state is not [ClientConnectorState::EnhancedSecurityUpgrade].
pub fn skip_connect_begin(connector: &mut ClientConnector) -> ShouldUpgrade {
    assert!(connector.should_perform_security_upgrade());
    ShouldUpgrade
}

#[non_exhaustive]
pub struct Upgraded;

#[instrument(skip_all)]
pub fn mark_as_upgraded(_: ShouldUpgrade, connector: &mut ClientConnector) -> Upgraded {
    trace!("Marked as upgraded");
    connector.mark_security_upgrade_as_done();
    Upgraded
}

#[instrument(skip_all)]
pub async fn connect_finalize<S, N>(
    _: Upgraded,
    mut connector: ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
) -> ConnectorResult<ConnectionResult>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    let mut buf = WriteBuf::new();

    if connector.should_perform_credssp() {
        perform_credssp_step(
            &mut connector,
            framed,
            network_client,
            &mut buf,
            server_name,
            server_public_key,
            kerberos_config,
        )
        .await?;
    }

    let result = loop {
        single_sequence_step(framed, &mut connector, &mut buf).await?;

        if let ClientConnectorState::Connected { result } = connector.state {
            break result;
        }
    };

    info!("Connected with success");

    Ok(result)
}

async fn resolve_generator(
    generator: &mut CredsspProcessGenerator<'_>,
    network_client: &mut impl NetworkClient,
) -> ConnectorResult<ClientState> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = network_client.send(&request).await?;
                state = generator.resume(Ok(response));
            }
            GeneratorState::Completed(client_state) => {
                break client_state
                    .map_err(|e| ConnectorError::new("CredSSP", ironrdp_connector::ConnectorErrorKind::Credssp(e)));
            }
        }
    }
}

#[instrument(level = "trace", skip_all)]
async fn perform_credssp_step<S, N>(
    connector: &mut ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    buf: &mut WriteBuf,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    assert!(connector.should_perform_credssp());

    let selected_protocol = match connector.state {
        ClientConnectorState::Credssp { selected_protocol, .. } => selected_protocol,
        _ => return Err(general_err!("invalid connector state for CredSSP sequence")),
    };

    let (mut sequence, mut ts_request) = CredsspSequence::init(
        connector.config.credentials.clone(),
        connector.config.domain.as_deref(),
        selected_protocol,
        server_name,
        server_public_key,
        kerberos_config,
        connector.config.credssp_credentialless,
    )?;

    loop {
        let client_state = {
            let mut generator = sequence.process_ts_request(ts_request);
            trace!("resolving network");
            resolve_generator(&mut generator, network_client).await?
        }; // drop generator

        buf.clear();
        let written = sequence.handle_process_result(client_state, buf)?;

        if let Some(response_len) = written.size() {
            let response = &buf[..response_len];
            trace!(response_len, "Send response");
            framed
                .write_all(response)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
        }

        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        debug!(
            connector.state = connector.state.name(),
            hint = ?next_pdu_hint,
            "Wait for PDU"
        );

        let pdu = framed
            .read_by_hint(next_pdu_hint)
            .await
            .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

        trace!(length = pdu.len(), "PDU received");

        if let Some(next_request) = sequence.decode_server_message(&pdu)? {
            ts_request = next_request;
        } else {
            break;
        }
    }

    connector.mark_credssp_as_done();

    Ok(())
}
