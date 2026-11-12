use ironrdp_connector::credssp::{CredsspProcessGenerator, CredsspSequence, KerberosConfig};
use ironrdp_connector::sspi::credssp::ClientState;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionOutcome, ConnectorError, ConnectorResult, ServerName, State as _,
    general_err,
};
use ironrdp_core::WriteBuf;
use tracing::{debug, info, instrument, trace, warn};

use crate::framed::{Framed, FramedRead, FramedWrite};
use crate::{NetworkClient, single_sequence_step};

#[non_exhaustive]
pub struct ShouldUpgrade;

#[instrument(skip_all)]
pub async fn connect_begin<S>(framed: &mut Framed<S>, connector: &mut ClientConnector) -> ConnectorResult<ShouldUpgrade>
where
    S: FramedRead + FramedWrite,
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
    upgraded: Upgraded,
    connector: ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
) -> ConnectorResult<ConnectionOutcome>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    Box::pin(connect_finalize_with_multitransport(
        upgraded,
        connector,
        framed,
        network_client,
        server_name,
        server_public_key,
        kerberos_config,
        |_, _| async {
            Ok(ironrdp_connector::MultitransportResult::Failure(
                ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu::E_ABORT,
            ))
        },
    ))
    .await
}

/// Completes the connection sequence with application-owned multitransport setup.
///
/// The handler receives one Initiate Multitransport Request at a time and returns the result to send over the main RDP connection.
///
/// Returning `MultitransportResult::Failure` reports setup failure and continues connection finalization over TCP.
/// Returning an error aborts connection finalization after attempting to report `E_ABORT` to the server.
/// Store each successfully established transport in application state that outlives this call.
#[expect(
    clippy::too_many_arguments,
    reason = "extends the established connection-finalization API with a multitransport callback"
)]
#[instrument(skip_all)]
pub async fn connect_finalize_with_multitransport<S, N, H>(
    _: Upgraded,
    mut connector: ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    server_name: ServerName,
    server_public_key: Vec<u8>,
    kerberos_config: Option<KerberosConfig>,
    mut multitransport_handler: H,
) -> ConnectorResult<ConnectionOutcome>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
    H: AsyncFnMut(
        ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu,
        bool,
    ) -> ConnectorResult<ironrdp_connector::MultitransportResult>,
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

    let outcome = loop {
        if connector.should_perform_multitransport() {
            let request = connector
                .multitransport_request()
                .cloned()
                .ok_or_else(|| general_err!("multitransport is pending without a request"))?;
            let soft_sync = connector
                .multitransport_soft_sync_negotiated()
                .ok_or_else(|| general_err!("multitransport is pending without Soft-Sync state"))?;
            let result = match multitransport_handler(request, soft_sync).await {
                Ok(result) => result,
                Err(error) => {
                    if let Err(response_error) = complete_multitransport(
                        &mut connector,
                        framed,
                        ironrdp_connector::MultitransportResult::Failure(
                            ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu::E_ABORT,
                        ),
                    )
                    .await
                    {
                        warn!(%response_error, "Failed to send multitransport abort response");
                    }

                    return Err(error);
                }
            };
            complete_multitransport(&mut connector, framed, result).await?;
            continue;
        }

        single_sequence_step(framed, &mut connector, &mut buf).await?;

        if let Some(outcome) = connector.state.take_outcome() {
            break outcome;
        }
    };

    match &outcome {
        ConnectionOutcome::Connected(_) => info!("Connected with success"),
        ConnectionOutcome::Redirected(redirection) => {
            info!(session_id = redirection.session_id, "Server redirected the connection");
        }
    }

    Ok(outcome)
}

/// Sends the response for the connector's pending multitransport request.
#[instrument(skip_all)]
pub async fn complete_multitransport<S>(
    connector: &mut ClientConnector,
    framed: &mut Framed<S>,
    result: ironrdp_connector::MultitransportResult,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();
    let written = connector.complete_multitransport(result, &mut buf)?;
    if written.size().is_some() {
        framed
            .write_all(buf.filled())
            .await
            .map_err(|e| ironrdp_connector::custom_err!("write multitransport response", e))?;
    }
    Ok(())
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

/// Run the CredSSP/NLA exchange on an already-TLS stream.
///
/// Does not touch [`ClientConnector`] state; callers that drive a connector should call
/// [`ClientConnector::mark_credssp_as_done`] afterwards when appropriate.
#[instrument(level = "trace", skip_all)]
pub async fn perform_credssp<S, N>(
    framed: &mut Framed<S>,
    network_client: &mut N,
    buf: &mut WriteBuf,
    mut sequence: CredsspSequence,
    mut ts_request: ironrdp_connector::sspi::credssp::TsRequest,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
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

        debug!(hint = ?next_pdu_hint, "Wait for PDU");

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

    Ok(())
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

    debug!(connector.state = connector.state.name(), "Begin CredSSP");

    let (sequence, ts_request) = CredsspSequence::init_with_mode(
        connector.config.credentials.clone(),
        connector.config.domain.as_deref(),
        selected_protocol,
        server_name,
        server_public_key,
        kerberos_config,
        connector.config.credssp_credentialless,
    )?;

    perform_credssp(framed, network_client, buf, sequence, ts_request).await?;

    connector.mark_credssp_as_done();

    Ok(())
}
