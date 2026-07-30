use std::mem;

use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE};
use picky_krb::gss_api::{NegTokenTarg, NegTokenTarg1};

use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::negotiate::extractors::{decode_initial_neg_init, negotiate_mech_type};
use crate::negotiate::generators::{generate_final_neg_token_targ, generate_neg_token_targ, generate_neg_token_targ_1};
use crate::negotiate::{GUEST_USERNAME, NegotiateState};
use crate::{
    AcceptSecurityContextResult, BufferType, ContextNames, Error, ErrorKind, Negotiate, NegotiatedProtocol, Result,
    SecurityBuffer, SecurityStatus, ServerRequestFlags, ServerResponseFlags, SspiImpl,
};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
#[instrument(ret, fields(protocol = negotiate.protocol_name()), skip_all)]
pub(crate) async fn accept_security_context(
    negotiate: &mut Negotiate,
    yield_point: &mut YieldPointLocal,
    mut builder: FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let input = builder
        .input
        .as_mut()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

    let input_token = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;

    let status = match negotiate.state {
        NegotiateState::Initial => {
            let (mech_token, mech_types) = decode_initial_neg_init(&input_token.buffer)?;
            let (mech_type, mech_index) = negotiate_mech_type(&mech_types, negotiate)?;
            negotiate.mech_types = picky_asn1_der::to_vec(&mech_types)?;

            let mut status = SecurityStatus::ContinueNeeded;

            let encoded_neg_token_targ = if mech_index != 0 {
                // The selected mech type is not the most preferred one by client, so MIC token exchange is required according to RFC 4178.
                //
                // [RFC 4178 5. Processing of mechListMIC](https://www.rfc-editor.org/rfc/rfc4178.html#section-5):
                // > if the accepted mechanism is the most preferred mechanism of both the initiator and the acceptor,
                // > then the MIC token exchange is OPTIONAL.
                // > In all other cases, MIC tokens MUST be exchanged after the mechanism context is fully established.
                // > ...Note that the MIC token exchange is required if a mechanism other than
                // > the initiator's first choice is chosen.
                negotiate.mic_needed = true;
                negotiate.mic_verified = false;

                negotiate.state = NegotiateState::InProgress;

                // The selected mech type is not the most preferred one by client, so we cannot use the token sent by the client.
                picky_asn1_der::to_vec(&generate_neg_token_targ(ACCEPT_INCOMPLETE.to_vec(), mech_type, None)?)?
            } else {
                // The selected mech type is the most preferred one by client.
                if negotiate.protocol.is_ntlm() {
                    // [MS-SPNG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f377a379-c24f-4a0f-a3eb-0d835389e28a):
                    // > If NTLM authentication is most preferred by the client and the server, and the client includes a MIC
                    // > in AUTHENTICATE_MESSAGE ([MS-NLMP] section 2.2.1.3), then the mechListMIC field becomes
                    // > mandatory in order for the authentication to succeed.
                    //
                    // We always include NTLM MIC token inside AUTHENTICATE_MESSAGE. So, we need to perform
                    // SPNEGO `mechListMIC` exchange.
                    negotiate.mic_needed = true;
                    negotiate.mic_verified = false;
                } else {
                    // So, MIC exchange is not needed and we can use the token sent by the client.
                    negotiate.mic_needed = false;
                }

                let (response_token, neg_result) = if let Some(mut mech_token) = mech_token {
                    input_token.buffer = mem::take(&mut mech_token);

                    let result = negotiate
                        .protocol
                        .accept_security_context(yield_point, &mut builder)
                        .await?;

                    let neg_result =
                        if result.status == SecurityStatus::Ok || result.status == SecurityStatus::CompleteNeeded {
                            if !negotiate.mic_needed || negotiate.mic_verified {
                                negotiate.state = NegotiateState::Ok;
                                status = SecurityStatus::Ok;

                                ACCEPT_COMPLETE
                            } else {
                                negotiate.state = NegotiateState::VerifyMic;

                                ACCEPT_INCOMPLETE
                            }
                        } else {
                            negotiate.state = NegotiateState::InProgress;

                            ACCEPT_INCOMPLETE
                        };

                    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                    (Some(mem::take(&mut output_token.buffer)), neg_result)
                } else {
                    (None, ACCEPT_INCOMPLETE)
                };

                picky_asn1_der::to_vec(&generate_neg_token_targ(
                    neg_result.to_vec(),
                    mech_type,
                    response_token,
                )?)?
            };

            let is_kerberos_u2u = if let NegotiatedProtocol::Kerberos(kerberos) = &negotiate.protocol {
                kerberos.krb5_user_to_user
            } else {
                false
            };
            if is_kerberos_u2u || builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                negotiate.mic_needed = true;
                negotiate.mic_verified = false;
            }

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_neg_token_targ;

            status
        }
        NegotiateState::InProgress => {
            let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
            let NegTokenTarg {
                neg_result,
                supported_mech: _,
                response_token,
                mech_list_mic,
            } = neg_token_targ.0;

            let input_token = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;
            let token = response_token.0.map(|token| token.0.0);
            if let Some(token) = token {
                input_token.buffer = token;
            } else {
                input_token.buffer.clear();
            }

            let mut result = negotiate
                .protocol
                .accept_security_context(yield_point, &mut builder)
                .await?;

            if result.status == SecurityStatus::Ok || result.status == SecurityStatus::CompleteNeeded {
                let mech_list_mic = mech_list_mic.0.map(|token| token.0.0);
                if mech_list_mic.is_some() && negotiate.mic_needed {
                    negotiate.set_auth_identity()?;
                    negotiate.verify_mic_token(mech_list_mic.as_deref())?;

                    negotiate.mic_verified = true;
                }

                if negotiate.mic_needed
                    && mech_list_mic.is_none()
                    && neg_result.0.as_ref().map(|neg_result| neg_result.0.0.as_slice()) == Some(&ACCEPT_COMPLETE)
                {
                    // We should skip `mechListMIC` exchange when the client tries guest logon.
                    let ContextNames { username } = negotiate.protocol.query_context_names()?;

                    if !username.inner().eq_ignore_ascii_case(GUEST_USERNAME) {
                        return Err(Error::new(
                            ErrorKind::InvalidToken,
                            "the client skipped `mechListMIC` exchange, but it is required for non-guest logon",
                        ));
                    }

                    negotiate.mic_needed = false;
                }

                let neg_result = if !negotiate.mic_needed || negotiate.mic_verified {
                    negotiate.state = NegotiateState::Ok;
                    result.status = SecurityStatus::Ok;

                    ACCEPT_COMPLETE.to_vec()
                } else {
                    negotiate.state = NegotiateState::VerifyMic;
                    result.status = SecurityStatus::ContinueNeeded;

                    ACCEPT_INCOMPLETE.to_vec()
                };

                prepare_neg_token(neg_result, negotiate, &mut builder)?;
            } else {
                // Wrap in a NegToken.
                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                let spnego_token =
                    picky_asn1_der::to_vec(&generate_neg_token_targ_1(Some(mem::take(&mut output_token.buffer))))?;

                output_token.buffer = spnego_token;
            }

            result.status
        }
        NegotiateState::VerifyMic => {
            if !negotiate.mic_verified && negotiate.mic_needed {
                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let NegTokenTarg {
                    neg_result: _,
                    supported_mech: _,
                    response_token: _,
                    mech_list_mic,
                } = neg_token_targ.0;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0.0);
                if mech_list_mic.is_some() {
                    negotiate.set_auth_identity()?;
                    negotiate.verify_mic_token(mech_list_mic.as_deref())?;
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "mech_list_mic is not present in SPNEGO message",
                    ));
                }
            }

            SecurityStatus::Ok
        }
        NegotiateState::Ok => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "accept_security_context called after negotiation completed",
            ));
        }
    };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}

fn prepare_neg_token(
    neg_result: Vec<u8>,
    negotiate: &mut Negotiate,
    builder: &mut FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<()> {
    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

    let response_token = if !output_token.buffer.is_empty() {
        Some(mem::take(&mut output_token.buffer))
    } else {
        None
    };

    let mic = if negotiate.mic_needed {
        Some(
            negotiate
                .protocol
                .generate_mic_token(&negotiate.mech_types, crate::private::Sealed)?,
        )
    } else {
        None
    };

    let neg_token_targ = generate_final_neg_token_targ(neg_result, response_token, mic);

    let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

    output_token.buffer = encoded_final_neg_token_targ;

    Ok(())
}
