# IronRDP Connector

Abstract state machine to drive an RDP connection sequence.

## Microsoft Entra session authentication

Call `ClientConnector::with_entra_auth()` before negotiation to require `PROTOCOL_RDSAAD`.
This overrides the TLS-only, CredSSP, and standard-security configuration choices without permitting fallback.
Generate a 2048-bit RSA PoP key, acquire an RDP access token bound to that key, and acquire a fresh AAD nonce for each handshake.
Complete TLS with target certificate and hostname validation before calling `mark_security_upgrade_as_done()`.

Drive the connector with `Sequence::next_pdu_hint()` and `Sequence::step()` until `entra_server_nonce()` returns a nonce.
Create a signed compact JWS RDP assertion bound to that server nonce as specified by [MS-RDPBCGR] sections 2.2.18.2.1 and 5.4.5.4.1.
The assertion requires the access token, resource URI, timestamp, server nonce, public PoP key, and AAD nonce; an ordinary OAuth bearer token is not a substitute.
Call `submit_entra_assertion(assertion, output)`, send the resulting JSON over the same TLS connection, and clear the output buffer.
Resume stepping to receive the authentication result; only `S_OK` advances to Basic Settings Exchange.
Other results abort with `ConnectorErrorKind::EntraAuth`, preserving the server's HRESULT.
The subsequent Client Info PDU omits the configured password or smart-card PIN and clears password-based autologon flags.

This is a sans-I/O session-authentication exchange, not a WAM token provider.
Applications using `ironrdp-client` can enable its optional `entra-auth` feature to acquire a PoP-bound token through the documented browser authorization-code flow and drive this exchange.
The connector itself does not acquire tokens, refresh them, invoke WAM, or permit fallback.
Applications using the connector directly remain responsible for token acquisition, PoP key storage, assertion signing, claim correctness, TLS validation, and driving this phase.
The connector bounds each JSON message to 64 KiB as a local resource policy, appends a trailing NUL terminator to outbound assertions as required by Windows `termsrv`, accepts optional NUL terminators and fragmented or coalesced JSON objects on input, and does not retain or log submitted assertions.
After successful authentication, it accepts JSON whitespace before the next X.224 response.
Live Entra host interoperability has not been verified.
InteractiveEntraAuth DVC, browser prompts, AVD feed discovery, and cloud broker orchestration are not implemented here.

This crate is part of the [IronRDP] project.

[IronRDP]: https://github.com/Devolutions/IronRDP
[MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
