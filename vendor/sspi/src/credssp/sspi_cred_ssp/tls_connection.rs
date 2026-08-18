use std::io::{Read, Write};

use picky_asn1_x509::Certificate;
use rustls::{Connection, ProtocolVersion};

use crate::credssp::sspi_cred_ssp::cipher_block_size::get_cipher_block_size;
use crate::{
    ConnectionCipher, ConnectionHash, ConnectionInfo, ConnectionKeyExchange, ConnectionProtocol, Error, ErrorKind,
    Result, StreamSizes,
};

// type + version + length
pub(super) const TLS_PACKET_HEADER_LEN: usize = 1 /* ContentType */ + 2 /* ProtocolVersion */ + 2 /* length: uint16 */;

// The Secure Sockets Layer (SSL) Protocol Version 3.0
// https://datatracker.ietf.org/doc/html/rfc6101#page-14
//
// ...Sequence numbers are of type uint64 and may not exceed 2^64-1.
const TLS_PACKET_SEQUENCE_NUMBER_LEN: usize = size_of::<u64>();

// The Secure Sockets Layer (SSL) Protocol Version 3.0
// https://datatracker.ietf.org/doc/html/rfc6101#appendix-A.1
//
// application_data(23)
const TLS_APPLICATION_DATA_CONTENT_TYPE: u8 = 0x17;

// [Processing Events and Sequencing Rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
// The CredSSP server does not request the client's X.509 certificate (thus far, the client is anonymous).
// Also, the CredSSP Protocol does not require the client to have a commonly trusted certification authority root with the CredSSP server.
//
// This configuration just accepts any certificate
pub(super) mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};

    #[derive(Debug)]
    pub(crate) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

/// Represents parsed part of the TLS traffic.
///
/// The input buffer can contain part of the TLS message, one TLS packet, or even more than one TLS packet.
/// To decrypt the incoming buffer sometimes we need to split it into parts. If it contains more then one TLS packet,
/// we should decrypt only first of them. This behavior corresponds to the SChannel behavior.
#[derive(Debug)]
struct TlsTrafficParts<'data> {
    /// TLS packet header with a sequence number.
    header: &'data mut [u8],
    /// Decrypted part of the TLS packet.
    ///
    /// *Pay attention*: the TLS packet sequence number must be in the [header] buffer.
    application_data: &'data mut [u8],
    /// Unprocessed TLS packets.
    extra: &'data mut [u8],
}

/// Represents buffers after the decryption.
///
/// We can not return just decrypted data because we also need a TLS header and unprocessed data buffers.
/// More info: https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
///
/// After the decryption, the original SChannel produces four buffers (the order is important):
/// * SECBUFFER_STREAM_HEADER. It contains TLS packet header with a sequence number.
/// * SECBUFFER_DATA. It contains a decrypted data.
/// * SECBUFFER_STREAM_TRAILER. It contains the TLS packet HMAC with all unprocessed data.
/// * SECBUFFER_EXTRA. It contains the rest of the unprocessed TLS traffic. Usually, the start of this buffer
///   points to the start of the next TLS packet in the input buffer.
#[derive(Debug)]
pub(super) struct DecryptionResultBuffers<'data> {
    /// TLS packet header with the sequence number.
    pub header: &'data mut [u8],
    /// Decrypted data.
    pub decrypted: &'data mut [u8],
    /// Unprocessed TLS packets.
    pub extra: &'data mut [u8],
}

/// Represent a successful [decrypt_message] function result.
///
/// This helper structure exists because sometimes the decrypt function can get incomplete TLS packet
/// and needs more bytes to perform the decryption. Such a situation is not an actual error but,
/// on the other hand, there is no data to return. So, this is why the [DecryptionResult::IncompleteMessage] exists.
#[derive(Debug)]
pub(super) enum DecryptionResult<'data> {
    /// Indicated successful TLS packet decryption.
    Success(DecryptionResultBuffers<'data>),
    /// Indicated that the input buffer is too small to perform the decryption and
    /// the function needs more bytes to do it.
    IncompleteMessage(usize),
}

#[derive(Debug)]
pub(super) enum TlsConnection {
    Rustls(Connection),
    // Schannel
}

/// Represents a result of extracting the first TLS packet from the TLS traffic buffer.
enum FindTlsPacketResult<'data> {
    /// TLS packet.
    TlsPacket(&'data mut [u8]),
    /// Indicated how many bytes the input buffer lacks to represent a complete TLS packet.
    Missing(usize),
}

impl TlsConnection {
    pub(super) fn encrypt_tls(&mut self, plain_data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let mut writer = tls_connection.writer();
                let _bytes_written = writer.write(plain_data)?;

                let mut tls_buffer = Vec::new();
                let _bytes_written = tls_connection.write_tls(&mut tls_buffer)?;

                Ok(tls_buffer)
            }
        }
    }

    // This function extracts the first TLS packet from the TLS traffic buffer.
    // If the input buffer contains less than one TLS packet (only a part of it), then
    // it returns how many bytes the input buffer lacks to represent a complete TLS packet.
    fn find_tls_data_to_decrypt<'data>(
        connection: &Connection,
        payload: &'data mut [u8],
    ) -> Result<FindTlsPacketResult<'data>> {
        if payload.len() < TLS_PACKET_HEADER_LEN {
            // We need at least TLS_PACKET_HEADER_LEN bytes to recognize the TLS packet, its type, and length.
            return Ok(FindTlsPacketResult::Missing(TLS_PACKET_HEADER_LEN));
        }

        // In the decryption stage, we accept only TLS packets with TLS_APPLICATION_CONTENT_TYPE specified.
        // Additional info: https://stackoverflow.com/a/65101172:
        // "...DecryptMessage() only works if the record type is "application data". For any other
        // record type (such as a TLS handshake "finished message"), DecryptMessage() won't even
        // try to decrypt it -- it will just return a SEC_E_DECRYPT_FAILURE code."
        let mut tls_packet_start = vec![TLS_APPLICATION_DATA_CONTENT_TYPE];

        let tls_version = connection
            .protocol_version()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "can not query negotiated TLS version"))?;
        let tls_version = u16::from(if tls_version == ProtocolVersion::TLSv1_3 {
            // TLS 1.3 uses the same version number as TLS 1.2 in the record layer.
            ProtocolVersion::TLSv1_2
        } else {
            tls_version
        });

        tls_packet_start.extend_from_slice(&tls_version.to_be_bytes());

        // Safe: payload length is checked above.
        if payload[0..1 /* ContentType */ + 2 /* ProtocolVersion */] != tls_packet_start {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "invalid TLS packet header: expected {:?} but got {:?}",
                    tls_packet_start,
                    &payload[0..3]
                ),
            ));
        }

        // Safe: payload length is checked above.
        let encrypted_application_data_len = usize::from(u16::from_be_bytes(payload[3..5].try_into().unwrap()));

        let tls_packet_len = TLS_PACKET_HEADER_LEN + encrypted_application_data_len;
        if payload.len() < tls_packet_len {
            return Ok(FindTlsPacketResult::Missing(
                TLS_PACKET_HEADER_LEN + encrypted_application_data_len - payload.len(),
            ));
        }

        // Safe: payload length is checked above.
        Ok(FindTlsPacketResult::TlsPacket(&mut payload[0..tls_packet_len]))
    }

    // This function splits the incoming TLS traffic into three parts (if possible):
    // * header.
    // * application_data.
    // * extra.
    // See the [TlsTrafficParts] documentation for a more detailed explanation of those buffers.
    fn split_tls_traffic<'a>(connection: &Connection, payload: &'a mut [u8]) -> Result<TlsTrafficParts<'a>> {
        const TLS_PACKET_PREFIX_LEN: usize = TLS_PACKET_HEADER_LEN + TLS_PACKET_SEQUENCE_NUMBER_LEN;

        if payload.len() < TLS_PACKET_PREFIX_LEN {
            return Err(Error::new(ErrorKind::InvalidToken, "Input TLS buffer is too short."));
        }

        // In the decryption stage, we accept only TLS packets with TLS_APPLICATION_CONTENT_TYPE specified.
        // Additional info: https://stackoverflow.com/a/65101172:
        // "...DecryptMessage() only works if the record type is "application data". For any other
        // record type (such as a TLS handshake "finished message"), DecryptMessage() won't even
        // try to decrypt it -- it will just return a SEC_E_DECRYPT_FAILURE code."
        let mut tls_packet_start = vec![TLS_APPLICATION_DATA_CONTENT_TYPE];

        let tls_version = connection
            .protocol_version()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "can not query negotiated TLS version"))?;
        let tls_version = u16::from(if tls_version == ProtocolVersion::TLSv1_3 {
            // TLS 1.3 uses the same version number as TLS 1.2 in the record layer.
            ProtocolVersion::TLSv1_2
        } else {
            tls_version
        });

        tls_packet_start.extend_from_slice(&tls_version.to_be_bytes());

        // Safe: payload length is checked above.
        if payload[0..1 /* ContentType */ + 2 /* ProtocolVersion */] != tls_packet_start {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "invalid TLS packet header: expected {:?} but got {:?}",
                    tls_packet_start,
                    &payload[0..3],
                ),
            ));
        }

        // Safe: payload length is checked above.
        let encrypted_application_data_len = usize::from(u16::from_be_bytes(payload[3..5].try_into().unwrap()));

        if payload.len() < TLS_PACKET_HEADER_LEN + encrypted_application_data_len {
            return Err(Error::new(ErrorKind::InvalidToken, "Input TLS buffer is too short."));
        }

        // Safe: payload length is checked above.
        let (header, rest) = payload.split_at_mut(TLS_PACKET_PREFIX_LEN);
        // `encrypted_application_data_len` is a len of the encrypted data with the sequence number.
        // But here we need the encrypted data *WITHOUT* a sequence number, so we subtract TLS_PACKET_SEQUENCE_NUMBER_LEN
        // from the overall data length.
        let (application_data, extra) =
            rest.split_at_mut(encrypted_application_data_len - TLS_PACKET_SEQUENCE_NUMBER_LEN);

        Ok(TlsTrafficParts {
            header,
            application_data,
            extra,
        })
    }

    /// Decrypt a part of the incoming TLS traffic.
    ///
    /// If the input buffer contains more than one TLS message,then only the first one will be decrypted.
    pub(super) fn decrypt_tls<'a>(&mut self, payload: &'a mut [u8]) -> Result<DecryptionResult<'a>> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let mut tls_packet = match TlsConnection::find_tls_data_to_decrypt(tls_connection, payload)? {
                    FindTlsPacketResult::TlsPacket(data) => data as &[u8],
                    FindTlsPacketResult::Missing(needed_bytes_amount) => {
                        return Ok(DecryptionResult::IncompleteMessage(needed_bytes_amount));
                    }
                };
                let mut plain_data = Vec::with_capacity(tls_packet.len());

                while !tls_packet.is_empty() {
                    let _ = tls_connection.read_tls(&mut tls_packet)?;

                    let tls_state = tls_connection
                        .process_new_packets()
                        .map_err(|err| Error::new(ErrorKind::DecryptFailure, err.to_string()))?;

                    let decrypted_data_len = plain_data.len();
                    plain_data.resize(decrypted_data_len + tls_state.plaintext_bytes_to_read(), 0);

                    let mut reader = tls_connection.reader();
                    let _plain_data_len = reader.read(&mut plain_data[decrypted_data_len..])?;
                }

                let TlsTrafficParts {
                    header,
                    application_data,
                    extra,
                } = TlsConnection::split_tls_traffic(tls_connection, payload)?;

                if application_data.len() < plain_data.len() {
                    return Err(Error::new(
                        ErrorKind::DecryptFailure,
                        "Decrypted data can not be larger then encrypted one.",
                    ));
                }

                let decrypted = &mut application_data[0..plain_data.len()];
                decrypted.copy_from_slice(&plain_data);

                Ok(DecryptionResult::Success(DecryptionResultBuffers {
                    header,
                    decrypted,
                    extra,
                }))
            }
        }
    }

    pub(super) fn peer_certificates(&self) -> Result<Vec<&[u8]>> {
        match self {
            TlsConnection::Rustls(tls_connection) => tls_connection
                .peer_certificates()
                .map(|certificates| certificates.iter().map(|cert| cert.as_ref()).collect())
                .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "The server certificate is not present")),
        }
    }

    pub(super) fn process_tls_packets(&mut self, mut input_token: &[u8]) -> Result<(usize, Vec<u8>)> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                if !input_token.is_empty() {
                    let _bytes_read = tls_connection.read_tls(&mut input_token)?;
                }

                let _io_status = tls_connection
                    .process_new_packets()
                    .map_err(|err| Error::new(ErrorKind::EncryptFailure, err.to_string()))?;

                let mut tls_buffer = Vec::new();
                let bytes_written = tls_connection.write_tls(&mut tls_buffer)?;

                Ok((bytes_written, tls_buffer))
            }
        }
    }

    pub(super) fn stream_sizes(&self) -> Result<StreamSizes> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let connection_cipher = tls_connection
                    .negotiated_cipher_suite()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "connection cipher is not negotiated"))?;

                let suite = match connection_cipher {
                    rustls::SupportedCipherSuite::Tls12(cipher_suite) => cipher_suite.common.suite,
                    rustls::SupportedCipherSuite::Tls13(cipher_suite) => cipher_suite.common.suite,
                };

                Ok(StreamSizes {
                    header: TLS_PACKET_HEADER_LEN as u32,
                    // trailer = tls mac + padding
                    // this value is taken from the win schannel
                    trailer: 0x2c,
                    // this value is taken from the win schannel
                    max_message: 0x4000,
                    // MSDN: message must contain four buffers
                    // https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
                    buffers: 4,
                    block_size: get_cipher_block_size(suite)?,
                })
            }
        }
    }

    pub(super) fn connection_info(&self) -> Result<ConnectionInfo> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let protocol_version = tls_connection.protocol_version().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidParameter,
                        "Can not acquire connection protocol version",
                    )
                })?;

                let protocol = match tls_connection {
                    Connection::Client(_) => match protocol_version {
                        ProtocolVersion::SSLv2 => ConnectionProtocol::SpProtSsl2Client,
                        ProtocolVersion::TLSv1_0 => ConnectionProtocol::SpProtTls1Client,
                        ProtocolVersion::TLSv1_1 => ConnectionProtocol::SpProtTls1_1Client,
                        ProtocolVersion::TLSv1_2 => ConnectionProtocol::SpProtTls1_2Client,
                        ProtocolVersion::TLSv1_3 => ConnectionProtocol::SpProtTls1_3Client,
                        version => {
                            return Err(Error::new(
                                ErrorKind::InternalError,
                                format!("Unsupported connection protocol was used: {version:?}"),
                            ));
                        }
                    },
                    Connection::Server(_) => match protocol_version {
                        ProtocolVersion::SSLv2 => ConnectionProtocol::SpProtSsl2Server,
                        ProtocolVersion::TLSv1_0 => ConnectionProtocol::SpProtTls1Server,
                        ProtocolVersion::TLSv1_1 => ConnectionProtocol::SpProtTls1_1Server,
                        ProtocolVersion::TLSv1_2 => ConnectionProtocol::SpProtTls1_2Server,
                        ProtocolVersion::TLSv1_3 => ConnectionProtocol::SpProtTls1_3Server,
                        version => {
                            return Err(Error::new(
                                ErrorKind::InternalError,
                                format!("Unsupported connection protocol was used: {version:?}"),
                            ));
                        }
                    },
                };

                let connection_cipher = tls_connection
                    .negotiated_cipher_suite()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "Connection cipher is not negotiated"))?;

                let common = match connection_cipher {
                    rustls::SupportedCipherSuite::Tls12(cipher_suite) => &cipher_suite.common,
                    rustls::SupportedCipherSuite::Tls13(cipher_suite) => &cipher_suite.common,
                };

                let (cipher, cipher_strength) = match common.suite.as_str() {
                    Some(name) if name.contains("AES_128_GCM") => (ConnectionCipher::CalgAes128, 128),
                    Some(name) if name.contains("AES_256_GCM") => (ConnectionCipher::CalgAes256, 256),
                    // NOTE: alg_id for CHACHA20_POLY1305 does not exist
                    _ => {
                        return Err(Error::new(
                            ErrorKind::UnsupportedFunction,
                            format!("alg_id for {:?} is not known", common.suite),
                        ));
                    }
                };

                let hash_strength = common.hash_provider.output_len().try_into()?;

                Ok(ConnectionInfo {
                    protocol,
                    cipher,
                    cipher_strength,
                    hash: ConnectionHash::CalgSha,
                    hash_strength,
                    key_exchange: ConnectionKeyExchange::CalgRsaKeyx,
                    exchange_strength: (self.raw_peer_public_key()?.len() * 8).try_into()?,
                })
            }
        }
    }

    pub(super) fn raw_peer_public_key(&self) -> Result<Vec<u8>> {
        let certificates = self.peer_certificates()?;
        let peer_certificate = certificates
            .first()
            .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "cannot acquire server certificate"))?;

        let peer_certificate: Certificate = picky_asn1_der::from_bytes(peer_certificate)?;

        let raw_public_key = match peer_certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
        {
            picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
            picky_asn1_x509::PublicKey::Ec(ec) => picky_asn1_der::to_vec(&ec)?,
            picky_asn1_x509::PublicKey::Ed(ed) => picky_asn1_der::to_vec(&ed)?,
            picky_asn1_x509::PublicKey::Mldsa(mldsa) => picky_asn1_der::to_vec(&mldsa)?,
        };

        Ok(raw_public_key)
    }
}
