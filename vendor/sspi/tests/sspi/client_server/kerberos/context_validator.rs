use sspi::NegotiatedProtocol;
use sspi::credssp::SspiContext;

/// Helper-trait to implement SSPI context validation in tests.
///
/// _Note_: this trait is not complete and may be extended in the future when needed.
pub(super) trait SspiContextValidator {
    /// Validates the client SSPI context after the provided number of iterations.
    fn validate_client(&mut self, step: usize, client: &SspiContext);
}

/// Empty validator that does not perform any validation.
pub(super) struct EmptySspiContextValidator;

impl SspiContextValidator for EmptySspiContextValidator {
    fn validate_client(&mut self, _step: usize, _client: &SspiContext) {}
}

/// Performs additional SPNEGO context validation for Kerberos over SPNEGO tests.
pub(super) struct SpnegoKerberosContextValidator;

impl SspiContextValidator for SpnegoKerberosContextValidator {
    fn validate_client(&mut self, _step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        assert!(matches!(
            negotiate.negotiated_protocol(),
            NegotiatedProtocol::Kerberos(_)
        ));
    }
}

/// Validates that the client correctly falls back to NTLM.
pub(super) struct SpnegoKerberosNtlmFallbackValidator;

impl SspiContextValidator for SpnegoKerberosNtlmFallbackValidator {
    fn validate_client(&mut self, _step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        assert!(matches!(negotiate.negotiated_protocol(), NegotiatedProtocol::Ntlm(_)));
    }
}

/// Validates that the client correctly falls back to NTLM when the server selected NTLM in SPNEGO instead of Kerberos.
pub(super) struct SpnegoServerNtlmFallbackValidator;

impl SspiContextValidator for SpnegoServerNtlmFallbackValidator {
    fn validate_client(&mut self, step: usize, client: &SspiContext) {
        let SspiContext::Negotiate(negotiate) = client else {
            panic!("Expected Negotiate context");
        };

        match step {
            0 => {
                assert!(matches!(
                    negotiate.negotiated_protocol(),
                    NegotiatedProtocol::Kerberos(_)
                ));
            }
            1 => {
                assert!(matches!(negotiate.negotiated_protocol(), NegotiatedProtocol::Ntlm(_)));
            }
            _ => {}
        }
    }
}
