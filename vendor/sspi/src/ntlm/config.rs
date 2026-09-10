use crate::negotiate::ProtocolConfig;
use crate::{NegotiatedProtocol, Ntlm, Result};

#[derive(Debug, Clone, Default)]
pub struct NtlmConfig {
    /// Computer name, or "workstation name", of the client machine performing the authentication attempt
    ///
    /// This is also referred to as the "Source Workstation".
    pub client_computer_name: Option<String>,
}

impl NtlmConfig {
    pub fn new(client_machine_name: String) -> Self {
        Self {
            client_computer_name: Some(client_machine_name),
        }
    }
}

impl ProtocolConfig for NtlmConfig {
    fn new_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Ntlm(Ntlm::with_config(Clone::clone(self))))
    }

    fn box_clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(Clone::clone(self))
    }
}
