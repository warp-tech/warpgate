use core::convert::Infallible;

use rsa::rand_core::{TryCryptoRng, TryRng};

// We use this generator only as a type parameter for the `rsa::hazmat::rsa_decrypt_and_check` function.
pub(crate) struct Dummy;

impl TryRng for Dummy {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Infallible> {
        Ok(())
    }
}

impl TryCryptoRng for Dummy {}
