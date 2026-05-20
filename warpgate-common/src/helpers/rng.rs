use rand::SeedableRng;
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;

pub fn get_crypto_rng() -> ChaCha20Rng {
    #[allow(clippy::unwrap_used)]
    ChaCha20Rng::try_from_rng(&mut SysRng).unwrap()
}
