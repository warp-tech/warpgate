use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub fn get_crypto_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}
