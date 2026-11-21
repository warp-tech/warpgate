//! PuTTY key format described in [Appendix C][1] of the PuTTY User Manual.
//!
//! Both private([`Ppk`]) and public([`PuttyPublicKey`]) keys are supported.
//!
//! [1]: https://the.earth.li/~sgtatham/putty/0.75/htmldoc/AppendixC.html#ppk

mod error;
mod key_value;
mod ppk;
mod private_key;
mod public_key;

pub use error::PuttyError;
pub use key_value::{
    Argon2FlavourValue as Argon2Flavour, PpkKeyAlgorithmValue as PpkKeyAlgorithm, PpkVersionKey as PpkVersion,
};
pub use ppk::{Argon2Params, Ppk, PpkEncryptionConfig, PpkEncryptionConfigBuilder};
pub use public_key::PuttyPublicKey;
