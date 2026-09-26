//! PPK encoding and decoding functions.

use crate::putty::key_value::{
    Base64PpkValue, HexPpkValue, PpkArgon2Memory, PpkArgon2MemoryValue, PpkArgon2Parallelism,
    PpkArgon2ParallelismValue, PpkArgon2Passes, PpkArgon2PassesValue, PpkArgon2Salt, PpkComment, PpkCommentValue,
    PpkEncryption, PpkEncryptionValue, PpkHeader, PpkKeyDerivation, PpkPrivateLines, PpkPrivateMac, PpkPublicLines,
    PpkVersionKey, PuttyKvReader, PuttyKvWriter,
};
use crate::putty::ppk::encryption::PpkEncryptionKind;
use crate::putty::{Argon2Params, Ppk, PuttyError};
use std::str::FromStr;

impl FromStr for Ppk {
    type Err = PuttyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut reader = PuttyKvReader::from_str(input);

        let (version, algorithm) = reader.next_key_value::<PpkHeader>()?;
        let encryption = reader.next_value::<PpkEncryption>()?;
        let comment = reader.next_value::<PpkComment>()?;
        let public_key = reader.next_multiline_value::<PpkPublicLines>()?;

        let encryption = match encryption {
            PpkEncryptionValue::None => None,
            PpkEncryptionValue::Aes256Cbc if version == PpkVersionKey::V2 => Some(PpkEncryptionKind::Aes256CbcV2),
            PpkEncryptionValue::Aes256Cbc => {
                let argon2_flavor = reader.next_value::<PpkKeyDerivation>()?;
                let argon2_memory = reader.next_value::<PpkArgon2Memory>()?;
                let argon2_passes = reader.next_value::<PpkArgon2Passes>()?;
                let argon2_parallelism = reader.next_value::<PpkArgon2Parallelism>()?;
                let argon2_salt = reader.next_value::<PpkArgon2Salt>()?;

                Some(PpkEncryptionKind::Aes256CbcV3(Argon2Params {
                    flavor: argon2_flavor,
                    memory: argon2_memory.into(),
                    passes: argon2_passes.into(),
                    parallelism: argon2_parallelism.into(),
                    salt: argon2_salt.into(),
                }))
            }
        };

        let private_key = reader.next_multiline_value::<PpkPrivateLines>()?;
        let mac = reader.next_value::<PpkPrivateMac>()?;

        let ppk = Ppk {
            version,
            algorithm,
            encryption,
            comment: comment.into(),
            public_key: public_key.into(),
            private_key: private_key.into(),
            mac: mac.into(),
        };

        // Validate MAC for file integrity check
        if ppk.encryption.is_none() {
            let mac = ppk.calculate_unencrypted_mac(ppk.private_key.as_slice())?;

            if mac.as_slice() != ppk.mac.as_slice() {
                return Err(PuttyError::MacValidation);
            }
        }

        Ok(ppk)
    }
}

impl Ppk {
    /// Encodes the PPK key to a string.
    pub fn to_string(&self) -> Result<String, PuttyError> {
        // NOTE: V2 uses CRLF line endings, V3 uses LF
        let crlf = match self.version {
            PpkVersionKey::V2 => true,
            PpkVersionKey::V3 => false,
        };

        let mut writer = PuttyKvWriter::new(crlf);

        writer.write_key_value::<PpkHeader>(self.version, self.algorithm);
        writer.write_value::<PpkEncryption>((self.encryption.as_ref()).into());
        writer.write_value::<PpkComment>(PpkCommentValue::from(self.comment.clone()));
        writer.write_multiline_value::<PpkPublicLines>(Base64PpkValue::from(self.public_key.clone()));
        match &self.encryption {
            Some(PpkEncryptionKind::Aes256CbcV3(argon2)) => {
                writer.write_value::<PpkKeyDerivation>(argon2.flavor);
                writer.write_value::<PpkArgon2Memory>(PpkArgon2MemoryValue::from(argon2.memory));
                writer.write_value::<PpkArgon2Passes>(PpkArgon2PassesValue::from(argon2.passes));
                writer.write_value::<PpkArgon2Parallelism>(PpkArgon2ParallelismValue::from(argon2.parallelism));
                writer.write_value::<PpkArgon2Salt>(HexPpkValue::from(argon2.salt.clone()));
            }
            None | Some(PpkEncryptionKind::Aes256CbcV2) => {}
        }

        writer.write_multiline_value::<PpkPrivateLines>(Base64PpkValue::from(self.private_key.clone()));
        writer.write_value::<PpkPrivateMac>(HexPpkValue::from(self.mac.clone()));

        Ok(writer.finish())
    }
}
