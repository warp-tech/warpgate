use super::{KV_DELIMITER, PpkKeyValue, PpkLiteral, PpkMultilineKeyValue, PpkValueParsingError};
use crate::putty::PuttyError;

/// Reader for PPK key-value format.
pub struct PuttyKvReader<'a> {
    input: std::str::Lines<'a>,
}

impl<'a> PuttyKvReader<'a> {
    pub fn from_str(input: &'a str) -> Self {
        Self { input: input.lines() }
    }

    pub fn next_value<T: PpkKeyValue>(&mut self) -> Result<T::Value, PuttyError> {
        let (_, value) = self.next_key_value::<T>()?;
        Ok(value)
    }

    pub fn next_key_value<T: PpkKeyValue>(&mut self) -> Result<(T::Key, T::Value), PuttyError> {
        let line = self.input.next().ok_or(PuttyError::EndOfInput)?;
        let (key, value) = line.split_once(KV_DELIMITER).ok_or(PuttyError::InvalidKeyValueFormat)?;

        let parsed_key = key
            .parse()
            .map_err(|e: PpkValueParsingError| PuttyError::InvalidInput {
                context: T::Key::context(),
                expected: e.expected,
                actual: e.actual,
            })?;

        let parsed_value = value
            .parse()
            .map_err(|e: PpkValueParsingError| PuttyError::InvalidInput {
                context: T::Key::context(),
                expected: e.expected,
                actual: e.actual,
            })?;

        Ok((parsed_key, parsed_value))
    }

    pub fn next_multiline_value<T: PpkMultilineKeyValue>(&mut self) -> Result<T::Value, PuttyError> {
        let (_, value) = self.next_multiline_key_value::<T>()?;
        Ok(value)
    }

    pub fn next_multiline_key_value<T: PpkMultilineKeyValue>(&mut self) -> Result<(T::Key, T::Value), PuttyError> {
        let line = self.input.next().ok_or(PuttyError::EndOfInput)?;
        let (key, value) = line.split_once(KV_DELIMITER).ok_or(PuttyError::InvalidKeyValueFormat)?;

        // Parse key early to check if it's valid before reading multiline value
        let parsed_key: T::Key = key
            .parse()
            .map_err(|e: PpkValueParsingError| PuttyError::InvalidInput {
                context: T::Key::context(),
                expected: e.expected,
                actual: e.actual,
            })?;

        // NOTE: u16 is enough for multiline fields, as in PPK format they are storing
        // base64-encoded private/public key data, and 65535 lines is more than enough for any
        // supported PPK key type.
        let lines_count: u16 = value.parse().map_err(|_| PuttyError::InvalidInput {
            context: T::Key::context(),
            expected: "<valid lines count>",
            actual: value.to_string(),
        })?;

        let mut encoded = String::new();

        for _ in 0..lines_count {
            // NOTE: we do not preserve newlines for multiline fields as in PPK they are
            // only used to split base64-encoded data into lines.
            encoded.push_str(self.input.next().ok_or(PuttyError::EndOfInput)?);
        }

        let parsed_value = encoded
            .parse()
            .map_err(|e: PpkValueParsingError| PuttyError::InvalidInput {
                context: T::Key::context(),
                expected: e.expected,
                actual: e.actual,
            })?;

        Ok((parsed_key, parsed_value))
    }
}
