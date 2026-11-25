use super::{KV_DELIMITER, PpkKeyValue, PpkLiteral as _, PpkMultilineKeyValue};

/// Writer for PPK key-value format.
pub(crate) struct PuttyKvWriter {
    output: String,
    line_end: &'static str,
}

impl PuttyKvWriter {
    pub fn new(crlf: bool) -> Self {
        Self {
            output: String::new(),
            line_end: if crlf { "\r\n" } else { "\n" },
        }
    }

    fn write_key_value_impl(&mut self, key: &str, value: &str) {
        self.output.push_str(key);
        self.output.push_str(KV_DELIMITER);
        self.output.push_str(value);
        self.output.push_str(self.line_end);
    }

    pub fn write_value<T: PpkKeyValue>(&mut self, value: T::Value)
    where
        T::Key: Default,
    {
        self.write_key_value::<T>(T::Key::default(), value);
    }

    pub fn write_key_value<T: PpkKeyValue>(&mut self, key: T::Key, value: T::Value) {
        self.write_key_value_impl(key.as_static_str(), &value.to_string());
    }

    pub fn write_multiline_value<T: PpkMultilineKeyValue>(&mut self, value: T::Value)
    where
        T::Key: Default,
    {
        self.write_multiline_key_value::<T>(T::Key::default(), value);
    }

    pub fn write_multiline_key_value<T: PpkMultilineKeyValue>(&mut self, key: T::Key, value: T::Value) {
        // PuTTY uses a maximum of 64 characters per line
        const MAX_CHARS_PER_LINE: usize = 64;

        let value = value.to_string();

        let lines_count = value.len() / MAX_CHARS_PER_LINE + (value.len() % MAX_CHARS_PER_LINE != 0) as usize;

        self.write_key_value_impl(key.as_static_str(), &lines_count.to_string());

        let mut value_remaining = value.as_str();

        while !value_remaining.is_empty() {
            let line_len = value_remaining.len().min(MAX_CHARS_PER_LINE);
            let (line, remaining) = value_remaining.split_at(line_len);
            value_remaining = remaining;

            self.output.push_str(line);
            self.output.push_str(self.line_end);
        }
    }

    pub fn finish(self) -> String {
        self.output
    }
}
