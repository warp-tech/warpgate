use core::{fmt, ops};

#[derive(Debug, Clone)]
pub(crate) struct Rc4 {
    i: usize,
    j: usize,
    state: State,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        // key scheduling
        let mut state = State::default();
        for (i, item) in (0..=255).zip(state.iter_mut()) {
            *item = i;
        }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + usize::from(state[i]) + usize::from(key[i % key.len()])) % 256;
            state.swap(i, j);
        }

        Self { i: 0, j: 0, state }
    }

    pub(crate) fn process(&mut self, message: &[u8]) -> Vec<u8> {
        // PRGA
        let mut output = Vec::with_capacity(message.len());
        while output.capacity() > output.len() {
            self.i = (self.i + 1) % 256;
            self.j = (self.j + usize::from(self.state[self.i])) % 256;
            self.state.swap(self.i, self.j);
            let idx_k = (usize::from(self.state[self.i]) + usize::from(self.state[self.j])) % 256;
            let k = self.state[idx_k];
            let idx_msg = output.len();
            output.push(k ^ message[idx_msg]);
        }

        output
    }
}

#[derive(Clone)]
struct State([u8; 256]);

impl Default for State {
    fn default() -> Self {
        Self([0; 256])
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ops::Deref for State {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl ops::DerefMut for State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_common_case() {
        let key = "key".to_owned();
        let message = "message".to_owned();
        let expected = [0x66, 0x09, 0x47, 0x9E, 0x45, 0xE8, 0x1E];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn one_symbol_key() {
        let key = "0".to_owned();
        let message = "message".to_owned();
        let expected = [0xE5, 0x1A, 0xD5, 0xF3, 0xA2, 0x1C, 0xB1];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn one_symbol_similar_key_and_message() {
        let key = "0".to_owned();
        let message = "0".to_owned();
        let expected = [0xb8];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn one_symbol_key_and_message() {
        let key = "0".to_owned();
        let message = "a".to_owned();
        let expected = [0xe9];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn empty_message() {
        let key = "key".to_owned();
        let message = "".to_owned();
        let expected = [];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn long_key() {
        let key = "oigjwr984 874Y8 7W68 8&$y*%&78 4  8724JIOGROGN I4UI928 98FRUWNKRJB GRGg ergeowp".to_owned();
        let message = "message".to_owned();
        let expected = [0xBE, 0x74, 0xEB, 0x88, 0x64, 0x8E, 0x6A];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected);
    }

    #[test]
    fn long_message() {
        let key = "key".to_owned();
        let message = "oigjwr984 874Y8 7W68 8&$y*%&78 4  8724JIOGROGN I4UI928 98FRUWNKRJB GRGg ergeowp".to_owned();
        let expected = [
            0x64, 0x05, 0x53, 0x87, 0x53, 0xFD, 0x42, 0x72, 0x7C, 0x6B, 0x30, 0x4C, 0x22, 0x04, 0x2A, 0xDD, 0xB8, 0x23,
            0xDB, 0x5E, 0x8B, 0xD9, 0xC5, 0xDB, 0x4F, 0xD9, 0x8D, 0x9B, 0x0E, 0xD4, 0x5B, 0xAA, 0x34, 0x1D, 0x8E, 0xB9,
            0x9B, 0xBB, 0xF0, 0xF5, 0x7C, 0x90, 0xAD, 0xFE, 0x64, 0x33, 0x06, 0xCA, 0xCE, 0x68, 0x71, 0x1E, 0x5E, 0xE1,
            0x29, 0xBD, 0xCB, 0x29, 0x6A, 0x6D, 0xD4, 0xC9, 0x99, 0x59, 0xE9, 0x3B, 0xCC, 0x97, 0xEE, 0x32, 0xB5, 0x98,
            0x57, 0x1C, 0x13, 0x6D, 0x35, 0x0C, 0xDE,
        ];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected[..]);
    }

    #[test]
    fn long_key_message() {
        let key = "iogjerwo ghoreh trojtrj trjrohjigjw9iehgfwe 315 989&*$*%&*  &*^*& q 4unkregeor 847847786 ^&**^*"
            .to_owned();
        let message = "oigjwr984 874Y8 7W68 8&$y*%&78 4  8724JIOGROGN I4UI928 98FRUWNKRJB GRGg ergeowp".to_owned();
        let expected = [
            0x6B, 0x92, 0x32, 0x1B, 0xAD, 0x5A, 0x3A, 0x62, 0xE4, 0xC9, 0xD4, 0x2A, 0xAF, 0x34, 0xF1, 0xA3, 0xA0, 0x23,
            0x5B, 0x8D, 0x12, 0x7B, 0x4C, 0xE6, 0x23, 0xE6, 0x13, 0x81, 0xF0, 0xDA, 0xE0, 0x02, 0x65, 0x71, 0x2B, 0x1D,
            0x39, 0x17, 0x2A, 0x7E, 0x60, 0x68, 0x26, 0x2B, 0xF0, 0x46, 0x03, 0xA0, 0x40, 0xC4, 0xBA, 0x78, 0xF9, 0x82,
            0x35, 0x42, 0xE2, 0x8A, 0x69, 0xEE, 0xE0, 0x29, 0x31, 0x66, 0xBE, 0xAF, 0x9E, 0x81, 0xD8, 0x58, 0xCC, 0xA6,
            0x4D, 0xBD, 0xEE, 0x31, 0x32, 0x2A, 0x2F,
        ];
        assert_eq!(Rc4::new(key.as_bytes()).process(message.as_bytes())[..], expected[..]);
    }
}
