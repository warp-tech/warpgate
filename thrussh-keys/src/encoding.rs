// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use crate::Error;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use cryptovec::CryptoVec;

#[doc(hidden)]
pub trait Bytes {
    fn bytes(&self) -> &[u8];
}

impl<A: AsRef<str>> Bytes for A {
    fn bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}

/// Encode in the SSH format.
pub trait Encoding {
    /// Push an SSH-encoded string to `self`.
    fn extend_ssh_string(&mut self, s: &[u8]);
    /// Push an SSH-encoded blank string of length `s` to `self`.
    fn extend_ssh_string_blank(&mut self, s: usize) -> &mut [u8];
    /// Push an SSH-encoded multiple-precision integer.
    fn extend_ssh_mpint(&mut self, s: &[u8]);
    /// Push an SSH-encoded list.
    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I);
    /// Push an SSH-encoded empty list.
    fn write_empty_list(&mut self);
}

/// Encoding length of the given mpint.
pub fn mpint_len(s: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    (if s[i] & 0x80 != 0 { 5 } else { 4 }) + s.len() - i
}

impl Encoding for Vec<u8> {
    fn extend_ssh_string(&mut self, s: &[u8]) {
        self.write_u32::<BigEndian>(s.len() as u32).unwrap();
        self.extend(s);
    }
    fn extend_ssh_string_blank(&mut self, len: usize) -> &mut [u8] {
        self.write_u32::<BigEndian>(len as u32).unwrap();
        let current = self.len();
        self.resize(current + len, 0u8);
        &mut self[current..]
    }
    fn extend_ssh_mpint(&mut self, s: &[u8]) {
        // Skip initial 0s.
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1
        }
        // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
        if s[i] & 0x80 != 0 {
            self.write_u32::<BigEndian>((s.len() - i + 1) as u32)
                .unwrap();
            self.push(0)
        } else {
            self.write_u32::<BigEndian>((s.len() - i) as u32).unwrap();
        }
        self.extend(&s[i..]);
    }

    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I) {
        let len0 = self.len();
        self.extend(&[0, 0, 0, 0]);
        let mut first = true;
        for i in list {
            if !first {
                self.push(b',')
            } else {
                first = false;
            }
            self.extend(i.bytes())
        }
        let len = (self.len() - len0 - 4) as u32;

        BigEndian::write_u32(&mut self[len0..], len);
    }

    fn write_empty_list(&mut self) {
        self.extend(&[0, 0, 0, 0]);
    }
}

impl Encoding for CryptoVec {
    fn extend_ssh_string(&mut self, s: &[u8]) {
        self.push_u32_be(s.len() as u32);
        self.extend(s);
    }
    fn extend_ssh_string_blank(&mut self, len: usize) -> &mut [u8] {
        self.push_u32_be(len as u32);
        let current = self.len();
        self.resize(current + len);
        &mut self[current..]
    }
    fn extend_ssh_mpint(&mut self, s: &[u8]) {
        // Skip initial 0s.
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1
        }
        // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
        if s[i] & 0x80 != 0 {
            self.push_u32_be((s.len() - i + 1) as u32);
            self.push(0)
        } else {
            self.push_u32_be((s.len() - i) as u32);
        }
        self.extend(&s[i..]);
    }

    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I) {
        let len0 = self.len();
        self.extend(&[0, 0, 0, 0]);
        let mut first = true;
        for i in list {
            if !first {
                self.push(b',')
            } else {
                first = false;
            }
            self.extend(i.bytes())
        }
        let len = (self.len() - len0 - 4) as u32;

        BigEndian::write_u32(&mut self[len0..], len);
    }

    fn write_empty_list(&mut self) {
        self.extend(&[0, 0, 0, 0]);
    }
}

/// A cursor-like trait to read SSH-encoded things.
pub trait Reader {
    /// Create an SSH reader for `self`.
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a>;
}

impl Reader for CryptoVec {
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a> {
        Position {
            s: &self,
            position: starting_at,
        }
    }
}

impl Reader for [u8] {
    fn reader<'a>(&'a self, starting_at: usize) -> Position<'a> {
        Position {
            s: self,
            position: starting_at,
        }
    }
}

/// A cursor-like type to read SSH-encoded values.
#[derive(Debug)]
pub struct Position<'a> {
    s: &'a [u8],
    #[doc(hidden)]
    pub position: usize,
}
impl<'a> Position<'a> {
    /// Read one string from this reader.
    pub fn read_string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.read_u32()? as usize;
        if self.position + len <= self.s.len() {
            let result = &self.s[self.position..(self.position + len)];
            self.position += len;
            Ok(result)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    /// Read a `u32` from this reader.
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        if self.position + 4 <= self.s.len() {
            let u = BigEndian::read_u32(&self.s[self.position..]);
            self.position += 4;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    /// Read one byte from this reader.
    pub fn read_byte(&mut self) -> Result<u8, Error> {
        if self.position + 1 <= self.s.len() {
            let u = self.s[self.position];
            self.position += 1;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }

    /// Read one byte from this reader.
    pub fn read_mpint(&mut self) -> Result<&'a [u8], Error> {
        let len = self.read_u32()? as usize;
        if self.position + len <= self.s.len() {
            let result = &self.s[self.position..(self.position + len)];
            self.position += len;
            Ok(result)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
}
