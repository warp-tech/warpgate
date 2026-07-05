/*
 * Copyright (c) 2016 Boucher, Antoni <bouanto@zoho.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#![allow(dead_code)]

pub type Key = [u8; 8];

const FIRST_BIT: u64 = 1 << 63;
const HALF_KEY_SIZE: i64 = KEY_SIZE / 2;
const KEY_SIZE: i64 = 56;

/// Do a circular left shift on a width of HALF_KEY_SIZE.
fn circular_left_shift(n1: u64, n2: u64, shift_count: i64) -> (u64, u64) {
    let mut new_value1 = n1;
    let mut new_value2 = n2;
    for _ in 0..shift_count {
        let first_bit = new_value1 & FIRST_BIT;
        new_value1 = (new_value1 << 1) | (first_bit >> (HALF_KEY_SIZE - 1));
        let first_bit = new_value2 & FIRST_BIT;
        new_value2 = (new_value2 << 1) | (first_bit >> (HALF_KEY_SIZE - 1));
    }
    (new_value1, new_value2)
}

/// Create the 16 subkeys.
fn compute_subkeys(key: u64) -> Vec<u64> {
    let table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    let k0 = pc1(key);
    let mut subkeys = vec![k0];

    for shift_count in &table {
        let last_key = subkeys.last().unwrap();
        let last_ci = last_key & 0xFFFFFFF000000000;
        let last_di = last_key << HALF_KEY_SIZE;
        let (ci, di) = circular_left_shift(last_ci, last_di, *shift_count);
        let current_key = ci | (di >> HALF_KEY_SIZE);
        subkeys.push(current_key);
    }

    subkeys.remove(0);
    subkeys.iter().map(|&n| pc2(n)).collect()
}

/// Swap bits using the E table.
fn e(block: u64) -> u64 {
    let table = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
        18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];

    swap_bits(block, &table)
}

/// Decrypt `message` using the `key`.
pub fn decrypt(cipher: &[u8], key: &Key) -> Vec<u8> {
    let key = key_to_u64(key);
    let mut subkeys = compute_subkeys(key);
    subkeys.reverse();
    des(cipher, subkeys)
}

/// Encrypt `message` using `subkeys`.
fn des(message: &[u8], subkeys: Vec<u64>) -> Vec<u8> {
    let blocks = message_to_u64s(message);

    let mut cipher = vec![];

    for block in blocks {
        let permuted = ip(block);
        let mut li = permuted & 0xFFFFFFFF00000000;
        let mut ri = permuted << 32;

        for subkey in &subkeys {
            let last_li = li;
            li = ri;
            ri = last_li ^ feistel(ri, *subkey);
        }

        let r16l16 = ri | (li >> 32);
        cipher.append(&mut to_u8_vec(fp(r16l16)));
    }

    cipher
}

/// Encrypt `message` using the `key`.
pub fn encrypt(message: &[u8], key: &Key) -> Vec<u8> {
    let key = key_to_u64(key);
    let subkeys = compute_subkeys(key);
    des(message, subkeys)
}

/// Feistel function.
fn feistel(half_block: u64, subkey: u64) -> u64 {
    let expanded = e(half_block);
    let mut intermediate = expanded ^ subkey;
    let mut result = 0;

    for i in 0..8 {
        let block = (intermediate & 0xFC00000000000000) >> 58;
        intermediate <<= 6;
        result <<= 4;
        result |= s(i, block);
    }

    p(result << 32)
}

/// Swap bits using the IP table.
fn ip(message: u64) -> u64 {
    let table = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
        6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
        3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];

    swap_bits(message, &table)
}

/// Convert a `Key` to a 64-bits integer.
fn key_to_u64(key: &Key) -> u64 {
    let mut result = 0;
    for &part in key {
        result <<= 8;
        result += part as u64;
    }
    result
}

/// Convert a message to a vector of 64-bits integer.
fn message_to_u64s(message: &[u8]) -> Vec<u64> {
    message.chunks(8).map(|m| key_to_u64(&to_key(m))).collect()
}

/// Swap bits using the P table.
fn p(block: u64) -> u64 {
    let table = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25,
    ];

    swap_bits(block, &table)
}

/// Swap bits using the PC-1 table.
fn pc1(key: u64) -> u64 {
    let table = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
        37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];

    swap_bits(key, &table)
}

/// Swap bits using the PC-2 table.
fn pc2(key: u64) -> u64 {
    let table = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
        52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];

    swap_bits(key, &table)
}

/// Swap bits using the reverse FP table.
fn fp(message: u64) -> u64 {
    let table = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62,
        30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
        59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];

    swap_bits(message, &table)
}

/// Produce 4-bits using an S box.
fn s(box_id: usize, block: u64) -> u64 {
    let tables = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ],
    ];
    let i = (((block & 0x20) >> 4) | (block & 1)) as usize;
    let j = ((block & 0x1E) >> 1) as usize;
    tables[box_id][i][j]
}

/// Swap bits using a table.
fn swap_bits(key: u64, table: &[u64]) -> u64 {
    let mut result = 0;

    for (pos, index) in table.iter().enumerate() {
        let bit = (key << (index - 1)) & FIRST_BIT;
        result |= bit >> pos;
    }

    result
}

/// Convert a slice to a `Key`.
fn to_key(slice: &[u8]) -> Key {
    let mut vec: Vec<u8> = slice.to_vec();
    let mut key = [0; 8];
    let diff = key.len() - vec.len();
    if diff > 0 {
        vec.append(&mut vec![0; diff]);
    }
    key.clone_from_slice(&vec);
    key
}

/// Convert a `u64` to a `Vec<u8>`.
fn to_u8_vec(num: u64) -> Vec<u8> {
    vec![
        ((num & 0xFF00000000000000) >> 56) as u8,
        ((num & 0x00FF000000000000) >> 48) as u8,
        ((num & 0x0000FF0000000000) >> 40) as u8,
        ((num & 0x000000FF00000000) >> 32) as u8,
        ((num & 0x00000000FF000000) >> 24) as u8,
        ((num & 0x0000000000FF0000) >> 16) as u8,
        ((num & 0x000000000000FF00) >> 8) as u8,
        (num & 0x00000000000000FF) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let message = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected_cipher = vec![0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let cipher = encrypt(&message, &key);
        assert_eq!(cipher, expected_cipher);

        let cipher = expected_cipher;
        let expected_message = message;
        let message = decrypt(&cipher, &key);
        assert_eq!(message, expected_message);

        let message = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let expected_cipher = vec![
            0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05, 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A,
            0xB4, 0x05,
        ];
        let cipher = encrypt(&message, &key);
        assert_eq!(cipher, expected_cipher);

        let cipher = expected_cipher;
        let expected_message = message;
        let message = decrypt(&cipher, &key);
        assert_eq!(message, expected_message);
    }
}
