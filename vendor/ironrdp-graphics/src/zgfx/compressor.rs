//! ZGFX (RDP8) LZ77 compression.
//!
//! Implements the compression side of the ZGFX codec defined in
//! [\[MS-RDPEGFX\] 2.2.1.1.1]. Uses a hash table mapping 3-byte prefixes to
//! history positions for O(1) match candidate lookup against the 2.5 MB
//! sliding window.
//!
//! [\[MS-RDPEGFX\] 2.2.1.1.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/

use std::collections::HashMap;

use bitvec::prelude::*;

use super::{HISTORY_SIZE, TOKEN_TABLE, ZgfxError};
const MIN_MATCH_LENGTH: usize = 3;
const MAX_MATCH_LENGTH: usize = 65535;
/// Maximum back-reference distance (last token in MS-RDPEGFX table)
const MAX_MATCH_DISTANCE: usize = 2_097_152;

/// Cap candidates per lookup to bound worst-case search time
const MAX_CANDIDATES: usize = 16;

/// Cap stored positions per prefix to bound memory
const MAX_POSITIONS_PER_PREFIX: usize = 32;

/// Trigger hash table compaction when entry count exceeds this
const MAX_HASH_TABLE_ENTRIES: usize = 50_000;

/// Compaction evicts down to this low watermark, so it runs at most once per
/// `MAX_HASH_TABLE_ENTRIES - COMPACT_TARGET_ENTRIES` inserted prefixes
const COMPACT_TARGET_ENTRIES: usize = MAX_HASH_TABLE_ENTRIES / 2;

/// ZGFX compressor maintaining a 2.5 MB history buffer and prefix hash table.
pub struct Compressor {
    history: Vec<u8>,
    /// 3-byte prefix → history positions, for O(1) match candidate lookup
    match_table: HashMap<[u8; 3], Vec<usize>>,
}

impl Compressor {
    pub fn new() -> Self {
        Self {
            history: Vec::with_capacity(HISTORY_SIZE),
            match_table: HashMap::new(),
        }
    }

    /// Compress `input` into raw ZGFX segment data (without segment headers).
    pub fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>, ZgfxError> {
        let mut bit_writer = BitWriter::new();
        let mut pos = 0;

        while pos < input.len() {
            let best_match = self.find_best_match(input, pos);

            if let Some(m) = best_match {
                if m.length >= MIN_MATCH_LENGTH {
                    Self::encode_match(&mut bit_writer, m.distance, m.length)?;
                    self.add_to_history(&input[pos..pos + m.length]);
                    pos += m.length;
                    continue;
                }
            }

            let byte = input[pos];
            Self::encode_literal(&mut bit_writer, byte)?;
            self.add_to_history(&[byte]);
            pos += 1;
        }

        Ok(bit_writer.finish())
    }

    /// Extend the sliding window, evicting oldest bytes when full.
    fn add_to_history(&mut self, bytes: &[u8]) {
        if self.history.len() + bytes.len() > HISTORY_SIZE {
            let overflow = (self.history.len() + bytes.len()) - HISTORY_SIZE;

            self.history.drain(..overflow);

            // Shift all stored positions to account for evicted bytes
            for positions in self.match_table.values_mut() {
                positions.retain_mut(|pos| {
                    if *pos >= overflow {
                        *pos -= overflow;
                        true
                    } else {
                        false
                    }
                });
            }
            self.match_table.retain(|_, positions| !positions.is_empty());
        }

        let base_pos = self.history.len();
        self.history.extend_from_slice(bytes);

        // For large chunks (match replays), sample every 4th position to keep
        // the hash table manageable without sacrificing much compression ratio
        let step_size = if bytes.len() > 256 { 4 } else { 1 };

        for i in (0..bytes.len().saturating_sub(MIN_MATCH_LENGTH - 1)).step_by(step_size) {
            let pos = base_pos + i;
            let prefix = [self.history[pos], self.history[pos + 1], self.history[pos + 2]];

            let entry = self.match_table.entry(prefix).or_default();

            if entry.len() < MAX_POSITIONS_PER_PREFIX {
                entry.push(pos);
            } else {
                // Evict oldest position to keep recent data preferred
                entry.remove(0);
                entry.push(pos);
            }
        }

        if self.match_table.len() > MAX_HASH_TABLE_ENTRIES {
            self.compact_hash_table();
        }

        // Index positions spanning the old/new data boundary so matches
        // that straddle the append point can be found
        for offset in [2, 1] {
            if base_pos >= offset && bytes.len() + offset > 2 {
                let pos = base_pos - offset;
                if pos + MIN_MATCH_LENGTH <= self.history.len() {
                    let prefix = [self.history[pos], self.history[pos + 1], self.history[pos + 2]];
                    let entry = self.match_table.entry(prefix).or_default();
                    if entry.last() != Some(&pos) {
                        if entry.len() >= MAX_POSITIONS_PER_PREFIX {
                            entry.remove(0);
                        }
                        entry.push(pos);
                    }
                }
            }
        }
    }

    /// Halve stored positions per prefix, then evict whole prefixes down to
    /// `COMPACT_TARGET_ENTRIES` when the table is over the cap.
    ///
    /// INVARIANT: the table holds at most `MAX_HASH_TABLE_ENTRIES` prefixes on
    /// return. Incompressible input yields a near-unique prefix per byte, so
    /// trimming position lists alone never lowers the prefix count; without
    /// evicting whole prefixes the table would stay above the threshold and the
    /// caller would re-run compaction on every literal byte at O(table) cost.
    /// Evicting to a lower watermark amortizes that cost to O(1) per byte.
    fn compact_hash_table(&mut self) {
        for positions in self.match_table.values_mut() {
            if positions.len() > MAX_POSITIONS_PER_PREFIX / 2 {
                let keep_from = positions.len() - (MAX_POSITIONS_PER_PREFIX / 2);
                *positions = positions[keep_from..].to_vec();
            }
        }
        self.match_table.retain(|_, positions| !positions.is_empty());

        if self.match_table.len() <= COMPACT_TARGET_ENTRIES {
            return;
        }

        // Keep the most-recently-seen prefixes; older ones point further back
        // than a fresh match can reach, and distance is capped at
        // MAX_MATCH_DISTANCE regardless. Each history position belongs to a
        // single prefix, so these newest positions are distinct and the cutoff
        // retains exactly COMPACT_TARGET_ENTRIES entries.
        let mut newest: Vec<usize> = self
            .match_table
            .values()
            .map(|positions| positions.last().copied().unwrap_or(0))
            .collect();
        let cutoff_index = newest.len() - COMPACT_TARGET_ENTRIES;
        let cutoff = *newest.select_nth_unstable(cutoff_index).1;
        self.match_table
            .retain(|_, positions| positions.last().is_some_and(|&pos| pos >= cutoff));
    }

    /// Search hash table for the longest match at `input[pos..]`.
    fn find_best_match(&self, input: &[u8], pos: usize) -> Option<Match> {
        let remaining = input.len() - pos;
        if remaining < MIN_MATCH_LENGTH || self.history.is_empty() {
            return None;
        }

        let prefix = [input[pos], input[pos + 1], input[pos + 2]];
        let candidates = self.match_table.get(&prefix)?;

        let max_match_len = remaining.min(MAX_MATCH_LENGTH);
        let mut best_match: Option<Match> = None;
        let search_limit = self.history.len().min(MAX_MATCH_DISTANCE);

        // Most recent candidates first — better locality, often longer matches
        for &hist_pos in candidates.iter().rev().take(MAX_CANDIDATES) {
            let distance = self.history.len() - hist_pos;

            if distance > search_limit {
                continue;
            }

            // Prefix already matched via hash table; extend from byte 3 onward
            let mut match_len = MIN_MATCH_LENGTH;

            while match_len < max_match_len
                && hist_pos + match_len < self.history.len()
                && self.history[hist_pos + match_len] == input[pos + match_len]
            {
                match_len += 1;
            }

            if best_match.as_ref().is_none_or(|b| match_len > b.length) {
                best_match = Some(Match {
                    distance,
                    length: match_len,
                });
            }

            // Good enough — diminishing returns from longer searches
            if match_len >= 32 {
                break;
            }
        }

        best_match
    }

    /// Select the ZGFX token whose distance range covers `distance`.
    #[expect(
        clippy::as_conversions,
        reason = "distance_base is u32 from TOKEN_TABLE, always fits usize on 32+ bit targets"
    )]
    fn find_match_token(distance: usize) -> MatchToken {
        for token in TOKEN_TABLE.iter().skip(26) {
            if let super::TokenType::Match {
                distance_value_size,
                distance_base,
            } = token.ty
            {
                let max_distance = distance_base as usize + (1 << distance_value_size) - 1;
                if distance <= max_distance {
                    return MatchToken {
                        prefix: token.prefix,
                        distance_value_size,
                        distance_base: distance_base as usize,
                    };
                }
            }
        }

        // Fallback: last token covers the full 2 MB history range
        if let super::TokenType::Match {
            distance_value_size,
            distance_base,
        } = TOKEN_TABLE[39].ty
        {
            MatchToken {
                prefix: TOKEN_TABLE[39].prefix,
                distance_value_size,
                distance_base: distance_base as usize,
            }
        } else {
            unreachable!("TOKEN_TABLE[39] is always a Match variant");
        }
    }

    /// Return the index of the literal token for `byte`, if one exists.
    fn find_literal_token(byte: u8) -> Option<usize> {
        for (i, token) in TOKEN_TABLE.iter().enumerate().take(26).skip(1) {
            if let super::TokenType::Literal { literal_value } = token.ty {
                if literal_value == byte {
                    return Some(i);
                }
            }
        }
        None
    }

    fn encode_literal(writer: &mut BitWriter, byte: u8) -> Result<(), ZgfxError> {
        if let Some(token_idx) = Self::find_literal_token(byte) {
            writer.write_bits_from_slice(TOKEN_TABLE[token_idx].prefix);
        } else {
            // Null literal: "0" prefix + 8-bit value
            writer.write_bit(false);
            writer.write_bits(u32::from(byte), 8);
        }
        Ok(())
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "distance_value bounded by token table, value fits u32"
    )]
    fn encode_match(writer: &mut BitWriter, distance: usize, length: usize) -> Result<(), ZgfxError> {
        let match_token = Self::find_match_token(distance);

        writer.write_bits_from_slice(match_token.prefix);

        let distance_value = distance - match_token.distance_base;
        writer.write_bits(distance_value as u32, match_token.distance_value_size);

        Self::encode_match_length(writer, length)?;

        Ok(())
    }

    /// Encode match length using the variable-length scheme from the spec.
    ///
    /// Length 3 is a special case (single zero bit). All other lengths use
    /// unary-coded token size: `token_size` one-bits, a zero bit, then
    /// `token_size + 1` value bits, where `length = 2^(token_size+1) + value`.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "length bounded by MAX_MATCH_LENGTH (u16), ilog2 result fits u32/usize"
    )]
    fn encode_match_length(writer: &mut BitWriter, length: usize) -> Result<(), ZgfxError> {
        if length == 3 {
            writer.write_bit(false);
        } else {
            let length_token_size = usize::try_from(length.ilog2()).expect("ilog2 of usize fits usize") - 1;
            let base = 1 << (length_token_size + 1);
            let value = length - base;

            for _ in 0..length_token_size {
                writer.write_bit(true);
            }
            writer.write_bit(false);

            writer.write_bits(value as u32, length_token_size + 1);
        }

        Ok(())
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
struct Match {
    distance: usize,
    length: usize,
}

struct MatchToken {
    prefix: &'static BitSlice<u8, Msb0>,
    distance_value_size: usize,
    distance_base: usize,
}

/// MSB-first bit writer for ZGFX token encoding.
struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bits_in_current: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current_byte: 0,
            bits_in_current: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bits_in_current);
        }
        self.bits_in_current += 1;

        if self.bits_in_current == 8 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_current = 0;
        }
    }

    fn write_bits(&mut self, value: u32, num_bits: usize) {
        for i in (0..num_bits).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn write_bits_from_slice(&mut self, bits: &BitSlice<u8, Msb0>) {
        for bit in bits {
            self.write_bit(*bit);
        }
    }

    /// Finalize: append partial byte (if any) and the ZGFX-required
    /// trailing byte indicating unused bits in the final data byte.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "unused_bits is 0..=7, always fits u8"
    )]
    fn finish(mut self) -> Vec<u8> {
        let unused_bits = if self.bits_in_current == 0 {
            0
        } else {
            8 - self.bits_in_current
        };

        if self.bits_in_current > 0 {
            self.bytes.push(self.current_byte);
        }

        self.bytes.push(unused_bits as u8);

        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_empty() {
        let mut compressor = Compressor::new();
        let compressed = compressor.compress(&[]).unwrap();

        assert_eq!(compressed.len(), 1);
        assert_eq!(compressed[0], 0);
    }

    #[test]
    fn compress_single_byte() {
        let mut compressor = Compressor::new();
        let compressed = compressor.compress(&[0x42]).unwrap();

        // Null literal: "0" + 8 bits + padding = 9 bits = 2 bytes + padding byte
        assert!(compressed.len() >= 2);
    }

    #[test]
    fn compress_round_trip() {
        use super::super::Decompressor;

        let mut compressor = Compressor::new();
        let mut decompressor = Decompressor::new();

        let data = b"Hello, ZGFX compression! This is a test.";
        let compressed = compressor.compress(data).unwrap();

        let mut output = Vec::new();
        decompressor.decompress_segment(&compressed, &mut output).unwrap();

        assert_eq!(&output, data);
    }

    #[test]
    fn compress_repetitive_data() {
        use super::super::Decompressor;

        let mut compressor = Compressor::new();
        let mut decompressor = Decompressor::new();

        let data = b"AAAAAAAAAABBBBBBBBBBCCCCCCCCCC";
        let compressed = compressor.compress(data).unwrap();

        let mut output = Vec::new();
        decompressor.decompress_segment(&compressed, &mut output).unwrap();

        assert_eq!(&output, data);
    }

    #[test]
    fn compress_large_patterned_data() {
        use super::super::Decompressor;

        let mut compressor = Compressor::new();
        let mut decompressor = Decompressor::new();

        let mut data = Vec::new();
        for i in 0..1000 {
            data.extend_from_slice(b"Pattern");
            data.push(u8::try_from(i % 256).unwrap());
        }

        let compressed = compressor.compress(&data).unwrap();

        let mut output = Vec::new();
        decompressor.decompress_segment(&compressed, &mut output).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn compress_high_entropy_round_trips_and_bounds_table() {
        use super::super::Decompressor;

        // A near-unique 3-byte prefix per byte is the compactor's worst case:
        // trimming per-prefix position lists frees nothing, so without evicting
        // whole prefixes the table grows past MAX_HASH_TABLE_ENTRIES and
        // compaction re-runs on every literal byte at O(table) cost. A
        // deterministic LCG makes the stream exceed the entry cap reproducibly.
        let mut state: u32 = 0x1234_5678;
        let data: Vec<u8> = core::iter::repeat_with(|| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            u8::try_from(state >> 24).unwrap()
        })
        .take(100_000)
        .collect();

        let mut compressor = Compressor::new();
        let compressed = compressor.compress(&data).unwrap();

        let mut decompressor = Decompressor::new();
        let mut output = Vec::new();
        decompressor.decompress_segment(&compressed, &mut output).unwrap();
        assert_eq!(output, data);

        assert!(
            compressor.match_table.len() <= MAX_HASH_TABLE_ENTRIES,
            "hash table must stay bounded, got {} entries",
            compressor.match_table.len()
        );
    }

    #[test]
    fn bit_writer_basic() {
        let mut writer = BitWriter::new();

        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bits(0b101, 3);

        let result = writer.finish();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0b10110100);
        assert_eq!(result[1], 2);
    }

    #[test]
    fn encode_literal_with_token() {
        let mut writer = BitWriter::new();

        Compressor::encode_literal(&mut writer, 0x00).unwrap();

        let result = writer.finish();
        assert!(!result.is_empty());
    }

    #[test]
    fn encode_literal_null_prefix() {
        let mut writer = BitWriter::new();

        Compressor::encode_literal(&mut writer, 0x42).unwrap();

        let result = writer.finish();
        assert_eq!(result.len(), 3);
        assert_eq!(result[2], 7);
    }
}
