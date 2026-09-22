//! Simplified Run-Length (SRL) entropy coding for progressive upgrade passes.
//!
//! SRL is a stateful bit stream for each component of a TILE_UPGRADE.
//! Its zero runs and adaptive `KP` state continue across DWT bands.
//! See MS-RDPEGFX sections 3.1.8.1.5 through 3.1.8.1.5.2.

const INITIAL_KP: u8 = 8;
const MAX_KP: u8 = 80;
// This conservative malformed-stream bound includes LL3 entries, although LL3 is raw-coded.
const MAX_ZERO_RUN: usize = 4096;

/// Errors encountered while decoding or encoding an SRL stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrlError {
    /// The required trailing zero byte is absent.
    MissingTerminator,
    /// The stream ended before a complete code word was read.
    Truncated,
    /// An SRL value requires between one and fifteen magnitude bits.
    InvalidBitCount(u8),
    /// A value cannot be represented by the magnitude width.
    MagnitudeOutOfRange { magnitude: u16, max: u16 },
    /// A zero run exceeds the number of coefficients in one component.
    ZeroRunTooLong,
}

impl core::fmt::Display for SrlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingTerminator => write!(f, "srl stream is missing its trailing zero byte"),
            Self::Truncated => write!(f, "srl stream is truncated"),
            Self::InvalidBitCount(bits) => write!(f, "invalid srl magnitude bit count {bits}"),
            Self::MagnitudeOutOfRange { magnitude, max } => {
                write!(f, "srl magnitude {magnitude} exceeds maximum {max}")
            }
            Self::ZeroRunTooLong => write!(f, "srl zero run exceeds the component coefficient count"),
        }
    }
}

impl core::error::Error for SrlError {}

/// Stateful decoder for one component's SRL stream.
///
/// Construct one decoder for each of the Y, Cb, and Cr streams in a
/// TILE_UPGRADE, then call [`Self::decode`] for each band that has SRL entries.
pub struct SrlDecoder<'a> {
    reader: BitReader<'a>,
    kp: u8,
    zero_run_remaining: usize,
    nonzero_pending: bool,
}

impl<'a> SrlDecoder<'a> {
    /// Create a decoder for an SRL stream, excluding its required trailing zero byte.
    pub fn new(data: &'a [u8]) -> Result<Self, SrlError> {
        let Some((&terminator, payload)) = data.split_last() else {
            return Err(SrlError::MissingTerminator);
        };

        if terminator != 0 {
            return Err(SrlError::MissingTerminator);
        }

        Ok(Self {
            reader: BitReader::new(payload),
            kp: INITIAL_KP,
            zero_run_remaining: 0,
            nonzero_pending: false,
        })
    }

    /// Decode `num_values` entries for one DWT band.
    ///
    /// The adaptive state and a partially consumed zero run are retained for the
    /// next call, as required when SRL entries span bands.
    pub fn decode(&mut self, num_values: usize, num_bits: u8) -> Result<Vec<i16>, SrlError> {
        let mut output = Vec::with_capacity(num_values);

        while output.len() < num_values {
            if self.zero_run_remaining != 0 {
                self.zero_run_remaining -= 1;
                output.push(0);
                continue;
            }

            if self.nonzero_pending {
                output.push(self.decode_nonzero(num_bits)?);
                self.nonzero_pending = false;
                continue;
            }

            self.zero_run_remaining = self.decode_zero_run()?;
            self.nonzero_pending = true;
        }

        Ok(output)
    }

    fn decode_zero_run(&mut self) -> Result<usize, SrlError> {
        let mut zeros = 0usize;

        loop {
            let k = self.kp / 8;

            if self.reader.read_bit()? {
                let tail = usize::try_from(self.reader.read_bits(k)?).map_err(|_| SrlError::ZeroRunTooLong)?;
                self.kp = self.kp.saturating_sub(6);

                let zeros = zeros.checked_add(tail).ok_or(SrlError::ZeroRunTooLong)?;
                return (zeros <= MAX_ZERO_RUN).then_some(zeros).ok_or(SrlError::ZeroRunTooLong);
            }

            let chunk = 1usize << k;
            zeros = zeros.checked_add(chunk).ok_or(SrlError::ZeroRunTooLong)?;
            if zeros > MAX_ZERO_RUN {
                return Err(SrlError::ZeroRunTooLong);
            }

            self.kp = self.kp.saturating_add(4).min(MAX_KP);
        }
    }

    fn decode_nonzero(&mut self, num_bits: u8) -> Result<i16, SrlError> {
        let maximum = max_magnitude(num_bits)?;
        let sign = self.reader.read_bit()?;
        let mut zero_count = 0u16;

        while zero_count + 1 < maximum {
            if self.reader.read_bit()? {
                break;
            }

            zero_count += 1;
        }

        let magnitude = zero_count + 1;
        let magnitude = i16::try_from(magnitude).map_err(|_| SrlError::MagnitudeOutOfRange {
            magnitude,
            max: maximum,
        })?;

        Ok(if sign { -magnitude } else { magnitude })
    }
}

/// Stateful encoder for one component's SRL stream.
pub struct SrlEncoder {
    writer: BitWriter,
    kp: u8,
    pending_zeros: usize,
}

impl SrlEncoder {
    /// Create an encoder for a component's SRL stream.
    pub fn new() -> Self {
        Self {
            writer: BitWriter::new(),
            kp: INITIAL_KP,
            pending_zeros: 0,
        }
    }

    /// Encode SRL entries for one DWT band.
    ///
    /// The caller must use one encoder across all bands in a component.
    pub fn encode(&mut self, values: &[i16], num_bits: u8) -> Result<(), SrlError> {
        let maximum = max_magnitude(num_bits)?;
        for &value in values {
            if value == 0 {
                let zeros = self.pending_zeros.checked_add(1).ok_or(SrlError::ZeroRunTooLong)?;
                self.pending_zeros = (zeros <= MAX_ZERO_RUN)
                    .then_some(zeros)
                    .ok_or(SrlError::ZeroRunTooLong)?;
                continue;
            }

            self.encode_zero_run(self.pending_zeros)?;
            self.pending_zeros = 0;

            let magnitude = value.unsigned_abs();
            if magnitude == 0 || magnitude > maximum {
                return Err(SrlError::MagnitudeOutOfRange {
                    magnitude,
                    max: maximum,
                });
            }

            self.writer.write_bit(value < 0);
            for _ in 1..magnitude {
                self.writer.write_bit(false);
            }
            if magnitude < maximum {
                self.writer.write_bit(true);
            }
        }

        Ok(())
    }

    /// Finish the stream, adding the required trailing zero byte.
    pub fn finish(mut self) -> Result<Vec<u8>, SrlError> {
        if self.pending_zeros != 0 {
            self.encode_zero_run(self.pending_zeros)?;
        }

        let mut result = self.writer.finish();
        result.push(0);
        Ok(result)
    }

    fn encode_zero_run(&mut self, mut zeros: usize) -> Result<(), SrlError> {
        while zeros >= 1usize << (self.kp / 8) {
            self.writer.write_bit(false);
            zeros -= 1usize << (self.kp / 8);
            self.kp = self.kp.saturating_add(4).min(MAX_KP);
        }

        let k = self.kp / 8;
        self.writer.write_bit(true);
        self.writer
            .write_bits(u32::try_from(zeros).map_err(|_| SrlError::ZeroRunTooLong)?, k);
        self.kp = self.kp.saturating_sub(6);

        Ok(())
    }
}

impl Default for SrlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode one complete SRL stream.
///
/// This convenience function is suitable when all entries use the same
/// magnitude width. Progressive tile decoding should use [`SrlDecoder`]
/// directly so its state continues between bands.
pub fn decode_srl(data: &[u8], num_values: usize, num_bits: u8) -> Result<Vec<i16>, SrlError> {
    let mut decoder = SrlDecoder::new(data)?;
    decoder.decode(num_values, num_bits)
}

/// Encode one complete SRL stream.
///
/// This convenience function is suitable when all entries use the same
/// magnitude width. Progressive tile encoding should use [`SrlEncoder`]
/// directly so its state continues between bands.
pub fn encode_srl(values: &[i16], num_bits: u8) -> Result<Vec<u8>, SrlError> {
    let mut encoder = SrlEncoder::new();
    encoder.encode(values, num_bits)?;
    encoder.finish()
}

fn max_magnitude(num_bits: u8) -> Result<u16, SrlError> {
    if !(1..=15).contains(&num_bits) {
        return Err(SrlError::InvalidBitCount(num_bits));
    }

    Ok((1u16 << num_bits) - 1)
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_idx: 0,
            bit_idx: 0,
        }
    }

    fn read_bit(&mut self) -> Result<bool, SrlError> {
        let Some(&byte) = self.data.get(self.byte_idx) else {
            return Err(SrlError::Truncated);
        };

        let bit = (byte >> (7 - self.bit_idx)) & 1 != 0;
        self.bit_idx += 1;
        if self.bit_idx == 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }

        Ok(bit)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32, SrlError> {
        let mut value = 0u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Ok(value)
    }
}

struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_count: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bit_count: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | u8::from(bit);
        self.bit_count += 1;
        if self.bit_count == 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bit_count = 0;
        }
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count != 0 {
            self.current <<= 8 - self.bit_count;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_initial_kp_and_unary_magnitude() {
        // MS-RDPEGFX 3.1.8.1.5.1 initializes KP to 8, so K is one.
        // The wire bits are zero run 0 (10), positive sign (0), magnitude 3 (001).
        assert_eq!(decode_srl(&[0x84, 0x00], 1, 4), Ok(vec![3]));
    }

    #[test]
    fn preserves_zero_run_and_kp_between_bands() {
        // A two-zero run (010) spans the first and second calls.
        // The following positive magnitude-one value uses K=0 after the run.
        let mut decoder = SrlDecoder::new(&[0x48, 0x00]).unwrap();
        assert_eq!(decoder.decode(1, 4), Ok(vec![0]));
        assert_eq!(decoder.decode(2, 4), Ok(vec![0, 1]));
    }

    #[test]
    fn decodes_unterminated_maximum_magnitude() {
        // MS-RDPEGFX 3.1.8.1.5.2 omits the unary terminator for the maximum value.
        // The payload is zero run 0, negative sign, and six zero unary bits for -7.
        assert_eq!(decode_srl(&[0xA0, 0x00, 0x00], 1, 3), Ok(vec![-7]));
    }

    #[test]
    fn rejects_truncated_stream() {
        assert_eq!(decode_srl(&[0x80, 0x00], 1, 4), Err(SrlError::Truncated));
    }

    #[test]
    fn rejects_missing_terminator() {
        assert_eq!(decode_srl(&[0x84], 1, 4), Err(SrlError::MissingTerminator));
    }

    #[test]
    fn rejects_out_of_range_magnitude() {
        assert_eq!(
            encode_srl(&[8], 3),
            Err(SrlError::MagnitudeOutOfRange { magnitude: 8, max: 7 })
        );
    }

    #[test]
    fn rejects_zero_run_longer_than_component() {
        assert_eq!(encode_srl(&vec![0; MAX_ZERO_RUN + 1], 1), Err(SrlError::ZeroRunTooLong));
    }

    #[test]
    fn encodes_empty_stream() {
        assert_eq!(encode_srl(&[], 1), Ok(vec![0x00]));
    }

    #[test]
    fn round_trips_mixed_values() {
        let original = [0, 0, 1, -1, 0, 3];
        let encoded = encode_srl(&original, 4).unwrap();
        assert_eq!(encoded, vec![0x4F, 0x44, 0x00]);
        let mut decoder = SrlDecoder::new(&encoded).unwrap();
        assert_eq!(decoder.decode(2, 4), Ok(vec![0, 0]));
        assert_eq!(decoder.decode(1, 4), Ok(vec![1]));
        assert_eq!(decoder.decode(1, 4), Ok(vec![-1]));
        assert_eq!(decoder.decode(1, 4), Ok(vec![0]));
        assert_eq!(decoder.decode(1, 4), Ok(vec![3]));
        assert_eq!(decode_srl(&encoded, original.len(), 4), Ok(original.to_vec()));
    }

    #[test]
    fn preserves_zero_runs_between_bands_when_encoding() {
        let mut encoder = SrlEncoder::new();
        encoder.encode(&[0], 4).unwrap();
        encoder.encode(&[0, 1], 4).unwrap();
        assert_eq!(encoder.finish(), Ok(vec![0x48, 0x00]));
    }

    #[test]
    fn bit_writer_multi_byte() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xFF, 8);
        writer.write_bits(0x00, 8);
        assert_eq!(writer.finish(), vec![0xFF, 0x00]);
    }
}
