use core::cmp::min;
use std::io;

pub(crate) struct FixedCircularBuffer {
    buffer: Vec<u8>,
    position: usize,
}

impl FixedCircularBuffer {
    pub(crate) fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            position: 0,
        }
    }

    pub(crate) fn read_with_offset(&self, offset: usize, length: usize, output: &mut impl io::Write) -> io::Result<()> {
        let position = (self.buffer.len() + self.position - offset) % self.buffer.len();

        // will take the offset if the destination length is greater than the offset,
        // i.e. greater than the current buffer position.
        let dst_length = min(offset, length);
        let mut written = 0;

        if position + dst_length <= self.buffer.len() {
            while written < length {
                let to_write = min(length - written, dst_length);
                output.write_all(&self.buffer[position..position + to_write])?;
                written += to_write;
            }
        } else {
            let to_front = &self.buffer[position..];
            let to_back = &self.buffer[..dst_length - to_front.len()];

            while written < length {
                let to_write = min(length - written, dst_length);

                let to_write_to_front = min(to_front.len(), to_write);
                output.write_all(&to_front[..to_write_to_front])?;
                output.write_all(&to_back[..to_write - to_write_to_front])?;

                written += to_write;
            }
        }

        Ok(())
    }
}

impl io::Write for FixedCircularBuffer {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let bytes_written = buf.len();

        if buf.len() > self.buffer.len() {
            let residue = buf.len() - self.buffer.len();
            buf = &buf[residue..];
            self.position = (self.position + residue) % self.buffer.len();
        }

        if self.position + buf.len() <= self.buffer.len() {
            self.buffer[self.position..self.position + buf.len()].clone_from_slice(buf);

            self.position += buf.len();
        } else {
            let (to_back, to_front) = buf.split_at(self.buffer.len() - self.position);
            self.buffer[self.position..].clone_from_slice(to_back);
            self.buffer[0..to_front.len()].clone_from_slice(to_front);

            self.position = buf.len() - to_back.len();
        }

        if self.position == self.buffer.len() {
            self.position = 0;
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn fixed_circular_buffer_correctly_writes_buffer_less_then_internal_buffer_size() {
        let size = 8;
        let mut circular_buffer = FixedCircularBuffer::new(size);
        let to_write = [1, 2, 3];

        circular_buffer.write_all(to_write.as_ref()).unwrap();

        assert_eq!(vec![1, 2, 3, 0, 0, 0, 0, 0], circular_buffer.buffer);
        assert_eq!(to_write.len(), circular_buffer.position);
    }

    #[test]
    fn fixed_circular_buffer_correctly_writes_buffer_less_then_internal_buffer_size_to_end() {
        let size = 8;
        let mut circular_buffer = FixedCircularBuffer::new(size);
        circular_buffer.position = 5;
        let to_write = [1, 2, 3];

        circular_buffer.write_all(to_write.as_ref()).unwrap();

        assert_eq!(vec![0, 0, 0, 0, 0, 1, 2, 3], circular_buffer.buffer);
        assert_eq!(0, circular_buffer.position);
    }

    #[test]
    fn fixed_circular_buffer_correctly_writes_buffer_bigger_then_position_with_remaining_size() {
        let size = 8;
        let mut circular_buffer = FixedCircularBuffer::new(size);
        circular_buffer.position = 6;
        let to_write = [1, 2, 3];

        circular_buffer.write_all(to_write.as_ref()).unwrap();

        assert_eq!(vec![3, 0, 0, 0, 0, 0, 1, 2], circular_buffer.buffer);
        assert_eq!(1, circular_buffer.position);
    }

    #[test]
    fn fixed_circular_buffer_correctly_writes_buffer_bigger_then_internal_buffer_size() {
        let size = 8;
        let mut circular_buffer = FixedCircularBuffer::new(size);
        let to_write = (1..=10).collect::<Vec<_>>();

        circular_buffer.write_all(to_write.as_ref()).unwrap();

        assert_eq!(vec![9, 10, 3, 4, 5, 6, 7, 8], circular_buffer.buffer);
        assert_eq!(2, circular_buffer.position);
    }

    #[test]
    fn fixed_circular_buffer_correctly_writes_buffer_bigger_then_internal_buffer_size_with_position_at_end() {
        let size = 8;
        let mut circular_buffer = FixedCircularBuffer::new(size);
        circular_buffer.position = 6;
        let to_write = (1..=10).collect::<Vec<_>>();

        circular_buffer.write_all(to_write.as_ref()).unwrap();

        assert_eq!(vec![3, 4, 5, 6, 7, 8, 9, 10], circular_buffer.buffer);
        assert_eq!(0, circular_buffer.position);
    }

    #[test]
    fn fixed_circular_buffer_correctly_reads_buffer_with_length_not_greater_then_buffer_length() {
        let circular_buffer = FixedCircularBuffer {
            buffer: vec![11, 12, 13, 14, 15, 16, 7, 8, 9, 10],
            position: 6,
        };
        let expected = vec![11, 12, 13, 14];

        let mut output = Vec::with_capacity(expected.len());
        circular_buffer.read_with_offset(6, 4, &mut output).unwrap();
        assert_eq!(expected, output);
    }

    #[test]
    fn fixed_circular_buffer_correctly_reads_buffer_from_end_to_start() {
        let circular_buffer = FixedCircularBuffer {
            buffer: vec![11, 12, 13, 14, 15, 16, 7, 8, 9, 10],
            position: 6,
        };
        let expected = vec![8, 9, 10, 11, 12, 13, 14];

        let mut output = Vec::with_capacity(expected.len());
        circular_buffer.read_with_offset(9, 7, &mut output).unwrap();
        assert_eq!(expected, output);
    }

    #[test]
    fn fixed_circular_buffer_correctly_reads_buffer_with_repeating_one_byte() {
        let circular_buffer = FixedCircularBuffer {
            buffer: vec![11, 12, 13, 14, 15, 16, 7, 8, 9, 10],
            position: 6,
        };
        let expected = vec![16; 7];

        let mut output = Vec::with_capacity(expected.len());
        circular_buffer.read_with_offset(1, 7, &mut output).unwrap();
        assert_eq!(expected, output);
    }

    #[test]
    fn fixed_circular_buffer_correctly_reads_buffer_with_repeating_multiple_bytes() {
        let circular_buffer = FixedCircularBuffer {
            buffer: vec![11, 12, 13, 14, 15, 16, 7, 8, 9, 10],
            position: 6,
        };
        let expected = vec![14, 15, 16, 14, 15, 16, 14];

        let mut output = Vec::with_capacity(expected.len());
        circular_buffer.read_with_offset(3, 7, &mut output).unwrap();
        assert_eq!(expected, output);
    }

    #[test]
    fn fixed_circular_buffer_correctly_reads_buffer_with_repeating_multiple_bytes_from_end_to_start() {
        let circular_buffer = FixedCircularBuffer {
            buffer: vec![11, 12, 3, 4, 5, 6, 7, 8, 9, 10],
            position: 2,
        };
        let expected = vec![9, 10, 11, 12, 9, 10, 11];

        let mut output = Vec::with_capacity(expected.len());
        circular_buffer.read_with_offset(4, 7, &mut output).unwrap();
        assert_eq!(expected, output);
    }
}
