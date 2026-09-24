pub fn decode(buffer: &mut [i16]) {
    for i in 1..buffer.len() {
        buffer[i] = buffer[i].overflowing_add(buffer[i - 1]).0;
    }
}

pub fn encode(buffer: &mut [i16]) {
    if buffer.is_empty() {
        return;
    }
    let mut prev = buffer[0];
    for buf in buffer.iter_mut().skip(1) {
        let b = *buf;
        *buf = b.overflowing_sub(prev).0;
        prev = b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_does_not_panic_for_empty_buffer() {
        let mut buffer = [];
        decode(&mut buffer);
        assert!(buffer.is_empty());
    }

    #[test]
    fn decode_does_not_change_buffer_with_one_element() {
        let mut buffer = [1];
        decode(&mut buffer);
        assert_eq!([1], buffer);
    }

    #[test]
    fn decode_changes_last_element_for_buffer_with_two_elements() {
        let mut buffer = [1, 2];
        let expected = [1, 3];
        decode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn decode_changes_last_element_for_buffer_with_min_elements() {
        let mut buffer = [-32768, -32768, -32768, -32768, -32768];
        let expected = [-32768, 0, -32768, 0, -32768];
        decode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn encode_changes_last_element_for_buffer_with_min_elements() {
        let mut buffer = [-32768, 0, -32768, 0, -32768];
        let expected = [-32768, -32768, -32768, -32768, -32768];
        encode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn decode_changes_last_element_for_buffer_with_max_elements() {
        let mut buffer = [32767, 32767, 32767, 32767, 32767];
        let expected = [32767, -2, 32765, -4, 32763];
        decode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn encode_changes_last_element_for_buffer_with_max_elements() {
        let mut buffer = [32767, -2, 32765, -4, 32763];
        let expected = [32767, 32767, 32767, 32767, 32767];
        encode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn decode_does_not_change_zeroed_buffer() {
        let mut buffer = [0, 0, 0, 0, 0];
        let expected = [0, 0, 0, 0, 0];
        decode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn encode_does_not_change_zeroed_buffer() {
        let mut buffer = [0, 0, 0, 0, 0];
        let expected = [0, 0, 0, 0, 0];
        encode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn decode_works_with_five_not_zeroed_elements() {
        let mut buffer = [1, 2, 3, 4, 5];
        let expected = [1, 3, 6, 10, 15];
        decode(&mut buffer);
        assert_eq!(expected, buffer);
    }

    #[test]
    fn encode_works_with_five_not_zeroed_elements() {
        let mut buffer = [1, 3, 6, 10, 15];
        let expected = [1, 2, 3, 4, 5];
        encode(&mut buffer);
        assert_eq!(expected, buffer);
    }
}
