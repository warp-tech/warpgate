//! Inputs shared by the unit tests.

/// `N` distinct bytes counting up from `start` (wrapping): a deterministic
/// stand-in for a random salt, key or nonce. Unlike a uniform fill, a byte
/// taken from the wrong offset changes the result.
pub(crate) fn counting_bytes<const N: usize>(start: u8) -> [u8; N] {
    let mut next = start;
    std::array::from_fn(|_| {
        let byte = next;
        next = next.wrapping_add(1);
        byte
    })
}
