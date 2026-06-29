pub fn username_eq_ci(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::username_eq_ci;

    #[test]
    fn matches_regardless_of_case() {
        assert!(username_eq_ci("Alice", "alice"));
        assert!(username_eq_ci("ALICE", "alice"));
        assert!(username_eq_ci("alice", "alice"));
    }

    #[test]
    fn rejects_different_names() {
        assert!(!username_eq_ci("alice", "bob"));
    }
}
