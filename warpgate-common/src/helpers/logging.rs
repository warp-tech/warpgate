/// Format a list of IDs for storage in LogEntry fields
pub fn format_related_ids<T: std::fmt::Display>(ids: &[T]) -> String {
    let mut result = String::new();
    for id in ids {
        result.push('$');
        result.push_str(&id.to_string());
    }
    result.push('$');
    result
}
