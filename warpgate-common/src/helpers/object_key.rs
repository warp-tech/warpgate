/// The key of the object at `path` in a store with a key prefix. A blank
/// prefix adds nothing: a key that starts with `/` gives a `//` in the request
/// path, and a proxy that merges slashes then breaks the request's signature.
pub fn prefixed(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_owned()
    } else {
        format!("{}/{path}", prefix.strip_suffix('/').unwrap_or(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::prefixed;

    #[test]
    fn a_prefix_is_joined_with_one_slash() {
        for (prefix, expected) in [
            ("", "rec/1"),
            ("warpgate", "warpgate/rec/1"),
            ("warpgate/", "warpgate/rec/1"),
            ("/", "/rec/1"),
        ] {
            assert_eq!(prefixed(prefix, "rec/1"), expected, "{prefix:?}");
        }
    }
}
