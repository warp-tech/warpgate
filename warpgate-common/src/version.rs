use git_version::git_version;

pub const fn warpgate_version() -> &'static str {
    git_version!(
        args = [
            "--tags",
            "--always",
            "--dirty=-modified",
            "--match",
            "v[0-9]*"
        ],
        fallback = "unknown"
    )
}

/// The release tag this build is at or descends from, from `git describe`
/// output such as `v0.30.4-12-gabc1234-modified`
fn release_tag(version: &str) -> Option<&str> {
    let version = version.strip_suffix("-modified").unwrap_or(version);
    // `-<commits since the tag>-g<hash>`
    let tag = match version.rsplitn(3, '-').collect::<Vec<_>>().as_slice() {
        [hash, commits, tag]
            if hash.starts_with('g') && commits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            tag
        }
        _ => version,
    };
    (tag.starts_with('v')
        && tag
            .get(1..2)
            .is_some_and(|c| c.bytes().all(|b| b.is_ascii_digit())))
    .then_some(tag)
}

/// A file in the repository as of this build's release, or of `main` for a
/// build without a release tag
pub fn repository_file_url(path: &str) -> String {
    let tree = release_tag(warpgate_version())
        .map_or_else(|| "heads/main".to_owned(), |tag| format!("tags/{tag}"));
    format!("https://raw.githubusercontent.com/warp-tech/warpgate/refs/{tree}/{path}")
}

#[cfg(test)]
mod tests {
    use super::release_tag;

    #[test]
    fn finds_the_release_tag() {
        assert_eq!(release_tag("v0.30.4"), Some("v0.30.4"));
        assert_eq!(release_tag("v0.30.4-modified"), Some("v0.30.4"));
        assert_eq!(release_tag("v0.30.4-12-gabc1234"), Some("v0.30.4"));
        assert_eq!(
            release_tag("v0.30.0-beta.2-3-gabc1234-modified"),
            Some("v0.30.0-beta.2")
        );
        assert_eq!(release_tag("v0.30.0-beta.2"), Some("v0.30.0-beta.2"));
        assert_eq!(release_tag("abc1234-modified"), None);
        assert_eq!(release_tag("unknown"), None);
    }
}
