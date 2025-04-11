use git_version::git_version;

pub fn warpgate_version() -> &'static str {
    git_version!(
        args = ["--tags", "--always", "--dirty=-modified"],
        fallback = "unknown"
    )
}
