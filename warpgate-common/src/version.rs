use git_version::git_version;

pub const fn warpgate_version() -> &'static str {
    git_version!(
        args = ["--tags", "--always", "--dirty=-modified", "--match", "v[0-9]*"],
        fallback = "unknown"
    )
}
